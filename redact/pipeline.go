package redact

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type mode uint8

const (
	modeField   mode = iota // Redact and RedactGroup
	modeUnit                // RedactUnitName (R11)
	modeRelease             // RedactReleaseVersion (R16)
	modeScan                // Scan (R18)
)

// pass is the state of redacting one item. Nothing in it outlives the
// item (R3).
type pass struct {
	r     *Redactor
	f     Field
	class Class
	mode  mode
	ctx   context.Context
	now   func() time.Time
	end   time.Time
	rep   Report
}

func (r *Redactor) newPass(ctx context.Context, f Field, m mode) *pass {
	return &pass{r: r, f: f, class: f.Class, mode: m, ctx: ctx, now: r.cfg.now, end: r.cfg.now().Add(ItemDeadline)}
}

// check enforces the per-item deadline (R36) and the caller's context.
func (ps *pass) check() error {
	if ps.ctx != nil && ps.ctx.Err() != nil {
		return ErrDeadline
	}
	if ps.now().After(ps.end) {
		return ErrDeadline
	}
	return nil
}

// seg is a piece of output that redaction inserted. A cut never falls
// inside one (R40); a marker segment may become the short marker.
type seg struct {
	start, end int
	marker     bool
}

// part is one field of an item: a P4 group has one per message.
type part struct {
	text string
	segs []seg
	cap  int // growth cap (R31)
}

// hit is a merged match over the joined text of an item.
type hit struct {
	start, end int
	repl       string
	det        int // index in the rule table; the earliest wins a merge
	ip         bool
}

// redactParts runs detection, replacement, the output limit and the
// post-check (R30–R32, R40) over the normalised parts of one item.
func (ps *pass) redactParts(parts []part) error {
	for round := 0; ; round++ {
		joined, offs := joinParts(parts)
		hits, err := ps.detect(joined)
		if err != nil {
			return err
		}
		if round > 0 && len(hits) == 0 {
			return nil
		}
		if round == 2 {
			return ErrPostCheck
		}
		if err := ps.check(); err != nil {
			return err
		}
		if ps.projected(joined, hits) > totalCap(parts) {
			// The growth cap (R31) is checked from the hits before any
			// output is built, so a crafted input never allocates the
			// oversized result.
			return ErrOutputTooLarge
		}
		if err := ps.apply(parts, hits, offs); err != nil {
			return err
		}
	}
}

// projected is the length the replaced text would have.
func (ps *pass) projected(s string, hits []hit) int {
	n := len(s)
	for _, h := range hits {
		r := h.repl
		if !h.ip {
			r = ps.marker(ps.r.rules[h.det].id)
		}
		n += len(r) - (h.end - h.start)
	}
	return n
}

func totalCap(parts []part) int {
	n := len(parts) - 1
	for _, p := range parts {
		n += p.cap
	}
	return n
}

func joinParts(parts []part) (string, []int) {
	offs := make([]int, len(parts))
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte('\n')
		}
		offs[i] = b.Len()
		b.WriteString(p.text)
	}
	return b.String(), offs
}

// detect runs every detector that applies to the item over s and returns
// the merged matches in order.
func (ps *pass) detect(s string) ([]hit, error) {
	unitEnd := len(s)
	if ps.mode == modeUnit && strings.HasSuffix(s, ".service") {
		unitEnd = len(s) - len(".service")
	}
	var hits []hit
	for i := range ps.r.rules {
		d := &ps.r.rules[i]
		if !ps.applies(d) {
			continue
		}
		if err := ps.check(); err != nil {
			return nil, err
		}
		if hooks.detect != nil {
			hooks.detect(d.id, len(s))
		}
		spans, err := d.find(s)
		if err != nil {
			return nil, ErrInternal
		}
		hits = slices.Grow(hits, len(spans))
		for _, sp := range spans {
			if sp.start < 0 || sp.end > len(s) || sp.start >= sp.end ||
				!utf8.RuneStart(byteAt(s, sp.start)) || !utf8.RuneStart(byteAt(s, sp.end)) {
				return nil, ErrInternal
			}
			if ps.mode == modeUnit {
				// R11: the span never includes the .service suffix.
				if sp.end = min(sp.end, unitEnd); sp.start >= sp.end {
					continue
				}
			}
			if isMarkerText(s[sp.start:sp.end]) || protectedSpan(s, d, sp) {
				continue
			}
			if d.extend && ps.mode == modeField {
				sp = extendSpan(s, sp, d.kind == kindValue)
			}
			hits = append(hits, hit{start: sp.start, end: sp.end, det: i, repl: sp.repl, ip: d.kind == kindIP})
		}
	}
	return mergeHits(hits), nil
}

// byteAt returns s[i], or a rune-start byte at the end of s.
func byteAt(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

func (ps *pass) applies(d *detector) bool {
	// Scan (U bodies) and the release version take every detector that
	// replaces with a marker: a match there withholds or replaces the whole
	// value (R16, R18).
	if ps.mode == modeScan || ps.mode == modeRelease {
		return d.kind != kindIP
	}
	if d.kind == kindIP && ps.f.MarkersOnly {
		return false
	}
	return d.classes.has(ps.class)
}

// tokenBoundary is R31's token boundary for "extend".
func tokenBoundary(c byte) bool {
	return strings.IndexByte(" \t\n\"',;&<>", c) >= 0
}

// extendSpan widens a match to the nearest token boundaries (R31). A value
// detector keeps its key and separator, so only the end moves.
func extendSpan(s string, sp span, valueOnly bool) span {
	if !valueOnly {
		for sp.start > 0 && !tokenBoundary(s[sp.start-1]) {
			sp.start--
		}
	}
	for sp.end < len(s) && !tokenBoundary(s[sp.end]) {
		sp.end++
	}
	return sp
}

// mergeHits merges overlapping and adjacent matches into one span with
// the earliest detector of §4.2 (R31), in place. Two adjacent IP
// truncations stay separate: each keeps its own network.
func mergeHits(hits []hit) []hit {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].det < hits[j].det
	})
	out := hits[:0]
	for _, h := range hits {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if h.start < last.end || (h.start == last.end && (!h.ip || !last.ip)) {
				last.end = max(last.end, h.end)
				if h.det < last.det {
					last.det, last.repl, last.ip = h.det, h.repl, h.ip
				}
				if !h.ip {
					last.ip = false
				}
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

// protectedSpan reports whether a match lies inside text no detector may
// change (R33): a pseudonym for every detector, a canonical UUID for every
// detector that does not read a key (ruling on issue #9, point 12), and a
// long hex run (a digest or container ID) for the number detectors. Only
// the token around the match is examined.
func protectedSpan(s string, d *detector, sp span) bool {
	a, b := sp.start, sp.end
	for a > 0 && isTokenHex(s[a-1]) {
		a--
	}
	for b < len(s) && isTokenHex(s[b]) {
		b++
	}
	token := s[a:b]
	if within(pseudonymRe.FindAllStringIndex(token, -1), a, sp) {
		return true
	}
	if d.kind != kindValue && within(uuidRe.FindAllStringIndex(token, -1), a, sp) {
		return true
	}
	return d.numeric && within(hexRunRe.FindAllStringIndex(token, -1), a, sp)
}

// isTokenHex is a character of a UUID, a hex run or a pseudonym.
func isTokenHex(c byte) bool { return isHexByte(c) || c == '-' || c == 'u' }

func within(spans [][]int, off int, sp span) bool {
	for _, o := range spans {
		if sp.start >= o[0]+off && sp.end <= o[1]+off {
			return true
		}
	}
	return false
}

// apply replaces the hits in every part, then applies the output limit.
func (ps *pass) apply(parts []part, hits []hit, offs []int) error {
	for i := range parts {
		a, b := offs[i], offs[i]+len(parts[i].text)
		local := make([]localHit, 0, len(hits))
		for k := range hits {
			h := &hits[k]
			s, e := max(h.start, a), min(h.end, b)
			if s >= e {
				continue
			}
			// A span that crosses into this message from an earlier one
			// leaves its marker there; here its text is only removed.
			cont := h.start < a && hitPlaced(h, offs, parts, i)
			local = append(local, localHit{hit: hit{start: s - a, end: e - a, det: h.det, repl: h.repl, ip: h.ip}, cont: cont})
		}
		out, segs, err := ps.replace(parts[i], local)
		if err != nil {
			return err
		}
		if ps.mode == modeField {
			out, segs = truncate(out, segs, ps.f.MaxBytes, ps.shortMarker())
		}
		parts[i].text, parts[i].segs = out, segs
	}
	return nil
}

type localHit struct {
	hit
	cont bool
}

// hitPlaced reports whether h already has text in a part before part i.
func hitPlaced(h *hit, offs []int, parts []part, i int) bool {
	for j := 0; j < i; j++ {
		if max(h.start, offs[j]) < min(h.end, offs[j]+len(parts[j].text)) {
			return true
		}
	}
	return false
}

// replace builds one part's output. The growth cap (R31) is checked while
// building, so a crafted input never allocates past it.
func (ps *pass) replace(p part, hits []localHit) (string, []seg, error) {
	var b strings.Builder
	segs := make([]seg, 0, len(hits)+len(p.segs))
	type chunk struct{ in, out, n int }
	chunks := make([]chunk, 0, len(hits)+1)
	pos := 0
	for _, h := range hits {
		chunks = append(chunks, chunk{in: pos, out: b.Len(), n: h.start - pos})
		b.WriteString(p.text[pos:h.start])
		var r string
		isMarker := false
		switch {
		case h.cont:
		case h.ip:
			r = h.repl
		default:
			r, isMarker = ps.marker(ps.r.rules[h.det].id), true
			ps.rep.MarkerFired = true
		}
		if !h.cont {
			if ps.rep.Replaced == nil {
				ps.rep.Replaced = map[string]int{}
			}
			ps.rep.Replaced[ps.r.rules[h.det].id]++
		}
		if r != "" {
			segs = append(segs, seg{start: b.Len(), end: b.Len() + len(r), marker: isMarker})
			b.WriteString(r)
		}
		if b.Len() > p.cap {
			return "", nil, ErrOutputTooLarge
		}
		pos = h.end
	}
	chunks = append(chunks, chunk{in: pos, out: b.Len(), n: len(p.text) - pos})
	b.WriteString(p.text[pos:])
	if b.Len() > p.cap {
		return "", nil, ErrOutputTooLarge
	}
	// Segments from earlier steps move with the unchanged text around them.
	for _, s := range p.segs {
		for _, c := range chunks {
			if s.start >= c.in && s.end <= c.in+c.n {
				d := c.out - c.in
				segs = append(segs, seg{start: s.start + d, end: s.end + d, marker: s.marker})
				break
			}
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].start < segs[j].start })
	return b.String(), segs, nil
}

func (ps *pass) marker(id string) string {
	switch {
	case ps.mode == modeUnit:
		return "REDACTED-" + id
	case ps.class == TName || ps.class == TPath:
		return "redacted-" + id
	}
	return Marker(id)
}

func (ps *pass) shortMarker() string {
	if ps.class == TName || ps.class == TPath {
		return NameShortMarker
	}
	return ShortMarker
}

// truncate applies the output limit at a UTF-8 boundary and never inside
// an inserted segment: the cut moves before it, or a marker becomes the
// short marker when that fits (R40).
func truncate(s string, segs []seg, limit int, short string) (string, []seg) {
	if len(s) <= limit {
		return s, segs
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	var kept []seg
	for _, sg := range segs {
		if sg.end <= cut {
			kept = append(kept, sg)
			continue
		}
		if sg.start < cut {
			if sg.marker && sg.start+len(short) <= limit {
				return s[:sg.start] + short, append(kept, seg{start: sg.start, end: sg.start + len(short), marker: true})
			}
			cut = sg.start
		}
		break
	}
	return s[:cut], kept
}
