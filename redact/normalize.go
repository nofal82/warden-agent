package redact

import (
	"strings"
	"unicode/utf8"
)

const esc = 0x1b

// The normalisation tables of R25a–R28b. Each is data the code reads, so
// the rule-set digest covers it (R43, §4.5).
var (
	// simpleEscapes are the fixed R25a escapes and the byte each decodes
	// to. "\\" is not one: it stays as text, read as a pair from the left.
	simpleEscapes = []struct {
		text string
		b    byte
	}{{`\/`, '/'}, {`\e`, esc}, {`\x1b`, esc}, {`\x1B`, esc}}
	// rsyslogEscapes are the "#ddd" octal escapes decoded (000–037, 177).
	rsyslogEscapes = func() []string {
		var out []string
		for v := 0; v < 0x20; v++ {
			out = append(out, string([]byte{'0', byte('0' + v>>3), byte('0' + v&7)}))
		}
		return append(out, "177")
	}()
	bidiRanges      = []runeRange{{0x061c, 0x061c}, {0x200e, 0x200f}, {0x202a, 0x202e}, {0x2066, 0x2069}}
	zeroWidthRanges = []runeRange{{0x00ad, 0x00ad}, {0x200b, 0x200d}, {0x2060, 0x2064}, {0xfeff, 0xfeff}}
	tagFillerRanges = []runeRange{{0x034f, 0x034f}, {0x115f, 0x1160}, {0x180e, 0x180e}, {0x3164, 0x3164},
		{0xfe00, 0xfe0f}, {0xffa0, 0xffa0}, {0xfff9, 0xfffb}, {0xe0000, 0xe007f}}
	// lineEnds are the R27 line ends other than LF (CR LF counts as one).
	lineEnds = []rune{'\r', 0x2028, 0x2029}
	// caseFolds is R28a: every non-ASCII character whose simple
	// case-folding orbit holds an ASCII letter, and that letter in
	// lowercase. A test checks it against unicode.SimpleFold.
	caseFolds = []struct {
		r  rune
		to byte
	}{{0x017f, 's'}, {0x212a, 'k'}}
)

// unicodeEscapeMax is the highest code point a \u00XX escape decodes
// (R25a: ASCII only).
const unicodeEscapeMax = 0x7f

// NormMaxPasses is REDACT_NORM_MAX_PASSES (R28b, §7): the confirming pass
// included, at most this many passes run.
const NormMaxPasses = 8

type runeRange struct{ lo, hi rune }

func inRanges(r rune, rs []runeRange) bool {
	for _, x := range rs {
		if r >= x.lo && r <= x.hi {
			return true
		}
	}
	return false
}

// Normalize applies the textual escapes of R25a (EText and TText only)
// and R25–R28a for class c, to a fixed point (R28b, §4.4). An item that
// still changes after NormMaxPasses passes is an error (ErrInternal).
func Normalize(c Class, in string) (string, NormCounts, error) {
	var n NormCounts
	out, err := normalise(c, in, &n, nil)
	if err != nil {
		return "", NormCounts{}, err
	}
	return out, n, nil
}

// normalise repeats one pass until a pass changes nothing (R28b). A single
// pass is not enough: removing a control character can join the halves of
// an escape ("#0\x0133"), and a decoded "\" starts a new one. Each pass
// counts only the changes it makes. The confirming pass counts toward
// NormMaxPasses, so a crafted alternation fails fast (ErrInternal, reason
// ERROR) instead of using the item deadline; check (R36) runs between
// passes.
func normalise(c Class, s string, n *NormCounts, check func() error) (string, error) {
	if hooks.normalise != nil {
		hooks.normalise(c, len(s))
	}
	for pass := 1; ; pass++ {
		next := normalisePass(c, s, n)
		if next == s {
			return s, nil
		}
		if pass == NormMaxPasses {
			return "", ErrInternal
		}
		s = next
		if check != nil {
			if err := check(); err != nil {
				return "", err
			}
		}
	}
}

func normalisePass(c Class, s string, n *NormCounts) string {
	if c == EText || c == TText {
		s = decodeEscapes(s)
	}
	if !utf8.ValidString(s) {
		// R25: remove each maximal invalid subsequence, so the halves of a
		// token split by a bad byte join up for the detectors.
		n[NormInvalidUTF8] += invalidRuns(s)
		s = strings.ToValidUTF8(s, "")
	}
	keepLines := c == EText
	special := func(r rune) bool {
		if r < 0x20 {
			return !keepLines || (r != '\n' && r != '\t')
		}
		return r == 0x7f || (r >= 0x80 && (r <= 0x9f || isLineEnd(r) ||
			isBidi(r) || isZeroWidth(r) || isTagOrFiller(r) || caseFold(r) != 0))
	}
	if strings.IndexFunc(s, special) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		// Copy the run of ordinary characters in one step.
		j := strings.IndexFunc(s[i:], special)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+j])
		i += j
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == esc:
			i = skipEscape(s, i)
			n[NormEscape]++
			continue
		case isLineEnd(r):
			if r == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				size = 2
			}
			n[NormLineSeparator]++
			lineBreak(&b, keepLines)
		case r == '\n' || r == '\t':
			if keepLines {
				b.WriteByte(s[i])
			} else {
				b.WriteByte(' ')
			}
		case isBidi(r):
			n[NormBidi]++
		case isZeroWidth(r):
			n[NormZeroWidth]++
		case isTagOrFiller(r):
			n[NormTagOrFiller]++
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			n[NormControl]++
		case caseFold(r) != 0:
			n[NormCaseFold]++
			b.WriteByte(caseFold(r))
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func lineBreak(b *strings.Builder, keepLines bool) {
	if keepLines {
		b.WriteByte('\n')
	} else {
		b.WriteByte(' ')
	}
}

// invalidRuns counts the maximal invalid UTF-8 subsequences of s, the
// units strings.ToValidUTF8 replaces.
func invalidRuns(s string) int {
	runs, inRun := 0, false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		bad := r == utf8.RuneError && size == 1
		if bad && !inRun {
			runs++
		}
		inRun = bad
		i += size
	}
	return runs
}

// skipEscape returns the index after the terminal escape sequence that
// starts with the ESC at s[i] (R26). s is valid UTF-8.
func skipEscape(s string, i int) int {
	j := i + 1
	if j >= len(s) {
		return j // lone ESC at the end
	}
	switch s[j] {
	case '[': // CSI: parameter and intermediate bytes, then one final byte
		j++
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
			j++
		}
		if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
			j++
		}
		return j
	case ']': // OSC, ended by BEL or ST
		return skipControlString(s, j+1, true)
	case 'P', 'X', '^', '_': // DCS, SOS, PM, APC, ended by ST
		return skipControlString(s, j+1, false)
	}
	// Any other ESC takes the whole next character with it, never one byte
	// of a multi-byte character.
	_, size := utf8.DecodeRuneInString(s[j:])
	return j + size
}

// skipControlString skips to the string terminator (ESC \, or BEL when bel
// is set). An unterminated string stops at the line end, so one stray
// ESC cannot erase the following lines of an extract.
func skipControlString(s string, j int, bel bool) int {
	for ; j < len(s); j++ {
		switch {
		case bel && s[j] == 0x07:
			return j + 1
		case s[j] == esc && j+1 < len(s) && s[j+1] == '\\':
			return j + 2
		case s[j] == '\n' || s[j] == '\r':
			return j
		}
	}
	return j
}

// decodeEscapes applies R25a: the JSON and rsyslog escapes that hide
// characters from the detectors become those characters. "\\" stays as
// text so an escaped backslash is never read as the start of an escape.
func decodeEscapes(s string) string {
	if !strings.ContainsAny(s, `\#`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '\\' {
			b.WriteString(`\\`)
			i += 2
			continue
		}
		if v, n, ok := escapeAt(s[i:]); ok {
			b.WriteByte(v)
			i += n
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// escapeAt decodes the R25a escape at the start of s: its byte and its
// length. A "\\" pair is not an escape; the caller reads pairs from the
// left.
func escapeAt(s string) (byte, int, bool) {
	switch {
	case strings.HasPrefix(s, `\u`):
		if v, ok := asciiEscape(s[2:]); ok {
			return v, 6, true
		}
	case strings.HasPrefix(s, "#"):
		if v, ok := rsyslogEscape(s[1:]); ok {
			return v, 4, true
		}
	}
	for _, e := range simpleEscapes {
		if strings.HasPrefix(s, e.text) {
			return e.b, len(e.text), true
		}
	}
	return 0, 0, false
}

// asciiEscape decodes the four hex digits of a \uXXXX escape when the code
// point is at most unicodeEscapeMax.
func asciiEscape(s string) (byte, bool) {
	if len(s) < 4 {
		return 0, false
	}
	v := 0
	for k := 0; k < 4; k++ {
		h, ok := hexValue(s[k])
		if !ok {
			return 0, false
		}
		v = v<<4 | int(h)
	}
	if v > unicodeEscapeMax {
		return 0, false
	}
	return byte(v), true
}

// rsyslogEscape decodes rsyslog's "#ddd" octal escapes of rsyslogEscapes.
func rsyslogEscape(s string) (byte, bool) {
	if len(s) < 3 {
		return 0, false
	}
	for _, e := range rsyslogEscapes {
		if s[:3] == e {
			return (s[0]-'0')<<6 | (s[1]-'0')<<3 | (s[2] - '0'), true
		}
	}
	return 0, false
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func isBidi(r rune) bool      { return inRanges(r, bidiRanges) }
func isZeroWidth(r rune) bool { return inRanges(r, zeroWidthRanges) }
func isTagOrFiller(r rune) bool {
	return inRanges(r, tagFillerRanges)
}

func isLineEnd(r rune) bool {
	for _, x := range lineEnds {
		if r == x {
			return true
		}
	}
	return false
}

// caseFold returns the ASCII letter r folds to (R28a), or 0.
func caseFold(r rune) byte {
	for _, f := range caseFolds {
		if r == f.r {
			return f.to
		}
	}
	return 0
}
