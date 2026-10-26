package redact

import (
	"context"
	"strings"
	"time"
)

// Class is the redaction class of a scanned field (§4.1). Structural (X),
// identity (I), signed (S) and unsigned-body (U) fields are never passed
// to Redact.
type Class uint8

// Scanned classes, numbered as RedactClass in the health report (§4.6a).
const (
	TName      Class = 1 // short name in a typed result
	TPath      Class = 2 // path in a typed result
	TText      Class = 3 // free text in a typed result (P4 messages)
	EText      Class = 4 // log extract
	LValue     Class = 5 // telemetry label value
	NPatterned Class = 6 // contract-patterned name: RedactUnitName, RedactReleaseVersion
)

// Limits from §7 and the contract specs they cite.
const (
	ItemDeadline           = 50 * time.Millisecond // REDACT_ITEM_DEADLINE (R36)
	MaxEventInput          = 64 << 10              // REDACT_MAX_EVENT_INPUT (R39)
	MaxLine                = 16 << 10              // REDACT_MAX_LINE (R39)
	ExtractMaxBytes        = 4096                  // LogEvent.extract (agent-api §4.7)
	LabelValueMaxBytes     = 256                   // label value (agent-api §4.7)
	UnitNameMaxBytes       = 256                   // unit name (typed-action-catalog §4.2)
	ReleaseVersionMaxBytes = 32                    // SemVer (agent-api §4.6)
)

// RulesVersion is REDACT_RULES_VERSION (§4.5). Raise it on every change to
// the rule table.
const RulesVersion uint32 = 1

// Fixed markers of §4.3. A detector marker is "[REDACTED-<id>]" (Marker),
// "redacted-<id>" in T-NAME and T-PATH, and "REDACTED-<id>" in unit names.
const (
	ShortMarker          = "[REDACTED]"
	NameShortMarker      = "redacted"
	UserNameMarker       = "[REDACTED-user-name]"
	NameUserNameMarker   = "redacted-user-name"
	ReleaseVersionMarker = "0.0.0-redacted"
	AuditFailureMarker   = "[REDACTED-scan-failed]"
	LineDroppedText      = "[LINE DROPPED: TOO LONG]"
)

// Field describes one scanned field. The field-class table generated from
// the contract supplies these values; Field never comes from the network.
type Field struct {
	Class Class
	// MaxBytes is the field's contract limit: the input limit (R39) and the
	// output limit (R40). For EText it is the output limit only; the input
	// is bounded by MaxEventInput and MaxLine.
	MaxBytes int
	// HomeRoot marks a P2 entries[].path whose request root is exactly
	// /home: its first component is a user name (R12a item 2).
	HomeRoot bool
	// DBUser marks P9 sessions[].user: the whole value is a database user
	// name (R12a item 3).
	DBUser bool
	// MarkersOnly runs only the detectors that replace a match with a
	// marker: no public-IP truncation and no user-name rule (R55).
	MarkersOnly bool
}

// NormKind is a kind of change made by normalisation (§4.6
// redact_normalised_total).
type NormKind uint8

// Normalisation kinds, in §4.6 order.
const (
	NormInvalidUTF8 NormKind = iota
	NormEscape
	NormBidi
	NormZeroWidth
	NormTagOrFiller
	NormLineSeparator
	NormControl
	numNormKinds
)

// NormCounts counts normalisation changes per kind.
type NormCounts [numNormKinds]int

// Report describes what redaction did to one item, for the caller's
// counters (R41). It never holds content.
type Report struct {
	Replaced        map[string]int // replacements per detector ID (public-ip: truncations)
	Pseudonymised   int            // user names replaced by a pseudonym (R12a)
	UserNameMarkers int            // user names replaced by the user-name marker (R12c, R12d)
	Normalised      NormCounts
	MarkerFired     bool // a marker-replacing detector fired (R55 text_redacted)
	LinesDropped    int  // lines replaced by LineDroppedText (R39)
	LinesOmitted    int  // whole tail lines left out over MaxEventInput (R39)
}

// Option configures a Redactor.
type Option func(*config)

type config struct {
	now func() time.Time
}

// WithClock sets the clock used for the per-item deadline (R36).
func WithClock(now func() time.Time) Option {
	return func(c *config) { c.now = now }
}

// Redactor applies the compiled rule table. It keeps no state between
// items (R3) and is safe for concurrent use.
type Redactor struct {
	cfg     config
	rules   []detector
	markers map[string]bool // exact markers of the known detectors (§4.3)
	err     error
}

// New compiles the rule table and runs its self-test (R42). When the
// self-test fails, Err and every method return ErrRulesUnavailable.
func New(opts ...Option) (r *Redactor) {
	defer func() {
		if recover() != nil {
			r = &Redactor{cfg: config{now: time.Now}, err: ErrRulesUnavailable}
		}
	}()
	return newRedactor(defaultRules(), opts...)
}

func newRedactor(rules []detector, opts ...Option) *Redactor {
	r := &Redactor{cfg: config{now: time.Now}, rules: rules}
	for _, o := range opts {
		o(&r.cfg)
	}
	if r.cfg.now == nil {
		r.cfg.now = time.Now
	}
	// Known detectors: the compiled table's, and those of this rule set.
	ids := Detectors()
	for _, d := range rules {
		ids = append(ids, d.id)
	}
	r.markers = markerSet(ids)
	if !selfTest(rules) {
		r.err = ErrRulesUnavailable
	}
	return r
}

// Err reports whether the rule set is usable: nil or ErrRulesUnavailable.
func (r *Redactor) Err() error { return r.err }

// Redact redacts one field of class TName, TPath, TText, EText or LValue.
// p is the agent's pseudonymizer, or nil (no key, or the control plane).
func (r *Redactor) Redact(ctx context.Context, f Field, in string, p *Pseudonymizer) (out string, rep Report, err error) {
	defer recoverItem(&err)
	switch f.Class {
	case TName, TPath, TText, EText, LValue:
	default:
		return "", Report{}, ErrInternal
	}
	parts, rep, err := r.run(ctx, f, modeField, []string{in}, p)
	if err != nil {
		return "", Report{}, err
	}
	return parts[0], rep, nil
}

// RedactGroup redacts P4 messages[] as one T-TEXT group joined by LF
// (R13), and maps the result back to the messages. f.MaxBytes is the
// per-message limit. A span that crosses messages leaves its marker in the
// first one and removes the covered text from the others.
func (r *Redactor) RedactGroup(ctx context.Context, f Field, in []string, p *Pseudonymizer) (out []string, rep Report, err error) {
	defer recoverItem(&err)
	if f.Class != TText {
		return nil, Report{}, ErrInternal
	}
	out, rep, err = r.run(ctx, f, modeField, in, p)
	if err != nil {
		return nil, Report{}, err
	}
	return out, rep, nil
}

// RedactUnitName redacts LogEvent.unit_id (R11): a match becomes
// "REDACTED-<id>" before the .service suffix and the event is kept. A
// result that fails the unit pattern or its limit is an error.
func (r *Redactor) RedactUnitName(ctx context.Context, in string) (out string, rep Report, err error) {
	defer recoverItem(&err)
	f := Field{Class: NPatterned, MaxBytes: UnitNameMaxBytes}
	parts, rep, err := r.run(ctx, f, modeUnit, []string{in}, nil)
	if err != nil {
		return "", Report{}, err
	}
	switch {
	case len(parts[0]) > UnitNameMaxBytes:
		return "", Report{}, ErrOutputTooLarge
	case !unitNamePattern.MatchString(parts[0]):
		return "", Report{}, ErrInternal
	}
	return parts[0], rep, nil
}

// RedactReleaseVersion redacts AdminToolRecord.release_version (R16). The
// returned string is always safe to send; a non-nil error is for counting.
func (r *Redactor) RedactReleaseVersion(ctx context.Context, in string) (out string, rep Report, err error) {
	defer func() {
		if recover() != nil {
			out, rep, err = ReleaseVersionMarker, Report{}, ErrInternal
		}
	}()
	norm, matched, rep, err := r.scan(ctx, in, ReleaseVersionMaxBytes, modeRelease)
	switch {
	case err != nil:
		return ReleaseVersionMarker, Report{}, err
	case matched:
		return ReleaseVersionMarker, rep, nil
	}
	return norm, rep, nil
}

// Scan reports whether any marker-replacing detector matches a string of an
// unsigned executor body (R18, R45a). The body itself is never edited.
func (r *Redactor) Scan(ctx context.Context, in string) (matched bool, err error) {
	defer recoverItem(&err)
	_, matched, _, err = r.scan(ctx, in, MaxEventInput, modeScan)
	if err != nil {
		return false, err
	}
	return matched, nil
}

// scan normalises and detects without replacing (R16, R18). It returns
// the normalised text.
func (r *Redactor) scan(ctx context.Context, in string, limit int, m mode) (string, bool, Report, error) {
	if r.err != nil {
		return "", false, Report{}, ErrRulesUnavailable
	}
	if len(in) > limit {
		return "", false, Report{}, ErrInputTooLarge
	}
	ps := r.newPass(ctx, Field{Class: NPatterned, MaxBytes: limit}, m)
	s, err := normalise(NPatterned, in, &ps.rep.Normalised, ps.check)
	if err != nil {
		return "", false, Report{}, err
	}
	hits, err := ps.detect(s)
	if err != nil {
		return "", false, Report{}, err
	}
	for _, h := range hits {
		if ps.rep.Replaced == nil {
			ps.rep.Replaced = map[string]int{}
		}
		ps.rep.Replaced[r.rules[h.det].id]++
		ps.rep.MarkerFired = true
	}
	return s, len(hits) > 0, ps.rep, nil
}

// run applies §4.4's order to the parts of one item.
func (r *Redactor) run(ctx context.Context, f Field, m mode, in []string, p *Pseudonymizer) ([]string, Report, error) {
	if r.err != nil {
		return nil, Report{}, ErrRulesUnavailable
	}
	if f.MaxBytes <= 0 {
		return nil, Report{}, ErrInternal
	}
	ps := r.newPass(ctx, f, m)
	texts, err := ps.limitInput(in)
	if err != nil {
		return nil, Report{}, err
	}
	parts := make([]part, len(texts))
	for i, t := range texts {
		n, err := normalise(f.Class, t, &ps.rep.Normalised, ps.check)
		if err != nil {
			return nil, Report{}, err
		}
		text, segs := ps.userNames(n, p)
		parts[i] = part{text: text, segs: segs, cap: max(4*len(n), f.MaxBytes)}
	}
	if err := ps.redactParts(parts); err != nil {
		return nil, Report{}, err
	}
	out := make([]string, len(parts))
	for i, pt := range parts {
		out[i] = pt.text
	}
	return out, ps.rep, nil
}

// limitInput applies R39 before anything else: an extract loses lines
// over MaxLine (replaced by fixed text, never scanned) and then whole tail
// lines over MaxEventInput; any other field over its limit is an error.
func (ps *pass) limitInput(in []string) ([]string, error) {
	if ps.class != EText {
		for _, s := range in {
			if len(s) > ps.f.MaxBytes {
				return nil, ErrInputTooLarge
			}
		}
		return in, nil
	}
	lines := strings.Split(in[0], "\n")
	total := len(lines) - 1
	for i, l := range lines {
		if len(l) > MaxLine {
			lines[i] = LineDroppedText
			ps.rep.LinesDropped++
		}
		total += len(lines[i])
	}
	for total > MaxEventInput && len(lines) > 1 {
		total -= len(lines[len(lines)-1]) + 1
		lines = lines[:len(lines)-1]
		ps.rep.LinesOmitted++
	}
	return []string{strings.Join(lines, "\n")}, nil
}

// recoverItem turns a panic into ErrInternal for this item only (R35).
func recoverItem(err *error) {
	if recover() != nil {
		*err = ErrInternal
	}
}

// Marker returns the text-class marker "[REDACTED-<id>]".
func Marker(id string) string { return "[REDACTED-" + id + "]" }
