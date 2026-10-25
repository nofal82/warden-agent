package redact

import (
	"context"
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
	cfg   config
	rules []detector
	err   error
}

// New compiles the rule table and runs its self-test (R42). When the
// self-test fails, Err and every method return ErrRulesUnavailable.
func New(opts ...Option) *Redactor {
	return newRedactor(defaultRules(), opts...)
}

func newRedactor(rules []detector, opts ...Option) *Redactor {
	r := &Redactor{cfg: config{now: time.Now}, rules: rules}
	for _, o := range opts {
		o(&r.cfg)
	}
	r.err = ErrInternal
	return r
}

// Err reports whether the rule set is usable: nil or ErrRulesUnavailable.
func (r *Redactor) Err() error { return r.err }

// Redact redacts one field of class TName, TPath, TText, EText or LValue.
// p is the agent's pseudonymizer, or nil (no key, or the control plane).
func (r *Redactor) Redact(ctx context.Context, f Field, in string, p *Pseudonymizer) (string, Report, error) {
	return "", Report{}, ErrInternal
}

// RedactGroup redacts P4 messages[] as one T-TEXT group joined by LF
// (R13), and maps the result back to the messages. f.MaxBytes is the
// per-message limit.
func (r *Redactor) RedactGroup(ctx context.Context, f Field, in []string, p *Pseudonymizer) ([]string, Report, error) {
	return nil, Report{}, ErrInternal
}

// RedactUnitName redacts LogEvent.unit_id (R11).
func (r *Redactor) RedactUnitName(ctx context.Context, in string) (string, Report, error) {
	return "", Report{}, ErrInternal
}

// RedactReleaseVersion redacts AdminToolRecord.release_version (R16). The
// returned string is always safe to send; a non-nil error is for counting.
func (r *Redactor) RedactReleaseVersion(ctx context.Context, in string) (string, Report, error) {
	return ReleaseVersionMarker, Report{}, ErrInternal
}

// Scan reports whether any marker-replacing detector matches a string of an
// unsigned executor body (R18, R45a).
func (r *Redactor) Scan(ctx context.Context, in string) (bool, error) {
	return false, ErrInternal
}

// Normalize applies R25a (EText and TText only) and R25–R28 for class c.
func Normalize(c Class, in string) (string, NormCounts) {
	return in, NormCounts{}
}

// Marker returns the text-class marker "[REDACTED-<id>]".
func Marker(id string) string { return "[REDACTED-" + id + "]" }

// Detectors returns the detector IDs in §4.2 order.
func Detectors() []string { return nil }

// RulesDigest is the SHA-256 of the canonical rule table (§4.5).
func RulesDigest() [32]byte { return [32]byte{} }

// Pseudonymizer replaces user names by keyed pseudonyms (R12a). The caller
// loads the key; this package never reads it from anywhere (R12b).
type Pseudonymizer struct {
	key [32]byte
}

// NewPseudonymizer returns a pseudonymizer for the agent's 32-byte key.
func NewPseudonymizer(key [32]byte) *Pseudonymizer {
	return &Pseudonymizer{key: key}
}
