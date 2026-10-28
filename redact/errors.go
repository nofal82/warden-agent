package redact

import "errors"

// The only errors the redactor returns (§4.9). They never carry content of
// the input, a match or a removed span (R4). Every one means "drop the
// item" (R35), except where the caller's field rule says otherwise (R16
// fixed value, R18 withhold, R55a failure marker). A detector match is
// never an error.
var (
	ErrDeadline         = errors.New("redact: item deadline exceeded")
	ErrBudget           = errors.New("redact: byte budget exhausted")
	ErrInputTooLarge    = errors.New("redact: input over its limit")
	ErrPostCheck        = errors.New("redact: match left after post-check")
	ErrPairing          = errors.New("redact: typed result cannot be paired with its request")
	ErrOutputTooLarge   = errors.New("redact: replacement over the growth cap")
	ErrRulesUnavailable = errors.New("redact: rule set failed its self-test")
	ErrInternal         = errors.New("redact: internal error")
	// ErrNormPasses is a normalisation that still changes the item after
	// NormMaxPasses passes (R28b): a crafted alternation of escapes, kept
	// apart from a redactor fault (human Go reviewer, 14th review).
	ErrNormPasses = errors.New("redact: normalisation pass cap reached")
)

// reasonTable maps each error to its redact_dropped_total reason (§4.6).
var reasonTable = []struct {
	err    error
	reason string
}{
	{ErrDeadline, "TIMEOUT"},
	{ErrBudget, "BUDGET"},
	{ErrInputTooLarge, "INPUT_TOO_LARGE"},
	{ErrOutputTooLarge, "OUTPUT_TOO_LARGE"},
	{ErrPostCheck, "POSTCHECK"},
	{ErrRulesUnavailable, "RULES_UNAVAILABLE"},
	{ErrNormPasses, "PASS_CAP"},
}

// DropReason returns the redact_dropped_total reason (§4.6) of an error
// the redactor returned: ERROR for ErrInternal, ErrPairing and anything
// it does not know.
func DropReason(err error) string {
	for _, d := range reasonTable {
		if errors.Is(err, d.err) {
			return d.reason
		}
	}
	return "ERROR"
}
