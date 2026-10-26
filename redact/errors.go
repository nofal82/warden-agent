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
)
