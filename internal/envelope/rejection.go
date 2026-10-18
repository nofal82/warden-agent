package envelope

import "fmt"

// Code is a rejection reason from action-envelope §4.5. The executor
// returns, and the agent reports, exactly one.
type Code string

// Codes for the stateless checks 1–11, in check order.
const (
	CodeOversized                Code = "OVERSIZED"                  // check 1
	CodeMalformed                Code = "MALFORMED"                  // check 2
	CodeUnknownKey               Code = "UNKNOWN_KEY"                // checks 3 and 7
	CodeBadSignature             Code = "BAD_SIGNATURE"              // check 4
	CodeBodyInvalid              Code = "BODY_INVALID"               // check 5
	CodeUnsupportedFormatVersion Code = "UNSUPPORTED_FORMAT_VERSION" // check 6
	CodeLifetimeInvalid          Code = "LIFETIME_INVALID"           // check 8
	CodeNotYetValid              Code = "NOT_YET_VALID"              // check 9
	CodeExpired                  Code = "EXPIRED"                    // check 10
	CodeWrongHost                Code = "WRONG_HOST"                 // check 11
)

// Rejection is the only error Verify returns. It carries the code and the
// §4.5 check number and deliberately nothing from the envelope, so it is
// safe to log before the signature has verified (R31).
type Rejection struct {
	Code  Code
	Check int
}

func (r *Rejection) Error() string {
	return fmt.Sprintf("envelope rejected: %s (check %d)", r.Code, r.Check)
}

func reject(code Code, check int) *Rejection {
	return &Rejection{Code: code, Check: check}
}
