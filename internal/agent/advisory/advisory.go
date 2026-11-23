package advisory

import (
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

// Verdict is the outcome of CheckEnvelope: forward the bytes unchanged,
// or do not forward and report Reason (agent-api R23, R34).
type Verdict struct {
	Forward bool
	Reason  agentapiv1.AdvisoryReason
}

// CheckEnvelope runs the advisory checks of action-envelope R6 on the
// SignedEnvelope bytes signed for the server serverID at time now.
func CheckEnvelope(signed []byte, serverID string, now time.Time) Verdict {
	return Verdict{}
}

// StatusHint is what the agent reads from an ExecutorStatusBody by an
// advisory decode: only to order replies (R31) and to report recovery IDs
// (R38). It is never trusted.
type StatusHint struct {
	BootID          []byte
	ResultSequence  uint64
	RecoveryPending bool
	RecoveryID      []byte
}

// DecodeStatus decodes body, the bytes of an ExecutorStatusBody. ok is
// false when it fails the strict decoder or the contract's declared values.
func DecodeStatus(body []byte) (h StatusHint, ok bool) {
	return StatusHint{}, false
}
