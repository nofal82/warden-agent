package advisory

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// maxSkew is MAX_SKEW of action-envelope R16, in seconds. The agent may
// not link the executor's verifier package (depguard
// agent-no-signature-verifier), so the value is carried here; the
// executor's own check is the one that counts.
const maxSkew = 60

// bootIDBytes is the length of ExecutorStatusBody.boot_id (executor-ipc
// §4.7, field 31).
const bootIDBytes = 16

// sizes are the limits the decoders check before decoding, read from the
// contract options so no second copy exists (agent-api R52c).
type sizes struct {
	envelope   int            // SignedEnvelope max_message_bytes (action-envelope R11)
	status     int            // SignedReplyReport.unsigned_body max_bytes: a status body never exceeds it
	minExpires int64          // EnvelopeBody.expires_at min_int (action-envelope R16)
	maxExpires int64          // EnvelopeBody.expires_at max_int
	serverID   *regexp.Regexp // EnvelopeBody.target_server_id pattern (UUID v4)
}

var limits = sync.OnceValues(func() (s sizes, err error) {
	defer func() {
		if recover() != nil {
			s, err = sizes{}, errors.New("advisory: reading the limits panicked")
		}
	}()
	env, _ := proto.GetExtension((&wardenv1.SignedEnvelope{}).ProtoReflect().Descriptor().Options(), wardenv1.E_MaxMessageBytes).(uint32)
	fd := (&agentapiv1.SignedReplyReport{}).ProtoReflect().Descriptor().Fields().ByName("unsigned_body")
	st, _ := proto.GetExtension(fd.Options(), wardenv1.E_MaxBytes).(uint32)
	bfs := (&wardenv1.EnvelopeBody{}).ProtoReflect().Descriptor().Fields()
	exp := bfs.ByName("expires_at").Options()
	lo, _ := proto.GetExtension(exp, wardenv1.E_MinInt).(int64)
	hi, _ := proto.GetExtension(exp, wardenv1.E_MaxInt).(int64)
	pat, _ := proto.GetExtension(bfs.ByName("target_server_id").Options(), wardenv1.E_Pattern).(string)
	if env == 0 || st == 0 || lo < 1 || hi <= lo || hi > math.MaxInt64-maxSkew || pat == "" {
		return sizes{}, errors.New("advisory: a limit option is missing")
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return sizes{}, fmt.Errorf("advisory: target_server_id pattern: %w", err)
	}
	return sizes{envelope: int(env), status: int(st), minExpires: lo, maxExpires: hi, serverID: re}, nil
})

// Verdict is the outcome of CheckEnvelope: forward the bytes unchanged,
// or do not forward and report Reason (agent-api R23, R34).
type Verdict struct {
	Forward bool
	Reason  agentapiv1.AdvisoryReason
}

var forward = Verdict{Forward: true}

// CheckEnvelope runs the advisory checks of action-envelope R6 on the
// SignedEnvelope bytes signed, for the server serverID at time now: size
// first, without decoding; then a strict decode of the container and its
// body (R13 rules and the declared values); then expiry and target host,
// in that order. Any decode failure forwards the bytes, and so does a
// missing limit: the executor decides (agent-api R23, action-envelope R7).
// The signature is not checked (the agent holds no keys), signed is never
// modified, and envelope_counter is not read (R52a).
func CheckEnvelope(signed []byte, serverID string, now time.Time) Verdict {
	l, err := limits()
	if err != nil {
		return forward
	}
	if len(signed) > l.envelope {
		return Verdict{Reason: agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_OVERSIZED}
	}
	var se wardenv1.SignedEnvelope
	if agentapiv1.StrictUnmarshal(signed, &se) != nil || agentapiv1.CheckDeclared(&se) != nil {
		return forward
	}
	var b wardenv1.EnvelopeBody
	if agentapiv1.StrictUnmarshal(se.GetBody(), &b) != nil || agentapiv1.CheckDeclared(&b) != nil {
		return forward
	}
	// An expires_at outside the contract's range, or an own server ID that
	// is not a UUID v4 (identity not loaded), is not the agent's to judge:
	// forward, and the executor answers BODY_INVALID or WRONG_HOST itself.
	exp := b.GetExpiresAt()
	if exp < l.minExpires || exp > l.maxExpires || !l.serverID.MatchString(serverID) {
		return forward
	}
	// Only "expired" has an advisory reason (R34); an envelope not yet
	// valid is left to the executor (action-envelope R16). exp+maxSkew
	// cannot overflow: limits() checked maxExpires <= MaxInt64-maxSkew.
	if now.Unix() > exp+maxSkew {
		return Verdict{Reason: agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_EXPIRED}
	}
	if b.GetTargetServerId() != serverID {
		return Verdict{Reason: agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_WRONG_HOST}
	}
	return forward
}

// StatusHint is what the agent reads from an ExecutorStatusBody by an
// advisory decode: only to order replies (R31) and to report recovery IDs
// (R38). It is never trusted, and highest_envelope_counter is not part of
// it: the agent never interprets the counters (R52a).
type StatusHint struct {
	BootID          []byte
	ResultSequence  uint64
	RecoveryPending bool
	RecoveryID      []byte
}

// DecodeStatus decodes body, the bytes of an ExecutorStatusBody, with the
// size check first, the strict decoder and the declared values. ok is false
// on any failure, so the caller queues the reply in arrival order (R31).
// The returned slices are copies.
func DecodeStatus(body []byte) (h StatusHint, ok bool) {
	l, err := limits()
	if err != nil || len(body) > l.status {
		return StatusHint{}, false
	}
	var s wardenv1.ExecutorStatusBody
	if agentapiv1.StrictUnmarshal(body, &s) != nil || agentapiv1.CheckDeclared(&s) != nil {
		return StatusHint{}, false
	}
	if len(s.GetBootId()) != bootIDBytes {
		return StatusHint{}, false
	}
	return StatusHint{
		BootID:          bytes.Clone(s.GetBootId()),
		ResultSequence:  s.GetResultSequence(),
		RecoveryPending: s.GetRecoveryPending(),
		RecoveryID:      bytes.Clone(s.GetRecoveryId()),
	}, true
}
