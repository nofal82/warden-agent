package controlplane

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/identity"
)

// R45 detail rules.
const (
	endDetailTypeURL = "type.googleapis.com/warden.agentapi.v1.EndDetail"
	maxEndDetailAny  = 128
)

type reason = agentapiv1.EndReason

// pairs is §4.8: the reasons each gRPC code may carry. The two library
// rows (RESOURCE_EXHAUSTED and UNIMPLEMENTED without a detail) have none.
var pairs = map[codes.Code][]reason{
	codes.Unauthenticated: {agentapiv1.EndReason_END_REASON_CERTIFICATE_REVOKED},
	codes.Unavailable: {
		agentapiv1.EndReason_END_REASON_REVOCATION_STATE_STALE,
		agentapiv1.EndReason_END_REASON_DATABASE_UNAVAILABLE,
		agentapiv1.EndReason_END_REASON_SHUTTING_DOWN,
	},
	codes.PermissionDenied: {
		agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED,
		agentapiv1.EndReason_END_REASON_IDENTITY_MISMATCH,
	},
	codes.ResourceExhausted: {agentapiv1.EndReason_END_REASON_RATE_LIMITED},
	codes.InvalidArgument: {
		agentapiv1.EndReason_END_REASON_TOO_LARGE,
		agentapiv1.EndReason_END_REASON_MALFORMED,
		agentapiv1.EndReason_END_REASON_MESSAGE_SEQ_UNREADABLE,
	},
	codes.FailedPrecondition: {
		agentapiv1.EndReason_END_REASON_HELLO_REQUIRED,
		agentapiv1.EndReason_END_REASON_DUPLICATE_STREAM,
		agentapiv1.EndReason_END_REASON_CONTRACT_VERSION_UNSUPPORTED,
	},
	codes.DeadlineExceeded: {agentapiv1.EndReason_END_REASON_HELLO_TIMEOUT},
	codes.Aborted: {
		agentapiv1.EndReason_END_REASON_CONNECTION_REPLACED,
		agentapiv1.EndReason_END_REASON_ACK_TIMEOUT,
		agentapiv1.EndReason_END_REASON_DUPLICATE_IDENTITY_CLOSED,
	},
	codes.AlreadyExists: {agentapiv1.EndReason_END_REASON_DUPLICATE_IDENTITY},
}

// StatusError is a gRPC error from the control plane, reduced to what R45
// lets the agent use: the code and the EndDetail reason. Reason is
// END_REASON_UNSPECIFIED when the status had no valid detail (none, more
// than one, or one that fails the R45 checks). HasDetail reports whether
// the status carried any detail at all. The peer's status message is
// dropped: it is peer-controlled text and never decides anything.
type StatusError struct {
	Code      codes.Code
	Reason    agentapiv1.EndReason
	HasDetail bool
}

func (e *StatusError) Error() string {
	s := "controlplane: " + e.Code.String()
	if e.Reason != agentapiv1.EndReason_END_REASON_UNSPECIFIED {
		s += " " + e.Reason.String()
	}
	return s
}

// ParseEndDetail applies R45 to st: exactly one detail, no unknown fields
// on the Status or the Any, type URL
// type.googleapis.com/warden.agentapi.v1.EndDetail, an Any of at most 128
// bytes, a value that passes the strict decoder, and a known EndReason that
// §4.8 pairs with st's code. It returns the reason and true only then.
// It reads Status.Proto().GetDetails(), never Status.Details(), which
// would decode the value with plain proto.Unmarshal.
func ParseEndDetail(st *status.Status) (agentapiv1.EndReason, bool) {
	const none = agentapiv1.EndReason_END_REASON_UNSPECIFIED
	if st == nil {
		return none, false
	}
	p := st.Proto()
	if p == nil || len(p.ProtoReflect().GetUnknown()) != 0 {
		return none, false
	}
	details := p.GetDetails()
	if len(details) != 1 {
		return none, false
	}
	a := details[0]
	if a == nil || len(a.ProtoReflect().GetUnknown()) != 0 || a.GetTypeUrl() != endDetailTypeURL || proto.Size(a) > maxEndDetailAny {
		return none, false
	}
	var d agentapiv1.EndDetail
	if err := agentapiv1.StrictUnmarshal(a.GetValue(), &d); err != nil {
		return none, false
	}
	r := d.GetReason()
	for _, allowed := range pairs[st.Code()] {
		if r == allowed {
			return r, true
		}
	}
	return none, false
}

// Action is what the enrollment loop does after a failed attempt.
type Action int

// Actions.
const (
	// ActionStop: do not retry; return the error to the caller.
	ActionStop Action = iota + 1
	// ActionRetry: retry under the enrollment backoff (§4.9).
	ActionRetry
	// ActionRetryLongest: retry after the longest enrollment backoff
	// (R45: unknown code or unknown reason).
	ActionRetryLongest
)

// ActionOf maps an error of one enrollment attempt to an Action, per R16,
// R45 and §4.8. Errors that did not come from the call (local file, key or
// R15 failures) are ActionStop, except an R15 clock-skew failure, which is
// retried on the normal backoff: once the server clock is fixed, the retry
// with the same pending key gets the same certificate (agent-identity R17;
// Nofal, PR #33).
//
// §4.8 rows marked terminal (UNIMPLEMENTED; INVALID_ARGUMENT; the library
// RESOURCE_EXHAUSTED with no detail) stop the loop. An honest control
// plane never sends them on Enroll, whose refusals are all
// ENROLLMENT_REFUSED (R16).
func ActionOf(err error) Action {
	if errors.Is(err, ErrNotConnected) || errors.Is(err, ErrResponseRefused) || errors.Is(err, identity.ErrClockSkew) {
		return ActionRetry
	}
	var se *StatusError
	if !errors.As(err, &se) {
		return ActionStop
	}
	switch se.Code {
	case codes.Unimplemented, codes.InvalidArgument:
		return ActionStop
	case codes.ResourceExhausted:
		switch {
		case !se.HasDetail:
			return ActionStop
		case se.Reason == agentapiv1.EndReason_END_REASON_RATE_LIMITED:
			return ActionRetry
		}
		return ActionRetryLongest
	case codes.Unauthenticated, codes.Unavailable, codes.PermissionDenied,
		codes.FailedPrecondition, codes.DeadlineExceeded, codes.Aborted, codes.AlreadyExists:
		return ActionRetry
	}
	return ActionRetryLongest
}
