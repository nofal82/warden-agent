package controlplane_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"strings"
	"testing"

	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

const endDetailURL = "type.googleapis.com/warden.agentapi.v1.EndDetail"

// pairs is the §4.8 table: the reasons each code may carry.
var pairs = map[codes.Code][]agentapiv1.EndReason{
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

func paired(c codes.Code, r agentapiv1.EndReason) bool {
	for _, p := range pairs[c] {
		if p == r {
			return true
		}
	}
	return false
}

func anyOf(url string, value []byte) *anypb.Any { return &anypb.Any{TypeUrl: url, Value: value} }

// reasonValue encodes field 1 as a raw varint, so tests can send values
// the generated encoder would never produce.
func reasonValue(r uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), r)
}

func st(code codes.Code, details ...*anypb.Any) *status.Status {
	p := status.New(code, "m").Proto()
	p.Details = details
	return status.FromProto(p)
}

// TestParseEndDetailTable checks every code against every reason 0…19.
func TestParseEndDetailTable(t *testing.T) {
	t.Parallel()
	for c := codes.Code(0); c <= 17; c++ {
		for r := agentapiv1.EndReason(0); r <= 19; r++ {
			// Reason 0 encodes as an empty value: field absent, invalid.
			want := paired(c, r)
			got, ok := controlplane.ParseEndDetail(st(c, anyOf(endDetailURL, marshalDet(t, &agentapiv1.EndDetail{Reason: r}))))
			if ok != want || (ok && got != r) {
				t.Errorf("code %v reason %d: got (%v, %v), want ok=%v", c, r, got, ok, want)
			}
			if !ok && got != agentapiv1.EndReason_END_REASON_UNSPECIFIED {
				t.Errorf("code %v reason %d: not ok but reason %v", c, r, got)
			}
		}
	}
}

func TestParseEndDetailAttacks(t *testing.T) {
	t.Parallel()
	good := marshalDet(t, &agentapiv1.EndDetail{Reason: agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED})
	goodAny := func() *anypb.Any { return anyOf(endDetailURL, good) }
	withUnknown := func(m proto.Message, n protowire.Number, pad int) {
		b := protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), bytes.Repeat([]byte{'p'}, pad))
		m.ProtoReflect().SetUnknown(b)
	}
	anyUnknownSmall := goodAny()
	withUnknown(anyUnknownSmall, 9, 1)
	anyUnknownBig := goodAny()
	withUnknown(anyUnknownBig, 9, 200)
	statusUnknown := &spb.Status{Code: int32(codes.PermissionDenied), Details: []*anypb.Any{goodAny()}}
	withUnknown(statusUnknown, 99, 1)
	padded := append(append([]byte(nil), good...), protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), make([]byte, 130))...)
	unknownInValue := protowire.AppendVarint(protowire.AppendTag(append([]byte(nil), good...), 2, protowire.VarintType), 1)

	cases := []struct {
		name string
		st   *status.Status
	}{
		{"nil status", nil},
		{"OK status", status.New(codes.OK, "")},
		{"no detail", st(codes.PermissionDenied)},
		{"nil detail", st(codes.PermissionDenied, nil)},
		{"two details", st(codes.PermissionDenied, goodAny(), goodAny())},
		{"good plus other", st(codes.PermissionDenied, goodAny(), anyOf("type.googleapis.com/google.rpc.ErrorInfo", nil))},
		{"URL lower case", st(codes.PermissionDenied, anyOf(strings.ToLower(endDetailURL), good))},
		{"URL upper case", st(codes.PermissionDenied, anyOf(strings.ToUpper(endDetailURL), good))},
		{"URL trailing slash", st(codes.PermissionDenied, anyOf(endDetailURL+"/", good))},
		{"URL trailing space", st(codes.PermissionDenied, anyOf(endDetailURL+" ", good))},
		{"URL leading space", st(codes.PermissionDenied, anyOf(" "+endDetailURL, good))},
		{"URL trailing NUL", st(codes.PermissionDenied, anyOf(endDetailURL+"\x00", good))},
		{"URL trailing newline", st(codes.PermissionDenied, anyOf(endDetailURL+"\n", good))},
		{"URL no prefix", st(codes.PermissionDenied, anyOf("warden.agentapi.v1.EndDetail", good))},
		{"URL other host", st(codes.PermissionDenied, anyOf("example.com/warden.agentapi.v1.EndDetail", good))},
		{"URL with scheme", st(codes.PermissionDenied, anyOf("https://"+endDetailURL, good))},
		{"URL suffix", st(codes.PermissionDenied, anyOf(endDetailURL+"X", good))},
		{"URL other package", st(codes.PermissionDenied, anyOf("type.googleapis.com/warden.agentapi.v2.EndDetail", good))},
		{"URL empty", st(codes.PermissionDenied, anyOf("", good))},
		{"URL look-alike Cyrillic", st(codes.PermissionDenied, anyOf(strings.Replace(endDetailURL, "a", "а", 1), good))},
		{"Any over 128 bytes (padded value)", st(codes.PermissionDenied, anyOf(endDetailURL, padded))},
		{"Any unknown field", status.FromProto(&spb.Status{Code: int32(codes.PermissionDenied), Details: []*anypb.Any{anyUnknownSmall}})},
		{"Any unknown field over 128", status.FromProto(&spb.Status{Code: int32(codes.PermissionDenied), Details: []*anypb.Any{anyUnknownBig}})},
		{"Status unknown field", status.FromProto(statusUnknown)},
		{"value unknown field", st(codes.PermissionDenied, anyOf(endDetailURL, unknownInValue))},
		{"value empty (reason absent)", st(codes.PermissionDenied, anyOf(endDetailURL, nil))},
		{"value reason 0 explicit", st(codes.PermissionDenied, anyOf(endDetailURL, reasonValue(0)))},
		{"value reason 19", st(codes.PermissionDenied, anyOf(endDetailURL, reasonValue(19)))},
		{"value reason 2^31-1", st(codes.PermissionDenied, anyOf(endDetailURL, reasonValue(math.MaxInt32)))},
		{"value reason -1", st(codes.PermissionDenied, anyOf(endDetailURL, reasonValue(math.MaxUint64)))},
		{"value reason 2^32+5", st(codes.PermissionDenied, anyOf(endDetailURL, reasonValue(1<<32+5)))},
		{"value duplicate reason", st(codes.PermissionDenied, anyOf(endDetailURL, append(append([]byte(nil), good...), good...)))},
		{"value reason 5 then 3", st(codes.Unavailable, anyOf(endDetailURL, append(reasonValue(5), reasonValue(3)...)))},
		{"value wrong wire type", st(codes.PermissionDenied, anyOf(endDetailURL, protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte{5})))},
		{"value non-minimal varint", st(codes.PermissionDenied, anyOf(endDetailURL, []byte{0x08, 0x85, 0x00}))},
		{"value truncated", st(codes.PermissionDenied, anyOf(endDetailURL, []byte{0x08}))},
		{"value trailing byte", st(codes.PermissionDenied, anyOf(endDetailURL, append(append([]byte(nil), good...), 0x00)))},
		{"mismatch PERMISSION_DENIED DATABASE_UNAVAILABLE", st(codes.PermissionDenied, anyOf(endDetailURL, reasonValue(3)))},
		{"mismatch UNAVAILABLE CERTIFICATE_REVOKED", st(codes.Unavailable, anyOf(endDetailURL, reasonValue(1)))},
		{"mismatch RESOURCE_EXHAUSTED TOO_LARGE", st(codes.ResourceExhausted, anyOf(endDetailURL, reasonValue(8)))},
		{"UNIMPLEMENTED with a reason", st(codes.Unimplemented, anyOf(endDetailURL, good))},
		{"OK with a reason", st(codes.OK, anyOf(endDetailURL, good))},
		{"INTERNAL with a reason", st(codes.Internal, anyOf(endDetailURL, good))},
		{"code out of range", st(codes.Code(99), anyOf(endDetailURL, good))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, ok := controlplane.ParseEndDetail(tc.st)
			if ok || r != agentapiv1.EndReason_END_REASON_UNSPECIFIED {
				t.Fatalf("got (%v, %v), want (UNSPECIFIED, false)", r, ok)
			}
		})
	}
	// Sanity: the base case is accepted, so the rejections above are for
	// the listed reason.
	if r, ok := controlplane.ParseEndDetail(st(codes.PermissionDenied, goodAny())); !ok || r != agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED {
		t.Fatalf("valid detail refused: (%v, %v)", r, ok)
	}
}

func TestActionOf(t *testing.T) {
	t.Parallel()
	se := func(c codes.Code, r agentapiv1.EndReason, has bool) error {
		return &controlplane.StatusError{Code: c, Reason: r, HasDetail: has}
	}
	none := agentapiv1.EndReason_END_REASON_UNSPECIFIED
	stop, retry, longest := controlplane.ActionStop, controlplane.ActionRetry, controlplane.ActionRetryLongest
	cases := []struct {
		name string
		err  error
		want controlplane.Action
	}{
		{"ErrNotConnected", controlplane.ErrNotConnected, retry},
		{"wrapped ErrNotConnected", fmt.Errorf("dial: %w", controlplane.ErrNotConnected), retry},
		{"identity-wrapped ErrNotConnected", fmt.Errorf("identity: enroll: %w", controlplane.ErrNotConnected), retry},
		{"ErrResponseRefused", controlplane.ErrResponseRefused, retry},
		{"identity-wrapped ErrResponseRefused", fmt.Errorf("identity: enroll: %w", controlplane.ErrResponseRefused), retry},

		{"UNIMPLEMENTED", se(codes.Unimplemented, none, false), stop},
		{"UNIMPLEMENTED with detail", se(codes.Unimplemented, none, true), stop},
		{"INVALID_ARGUMENT", se(codes.InvalidArgument, none, false), stop},
		{"INVALID_ARGUMENT TOO_LARGE", se(codes.InvalidArgument, agentapiv1.EndReason_END_REASON_TOO_LARGE, true), stop},
		{"INVALID_ARGUMENT MALFORMED", se(codes.InvalidArgument, agentapiv1.EndReason_END_REASON_MALFORMED, true), stop},
		{"RESOURCE_EXHAUSTED no detail", se(codes.ResourceExhausted, none, false), stop},
		{"RESOURCE_EXHAUSTED RATE_LIMITED", se(codes.ResourceExhausted, agentapiv1.EndReason_END_REASON_RATE_LIMITED, true), retry},
		{"RESOURCE_EXHAUSTED invalid detail", se(codes.ResourceExhausted, none, true), longest},
		{"identity-wrapped RESOURCE_EXHAUSTED no detail", fmt.Errorf("identity: enroll: %w", se(codes.ResourceExhausted, none, false)), stop},
		{"identity-wrapped RESOURCE_EXHAUSTED invalid detail", fmt.Errorf("identity: enroll: %w", se(codes.ResourceExhausted, none, true)), longest},

		{"UNAUTHENTICATED", se(codes.Unauthenticated, none, false), retry},
		{"UNAUTHENTICATED CERTIFICATE_REVOKED", se(codes.Unauthenticated, agentapiv1.EndReason_END_REASON_CERTIFICATE_REVOKED, true), retry},
		{"UNAVAILABLE", se(codes.Unavailable, none, false), retry},
		{"UNAVAILABLE DATABASE_UNAVAILABLE", se(codes.Unavailable, agentapiv1.EndReason_END_REASON_DATABASE_UNAVAILABLE, true), retry},
		{"PERMISSION_DENIED", se(codes.PermissionDenied, none, false), retry},
		{"PERMISSION_DENIED ENROLLMENT_REFUSED", se(codes.PermissionDenied, agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED, true), retry},
		{"identity-wrapped PERMISSION_DENIED", fmt.Errorf("identity: enroll: %w", se(codes.PermissionDenied, agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED, true)), retry},
		{"FAILED_PRECONDITION", se(codes.FailedPrecondition, none, true), retry},
		{"DEADLINE_EXCEEDED", se(codes.DeadlineExceeded, none, false), retry},
		{"ABORTED", se(codes.Aborted, none, false), retry},
		{"ALREADY_EXISTS", se(codes.AlreadyExists, none, false), retry},

		{"OK", se(codes.OK, none, false), longest},
		{"CANCELED", se(codes.Canceled, none, false), longest},
		{"UNKNOWN", se(codes.Unknown, none, false), longest},
		{"INTERNAL", se(codes.Internal, none, false), longest},
		{"NOT_FOUND", se(codes.NotFound, none, false), longest},
		{"OUT_OF_RANGE", se(codes.OutOfRange, none, false), longest},
		{"DATA_LOSS", se(codes.DataLoss, none, true), longest},
		{"code 17", se(codes.Code(17), none, false), longest},
		{"code 2^32-1", se(codes.Code(math.MaxUint32), none, false), longest},
		{"identity-wrapped INTERNAL", fmt.Errorf("identity: enroll: %w", se(codes.Internal, none, false)), longest},

		{"plain error", errors.New("local failure"), stop},
		{"ErrCertificateRejected", identity.ErrCertificateRejected, stop},
		{"wrapped ErrCertificateRejected", fmt.Errorf("x: %w", identity.ErrCertificateRejected), stop},
		// A clock-skew R15 failure is retried on the normal backoff (Nofal, PR #33).
		{"ErrClockSkew", identity.ErrClockSkew, controlplane.ActionRetry},
		{"R15 clock skew as identity returns it", fmt.Errorf("%w: %w (valid …)", identity.ErrCertificateRejected, identity.ErrClockSkew), controlplane.ActionRetry},
		{"R15 clock skew wrapped again", fmt.Errorf("identity: enroll: %w", fmt.Errorf("%w: %w", identity.ErrCertificateRejected, identity.ErrClockSkew)), controlplane.ActionRetry},
		{"ErrInvalidTrust", identity.ErrInvalidTrust, stop},
		{"ErrUnsafeFile", identity.ErrUnsafeFile, stop},
		{"fs.ErrNotExist", fs.ErrNotExist, stop},
		{"ErrInvalidEndpoint", controlplane.ErrInvalidEndpoint, stop},
		{"ErrCompressorRegistered", controlplane.ErrCompressorRegistered, stop},
		// Enroll never returns a raw gRPC status; one that reaches
		// ActionOf is not a *StatusError and is not trusted.
		{"raw gRPC status error", status.Error(codes.Unavailable, "x"), stop},
		{"text that looks like a code", errors.New("controlplane: Unavailable DATABASE_UNAVAILABLE"), stop},
		{"context canceled wrapped by identity", fmt.Errorf("identity: enroll: %w", context.Canceled), stop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := controlplane.ActionOf(tc.err); got != tc.want {
				t.Fatalf("ActionOf(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestStatusErrorText(t *testing.T) {
	t.Parallel()
	e := &controlplane.StatusError{Code: codes.PermissionDenied, Reason: agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED, HasDetail: true}
	s := e.Error()
	if !strings.HasPrefix(s, "controlplane: ") || strings.ContainsAny(s, "\n\r\x1b") {
		t.Fatalf("Error() = %q", s)
	}
}

func FuzzParseEndDetail(f *testing.F) {
	good := reasonValue(5)
	f.Add(endDetailURL, good, uint32(codes.PermissionDenied))
	f.Add(endDetailURL, reasonValue(7), uint32(codes.ResourceExhausted))
	f.Add(endDetailURL, reasonValue(19), uint32(codes.ResourceExhausted))
	f.Add(endDetailURL, reasonValue(0), uint32(codes.PermissionDenied))
	f.Add(endDetailURL, []byte{}, uint32(codes.PermissionDenied))
	f.Add(endDetailURL, append(good, good...), uint32(codes.PermissionDenied))
	f.Add(endDetailURL, []byte{0x08, 0x85, 0x00}, uint32(codes.PermissionDenied))
	f.Add(endDetailURL+"/", good, uint32(codes.PermissionDenied))
	f.Add(strings.ToLower(endDetailURL), good, uint32(codes.PermissionDenied))
	f.Add(endDetailURL, append(good, make([]byte, 130)...), uint32(codes.PermissionDenied))
	f.Add(endDetailURL, reasonValue(3), uint32(codes.PermissionDenied))
	f.Add(endDetailURL, reasonValue(5), uint32(99))
	f.Fuzz(func(t *testing.T, url string, value []byte, code uint32) {
		a := anyOf(url, value)
		r, ok := controlplane.ParseEndDetail(st(codes.Code(code), a))
		if !ok {
			if r != agentapiv1.EndReason_END_REASON_UNSPECIFIED {
				t.Fatalf("not ok but reason %v", r)
			}
			return
		}
		if url != endDetailURL {
			t.Fatalf("accepted type URL %q", url)
		}
		if proto.Size(a) > 128 {
			t.Fatalf("accepted Any of %d bytes", proto.Size(a))
		}
		if r < 1 || r > 18 {
			t.Fatalf("accepted reason %d", r)
		}
		if !paired(codes.Code(code), r) {
			t.Fatalf("accepted reason %v under code %v", r, codes.Code(code))
		}
		if !bytes.Equal(marshalDet(t, &agentapiv1.EndDetail{Reason: r}), value) {
			t.Fatalf("accepted non-canonical value %x", value)
		}
	})
}
