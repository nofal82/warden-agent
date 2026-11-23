package agentapiv1_test

// Attack tests for the R11/R32a peeks and the R12 declared-value check
// (issue #59). Written before the implementation; they fail against the
// stubs in peek.go.

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// seqField is OutboxMessage field 1 = v, canonically encoded.
func seqField(v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), v)
}

// payloadField is a valid OutboxMessage field 2 (a RecoveryReport payload).
func payloadField(t testing.TB) []byte {
	t.Helper()
	b, err := deterministic.Marshal(&agentapiv1.OutboxMessage{Payload: &agentapiv1.OutboxPayload{
		Payload: &agentapiv1.OutboxPayload_RecoveryReport{
			RecoveryReport: &agentapiv1.RecoveryReport{RecoveryId: make([]byte, 24)},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReadMessageSeq: agent-api R32a (field 1 missing, duplicated, wrong
// wire type, zero) and R11 (strict scanner: minimal varints, no groups,
// nothing truncated anywhere in the top-level message).
func TestReadMessageSeq(t *testing.T) {
	t.Parallel()
	p := payloadField(t)
	overlongKey := cat([]byte{0x88, 0x00}, protowire.AppendVarint(nil, 7)) // key 0x08 as two bytes
	overlongVal := cat([]byte{0x08, 0x87, 0x00})                           // 7 as two bytes
	// 10-byte varint whose last byte carries bits above 2^64-1.
	tooBig := cat([]byte{0x08}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02})
	group := cat(seqField(3), []byte{0x1b, 0x1c}) // field 3 start-group, end-group
	cases := []struct {
		name string
		b    []byte
		want uint64 // 0 means an error is expected
	}{
		{"valid, field 1 first", cat(seqField(7), p), 7},
		{"valid, field 1 after field 2", cat(p, seqField(1<<40)), 1 << 40},
		{"missing", p, 0},
		{"duplicated", cat(seqField(7), p, seqField(7)), 0},
		{"wrong wire type", cat(protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte{7}), p), 0},
		{"zero", cat(seqField(0), p), 0},
		{"overlong key varint", cat(overlongKey, p), 0},
		{"overlong value varint", cat(overlongVal, p), 0},
		{"10-byte varint above 2^64-1", cat(tooBig, p), 0},
		{"truncated value", []byte{0x08, 0x87}, 0},
		{"malformed field after seq", cat(seqField(7), p[:len(p)-1]), 0},
		{"group wire type", group, 0},
		// Security review of #59: the scanner refuses field numbers
		// above 2^29-1, so the peek must too.
		{"field number 2^29 after seq", cat(seqField(7), protowire.AppendVarint(protowire.AppendTag(nil, 1<<29, protowire.VarintType), 1)), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := agentapiv1.ReadMessageSeq(tc.b)
			if tc.want != 0 {
				if err != nil || got != tc.want {
					t.Fatalf("ReadMessageSeq = %d, %v; want %d", got, err, tc.want)
				}
				return
			}
			if !errors.Is(err, agentapiv1.ErrMessageSeqUnreadable) {
				t.Fatalf("ReadMessageSeq = %d, %v; want ErrMessageSeqUnreadable", got, err)
			}
		})
	}
}

// TestPeekMember: agent-api R11 tag peek of a oneof-only message.
func TestPeekMember(t *testing.T) {
	t.Parallel()
	agent := (&agentapiv1.AgentMessage{}).ProtoReflect().Descriptor()
	control := (&agentapiv1.ControlMessage{}).ProtoReflect().Descriptor()
	lenField := func(n protowire.Number) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), []byte{0x08, 0x01})
	}
	cases := []struct {
		name string
		b    []byte
		md   protoreflect.MessageDescriptor
		want protoreflect.FieldNumber // 0 means an error is expected
	}{
		{"AgentMessage outbox", lenField(3), agent, 3},
		{"ControlMessage delivery", lenField(2), control, 2},
		{"empty", nil, agent, 0},
		{"overlong key varint", []byte{0x9a, 0x00, 0x00}, agent, 0},
		{"truncated key varint", []byte{0x80}, agent, 0},
		{"not a member of AgentMessage", lenField(15), agent, 0},
		{"member with varint wire type", []byte{0x18, 0x01}, agent, 0},
		{"not a member of ControlMessage", lenField(4), control, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := agentapiv1.PeekMember(tc.b, tc.md)
			if tc.want != 0 {
				if err != nil || got != tc.want {
					t.Fatalf("PeekMember = %d, %v; want %d", got, err, tc.want)
				}
				return
			}
			if !errors.Is(err, agentapiv1.ErrMemberUnreadable) {
				t.Fatalf("PeekMember = %d, %v; want ErrMemberUnreadable", got, err)
			}
		})
	}
}

func validEnvelopeBody() *wardenv1.EnvelopeBody {
	return &wardenv1.EnvelopeBody{
		FormatVersion:  1,
		TargetServerId: "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
		Params: &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_MemStatus{
			MemStatus: &wardenv1.MemStatusRequest{},
		}},
		PolicyDecision:  &wardenv1.PolicyDecision{AutonomyLevel: wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L1},
		ExpiresAt:       100,
		EnvelopeCounter: 1,
	}
}

// TestCheckDeclared: agent-api R12 (undeclared enum values anywhere) and
// PR #60 ruling V4 (an UNSPECIFIED required field or absent required
// message is refused).
func TestCheckDeclared(t *testing.T) {
	t.Parallel()
	badRefusal := wardenv1.IpcRefusalCode(99)
	noAutonomy := validEnvelopeBody()
	noAutonomy.PolicyDecision.AutonomyLevel = wardenv1.AutonomyLevel_AUTONOMY_LEVEL_UNSPECIFIED
	noParams := validEnvelopeBody()
	noParams.Params = nil
	cases := []struct {
		name string
		m    proto.Message
		ok   bool
	}{
		{"valid MessageAck", &agentapiv1.MessageAck{MessageSeq: 1, Outcome: agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED}, true},
		{"valid EnvelopeBody", validEnvelopeBody(), true},
		{"MessageAck outcome 99", &agentapiv1.MessageAck{MessageSeq: 1, Outcome: agentapiv1.AckOutcome(99)}, false},
		{"TrustDocument kind 99", &agentapiv1.TrustDocument{Kind: wardenv1.TrustKind(99), Document: []byte{1}}, false},
		{"SignedReplyReport kind UNSPECIFIED", &agentapiv1.SignedReplyReport{Signed: []byte{1}}, false},
		{"EnvelopeAdvisory reason 99 (nested in OutboxMessage)", &agentapiv1.OutboxMessage{MessageSeq: 1, Payload: &agentapiv1.OutboxPayload{
			Payload: &agentapiv1.OutboxPayload_EnvelopeAdvisory{EnvelopeAdvisory: &agentapiv1.EnvelopeAdvisory{
				EnvelopeSha256: make([]byte, 32), Reason: agentapiv1.AdvisoryReason(99),
			}},
		}}, false},
		{"EnvelopeAdvisory optional last_ipc_refusal 99", &agentapiv1.EnvelopeAdvisory{
			EnvelopeSha256: make([]byte, 32),
			Reason:         agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_DELIVERED_EXECUTOR_UNAVAILABLE,
			LastIpcRefusal: &badRefusal,
		}, false},
		{"HealthReport repeated condition 99", &agentapiv1.HealthReport{
			AgentTimeMs: 1, Conditions: []agentapiv1.AgentCondition{1, 99},
		}, false},
		{"EnvelopeBody autonomy_level UNSPECIFIED", noAutonomy, false},
		{"EnvelopeBody params absent", noParams, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := agentapiv1.CheckDeclared(tc.m)
			if tc.ok {
				if err != nil {
					t.Fatalf("CheckDeclared = %v; want nil", err)
				}
				return
			}
			if !errors.Is(err, agentapiv1.ErrUndeclared) {
				t.Fatalf("CheckDeclared = %v; want ErrUndeclared", err)
			}
		})
	}
}

// FuzzReadMessageSeq: AC47, R32a. Never panics; whenever the strict
// decoder accepts an OutboxMessage with message_seq != 0, ReadMessageSeq
// agrees with it; and a nil error never carries a zero value.
func FuzzReadMessageSeq(f *testing.F) {
	p := payloadField(f)
	f.Add(cat(seqField(7), p))
	f.Add(cat(p, seqField(9)))
	f.Add(p)
	f.Add(cat(seqField(7), p, seqField(7)))
	f.Add(cat(seqField(0), p))
	f.Add([]byte{0x88, 0x00, 0x07})
	f.Add([]byte{0x08, 0x87, 0x00})
	f.Add([]byte{0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02})
	f.Add([]byte{0x08, 0x01, 0x1b, 0x1c})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := agentapiv1.ReadMessageSeq(b)
		if err == nil && got == 0 {
			t.Fatal("ReadMessageSeq returned 0 with a nil error")
		}
		if err != nil && !errors.Is(err, agentapiv1.ErrMessageSeqUnreadable) {
			t.Fatalf("error %v does not wrap ErrMessageSeqUnreadable", err)
		}
		var m agentapiv1.OutboxMessage
		if agentapiv1.StrictUnmarshal(b, &m) != nil || m.GetMessageSeq() == 0 {
			return
		}
		if err != nil || got != m.GetMessageSeq() {
			t.Fatalf("ReadMessageSeq = %d, %v; strict decoder says %d", got, err, m.GetMessageSeq())
		}
	})
}

// FuzzPeekMember: AC47, R11. Never panics; whenever the strict decoder
// accepts an AgentMessage with a member set, PeekMember names that member.
func FuzzPeekMember(f *testing.F) {
	md := (&agentapiv1.AgentMessage{}).ProtoReflect().Descriptor()
	od := md.Oneofs().Get(0)
	f.Add([]byte{0x1a, 0x02, 0x08, 0x01})
	f.Add([]byte{0x22, 0x02, 0x08, 0x01})
	f.Add([]byte{})
	f.Add([]byte{0x9a, 0x00, 0x00})
	f.Add([]byte{0x80})
	f.Add([]byte{0x7a, 0x00})
	f.Add([]byte{0x18, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := agentapiv1.PeekMember(b, md)
		if err == nil && od.Fields().ByNumber(got) == nil {
			t.Fatalf("PeekMember returned %d, not a member", got)
		}
		var m agentapiv1.AgentMessage
		if agentapiv1.StrictUnmarshal(b, &m) != nil {
			return
		}
		fd := m.ProtoReflect().WhichOneof(od)
		if fd == nil {
			return
		}
		if err != nil || got != fd.Number() {
			t.Fatalf("PeekMember = %d, %v; strict decoder set member %d", got, err, fd.Number())
		}
	})
}
