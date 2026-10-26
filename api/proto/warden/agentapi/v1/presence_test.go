package agentapiv1_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// agentapiOptional is R52b's allow-list for warden.agentapi.v1: exactly the
// four fields §4 marks optional.
var agentapiOptional = []protoreflect.FullName{
	"warden.agentapi.v1.SignedReplyReport.advisory_document_sequence",
	"warden.agentapi.v1.EnvelopeAdvisory.last_ipc_refusal",
	"warden.agentapi.v1.AdminToolRecord.refused_sequence",
	"warden.agentapi.v1.AdminToolRecord.release_sequence",
}

// v1TypedResultOptional: the five typed-result fields of R52b (0 is a real
// reading; absence is shown by no other field).
var v1TypedResultOptional = []protoreflect.FullName{
	"warden.v1.PrimitiveResult.exit_status",
	"warden.v1.MemStatusResult.psi_some_avg10",
	"warden.v1.MemStatusResult.psi_full_avg10",
	"warden.v1.DbReplicationStatus.lag_seconds",
	"warden.v1.DbReplsetMember.optime_lag_seconds",
}

// v1SignedBodyOptional: the six signed-body fields of R52b (executor-ipc
// §4.6, §4.7), where a present zero is encoded and canonical (R13 (j)).
var v1SignedBodyOptional = []protoreflect.FullName{
	"warden.v1.ExecutorResultBody.exit_status",
	"warden.v1.ExecutorResultBody.stored_action_id",
	"warden.v1.TrustInstallResultBody.received_length",
	"warden.v1.TrustInstallResultBody.minimum_sequence",
	"warden.v1.TrustInstallResultBody.document_sequence",
	"warden.v1.ExecutorStatusBody.recovery_floor",
}

func v1Optional() []protoreflect.FullName {
	return append(slices.Clone(v1TypedResultOptional), v1SignedBodyOptional...)
}

// TestOptionalAllowListAgentapi (AC48): the fields declared proto3
// optional in warden.agentapi.v1 are exactly the four of R52b.
func TestOptionalAllowListAgentapi(t *testing.T) {
	if len(agentapiOptional) != 4 {
		t.Fatalf("allow-list has %d fields, R52b lists 4", len(agentapiOptional))
	}
	for _, v := range optionalViolations(allMessages(packageFiles(t, agentapiPkg)), agentapiOptional) {
		t.Error(v)
	}
}

// TestOptionalAllowListWardenV1 (AC48): the fields declared proto3
// optional in warden.v1, every file included, are exactly the eleven of
// R52b.
func TestOptionalAllowListWardenV1(t *testing.T) {
	if got := len(v1Optional()); got != 11 {
		t.Fatalf("allow-list has %d fields, R52b lists 11", got)
	}
	for _, v := range optionalViolations(allMessages(packageFiles(t, wardenPkg)), v1Optional()) {
		t.Error(v)
	}
}

// optionalTestFile builds a test-only file, outside the contract, from
// (name, proto3 optional?) pairs of uint64 fields in one message.
func optionalTestFile(t *testing.T, pkg, msg string, fields []struct {
	name     string
	optional bool
}) []protoreflect.MessageDescriptor {
	t.Helper()
	dp := &descriptorpb.DescriptorProto{Name: proto.String(msg)}
	for i, f := range fields {
		fdp := &descriptorpb.FieldDescriptorProto{
			Name: proto.String(f.name), Number: proto.Int32(int32(i + 1)),
			Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			Type:  descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum(),
		}
		if f.optional {
			fdp.Proto3Optional = proto.Bool(true)
			fdp.OneofIndex = proto.Int32(int32(len(dp.OneofDecl)))
			dp.OneofDecl = append(dp.OneofDecl, &descriptorpb.OneofDescriptorProto{Name: proto.String("_" + f.name)})
		}
		dp.Field = append(dp.Field, fdp)
	}
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:        proto.String(strings.ReplaceAll(pkg, ".", "/") + "/optional.proto"),
		Package:     proto.String(pkg),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{dp},
	}, new(protoregistry.Files))
	if err != nil {
		t.Fatal(err)
	}
	return allMessages([]protoreflect.FileDescriptor{fd})
}

// TestOptionalAllowListDetects (AC48): a test-only copy of a §4 message
// with a fifth optional field, a test-only warden.v1-style message with an
// optional field outside the eleven, and a listed field declared without
// optional each fail the check.
func TestOptionalAllowListDetects(t *testing.T) {
	type f = struct {
		name     string
		optional bool
	}
	t.Run("fifth optional in a copy of a §4 message", func(t *testing.T) {
		mds := optionalTestFile(t, "wardentest.agentapi", "SignedReplyReport", []f{
			{"advisory_document_sequence", true}, {"primitive_result_omitted_reason", true},
		})
		got := optionalViolations(mds, []protoreflect.FullName{"wardentest.agentapi.SignedReplyReport.advisory_document_sequence"})
		want := []string{"wardentest.agentapi.SignedReplyReport.primitive_result_omitted_reason: optional field not in the R52b allow-list"}
		if !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("optional outside the eleven", func(t *testing.T) {
		mds := optionalTestFile(t, "wardentest.v1", "FsUsageResult", []f{{"total_bytes", true}})
		got := optionalViolations(mds, nil)
		want := []string{"wardentest.v1.FsUsageResult.total_bytes: optional field not in the R52b allow-list"}
		if !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("listed field declared without optional", func(t *testing.T) {
		mds := optionalTestFile(t, "wardentest.v1", "ExecutorStatusBody", []f{{"recovery_floor", false}})
		got := optionalViolations(mds, []protoreflect.FullName{
			"wardentest.v1.ExecutorStatusBody.recovery_floor",
			"wardentest.v1.ExecutorStatusBody.missing",
		})
		want := []string{
			"wardentest.v1.ExecutorStatusBody.recovery_floor: allow-listed field declared without optional",
			"wardentest.v1.ExecutorStatusBody.missing: allow-listed field not declared",
		}
		if !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// newMessage returns an empty instance of a registered message type.
func newMessage(t *testing.T, name protoreflect.FullName) protoreflect.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return mt.New()
}

func splitField(name protoreflect.FullName) (protoreflect.FullName, protoreflect.Name) {
	return name.Parent(), name.Name()
}

// zeroOf is the proto3 default of a scalar or enum field.
func zeroOf(fd protoreflect.FieldDescriptor) protoreflect.Value {
	if fd.Kind() == protoreflect.EnumKind {
		return protoreflect.ValueOfEnum(0)
	}
	return fd.Default()
}

var deterministic = proto.MarshalOptions{Deterministic: true}

// TestOptionalFieldsRoundTrip (AC48): each of the fifteen optional fields
// round-trips absent, present with zero (or the empty string) and present
// with a non-zero value, and absent stays distinct from a present zero,
// through both proto.Unmarshal and the strict scanner.
func TestOptionalFieldsRoundTrip(t *testing.T) {
	all := append(v1Optional(), agentapiOptional...)
	for _, name := range all {
		msgName, fieldName := splitField(name)
		t.Run(string(name), func(t *testing.T) {
			m := newMessage(t, msgName)
			fd := m.Descriptor().Fields().ByName(fieldName)
			if fd == nil || !fd.HasPresence() {
				t.Fatalf("%s missing or without presence", name)
			}
			nonZero := protoreflect.ValueOfUint64(7)
			switch fd.Kind() {
			case protoreflect.Int32Kind:
				nonZero = protoreflect.ValueOfInt32(-1)
			case protoreflect.Int64Kind:
				nonZero = protoreflect.ValueOfInt64(1_700_000_000)
			case protoreflect.Uint32Kind:
				nonZero = protoreflect.ValueOfUint32(100)
			case protoreflect.StringKind:
				nonZero = protoreflect.ValueOfString("01890a5d-ac96-774b-bcce-b302099a8057")
			case protoreflect.EnumKind:
				nonZero = protoreflect.ValueOfEnum(1)
			}
			for _, c := range []struct {
				label string
				set   *protoreflect.Value
			}{{"absent", nil}, {"present zero", ptr(zeroOf(fd))}, {"present", &nonZero}} {
				msg := m.New()
				if c.set != nil {
					msg.Set(fd, *c.set)
				}
				b, err := deterministic.Marshal(msg.Interface())
				if err != nil {
					t.Fatal(err)
				}
				if (c.set == nil) != (len(b) == 0) {
					t.Errorf("%s: %d bytes marshalled", c.label, len(b))
				}
				for _, decode := range []struct {
					name string
					fn   func([]byte, proto.Message) error
				}{{"proto.Unmarshal", proto.Unmarshal}, {"wirescan.Unmarshal", wirescan.Unmarshal}} {
					got := m.New()
					if err := decode.fn(b, got.Interface()); err != nil {
						t.Fatalf("%s: %s: %v", c.label, decode.name, err)
					}
					if got.Has(fd) != (c.set != nil) {
						t.Errorf("%s: %s: Has = %v", c.label, decode.name, got.Has(fd))
					}
					if c.set != nil && !got.Get(fd).Equal(*c.set) {
						t.Errorf("%s: %s: value %v, want %v", c.label, decode.name, got.Get(fd), *c.set)
					}
				}
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestOptionalGoTypes: the generated Go fields of the fifteen optional
// fields are pointers, so absent (nil) and a present zero are distinct in
// code too.
func TestOptionalGoTypes(t *testing.T) {
	msgs := []proto.Message{
		&wardenv1.PrimitiveResult{ExitStatus: proto.Int32(0)},
		&wardenv1.MemStatusResult{PsiSomeAvg10: proto.Uint32(0), PsiFullAvg10: proto.Uint32(0)},
		&wardenv1.DbReplicationStatus{LagSeconds: proto.Uint64(0)},
		&wardenv1.DbReplsetMember{OptimeLagSeconds: proto.Uint64(0)},
		&wardenv1.ExecutorResultBody{ExitStatus: proto.Int32(0), StoredActionId: proto.String("")},
		&wardenv1.TrustInstallResultBody{ReceivedLength: proto.Uint32(0), MinimumSequence: proto.Uint64(0), DocumentSequence: proto.Uint64(0)},
		&wardenv1.ExecutorStatusBody{RecoveryFloor: proto.Int64(0)},
		&agentapiv1.SignedReplyReport{AdvisoryDocumentSequence: proto.Uint64(0)},
		&agentapiv1.EnvelopeAdvisory{LastIpcRefusal: wardenv1.IpcRefusalCode_IPC_REFUSAL_CODE_UNSPECIFIED.Enum()},
		&agentapiv1.AdminToolRecord{RefusedSequence: proto.Uint64(0), ReleaseSequence: proto.Uint64(0)},
	}
	present := 0
	for _, m := range msgs {
		b, err := deterministic.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 {
			t.Errorf("%T: a present zero marshalled to nothing", m)
		}
		m.ProtoReflect().Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool {
			present++
			return true
		})
	}
	if present != 15 {
		t.Errorf("%d present fields, want 15", present)
	}
}

// TestSignedBodyPresentZeroPassesScan (AC48, R13 (j)): a deterministically
// marshalled signed body with a present zero in one of its optional fields
// is canonical and passes the strict scanner, while the same zero
// explicitly encoded in an implicit-presence field of the same body is
// refused.
func TestSignedBodyPresentZeroPassesScan(t *testing.T) {
	for _, name := range v1SignedBodyOptional {
		msgName, fieldName := splitField(name)
		t.Run(string(name), func(t *testing.T) {
			m := newMessage(t, msgName)
			md := m.Descriptor()
			// A realistic body: format_version 1, a server ID, a boot ID
			// and a result sequence, around the optional field.
			m.Set(md.Fields().ByName("format_version"), protoreflect.ValueOfUint32(1))
			m.Set(md.Fields().ByName("server_id"), protoreflect.ValueOfString("4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f"))
			m.Set(md.Fields().ByName("result_sequence"), protoreflect.ValueOfUint64(42))
			if fd := md.Fields().ByName("boot_id"); fd != nil {
				m.Set(fd, protoreflect.ValueOfBytes(make([]byte, 16)))
			}
			fd := md.Fields().ByName(fieldName)
			m.Set(fd, zeroOf(fd))
			b, err := deterministic.Marshal(m.Interface())
			if err != nil {
				t.Fatal(err)
			}
			got := m.New()
			if err := wirescan.Unmarshal(b, got.Interface()); err != nil {
				t.Fatalf("present zero refused: %v", err)
			}
			if !got.Has(fd) {
				t.Error("present zero decoded as absent")
			}
			if !proto.Equal(got.Interface(), m.Interface()) {
				t.Error("round trip changed the body")
			}
		})
	}
	// The contrast: format_version (field 1, implicit presence) explicitly
	// encoded as 0 is non-canonical in each body.
	for _, msgName := range []protoreflect.FullName{"warden.v1.ExecutorResultBody", "warden.v1.TrustInstallResultBody", "warden.v1.ExecutorStatusBody"} {
		got := newMessage(t, msgName)
		if err := wirescan.Unmarshal([]byte{0x08, 0x00}, got.Interface()); !errors.Is(err, wirescan.ErrNonCanonical) {
			t.Errorf("%s: explicit format_version 0: err = %v, want ErrNonCanonical", msgName, err)
		}
	}
}

// TestAgentapiOptionalPassesOrderScan (AC48, R13 (k)): a marshalled
// message with a present optional field, beside fields numbered on both
// sides of it, is written in ascending order and passes the strict scan;
// proto3 optional fields are synthetic oneofs, which protobuf-go does not
// move to the end (action-envelope §4.1a).
func TestAgentapiOptionalPassesOrderScan(t *testing.T) {
	for _, seq := range []uint64{0, 1, 1<<63 - 1} {
		msgs := []proto.Message{
			&agentapiv1.SignedReplyReport{
				Kind:                         agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT,
				Signed:                       []byte{1, 2, 3},
				AdvisoryDocumentSequence:     proto.Uint64(seq),
				PrimitiveResultOmitted:       true,
				PrimitiveResultOmittedReason: agentapiv1.OmitReason_OMIT_REASON_SIZE,
			},
			&agentapiv1.EnvelopeAdvisory{
				EnvelopeSha256: make([]byte, 32),
				Reason:         agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_DELIVERED_EXECUTOR_UNAVAILABLE,
				LastIpcRefusal: wardenv1.IpcRefusalCode(seq % 7).Enum(),
			},
			&agentapiv1.AdminToolRecord{
				RecordId:        make([]byte, 16),
				Mode:            agentapiv1.AdminToolMode_ADMIN_TOOL_MODE_STAGE,
				Code:            agentapiv1.AdminToolCode_ADMIN_TOOL_CODE_DOWNGRADE,
				RefusedSequence: proto.Uint64(seq),
				ReleaseVersion:  "1.2.3",
				ReleaseSequence: proto.Uint64(seq),
				RecordedAt:      1_700_000_000_000,
				SignedReplies:   [][]byte{{1}, {2}},
			},
		}
		for _, m := range msgs {
			// Inside the stream's carriers too, as the control plane
			// receives them.
			wrapped := wrapOutbox(m)
			for _, msg := range []proto.Message{m, wrapped} {
				b, err := deterministic.Marshal(msg)
				if err != nil {
					t.Fatal(err)
				}
				got := msg.ProtoReflect().New().Interface()
				if err := wirescan.Unmarshal(b, got); err != nil {
					t.Errorf("%T with sequence %d: %v", msg, seq, err)
				}
				if !proto.Equal(got, msg) {
					t.Errorf("%T with sequence %d: round trip changed the message", msg, seq)
				}
			}
		}
	}
}

func wrapOutbox(m proto.Message) *agentapiv1.AgentMessage {
	p := &agentapiv1.OutboxPayload{}
	switch v := m.(type) {
	case *agentapiv1.SignedReplyReport:
		p.Payload = &agentapiv1.OutboxPayload_SignedReply{SignedReply: v}
	case *agentapiv1.EnvelopeAdvisory:
		p.Payload = &agentapiv1.OutboxPayload_EnvelopeAdvisory{EnvelopeAdvisory: v}
	case *agentapiv1.AdminToolRecord:
		p.Payload = &agentapiv1.OutboxPayload_AdminToolRecord{AdminToolRecord: v}
	}
	return &agentapiv1.AgentMessage{Body: &agentapiv1.AgentMessage_Outbox{
		Outbox: &agentapiv1.OutboxMessage{MessageSeq: 9, Payload: p},
	}}
}
