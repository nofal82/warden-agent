package wirescan_test

// Tests for the shared strict wire scanner (action-envelope.md R13 b–d,
// §5.3). Inputs are hand-encoded with protowire.

import (
	"bytes"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/structpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

func validBody() *wardenv1.EnvelopeBody {
	return &wardenv1.EnvelopeBody{
		FormatVersion:   1,
		ActionId:        "01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f",
		TargetServerId:  "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5",
		PlaybookId:      "service-recover",
		PlaybookVersion: "1.2.3",
		PlaybookDigest:  make([]byte, 32),
		StepId:          "restart",
		Params: &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_ServiceRestart{
			ServiceRestart: &wardenv1.ServiceRestartRequest{Unit: "nginx.service"}}},
		PolicyDecision: &wardenv1.PolicyDecision{
			DecisionId:         "3c4d5e6f-7a8b-4c9d-ae0f-1a2b3c4d5e6f",
			AutonomyLevel:      wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L2,
			PolicyBundleDigest: make([]byte, 32),
		},
		CreatedAt:      1_800_000_000,
		ExpiresAt:      1_800_000_300,
		IdempotencyKey: "wf-0001:step-restart:1",
	}
}

// Every message type in the contract, fully populated and deterministically
// marshalled, passes Check and Unmarshal.
func TestValidEveryMessageType(t *testing.T) {
	var mds []protoreflect.MessageDescriptor
	for _, file := range []protoreflect.FileDescriptor{
		wardenv1.File_warden_v1_envelope_proto, wardenv1.File_warden_v1_typed_request_proto,
	} {
		for i := 0; i < file.Messages().Len(); i++ {
			mds = append(mds, file.Messages().Get(i))
		}
	}
	if len(mds) < 25 {
		t.Fatalf("found only %d message types", len(mds))
	}
	for _, md := range mds {
		t.Run(string(md.Name()), func(t *testing.T) {
			mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
			if err != nil {
				t.Fatal(err)
			}
			m := mt.New()
			populate(m)
			b := marshalDet(t, m.Interface())
			assertSentinel(t, wirescan.Check(b, md), nil)
			out := mt.New().Interface()
			assertSentinel(t, wirescan.Unmarshal(b, out), nil)
			if !proto.Equal(out, m.Interface()) {
				t.Fatalf("Unmarshal result differs")
			}
			// Empty encoding is a valid (empty) message.
			assertSentinel(t, wirescan.Check(nil, md), nil)
			assertSentinel(t, wirescan.Check([]byte{}, md), nil)
		})
	}
}

// Every params member through the whole EnvelopeBody passes.
func TestValidEveryParamsMember(t *testing.T) {
	od := paramsMD.Oneofs().ByName("request")
	for i := 0; i < od.Fields().Len(); i++ {
		fd := od.Fields().Get(i)
		t.Run(string(fd.Name()), func(t *testing.T) {
			tr := (&wardenv1.TypedRequest{}).ProtoReflect()
			inner := tr.NewField(fd)
			populate(inner.Message())
			tr.Set(fd, inner)
			body := validBody()
			body.Params = tr.Interface().(*wardenv1.TypedRequest)
			b := marshalDet(t, body)
			assertSentinel(t, wirescan.Check(b, bodyMD), nil)
			var out wardenv1.EnvelopeBody
			assertSentinel(t, wirescan.Unmarshal(b, &out), nil)
			if !proto.Equal(&out, body) {
				t.Fatalf("round trip differs")
			}
		})
	}
}

type scanCase struct {
	name string
	md   protoreflect.MessageDescriptor
	b    []byte
	want error
}

func runScanCases(t *testing.T, cases []scanCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSentinel(t, wirescan.Check(c.b, c.md), c.want)
			mt, err := protoregistry.GlobalTypes.FindMessageByName(c.md.FullName())
			if err != nil {
				t.Fatal(err)
			}
			// Unmarshal must agree with Check on every case.
			assertSentinel(t, wirescan.Unmarshal(c.b, mt.New().Interface()), c.want)
		})
	}
}

func TestBodyCases(t *testing.T) {
	base := marshalDet(t, validBody())
	noParams := func() []byte { b := validBody(); b.Params = nil; return marshalDet(t, b) }()
	noPD := func() []byte { b := validBody(); b.PolicyDecision = nil; return marshalDet(t, b) }()
	pd := marshalDet(t, validBody().PolicyDecision)
	restart := marshalDet(t, &wardenv1.ServiceRestartRequest{Unit: "nginx.service"})
	without := func(m func(b *wardenv1.EnvelopeBody)) []byte { b := validBody(); m(b); return marshalDet(t, b) }
	app := func(b []byte, more ...[]byte) []byte {
		return cat(append([][]byte{append([]byte(nil), b...)}, more...)...)
	}
	withParams := func(tr []byte) []byte { return fBytes(append([]byte(nil), noParams...), 8, tr) }
	withPD := func(p []byte) []byte { return fBytes(append([]byte(nil), noPD...), 9, p) }

	// Field number beyond 2^29-1, encoded as a raw tag varint.
	tooBig := protowire.AppendVarint(nil, uint64(protowire.MaxValidNumber+1)<<3)
	tooBig = protowire.AppendVarint(tooBig, 1)
	hugeNum := protowire.AppendVarint(nil, uint64(math.MaxUint32)<<3)
	hugeNum = protowire.AppendVarint(hugeNum, 1)

	runScanCases(t, []scanCase{
		{"valid", bodyMD, base, nil},
		{"valid_params_last_out_of_order", bodyMD, withParams(fBytes(nil, 11, restart)), nil},
		{"valid_empty_pd", bodyMD, withPD(nil), nil},
		{"valid_field_less_member", bodyMD, withParams(fBytes(nil, 7, nil)), nil},

		// unknown fields
		{"unknown_99_varint", bodyMD, fVarint(app(base), 99, 1), wirescan.ErrUnknownField},
		{"unknown_99_bytes", bodyMD, fBytes(app(base), 99, []byte("x")), wirescan.ErrUnknownField},
		{"unknown_99_fixed32", bodyMD, fFixed32(app(base), 99, 1), wirescan.ErrUnknownField},
		{"unknown_99_fixed64", bodyMD, fFixed64(app(base), 99, 1), wirescan.ErrUnknownField},
		{"unknown_13", bodyMD, fVarint(app(base), 13, 0), wirescan.ErrUnknownField},
		{"unknown_max_number", bodyMD, fVarint(app(base), protowire.MaxValidNumber, 0), wirescan.ErrUnknownField},
		{"unknown_first", bodyMD, cat(fVarint(nil, 50, 0), base), wirescan.ErrUnknownField},
		{"unknown_in_pd", bodyMD, withPD(fVarint(app(pd), 99, 1)), wirescan.ErrUnknownField},
		{"unknown_in_params", bodyMD, withParams(cat(fBytes(nil, 11, restart), fVarint(nil, 99, 1))), wirescan.ErrUnknownField},
		{"reserved_20_in_params", bodyMD, withParams(fBytes(nil, 20, nil)), wirescan.ErrUnknownField},
		{"unknown_23_in_params", bodyMD, withParams(fBytes(nil, 23, nil)), wirescan.ErrUnknownField},
		{"unknown_in_request", bodyMD, withParams(fBytes(nil, 11, fVarint(app(restart), 99, 1))), wirescan.ErrUnknownField},
		{"unknown_in_field_less_request", bodyMD, withParams(fBytes(nil, 19, fVarint(nil, 1, 0))), wirescan.ErrUnknownField},

		// duplicates
		{"dup_format_version", bodyMD, fVarint(app(base), 1, 1), wirescan.ErrDuplicateField},
		{"dup_action_id", bodyMD, fBytes(app(base), 2, []byte("x")), wirescan.ErrDuplicateField},
		{"dup_created_at_same_value", bodyMD, fVarint(app(base), 10, 1_800_000_000), wirescan.ErrDuplicateField},
		{"dup_playbook_digest", bodyMD, fBytes(app(base), 6, make([]byte, 32)), wirescan.ErrDuplicateField},
		{"dup_idempotency_key", bodyMD, fBytes(app(base), 12, []byte("k")), wirescan.ErrDuplicateField},
		{"repeated_policy_decision", bodyMD, fBytes(app(base), 9, pd), wirescan.ErrDuplicateField},
		{"repeated_policy_decision_empty", bodyMD, fBytes(withPD(nil), 9, nil), wirescan.ErrDuplicateField},
		{"dup_in_pd", bodyMD, withPD(fBytes(app(pd), 1, []byte("x"))), wirescan.ErrDuplicateField},
		{"dup_autonomy_in_pd", bodyMD, withPD(fVarint(app(pd), 2, 1)), wirescan.ErrDuplicateField},
		{"two_params_fields_same_member", bodyMD, fBytes(app(base), 8, fBytes(nil, 11, restart)), wirescan.ErrDuplicateField},
		{"two_params_fields_diff_member", bodyMD, fBytes(withParams(fBytes(nil, 11, restart)), 8, fBytes(nil, 7, nil)), wirescan.ErrDuplicateField},
		{"two_oneof_members", bodyMD, withParams(cat(fBytes(nil, 11, restart), fBytes(nil, 7, nil))), wirescan.ErrDuplicateField},
		{"two_oneof_members_far_apart", bodyMD, withParams(cat(fBytes(nil, 1, nil), fBytes(nil, 22, nil))), wirescan.ErrDuplicateField},
		{"same_oneof_member_twice", bodyMD, withParams(cat(fBytes(nil, 11, restart), fBytes(nil, 11, restart))), wirescan.ErrDuplicateField},
		{"same_empty_member_twice", bodyMD, withParams(cat(fBytes(nil, 7, nil), fBytes(nil, 7, nil))), wirescan.ErrDuplicateField},
		{"dup_in_request", bodyMD, withParams(fBytes(nil, 11, fBytes(app(restart), 1, []byte("sshd.service")))), wirescan.ErrDuplicateField},

		// groups at depth 0, 1, 2
		{"group_depth0_unknown_number", bodyMD, fGroup(app(base), 99, nil), wirescan.ErrGroup},
		{"group_depth0_known_number", bodyMD, fGroup(without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2, nil), wirescan.ErrGroup},
		{"group_depth0_with_content", bodyMD, fGroup(app(base), 50, fVarint(nil, 1, 1)), wirescan.ErrGroup},
		{"lone_end_group_depth0", bodyMD, app(base, protowire.AppendTag(nil, 7, protowire.EndGroupType)), wirescan.ErrGroup},
		{"lone_start_group_depth0", bodyMD, app(base, protowire.AppendTag(nil, 99, protowire.StartGroupType)), wirescan.ErrGroup},
		{"group_depth1_pd", bodyMD, withPD(fGroup(app(pd), 9, nil)), wirescan.ErrGroup},
		{"group_depth1_params", bodyMD, withParams(fGroup(nil, 11, restart)), wirescan.ErrGroup},
		{"group_depth2_request", bodyMD, withParams(fBytes(nil, 11, fGroup(app(restart), 2, nil))), wirescan.ErrGroup},
		{"end_group_depth2_request", bodyMD, withParams(fBytes(nil, 11, protowire.AppendTag(app(restart), 1, protowire.EndGroupType))), wirescan.ErrGroup},

		// wire-type mismatch
		{"created_at_as_bytes", bodyMD, fBytes(without(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 }), 10, []byte{1}), wirescan.ErrWireType},
		{"created_at_as_fixed64", bodyMD, fFixed64(without(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 }), 10, 1), wirescan.ErrWireType},
		{"format_as_fixed32", bodyMD, fFixed32(without(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 }), 1, 1), wirescan.ErrWireType},
		{"format_packed_bytes", bodyMD, fBytes(without(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 }), 1, []byte{1}), wirescan.ErrWireType},
		{"action_id_as_varint", bodyMD, fVarint(without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2, 7), wirescan.ErrWireType},
		{"digest_as_fixed64", bodyMD, fFixed64(without(func(b *wardenv1.EnvelopeBody) { b.PlaybookDigest = nil }), 6, 7), wirescan.ErrWireType},
		{"params_as_varint", bodyMD, fVarint(app(noParams), 8, 11), wirescan.ErrWireType},
		{"pd_as_fixed32", bodyMD, fFixed32(app(noPD), 9, 0), wirescan.ErrWireType},
		{"autonomy_as_bytes_in_pd", bodyMD, withPD(fBytes(marshalDet(t, &wardenv1.PolicyDecision{DecisionId: "x"}), 2, []byte{1})), wirescan.ErrWireType},
		{"member_as_varint", bodyMD, withParams(fVarint(nil, 11, 1)), wirescan.ErrWireType},
		{"unit_as_varint_in_request", bodyMD, withParams(fBytes(nil, 11, fVarint(nil, 1, 1))), wirescan.ErrWireType},

		// malformed
		{"truncated_last_byte", bodyMD, base[:len(base)-1], wirescan.ErrMalformed},
		{"truncated_varint", bodyMD, []byte{0x08, 0x80}, wirescan.ErrMalformed},
		{"truncated_length", bodyMD, []byte{0x12, 0x05, 'a'}, wirescan.ErrMalformed},
		{"truncated_tag", bodyMD, []byte{0x80}, wirescan.ErrMalformed},
		{"length_overflow", bodyMD, []byte{0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, wirescan.ErrMalformed},
		{"length_max_int", bodyMD, append([]byte{0x12}, protowire.AppendVarint(nil, math.MaxInt64)...), wirescan.ErrMalformed},
		{"varint_11_bytes", bodyMD, append([]byte{0x08}, append(bytes.Repeat([]byte{0xff}, 10), 0x01)...), wirescan.ErrMalformed},
		{"field_number_zero_varint", bodyMD, []byte{0x00, 0x01}, wirescan.ErrMalformed},
		{"field_number_zero_bytes", bodyMD, []byte{0x02, 0x00}, wirescan.ErrMalformed},
		{"truncated_nested_pd", bodyMD, withPD(pd[:len(pd)-2]), wirescan.ErrMalformed},
		{"nested_length_beyond_parent", bodyMD, withParams([]byte{0x5a, 0x7f, 0x0a}), wirescan.ErrMalformed},
		{"bad_varint_in_request", bodyMD, withParams(fBytes(nil, 21, []byte{0x10, 0x80})), wirescan.ErrMalformed},
	})
	cases := []scanCase{
		{"field_number_2^29", bodyMD, app(base, tooBig), wirescan.ErrMalformed},
		{"field_number_max_uint32", bodyMD, app(base, hugeNum), wirescan.ErrMalformed},
		{"field_number_2^29_in_pd", bodyMD, withPD(app(pd, tooBig)), wirescan.ErrMalformed},
		{"field_number_zero_in_request", bodyMD, withParams(fBytes(nil, 11, []byte{0x00, 0x00})), wirescan.ErrMalformed},
	}
	runScanCases(t, cases)
}

func TestOuterCases(t *testing.T) {
	kid, body, sig := make([]byte, 32), []byte{0x08, 0x01}, make([]byte, 64)
	good := cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, sig))
	runScanCases(t, []scanCase{
		{"valid", outerMD, good, nil},
		{"valid_reordered", outerMD, cat(fBytes(nil, 3, sig), fBytes(nil, 1, kid), fBytes(nil, 2, body)), nil},
		{"valid_empty_fields", outerMD, cat(fBytes(nil, 1, nil), fBytes(nil, 2, nil), fBytes(nil, 3, nil)), nil},
		{"dup_key_id", outerMD, fBytes(append([]byte(nil), good...), 1, kid), wirescan.ErrDuplicateField},
		{"dup_body", outerMD, fBytes(append([]byte(nil), good...), 2, body), wirescan.ErrDuplicateField},
		{"dup_signature", outerMD, fBytes(append([]byte(nil), good...), 3, sig), wirescan.ErrDuplicateField},
		{"unknown_4", outerMD, fBytes(append([]byte(nil), good...), 4, nil), wirescan.ErrUnknownField},
		{"group", outerMD, fGroup(append([]byte(nil), good...), 4, nil), wirescan.ErrGroup},
		{"group_known_number", outerMD, fGroup(nil, 2, nil), wirescan.ErrGroup},
		{"key_id_as_varint", outerMD, fVarint(nil, 1, 1), wirescan.ErrWireType},
		{"body_as_fixed32", outerMD, fFixed32(nil, 2, 1), wirescan.ErrWireType},
		{"signature_as_fixed64", outerMD, fFixed64(nil, 3, 1), wirescan.ErrWireType},
		{"truncated", outerMD, good[:len(good)-1], wirescan.ErrMalformed},
		{"empty_length_prefix_only", outerMD, []byte{0x0a}, wirescan.ErrMalformed},
		{"field_zero", outerMD, []byte{0x02, 0x00}, wirescan.ErrMalformed},
	})
	// The outer scanner must not descend into body (it is opaque bytes):
	// a body that is not a valid EnvelopeBody still passes the outer scan.
	opaque := cat(fBytes(nil, 1, kid), fBytes(nil, 2, []byte{0xff, 0xff, 0x0c, 0x00}), fBytes(nil, 3, sig))
	assertSentinel(t, wirescan.Check(opaque, outerMD), nil)
}

func TestRepeatedFields(t *testing.T) {
	ids := []uint64{1, 300, 1 << 40}
	starts := []int64{-1, 0, 1_700_000_000_000_000}
	packedStarts := func() []byte {
		var b []byte
		for _, v := range starts {
			b = protowire.AppendVarint(b, uint64(v))
		}
		return b
	}()
	unpackedIDs := func() []byte {
		var b []byte
		for _, v := range ids {
			b = fVarint(b, 3, v)
		}
		return b
	}()
	digest := make([]byte, 32)
	runScanCases(t, []scanCase{
		{"packed_ids", dbTermMD, fBytes(nil, 3, packedVarints(ids...)), nil},
		{"unpacked_ids", dbTermMD, unpackedIDs, nil},
		{"packed_then_unpacked", dbTermMD, cat(fBytes(nil, 3, packedVarints(1, 2)), fVarint(nil, 3, 3)), nil},
		{"two_packed_runs", dbTermMD, cat(fBytes(nil, 3, packedVarints(1)), fBytes(nil, 3, packedVarints(2))), nil},
		{"packed_empty", dbTermMD, fBytes(nil, 3, nil), nil},
		{"packed_starts_negative", dbTermMD, fBytes(nil, 4, packedStarts), nil},
		{"unpacked_starts", dbTermMD, cat(fVarint(nil, 4, uint64(starts[0])), fVarint(nil, 4, 5)), nil},
		{"repeated_bytes_three_times", dbTermMD, cat(fBytes(nil, 6, digest), fBytes(nil, 6, digest), fBytes(nil, 6, digest)), nil},
		{"many_ids", dbTermMD, fBytes(nil, 3, packedVarints(make([]uint64, 1000)...)), nil},
		{"full_message", dbTermMD, marshalDet(t, &wardenv1.DbTerminateSessionRequest{
			Engine: wardenv1.Engine_ENGINE_MYSQL, Instance: "mysql.service", SessionIds: ids, SessionStartedAt: starts,
			ServerStartedAt: 1_700_000_000, SessionOwnerDigests: [][]byte{digest, digest, digest}, MinIdleSeconds: 600,
		}), nil},

		{"ids_as_fixed64", dbTermMD, fFixed64(nil, 3, 1), wirescan.ErrWireType},
		{"ids_as_fixed32", dbTermMD, fFixed32(nil, 3, 1), wirescan.ErrWireType},
		{"starts_as_fixed32", dbTermMD, fFixed32(nil, 4, 1), wirescan.ErrWireType},
		{"starts_as_fixed64", dbTermMD, fFixed64(nil, 4, 1), wirescan.ErrWireType},
		{"digests_as_varint", dbTermMD, fVarint(nil, 6, 1), wirescan.ErrWireType},
		{"ids_group", dbTermMD, fGroup(nil, 3, nil), wirescan.ErrGroup},
		{"dup_engine", dbTermMD, cat(fVarint(nil, 1, 1), fVarint(nil, 1, 2)), wirescan.ErrDuplicateField},
		{"dup_instance", dbTermMD, cat(fBytes(nil, 2, []byte("a")), fBytes(nil, 2, []byte("b"))), wirescan.ErrDuplicateField},
		{"dup_server_started_at", dbTermMD, cat(fVarint(nil, 5, 1), fVarint(nil, 5, 1)), wirescan.ErrDuplicateField},
		{"dup_min_idle", dbTermMD, cat(fVarint(nil, 7, 60), fVarint(nil, 7, 60)), wirescan.ErrDuplicateField},
		{"packed_truncated_varint", dbTermMD, fBytes(nil, 3, []byte{0x80}), wirescan.ErrMalformed},
		{"unknown_8", dbTermMD, fVarint(nil, 8, 1), wirescan.ErrUnknownField},
		// non-repeated scalar sent packed: wire-type mismatch.
		{"engine_packed", dbTermMD, fBytes(nil, 1, packedVarints(1)), wirescan.ErrWireType},
		{"server_started_packed", dbTermMD, fBytes(nil, 5, packedVarints(1)), wirescan.ErrWireType},
	})
}

// Invalid UTF-8 in a string field is ErrMalformed from Unmarshal.
func TestUnmarshalInvalidUTF8(t *testing.T) {
	cases := map[string]struct {
		b []byte
		m proto.Message
	}{
		"action_id":      {fBytes(nil, 2, []byte("ab\xffcd")), &wardenv1.EnvelopeBody{}},
		"overlong_nul":   {fBytes(nil, 12, []byte{0xc0, 0x80}), &wardenv1.EnvelopeBody{}},
		"surrogate":      {fBytes(nil, 4, []byte("\xed\xa0\x80")), &wardenv1.EnvelopeBody{}},
		"in_pd":          {fBytes(nil, 9, fBytes(nil, 4, []byte{0xfe})), &wardenv1.EnvelopeBody{}},
		"in_request":     {fBytes(nil, 8, fBytes(nil, 3, fBytes(nil, 1, []byte{0x80}))), &wardenv1.EnvelopeBody{}},
		"truncated_rune": {fBytes(nil, 1, []byte("\xe2\x82")), &wardenv1.ServiceRestartRequest{}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			assertSentinel(t, wirescan.Unmarshal(c.b, c.m), wirescan.ErrMalformed)
		})
	}
	// Bytes fields accept arbitrary bytes.
	var out wardenv1.EnvelopeBody
	assertSentinel(t, wirescan.Unmarshal(fBytes(nil, 6, []byte{0xff, 0xfe}), &out), nil)
}

// Unmarshal leaves no unknown fields anywhere and equals proto.Unmarshal.
func TestUnmarshalMatchesProto(t *testing.T) {
	b := marshalDet(t, validBody())
	var got, want wardenv1.EnvelopeBody
	assertSentinel(t, wirescan.Unmarshal(b, &got), nil)
	if err := proto.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&got, &want) {
		t.Fatalf("differs from proto.Unmarshal")
	}
	if len(got.ProtoReflect().GetUnknown()) != 0 ||
		len(got.GetPolicyDecision().ProtoReflect().GetUnknown()) != 0 ||
		len(got.GetParams().ProtoReflect().GetUnknown()) != 0 ||
		len(got.GetParams().GetServiceRestart().ProtoReflect().GetUnknown()) != 0 {
		t.Fatalf("unknown fields kept")
	}
}

// On error, Unmarshal must not leave a half-decoded message that a careless
// caller could use: either untouched or reset. We only require that an
// unknown-field input never yields a message with unknown fields.
func TestUnmarshalErrorNoUnknownLeak(t *testing.T) {
	b := fVarint(marshalDet(t, validBody()), 99, 1)
	var out wardenv1.EnvelopeBody
	if err := wirescan.Unmarshal(b, &out); err == nil {
		t.Fatalf("accepted unknown field")
	}
	if len(out.ProtoReflect().GetUnknown()) != 0 {
		t.Fatalf("Unmarshal ran proto.Unmarshal before the scan")
	}
}

// ErrTooDeep cannot be reached through the warden schema (it is not
// recursive), so it is exercised with the recursive well-known type
// google.protobuf.Value (Value -> ListValue -> Value ...).
func TestTooDeep(t *testing.T) {
	valueMD := (&structpb.Value{}).ProtoReflect().Descriptor()
	nest := func(levels int) []byte {
		v := fVarint(nil, 4, 1) // bool_value = true
		for i := 0; i < levels; i++ {
			lv := fBytes(nil, 1, v) // ListValue.values
			v = fBytes(nil, 6, lv)  // Value.list_value
		}
		return v
	}
	assertSentinel(t, wirescan.Check(nest(1), valueMD), nil)
	assertSentinel(t, wirescan.Check(nest(5000), valueMD), wirescan.ErrTooDeep)
	assertSentinel(t, wirescan.Unmarshal(nest(5000), &structpb.Value{}), wirescan.ErrTooDeep)
	// Deep group nesting is a group error, not a stack overflow.
	deep := []byte{}
	for i := 0; i < 100000; i++ {
		deep = protowire.AppendTag(deep, 1, protowire.StartGroupType)
	}
	if err := wirescan.Check(deep, bodyMD); err == nil {
		t.Fatalf("deep group nesting accepted")
	}
}

func TestSentinelsDistinct(t *testing.T) {
	seen := map[error]string{}
	for name, s := range sentinels {
		if s == nil {
			t.Fatalf("%s is nil", name)
		}
		if other, ok := seen[s]; ok {
			t.Fatalf("%s and %s are the same error", name, other)
		}
		seen[s] = name
	}
}

// Every request message rejects an unknown field and a group.
func TestUnmarshalIntoEveryRequestType(t *testing.T) {
	od := paramsMD.Oneofs().ByName("request")
	for i := 0; i < od.Fields().Len(); i++ {
		md := od.Fields().Get(i).Message()
		assertSentinel(t, wirescan.Check(fVarint(nil, 99, 1), md), wirescan.ErrUnknownField)
		assertSentinel(t, wirescan.Check(fGroup(nil, 1, nil), md), wirescan.ErrGroup)
	}
}
