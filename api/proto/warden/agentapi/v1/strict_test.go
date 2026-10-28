package agentapiv1_test

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// Issue #19: StrictUnmarshal is the public door to the shared strict
// decoder for the control plane, which cannot import internal/ (agent-api
// R12; action-envelope R13 (a)–(l); redaction R45a). It must behave exactly
// as wirescan.Unmarshal: same acceptance, same error values, same decoded
// message.

// The signature the control plane codes against.
var _ func([]byte, proto.Message) error = agentapiv1.StrictUnmarshal

// strictSentinels are every exported wirescan error value.
var strictSentinels = map[string]error{
	"ErrMalformed":      wirescan.ErrMalformed,
	"ErrUnknownField":   wirescan.ErrUnknownField,
	"ErrDuplicateField": wirescan.ErrDuplicateField,
	"ErrGroup":          wirescan.ErrGroup,
	"ErrWireType":       wirescan.ErrWireType,
	"ErrTooDeep":        wirescan.ErrTooDeep,
	"ErrNonCanonical":   wirescan.ErrNonCanonical,
}

// sameStrictError reports how err and want differ: one nil and not the
// other, a different text, or a different answer to errors.Is for any
// wirescan sentinel. "" means they are the same result.
func sameStrictError(err, want error) string {
	switch {
	case err == nil && want == nil:
		return ""
	case err == nil || want == nil:
		return "StrictUnmarshal: " + errText(err) + "; wirescan.Unmarshal: " + errText(want)
	case err.Error() != want.Error():
		return "error text " + strconv.Quote(err.Error()) + ", wirescan gives " + strconv.Quote(want.Error())
	}
	for name, s := range strictSentinels {
		if errors.Is(err, s) != errors.Is(want, s) {
			return "errors.Is(" + name + ") differs"
		}
	}
	return ""
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return strconv.Quote(err.Error())
}

// wantOnlySentinel fails unless err wraps want and no other sentinel.
func wantOnlySentinel(t *testing.T, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error %v does not wrap %v", err, want)
	}
	for name, s := range strictSentinels {
		if !errors.Is(s, want) && errors.Is(err, s) {
			t.Fatalf("error %v also wraps %s", err, name)
		}
	}
}

// ---------------------------------------------------------------------------
// Raw wire builders. Hostile bytes are built at run time from tags and
// values, never from a canonical marshal, so each case breaks exactly one
// R13 rule.

func wVarint(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func wBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func wString(b []byte, num protowire.Number, s string) []byte {
	return wBytes(b, num, []byte(s))
}

// cat joins wire fragments in order.
func cat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// Field numbers used below (outbox.proto, stream.proto, executor.proto).
const (
	outboxSeq     protowire.Number = 1 // OutboxMessage.message_seq
	outboxPayload protowire.Number = 2 // OutboxMessage.payload

	payloadSignedReply protowire.Number = 1 // OutboxPayload.signed_reply
	payloadAdvisory    protowire.Number = 2 // OutboxPayload.envelope_advisory
	payloadAdminTool   protowire.Number = 5 // OutboxPayload.admin_tool_record

	replyKind         protowire.Number = 1 // SignedReplyReport.kind
	replySigned       protowire.Number = 2 // SignedReplyReport.signed
	replyUnsignedBody protowire.Number = 3 // SignedReplyReport.unsigned_body

	advisoryReason protowire.Number = 2 // EnvelopeAdvisory.reason

	adminRecordID       protowire.Number = 1 // AdminToolRecord.record_id
	adminMode           protowire.Number = 2 // AdminToolRecord.mode
	adminReleaseVersion protowire.Number = 5 // AdminToolRecord.release_version

	agentOutbox protowire.Number = 3 // AgentMessage.outbox

	statusFormatVersion protowire.Number = 1 // ExecutorStatusBody.format_version
	statusServerID      protowire.Number = 2 // ExecutorStatusBody.server_id
	statusBinaryVersion protowire.Number = 5 // ExecutorStatusBody.binary_version
	statusInstalledRel  protowire.Number = 6 // ExecutorStatusBody.installed_release_version

	trustFormatVersion protowire.Number = 1 // TrustInstallResultBody.format_version
	trustServerID      protowire.Number = 2 // TrustInstallResultBody.server_id
)

// fixed returns n copies of c: stand-ins for hashes, keys and ids.
func fixed(c byte, n int) []byte { return bytes.Repeat([]byte{c}, n) }

// validReply is a canonical SignedReplyReport (kind STATUS, opaque signed
// bytes) used inside hostile outbox messages.
func validReply() []byte {
	return cat(
		wVarint(nil, replyKind, uint64(agentapiv1.ReplyKind_REPLY_KIND_STATUS)),
		wBytes(nil, replySigned, fixed(0x5a, 48)),
	)
}

// outbox builds OutboxMessage{message_seq: seq, payload: payload}.
func outbox(seq uint64, payload []byte) []byte {
	return cat(wVarint(nil, outboxSeq, seq), wBytes(nil, outboxPayload, payload))
}

// ---------------------------------------------------------------------------
// Realistic messages. Every identifier is an obvious fake.

func realisticStatusBody() *wardenv1.ExecutorStatusBody {
	floor := int64(1_760_000_000)
	return &wardenv1.ExecutorStatusBody{
		FormatVersion:            1,
		ServerId:                 "00000000-0000-4000-8000-000000000019",
		Challenge:                fixed(0x11, 32),
		ExecutorTime:             1_760_000_123_456,
		BinaryVersion:            "1.4.2",
		InstalledReleaseVersion:  "1.4.2",
		InstalledReleaseSequence: 7,
		Conditions: []wardenv1.HealthCondition{
			wardenv1.HealthCondition_HEALTH_CONDITION_RECOVERY_PENDING,
			wardenv1.HealthCondition_HEALTH_CONDITION_DATABASE_PLAYBOOKS_UNAVAILABLE,
		},
		Healthy:    false,
		TrustState: wardenv1.TrustState_TRUST_STATE_AVAILABLE,
		Installed: []*wardenv1.InstalledDocument{
			{Kind: wardenv1.TrustKind_TRUST_KIND_KEYSET, SequenceState: wardenv1.SequenceState_SEQUENCE_STATE_RECORDED, Sequence: 3, HashState: wardenv1.HashState_HASH_STATE_KNOWN, Hash: fixed(0x21, 32), InstalledMatches: true},
			{Kind: wardenv1.TrustKind_TRUST_KIND_CATALOG, SequenceState: wardenv1.SequenceState_SEQUENCE_STATE_RECORDED, Sequence: 12, HashState: wardenv1.HashState_HASH_STATE_KNOWN, Hash: fixed(0x22, 32), InstalledMatches: true},
			{Kind: wardenv1.TrustKind_TRUST_KIND_MANIFEST, SequenceState: wardenv1.SequenceState_SEQUENCE_STATE_RECORDED, Sequence: 40, HashState: wardenv1.HashState_HASH_STATE_KNOWN, Hash: fixed(0x23, 32)},
		},
		KeysetSignedBytes:    fixed(0x31, 96),
		RecoveryPending:      true,
		RecoveryId:           fixed(0x41, 24),
		RecoveryTime:         1_760_000_100,
		RecoveryFloor:        &floor,
		Frozen:               []*wardenv1.FrozenPlaybook{{PlaybookId: "nginx-restart", FrozenAt: 1_760_000_050_000}},
		ControlplaneCaSha256: [][]byte{fixed(0x51, 32), fixed(0x52, 32)},
		RootKeyFingerprint:   fixed(0x61, 32),
		ResultPublicKey:      fixed(0x62, 32),
		StoreRecords:         5,
		Busy:                 true,
		StartedAt:            1_759_999_000_000,
		ResultSequence:       901,
	}
}

func realisticTrustBody() *wardenv1.TrustInstallResultBody {
	length := uint32(2048)
	minSeq := uint64(12)
	docSeq := uint64(13)
	return &wardenv1.TrustInstallResultBody{
		FormatVersion:    1,
		ServerId:         "00000000-0000-4000-8000-000000000019",
		Kind:             wardenv1.TrustKind_TRUST_KIND_CATALOG,
		DocumentSha256:   fixed(0x71, 32),
		ReceivedLength:   &length,
		Result:           wardenv1.TrustInstallResult_TRUST_INSTALL_RESULT_INSTALLED,
		MinimumSequence:  &minSeq,
		DocumentSequence: &docSeq,
		Installed: []*wardenv1.InstalledDocument{
			{Kind: wardenv1.TrustKind_TRUST_KIND_KEYSET, SequenceState: wardenv1.SequenceState_SEQUENCE_STATE_RECORDED, Sequence: 3, HashState: wardenv1.HashState_HASH_STATE_KNOWN, Hash: fixed(0x21, 32), InstalledMatches: true},
			{Kind: wardenv1.TrustKind_TRUST_KIND_CATALOG, SequenceState: wardenv1.SequenceState_SEQUENCE_STATE_RECORDED, Sequence: 13, HashState: wardenv1.HashState_HASH_STATE_KNOWN, Hash: fixed(0x71, 32), InstalledMatches: true},
			{Kind: wardenv1.TrustKind_TRUST_KIND_MANIFEST, SequenceState: wardenv1.SequenceState_SEQUENCE_STATE_RECORDED, Sequence: 40, HashState: wardenv1.HashState_HASH_STATE_KNOWN, Hash: fixed(0x23, 32), InstalledMatches: true},
		},
		ReceivedAt:     1_760_000_200_000,
		SignedAt:       1_760_000_200_010,
		ResultSequence: 902,
		BootId:         fixed(0x81, 16),
	}
}

// realisticOutbox is an agent's STATUS report: the executor's signed reply
// bytes and its unsigned body (the R45a intake case).
func realisticOutbox(t testing.TB) *agentapiv1.OutboxMessage {
	t.Helper()
	body, err := deterministic.Marshal(realisticStatusBody())
	if err != nil {
		t.Fatal(err)
	}
	return &agentapiv1.OutboxMessage{
		MessageSeq: 4711,
		Payload: &agentapiv1.OutboxPayload{
			Payload: &agentapiv1.OutboxPayload_SignedReply{
				SignedReply: &agentapiv1.SignedReplyReport{
					Kind:         agentapiv1.ReplyKind_REPLY_KIND_STATUS,
					Signed:       fixed(0x5a, 200),
					UnsignedBody: body,
				},
			},
		},
	}
}

// fullyPopulated sets every field of a new mt (populate, roundtrip_test.go).
func fullyPopulated(t testing.TB, mt protoreflect.MessageType, variant int) proto.Message {
	t.Helper()
	m := mt.New()
	populate(m, variant, 0)
	return m.Interface()
}

type strictAccept struct {
	name string
	msg  proto.Message
}

func strictAcceptCases(t testing.TB) []strictAccept {
	t.Helper()
	cases := []strictAccept{
		{"OutboxMessage/realistic", realisticOutbox(t)},
		{"AgentMessage/outbox", &agentapiv1.AgentMessage{Body: &agentapiv1.AgentMessage_Outbox{Outbox: realisticOutbox(t)}}},
		{"ExecutorStatusBody/realistic", realisticStatusBody()},
		{"TrustInstallResultBody/realistic", realisticTrustBody()},
	}
	for _, mt := range []protoreflect.MessageType{
		(&agentapiv1.OutboxMessage{}).ProtoReflect().Type(),
		(&wardenv1.ExecutorStatusBody{}).ProtoReflect().Type(),
		(&wardenv1.TrustInstallResultBody{}).ProtoReflect().Type(),
	} {
		// OutboxPayload has five members; variants 0–4 set each in turn.
		for variant := 0; variant < 5; variant++ {
			cases = append(cases, strictAccept{
				name: string(mt.Descriptor().Name()) + "/populated-" + strconv.Itoa(variant),
				msg:  fullyPopulated(t, mt, variant),
			})
		}
	}
	return cases
}

// TestStrictUnmarshalAcceptsCanonical: deterministic-marshalled outbox
// messages and unsigned executor bodies decode, unchanged, through
// StrictUnmarshal, exactly as through wirescan.Unmarshal.
func TestStrictUnmarshalAcceptsCanonical(t *testing.T) {
	for _, tc := range strictAcceptCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			b, err := deterministic.Marshal(tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			got := tc.msg.ProtoReflect().New().Interface()
			if err := agentapiv1.StrictUnmarshal(b, got); err != nil {
				t.Fatalf("StrictUnmarshal refused canonical bytes: %v", err)
			}
			if !proto.Equal(got, tc.msg) {
				t.Fatal("decoded message differs from the original")
			}
			ref := tc.msg.ProtoReflect().New().Interface()
			if err := wirescan.Unmarshal(b, ref); err != nil || !proto.Equal(got, ref) {
				t.Fatalf("wirescan.Unmarshal disagrees: %v", err)
			}
		})
	}
}

// TestStrictUnmarshalRealisticCoversPayload guards the accept test: the
// realistic outbox message really carries a status body in its payload,
// so the R45a path (an unsigned body inside an outbox message) is tested.
func TestStrictUnmarshalRealisticCoversPayload(t *testing.T) {
	m := realisticOutbox(t)
	reply := m.GetPayload().GetSignedReply()
	if reply == nil || len(reply.GetUnsignedBody()) == 0 {
		t.Fatal("realistic outbox message has no unsigned body")
	}
	body := &wardenv1.ExecutorStatusBody{}
	if err := agentapiv1.StrictUnmarshal(reply.GetUnsignedBody(), body); err != nil {
		t.Fatalf("unsigned body: %v", err)
	}
	if !proto.Equal(body, realisticStatusBody()) {
		t.Fatal("unsigned body changed")
	}
}

// ---------------------------------------------------------------------------
// Refusals.

type strictRefuse struct {
	name string
	root func() proto.Message
	b    []byte
	want error
}

func newOutbox() proto.Message { return &agentapiv1.OutboxMessage{} }
func newAgent() proto.Message  { return &agentapiv1.AgentMessage{} }
func newStatus() proto.Message { return &wardenv1.ExecutorStatusBody{} }
func newTrust() proto.Message  { return &wardenv1.TrustInstallResultBody{} }

// invalidUTF8 is a lone continuation byte between ASCII, built at run time.
func invalidUTF8() string { return "1.0." + string([]byte{0x80}) }

func strictRefuseCases() []strictRefuse {
	reply := validReply()
	return []strictRefuse{
		// R13 (a): unknown fields, at the top level and nested.
		{"unknown/top", newOutbox, cat(outbox(1, wBytes(nil, payloadSignedReply, reply)), wVarint(nil, 99, 1)), wirescan.ErrUnknownField},
		{"unknown/nested-reply", newOutbox, outbox(1, wBytes(nil, payloadSignedReply, cat(reply, wVarint(nil, 50, 1)))), wirescan.ErrUnknownField},
		{"unknown/status-body", newStatus, cat(wVarint(nil, statusFormatVersion, 1), wVarint(nil, 31, 1)), wirescan.ErrUnknownField},
		{"unknown/trust-body", newTrust, cat(wVarint(nil, trustFormatVersion, 1), wVarint(nil, 15, 1)), wirescan.ErrUnknownField},
		{"unknown/agent-message", newAgent, wVarint(nil, 9, 1), wirescan.ErrUnknownField},

		// R13 (b): a non-repeated field twice.
		{"duplicate/message_seq", newOutbox, cat(wVarint(nil, outboxSeq, 1), wVarint(nil, outboxSeq, 2), wBytes(nil, outboxPayload, wBytes(nil, payloadSignedReply, reply))), wirescan.ErrDuplicateField},
		{"duplicate/payload", newOutbox, cat(wVarint(nil, outboxSeq, 1), wBytes(nil, outboxPayload, wBytes(nil, payloadSignedReply, reply)), wBytes(nil, outboxPayload, wBytes(nil, payloadSignedReply, reply))), wirescan.ErrDuplicateField},
		{"duplicate/nested-signed", newOutbox, outbox(1, wBytes(nil, payloadSignedReply, cat(reply, wBytes(nil, replySigned, fixed(0x5b, 8))))), wirescan.ErrDuplicateField},
		{"duplicate/status-binary_version", newStatus, statusDuplicateBinaryVersion(), wirescan.ErrDuplicateField},
		{"duplicate/status-server_id", newStatus, cat(wVarint(nil, statusFormatVersion, 1), wString(nil, statusServerID, "srv-a"), wString(nil, statusServerID, "srv-b")), wirescan.ErrDuplicateField},
		{"duplicate/trust-server_id", newTrust, cat(wVarint(nil, trustFormatVersion, 1), wString(nil, trustServerID, "srv-a"), wString(nil, trustServerID, "srv-b")), wirescan.ErrDuplicateField},

		// R13 (c): two members of one oneof.
		{"oneof/two-payload-members", newOutbox, outbox(1, cat(wBytes(nil, payloadSignedReply, reply), wBytes(nil, payloadAdvisory, wVarint(nil, advisoryReason, 1)))), wirescan.ErrDuplicateField},
		{"oneof/agent-message", newAgent, cat(wBytes(nil, agentOutbox, outbox(1, wBytes(nil, payloadSignedReply, reply))), wBytes(nil, 4, nil)), wirescan.ErrDuplicateField},

		// R13 (d), (e): group and wrong wire types.
		{"wiretype/seq-as-bytes", newOutbox, wBytes(nil, outboxSeq, []byte{1}), wirescan.ErrWireType},
		{"wiretype/payload-as-varint", newOutbox, cat(wVarint(nil, outboxSeq, 1), wVarint(nil, outboxPayload, 1)), wirescan.ErrWireType},
		{"wiretype/status-string-as-fixed32", newStatus, protowire.AppendFixed32(protowire.AppendTag(nil, statusBinaryVersion, protowire.Fixed32Type), 1), wirescan.ErrWireType},
		{"group/start", newOutbox, protowire.AppendTag(nil, outboxSeq, protowire.StartGroupType), wirescan.ErrGroup},

		// R13 (l): overlong varints in a value, a tag and a length.
		{"noncanonical/overlong-value", newOutbox, cat(protowire.AppendTag(nil, outboxSeq, protowire.VarintType), []byte{0x81, 0x00}), wirescan.ErrNonCanonical},
		{"noncanonical/overlong-tag", newOutbox, []byte{0x88, 0x00, 0x01}, wirescan.ErrNonCanonical},
		{"noncanonical/overlong-length", newStatus, cat(protowire.AppendTag(nil, statusBinaryVersion, protowire.BytesType), []byte{0x85, 0x00}, []byte("1.4.2")), wirescan.ErrNonCanonical},

		// R13 (j): an explicitly encoded proto3 default.
		{"default/message_seq-zero", newOutbox, cat(wVarint(nil, outboxSeq, 0), wBytes(nil, outboxPayload, wBytes(nil, payloadSignedReply, reply))), wirescan.ErrNonCanonical},
		{"default/empty-string", newStatus, cat(wVarint(nil, statusFormatVersion, 1), wString(nil, statusBinaryVersion, "")), wirescan.ErrNonCanonical},
		{"default/enum-zero-nested", newOutbox, outbox(1, wBytes(nil, payloadSignedReply, wVarint(nil, replyKind, 0))), wirescan.ErrNonCanonical},

		// R13 (k): fields out of ascending order.
		{"order/payload-before-seq", newOutbox, cat(wBytes(nil, outboxPayload, wBytes(nil, payloadSignedReply, reply)), wVarint(nil, outboxSeq, 1)), wirescan.ErrNonCanonical},
		{"order/status-body", newStatus, cat(wString(nil, statusBinaryVersion, "1.4.2"), wVarint(nil, statusFormatVersion, 1)), wirescan.ErrNonCanonical},
		{"order/nested-reply", newOutbox, outbox(1, wBytes(nil, payloadSignedReply, cat(wBytes(nil, replySigned, fixed(0x5a, 4)), wVarint(nil, replyKind, 3)))), wirescan.ErrNonCanonical},

		// UTF-8 (proto3 strings), at the top of a body and deep in an
		// outbox message.
		{"utf8/status-binary_version", newStatus, cat(wVarint(nil, statusFormatVersion, 1), wString(nil, statusBinaryVersion, invalidUTF8())), wirescan.ErrMalformed},
		{"utf8/status-installed_release", newStatus, wString(nil, statusInstalledRel, invalidUTF8()), wirescan.ErrMalformed},
		{"utf8/trust-server_id", newTrust, wString(nil, trustServerID, invalidUTF8()), wirescan.ErrMalformed},
		{"utf8/outbox-admin-release_version", newOutbox, outbox(1, wBytes(nil, payloadAdminTool, cat(wBytes(nil, adminRecordID, fixed(0x91, 16)), wVarint(nil, adminMode, uint64(agentapiv1.AdminToolMode_ADMIN_TOOL_MODE_STAGE)), wString(nil, adminReleaseVersion, invalidUTF8())))), wirescan.ErrMalformed},

		// Truncation.
		{"malformed/truncated-length", newOutbox, cat(wVarint(nil, outboxSeq, 1), protowire.AppendTag(nil, outboxPayload, protowire.BytesType), []byte{0x05, 0x0a}), wirescan.ErrMalformed},
		{"malformed/truncated-varint", newOutbox, cat(protowire.AppendTag(nil, outboxSeq, protowire.VarintType), []byte{0x80}), wirescan.ErrMalformed},
		{"malformed/field-zero", newOutbox, []byte{0x00, 0x01}, wirescan.ErrMalformed},
	}
}

// statusDuplicateBinaryVersion is an ExecutorStatusBody whose
// binary_version is written twice with different values: the R45a case
// where a lenient decoder would let the last copy win, and a redaction
// scan of the decoded message would miss what the first copy held.
func statusDuplicateBinaryVersion() []byte {
	return cat(
		wVarint(nil, statusFormatVersion, 1),
		wString(nil, statusBinaryVersion, "first-copy-FAKE-SECRET-123"),
		wString(nil, statusBinaryVersion, "1.4.2"),
	)
}

// TestStrictUnmarshalRefusesHostile: each R13 violation is refused with
// the exact wirescan error value, and with the same error wirescan gives
// for the same bytes.
func TestStrictUnmarshalRefusesHostile(t *testing.T) {
	for _, tc := range strictRefuseCases() {
		t.Run(tc.name, func(t *testing.T) {
			ref := wirescan.Unmarshal(tc.b, tc.root())
			wantOnlySentinel(t, ref, tc.want) // the case is well built
			err := agentapiv1.StrictUnmarshal(tc.b, tc.root())
			wantOnlySentinel(t, err, tc.want)
			if d := sameStrictError(err, ref); d != "" {
				t.Fatal(d)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// M1 ruling: no partial data on error. StrictUnmarshal resets m before
// returning any error, so a caller that ignores or mishandles the error
// can never read stale content (a reused message) or attacker-chosen
// fields that proto.Unmarshal filled before it reached invalid UTF-8.

// prefilled returns a fully populated message of the same type as root(),
// standing in for a message a caller reuses across decodes.
func prefilled(t testing.TB, root func() proto.Message) proto.Message {
	t.Helper()
	m := fullyPopulated(t, root().ProtoReflect().Type(), 0)
	if proto.Size(m) == 0 {
		t.Fatalf("%s: populated message is empty", m.ProtoReflect().Descriptor().FullName())
	}
	return m
}

// wantEmpty fails unless m equals a new message of its type.
func wantEmpty(t *testing.T, m proto.Message) {
	t.Helper()
	if fresh := m.ProtoReflect().Type().New().Interface(); !proto.Equal(m, fresh) {
		t.Fatalf("%s left non-empty after refusal: %v", m.ProtoReflect().Descriptor().FullName(), m)
	}
}

// TestStrictUnmarshalRefusalLeavesMessageEmpty: for every hostile case,
// after the refusal m is empty, whether it started fresh or pre-filled.
// The error is still exactly wirescan's.
func TestStrictUnmarshalRefusalLeavesMessageEmpty(t *testing.T) {
	for _, tc := range strictRefuseCases() {
		for _, start := range []struct {
			name string
			m    func(testing.TB) proto.Message
		}{
			{"fresh", func(testing.TB) proto.Message { return tc.root() }},
			{"prefilled", func(t testing.TB) proto.Message { return prefilled(t, tc.root) }},
		} {
			t.Run(tc.name+"/"+start.name, func(t *testing.T) {
				m := start.m(t)
				err := agentapiv1.StrictUnmarshal(tc.b, m)
				wantOnlySentinel(t, err, tc.want)
				if d := sameStrictError(err, wirescan.Unmarshal(tc.b, tc.root())); d != "" {
					t.Fatal(d)
				}
				wantEmpty(t, m)
			})
		}
	}
}

// TestStrictUnmarshalRefusalStatesFromReview pins the three states the
// security review observed with the plain wrapper.
func TestStrictUnmarshalRefusalStatesFromReview(t *testing.T) {
	// (a) A scan refusal never touches m, so a reused message kept its old
	// content: a caller ignoring the error would read stale data.
	t.Run("scan-refusal/prefilled-status-body", func(t *testing.T) {
		b := []byte{0x00}
		ref := realisticStatusBody()
		if err := wirescan.Unmarshal(b, ref); !errors.Is(err, wirescan.ErrMalformed) {
			t.Fatalf("premise: wirescan gave %v, want ErrMalformed", err)
		}
		if !proto.Equal(ref, realisticStatusBody()) {
			t.Fatal("premise changed: wirescan's scan refusal now touches m")
		}

		m := realisticStatusBody()
		err := agentapiv1.StrictUnmarshal(b, m)
		wantOnlySentinel(t, err, wirescan.ErrMalformed)
		wantEmpty(t, m)
		if m.GetServerId() != "" || m.GetResultSequence() != 0 {
			t.Fatalf("stale content survived: server_id %q, result_sequence %d", m.GetServerId(), m.GetResultSequence())
		}
	})

	// (b) Invalid UTF-8 is caught by proto.Unmarshal after the scan passed,
	// once it has already set earlier fields from attacker bytes.
	statusUTF8 := cat(
		wVarint(nil, statusFormatVersion, 1),
		wString(nil, statusServerID, "srv-from-attacker"),
		wString(nil, statusBinaryVersion, invalidUTF8()),
	)
	t.Run("utf8/status-body-partial", func(t *testing.T) {
		ref := &wardenv1.ExecutorStatusBody{}
		if err := wirescan.Unmarshal(statusUTF8, ref); !errors.Is(err, wirescan.ErrMalformed) {
			t.Fatalf("premise: wirescan gave %v, want ErrMalformed", err)
		}
		if ref.GetServerId() != "srv-from-attacker" {
			t.Logf("note: wirescan no longer leaves server_id behind (got %q)", ref.GetServerId())
		}
		for _, start := range []*wardenv1.ExecutorStatusBody{{}, realisticStatusBody()} {
			m := start
			err := agentapiv1.StrictUnmarshal(statusUTF8, m)
			wantOnlySentinel(t, err, wirescan.ErrMalformed)
			wantEmpty(t, m)
			if m.GetServerId() != "" || m.GetFormatVersion() != 0 {
				t.Fatalf("attacker data survived: server_id %q, format_version %d", m.GetServerId(), m.GetFormatVersion())
			}
		}
	})

	outboxUTF8 := outbox(42, wBytes(nil, payloadAdminTool, cat(
		wBytes(nil, adminRecordID, fixed(0x91, 16)),
		wVarint(nil, adminMode, uint64(agentapiv1.AdminToolMode_ADMIN_TOOL_MODE_STAGE)),
		wString(nil, adminReleaseVersion, string([]byte{0xff})),
	)))
	t.Run("utf8/outbox-admin-partial", func(t *testing.T) {
		ref := &agentapiv1.OutboxMessage{}
		if err := wirescan.Unmarshal(outboxUTF8, ref); !errors.Is(err, wirescan.ErrMalformed) {
			t.Fatalf("premise: wirescan gave %v, want ErrMalformed", err)
		}
		if ref.GetMessageSeq() != 42 {
			t.Logf("note: wirescan no longer leaves message_seq behind (got %d)", ref.GetMessageSeq())
		}
		for _, start := range []*agentapiv1.OutboxMessage{{}, realisticOutbox(t)} {
			m := start
			err := agentapiv1.StrictUnmarshal(outboxUTF8, m)
			wantOnlySentinel(t, err, wirescan.ErrMalformed)
			wantEmpty(t, m)
			if m.GetMessageSeq() != 0 || m.GetPayload() != nil {
				t.Fatalf("attacker data survived: message_seq %d, payload %v", m.GetMessageSeq(), m.GetPayload())
			}
		}
	})
}

// TestStrictUnmarshalSuccessReplacesPrefilled: success is unchanged. A
// fresh m holds exactly the decoded message, and a pre-filled m holds
// exactly the new message, with nothing of the old one merged in (wirescan
// calls proto.Unmarshal, which resets m first; this pins that).
func TestStrictUnmarshalSuccessReplacesPrefilled(t *testing.T) {
	for _, tc := range strictAcceptCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			b, err := deterministic.Marshal(tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			mt := tc.msg.ProtoReflect().Type()

			fresh := mt.New().Interface()
			if err := agentapiv1.StrictUnmarshal(b, fresh); err != nil {
				t.Fatalf("fresh m: %v", err)
			}
			if !proto.Equal(fresh, tc.msg) {
				t.Fatal("fresh m: decoded message differs")
			}

			// A different populated variant, so old and new differ.
			for _, variant := range []int{0, 3} {
				reused := fullyPopulated(t, mt, variant)
				if err := agentapiv1.StrictUnmarshal(b, reused); err != nil {
					t.Fatalf("pre-filled m (variant %d): %v", variant, err)
				}
				if !proto.Equal(reused, tc.msg) {
					t.Fatalf("pre-filled m (variant %d): result is not exactly the new message", variant)
				}
			}

			// Empty input into a pre-filled m gives the empty message.
			reused := fullyPopulated(t, mt, 1)
			if err := agentapiv1.StrictUnmarshal(nil, reused); err != nil {
				t.Fatalf("empty input: %v", err)
			}
			wantEmpty(t, reused)
		})
	}
}

// TestStrictUnmarshalRefuseCasesCoverEveryRule guards the table: every
// rule the issue lists has at least one case.
func TestStrictUnmarshalRefuseCasesCoverEveryRule(t *testing.T) {
	have := map[string]bool{}
	for _, tc := range strictRefuseCases() {
		have[strings.SplitN(tc.name, "/", 2)[0]] = true
	}
	for _, want := range []string{"unknown", "duplicate", "oneof", "wiretype", "noncanonical", "default", "order", "utf8"} {
		if !have[want] {
			t.Errorf("no refusal case for %s", want)
		}
	}
}

// TestStrictUnmarshalDuplicateStringWhyNotProtoUnmarshal documents why the
// wrapper exists: proto.Unmarshal accepts a duplicated string in an
// unsigned body and keeps only the last copy, so the first copy would
// never be scanned; StrictUnmarshal refuses the bytes.
func TestStrictUnmarshalDuplicateStringWhyNotProtoUnmarshal(t *testing.T) {
	b := statusDuplicateBinaryVersion()

	lenient := &wardenv1.ExecutorStatusBody{}
	if err := proto.Unmarshal(b, lenient); err != nil {
		t.Fatalf("proto.Unmarshal refused the duplicate (the reason for this wrapper is gone?): %v", err)
	}
	if got := lenient.GetBinaryVersion(); got != "1.4.2" {
		t.Fatalf("proto.Unmarshal kept %q; expected the last copy to win", got)
	}
	if strings.Contains(lenient.String(), "first-copy") {
		t.Fatal("the first copy survived proto.Unmarshal; the attack premise changed")
	}

	err := agentapiv1.StrictUnmarshal(b, &wardenv1.ExecutorStatusBody{})
	wantOnlySentinel(t, err, wirescan.ErrDuplicateField)

	// The same body inside a realistic outbox message decodes as opaque
	// bytes at the outer layer; the intake decode of the body itself
	// (R45a) is what refuses it.
	m := realisticOutbox(t)
	m.GetPayload().GetSignedReply().UnsignedBody = b
	outer, err := deterministic.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	got := &agentapiv1.OutboxMessage{}
	if err := agentapiv1.StrictUnmarshal(outer, got); err != nil {
		t.Fatalf("outer message: %v", err)
	}
	inner := got.GetPayload().GetSignedReply().GetUnsignedBody()
	wantOnlySentinel(t, agentapiv1.StrictUnmarshal(inner, &wardenv1.ExecutorStatusBody{}), wirescan.ErrDuplicateField)
}

// TestStrictUnmarshalNilAndEmpty: empty input decodes to the empty
// message for every root, exactly as wirescan does; that is not a
// refusal, since required fields are checked by hand (R12 rules).
func TestStrictUnmarshalNilAndEmpty(t *testing.T) {
	for _, root := range []func() proto.Message{newOutbox, newAgent, newStatus, newTrust} {
		for _, b := range [][]byte{nil, {}} {
			m := root()
			err := agentapiv1.StrictUnmarshal(b, m)
			if d := sameStrictError(err, wirescan.Unmarshal(b, root())); d != "" {
				t.Errorf("%s: %s", m.ProtoReflect().Descriptor().FullName(), d)
			}
			if err == nil && proto.Size(m) != 0 {
				t.Errorf("%s: empty input gave a non-empty message", m.ProtoReflect().Descriptor().FullName())
			}
		}
	}
}

// TestStrictUnmarshalOversizedInput: a large run of a valid repeated
// record and a large unknown blob give the same result through both.
func TestStrictUnmarshalOversizedInput(t *testing.T) {
	big := cat(wVarint(nil, statusFormatVersion, 1), wBytes(nil, 12, fixed(0x33, 1<<20)))
	unknown := cat(wVarint(nil, statusFormatVersion, 1), wBytes(nil, 4000, fixed(0x33, 1<<20)))
	for name, b := range map[string][]byte{"big-bytes": big, "big-unknown": unknown} {
		err := agentapiv1.StrictUnmarshal(b, newStatus())
		if d := sameStrictError(err, wirescan.Unmarshal(b, newStatus())); d != "" {
			t.Errorf("%s: %s", name, d)
		}
	}
	wantOnlySentinel(t, agentapiv1.StrictUnmarshal(unknown, newStatus()), wirescan.ErrUnknownField)
}

// ---------------------------------------------------------------------------
// Fuzz: StrictUnmarshal and wirescan.Unmarshal agree on every input.

// strictRoots are fuzzRoots plus OutboxMessage, which the control plane
// also decodes on its own (stored inbox rows).
func strictRoots() []protoreflect.FullName {
	roots := append([]protoreflect.FullName{"warden.agentapi.v1.OutboxMessage"}, fuzzRoots...)
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })
	return slices.Compact(roots)
}

// FuzzStrictUnmarshalMatchesWirescan: for any bytes and any root,
// StrictUnmarshal gives the same error as wirescan.Unmarshal (both nil, or
// the same text and the same errors.Is answer for every sentinel). On
// success the message equals wirescan's; on error it is empty (M1: no
// partial or stale data), whether m started fresh or pre-filled. wirescan's
// own message may be partial on error, so the two are not compared then.
func FuzzStrictUnmarshalMatchesWirescan(f *testing.F) {
	names := strictRoots()
	types := make([]protoreflect.MessageType, len(names))
	index := map[protoreflect.FullName]uint8{}
	for i, name := range names {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(name)
		if err != nil {
			f.Fatalf("%s: %v", name, err)
		}
		types[i] = mt
		index[name] = uint8(i)
	}
	for _, want := range []protoreflect.FullName{
		"warden.agentapi.v1.OutboxMessage", "warden.agentapi.v1.AgentMessage",
		"warden.agentapi.v1.TelemetryBatch", "warden.v1.ExecutorStatusBody",
		"warden.v1.TrustInstallResultBody",
	} {
		if _, ok := index[want]; !ok {
			f.Fatalf("fuzz roots lack %s", want)
		}
	}
	for _, tc := range strictAcceptCases(f) {
		b, err := deterministic.Marshal(tc.msg)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(index[tc.msg.ProtoReflect().Descriptor().FullName()], b)
	}
	for _, tc := range strictRefuseCases() {
		f.Add(index[tc.root().ProtoReflect().Descriptor().FullName()], tc.b)
	}
	for i, mt := range types {
		f.Add(uint8(i), []byte(nil))
		b, err := deterministic.Marshal(fullyPopulated(f, mt, i))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(i), b)
	}
	f.Fuzz(func(t *testing.T, which uint8, b []byte) {
		mt := types[int(which)%len(types)]
		got := mt.New().Interface()
		ref := mt.New().Interface()
		err := agentapiv1.StrictUnmarshal(b, got)
		refErr := wirescan.Unmarshal(b, ref)
		if d := sameStrictError(err, refErr); d != "" {
			t.Fatalf("%s: %s\nin: %x", mt.Descriptor().FullName(), d, b)
		}
		if err == nil && !proto.Equal(got, ref) {
			t.Fatalf("%s: decoded messages differ\nin: %x", mt.Descriptor().FullName(), b)
		}
		if err != nil && !proto.Equal(got, mt.New().Interface()) {
			t.Fatalf("%s: refused input left data in m: %v\nin: %x", mt.Descriptor().FullName(), err, b)
		}

		// The same bytes into a reused, pre-filled message.
		reused := fullyPopulated(t, mt, int(which))
		reusedErr := agentapiv1.StrictUnmarshal(b, reused)
		if d := sameStrictError(reusedErr, refErr); d != "" {
			t.Fatalf("%s: pre-filled m: %s\nin: %x", mt.Descriptor().FullName(), d, b)
		}
		if reusedErr == nil && !proto.Equal(reused, ref) {
			t.Fatalf("%s: pre-filled m: decoded message is not exactly the new one\nin: %x", mt.Descriptor().FullName(), b)
		}
		if reusedErr != nil && !proto.Equal(reused, mt.New().Interface()) {
			t.Fatalf("%s: pre-filled m: refused input left stale or partial data: %v\nin: %x", mt.Descriptor().FullName(), reusedErr, b)
		}
	})
}

// ---------------------------------------------------------------------------
// Source checks: the public API gained exactly StrictUnmarshal, a thin
// wrapper whose doc comment states the rule.

// strictFile is the file the issue names for the wrapper.
const strictFile = "strict.go"

// handWrittenExports are the exported top-level names of the package's
// non-generated, non-test files before issue #19.
var handWrittenExports = []string{"CheckRules", "FieldClass", "RefusedItems", "ValidUnitID"}

// exportedNames lists the exported top-level identifiers (and exported
// methods, as Recv.Name) of every non-test, non-generated Go file here.
func exportedNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, ".pb.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv != nil {
					out = append(out, "method "+d.Name.Name+" in "+name)
					continue
				}
				out = append(out, d.Name.Name)
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							out = append(out, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								out = append(out, n.Name)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestStrictUnmarshalOnlyNewExport: the hand-written public API of the
// package is what it was, plus StrictUnmarshal and nothing else.
func TestStrictUnmarshalOnlyNewExport(t *testing.T) {
	want := append(slices.Clone(handWrittenExports), "StrictUnmarshal")
	sort.Strings(want)
	if got := exportedNames(t); !slices.Equal(got, want) {
		t.Fatalf("exported hand-written API = %v, want %v", got, want)
	}
}

// parseStrict returns strict.go and its StrictUnmarshal declaration.
func parseStrict(t *testing.T) (*ast.File, *ast.FuncDecl) {
	t.Helper()
	path := filepath.Join(".", strictFile)
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s: %v", strictFile, err)
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "StrictUnmarshal" {
			return f, fd
		}
	}
	t.Fatalf("%s does not declare StrictUnmarshal", strictFile)
	return nil, nil
}

// TestStrictUnmarshalDocComment: the doc comment states that this is the
// only way the control plane decodes agent input, never proto.Unmarshal.
func TestStrictUnmarshalDocComment(t *testing.T) {
	_, fd := parseStrict(t)
	if fd.Doc == nil {
		t.Fatal("StrictUnmarshal has no doc comment")
	}
	doc := strings.Join(strings.Fields(fd.Doc.Text()), " ")
	if !strings.HasPrefix(doc, "StrictUnmarshal ") {
		t.Errorf("doc comment does not start with the function name: %q", doc)
	}
	for _, phrase := range []string{"only way", "control plane", "agent", "never", "proto.Unmarshal", "wirescan"} {
		if !strings.Contains(doc, phrase) {
			t.Errorf("doc comment lacks %q: %q", phrase, doc)
		}
	}
	// M1 ruling: wirescan's error values are not exported from this
	// package, so the doc must tell callers to treat every error as
	// MALFORMED, and that m is reset (left empty) on error.
	if !strings.Contains(doc, "MALFORMED") {
		t.Errorf("doc comment does not say every error is treated as MALFORMED: %q", doc)
	}
	if !strings.Contains(strings.ToLower(doc), "reset") {
		t.Errorf("doc comment does not say m is reset on error: %q", doc)
	}
}

// TestStrictUnmarshalIsThinWrapper: the body is exactly
//
//	if err := wirescan.Unmarshal(b, m); err != nil {
//		proto.Reset(m)
//		return err
//	}
//	return nil
//
// with the parameters in order (M1 ruling), so the error is returned
// unchanged, m is left empty on error, and no second decoding path exists;
// and strict.go imports nothing but wirescan and protobuf's proto package
// (no new dependency), neither renamed.
func TestStrictUnmarshalIsThinWrapper(t *testing.T) {
	f, fd := parseStrict(t)

	var names []string
	for _, p := range fd.Type.Params.List {
		for _, n := range p.Names {
			names = append(names, n.Name)
		}
	}
	if len(names) != 2 {
		t.Fatalf("StrictUnmarshal has %d named parameters, want 2", len(names))
	}
	if fd.Body == nil || len(fd.Body.List) != 2 {
		t.Fatalf("StrictUnmarshal body has %d statements, want an if and a return", len(fd.Body.List))
	}

	ifs, ok := fd.Body.List[0].(*ast.IfStmt)
	if !ok {
		t.Fatal("first statement is not an if")
	}
	if ifs.Else != nil {
		t.Fatal("the if has an else branch")
	}

	// Init: errName := wirescan.Unmarshal(<param0>, <param1>)
	init, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 || len(init.Rhs) != 1 {
		t.Fatal("the if does not start with a single := assignment")
	}
	errID, ok := init.Lhs[0].(*ast.Ident)
	if !ok || errID.Name == "_" {
		t.Fatal("the assignment does not bind the error to a name")
	}
	errName := errID.Name
	wantSelectorCall(t, init.Rhs[0], "wirescan", "Unmarshal", names)

	// Cond: errName != nil
	cond, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ || !isIdent(cond.X, errName) || !isIdent(cond.Y, "nil") {
		t.Fatalf("the if condition is not %s != nil", errName)
	}

	// Then: proto.Reset(<param1>); return errName
	if len(ifs.Body.List) != 2 {
		t.Fatalf("the if body has %d statements, want proto.Reset and return", len(ifs.Body.List))
	}
	reset, ok := ifs.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatal("the if body does not start with a call statement")
	}
	wantSelectorCall(t, reset.X, "proto", "Reset", names[1:])
	ret, ok := ifs.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 || !isIdent(ret.Results[0], errName) {
		t.Fatalf("the if body does not end with return %s (unchanged)", errName)
	}

	// Last: return nil
	last, ok := fd.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(last.Results) != 1 || !isIdent(last.Results[0], "nil") {
		t.Fatal("StrictUnmarshal does not end with return nil")
	}

	allowed := map[string]bool{
		"github.com/nofal82/warden-agent/internal/envelope/wirescan": true,
		"google.golang.org/protobuf/proto":                           true,
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed[p] {
			t.Errorf("%s imports %s; only wirescan and protobuf proto are expected", strictFile, p)
		}
		if imp.Name != nil && imp.Name.Name != "wirescan" && imp.Name.Name != "proto" {
			t.Errorf("%s renames import %s to %s", strictFile, p, imp.Name.Name)
		}
	}
}

// isIdent reports whether e is the bare identifier name.
func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// wantSelectorCall fails unless e is pkg.fn(args...) with each argument the
// bare identifier given, in order.
func wantSelectorCall(t *testing.T, e ast.Expr, pkg, fn string, args []string) {
	t.Helper()
	call, ok := e.(*ast.CallExpr)
	if !ok {
		t.Fatalf("expected a call to %s.%s", pkg, fn)
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !isIdent(sel.X, pkg) || sel.Sel.Name != fn {
		t.Fatalf("expected a call to %s.%s", pkg, fn)
	}
	if call.Ellipsis.IsValid() || len(call.Args) != len(args) {
		t.Fatalf("%s.%s called with %d arguments, want %d", pkg, fn, len(call.Args), len(args))
	}
	for i, a := range call.Args {
		if !isIdent(a, args[i]) {
			t.Errorf("%s.%s argument %d is not parameter %s unchanged", pkg, fn, i, args[i])
		}
	}
}
