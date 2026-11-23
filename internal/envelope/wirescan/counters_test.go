package wirescan_test

// Tests for the counter fields added by issue #57 (agent-api R52a: the
// scanner tests change together with the contract fields):
//
//   - EnvelopeBody field 13 envelope_counter (uint64; action-envelope §4.2,
//     R23a).
//   - ExecutorStatusBody field 31 boot_id (bytes) and field 32
//     highest_envelope_counter (uint64; executor-ipc §4.7).
//
// The scanner is descriptor-driven, so these tests prove that the new
// fields get the same R13 wire rules as every other field: (b) duplicates,
// (d) wire type, (e) minimal varints, (j) no explicit proto3 default,
// (k) strictly ascending field order, (l) 10-byte varints end in 0x01, and
// unknown fields rejected. Ranges (1 … 2^63−1) and the 16-byte length are
// validator rules, not scanner rules (TestCountersRangesAreNotScanned).

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

var statusMD = (&wardenv1.ExecutorStatusBody{}).ProtoReflect().Descriptor()

// bootID16 is a 16-byte boot_id, the length executor-ipc §4.7 requires.
func bootID16() []byte { return bytes.Repeat([]byte{0xb0}, 16) }

// statusBase is a fully populated ExecutorStatusBody with fields 31 and 32
// left out, so a test can append them by hand after field 30.
func statusBase() *wardenv1.ExecutorStatusBody {
	m := &wardenv1.ExecutorStatusBody{}
	populate(m.ProtoReflect())
	m.BootId = nil
	m.HighestEnvelopeCounter = 0
	return m
}

// assertRoundTrip checks Unmarshal accepts b and that deterministic
// re-marshalling gives back b byte for byte (R3, R13 (k), AC8a).
func assertRoundTrip(t *testing.T, b []byte, out proto.Message) {
	t.Helper()
	assertSentinel(t, wirescan.Unmarshal(b, out), nil)
	if got := marshalDet(t, out); !bytes.Equal(got, b) {
		t.Fatalf("re-marshal differs:\n got  %x\n want %x", got, b)
	}
}

// R13 + §4.2/R23a: a body with fields 1–13 all set, envelope_counter at the
// low bound, the high bound and a mid value, is accepted and canonical.
func TestCountersEnvelopeBodyAccepted(t *testing.T) {
	for _, c := range []struct {
		name string
		v    uint64
	}{
		{"min_1", 1},
		{"max_2^63-1", 1<<63 - 1},
		{"mid", 1<<32 + 7},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := validBody()
			body.EnvelopeCounter = c.v
			assertRoundTrip(t, marshalDet(t, body), &wardenv1.EnvelopeBody{})
		})
	}
}

// R13 + executor-ipc §4.7: a status body with result_sequence (30),
// boot_id (31) and highest_envelope_counter (32) is accepted and canonical;
// with no counter recorded, field 32 is absent (0 is not encoded).
func TestCountersStatusBodyAccepted(t *testing.T) {
	withCounter := statusBase()
	withCounter.ResultSequence = 41
	withCounter.BootId = bootID16()
	withCounter.HighestEnvelopeCounter = 1_000_000

	noCounter := statusBase()
	noCounter.ResultSequence = 41
	noCounter.BootId = bootID16()

	for name, m := range map[string]*wardenv1.ExecutorStatusBody{
		"boot_id_and_counter": withCounter,
		"counter_absent":      noCounter,
	} {
		t.Run(name, func(t *testing.T) {
			b := marshalDet(t, m)
			if name == "counter_absent" {
				// Field 32 must not appear: proto3 drops the zero value.
				recs := splitRecords(t, b)
				last := recs[len(recs)-1]
				if num, _, _ := protowire.ConsumeTag(last); num != 31 {
					t.Fatalf("last field is %d, want 31 (no field 32)", num)
				}
			}
			assertRoundTrip(t, b, &wardenv1.ExecutorStatusBody{})
		})
	}
}

// R13 (b), (d), (e), (j), (k), (l) and unknown fields, applied to
// EnvelopeBody field 13 envelope_counter.
func TestCountersEnvelopeCounterRejected(t *testing.T) {
	base := marshalDet(t, validBody()) // fields 1–12
	app := func(parts ...[]byte) []byte { return cat(append([][]byte{base}, parts...)...) }
	tag13 := protowire.AppendTag(nil, 13, protowire.VarintType)

	no12 := validBody()
	no12.IdempotencyKey = ""
	before12 := cat(marshalDet(t, no12), fVarint(nil, 13, 5), fBytes(nil, 12, []byte("wf-0001:step-restart:1")))

	runCanonCases(t, []scanCase{
		// (b) a second envelope_counter: the verifier and executor could
		// read different counters from one signed body.
		{"duplicate", bodyMD, app(fVarint(nil, 13, 5), fVarint(nil, 13, 6)), wirescan.ErrDuplicateField},
		// (j) 0 is the proto3 default and must be left out, not encoded.
		{"explicit_zero", bodyMD, app(fVarint(nil, 13, 0)), wirescan.ErrNonCanonical},
		// (e) non-minimal varint value.
		{"overlong_value", bodyMD, fVarintOverlong(base, 13, 5), wirescan.ErrNonCanonical},
		// (l) 10-byte varint whose last byte is above 0x01 (value >= 2^64).
		{"ten_bytes_last_byte_2", bodyMD, app(tag13, ten(0xff, 0x02)), wirescan.ErrMalformed},
		// (d) wrong wire types for a uint64 field.
		{"wire_fixed64", bodyMD, fFixed64(base, 13, 5), wirescan.ErrWireType},
		{"wire_bytes", bodyMD, fBytes(base, 13, []byte{5}), wirescan.ErrWireType},
		// (k) field 13 before field 12.
		{"before_field_12", bodyMD, before12, wirescan.ErrNonCanonical},
		// Unknown field 14 after a valid field 13.
		{"unknown_field_14", bodyMD, app(fVarint(nil, 13, 5), fVarint(nil, 14, 1)), wirescan.ErrUnknownField},
	})
}

// R13 (b), (d), (e), (j), (k), (l) and unknown fields, applied to
// ExecutorStatusBody fields 31 boot_id and 32 highest_envelope_counter.
func TestCountersStatusFieldsRejected(t *testing.T) {
	base := marshalDet(t, statusBase()) // fields 1–30
	app := func(parts ...[]byte) []byte { return cat(append([][]byte{base}, parts...)...) }
	boot := fBytes(nil, 31, bootID16())
	tag32 := protowire.AppendTag(nil, 32, protowire.VarintType)

	no30 := statusBase()
	no30.ResultSequence = 0
	before30 := cat(marshalDet(t, no30), boot, fVarint(nil, 30, 41))

	runCanonCases(t, []scanCase{
		// Field 32 highest_envelope_counter.
		// (b) duplicate.
		{"32_duplicate", statusMD, app(boot, fVarint(nil, 32, 5), fVarint(nil, 32, 6)), wirescan.ErrDuplicateField},
		// (j) "none recorded" is encoded by leaving 32 out, never as 0.
		{"32_explicit_zero", statusMD, app(boot, fVarint(nil, 32, 0)), wirescan.ErrNonCanonical},
		// (e) non-minimal varint value.
		{"32_overlong_value", statusMD, fVarintOverlong(app(boot), 32, 5), wirescan.ErrNonCanonical},
		// (l) 10-byte varint whose last byte is above 0x01.
		{"32_ten_bytes_last_byte_2", statusMD, app(boot, tag32, ten(0xff, 0x02)), wirescan.ErrMalformed},
		// (d) wrong wire types.
		{"32_wire_fixed64", statusMD, fFixed64(app(boot), 32, 5), wirescan.ErrWireType},
		{"32_wire_bytes", statusMD, fBytes(app(boot), 32, []byte{5}), wirescan.ErrWireType},
		// (k) field 32 before field 31.
		{"32_before_31", statusMD, app(fVarint(nil, 32, 5), boot), wirescan.ErrNonCanonical},
		// Unknown field 33 after a valid field 32.
		{"unknown_field_33", statusMD, app(boot, fVarint(nil, 32, 5), fVarint(nil, 33, 1)), wirescan.ErrUnknownField},

		// Field 31 boot_id.
		// (b) duplicate: two boot ids would let readers disagree on which
		// boot the counter belongs to.
		{"31_duplicate", statusMD, app(boot, boot), wirescan.ErrDuplicateField},
		// (k) field 31 before field 30.
		{"31_before_30", statusMD, before30, wirescan.ErrNonCanonical},
		// (d) bytes field sent as a varint.
		{"31_wire_varint", statusMD, fVarint(base, 31, 5), wirescan.ErrWireType},
	})
}

// Ranges and lengths are not scanner rules: envelope_counter = 2^63
// (outside 1 … 2^63−1, R23a) and a 15-byte boot_id (executor-ipc §4.7
// requires 16) pass the wire scan and Unmarshal. The envelope verifier's
// check 5 rejects the counter (internal/envelope, bodyWithinLimits); the
// agent never validates status bodies beyond the scan (agent-api R52a,
// advisory decoders in #59), and the control plane validates them at
// intake. This test pins that split so a later change cannot silently move
// range checks into, or out of, the scanner.
func TestCountersRangesAreNotScanned(t *testing.T) {
	body := cat(marshalDet(t, validBody()), fVarint(nil, 13, 1<<63))
	assertSentinel(t, wirescan.Unmarshal(body, &wardenv1.EnvelopeBody{}), nil)

	status := cat(marshalDet(t, statusBase()), fBytes(nil, 31, bytes.Repeat([]byte{0xb0}, 15)))
	assertSentinel(t, wirescan.Unmarshal(status, &wardenv1.ExecutorStatusBody{}), nil)
}
