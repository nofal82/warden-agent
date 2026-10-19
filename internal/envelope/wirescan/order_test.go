package wirescan_test

// Tests for action-envelope.md R13 (k), (l) and the (f) semantics (amended
// 2026-10-19, human Go reviewer, signing-and-updates OQ37) and the matching
// AC8 paragraph.
//
// (k) Field order: within each message, field numbers must be strictly
// ascending record by record, except that the records of one repeated
// string, bytes or message field are consecutive and share one position.
// Deterministic Go marshalling of the generated contract types emits that
// order, so with (k) the scanner accepts exactly one encoding of a value,
// byte for byte. Without it, the same EnvelopeBody could be signed in
// 12! different byte orders, and a store or cache keyed on bytes would see
// them as different envelopes.
//
// (l) A 10-byte varint must end in 0x01: a larger last byte would be a
// value of 2^64 or more (ErrMalformed); 0x00 is non-minimal under (e)
// (ErrNonCanonical).
//
// (f) semantics: every varint is a uint64 first, then range-checked for its
// kind, so the 5-byte FF FF FF FF 0F is 4,294,967,295 (not -1): rejected for
// int32 and enum, valid for 64-bit kinds.
//
// When an input breaks several rules, which one is reported is unspecified
// (R13 notes); such cases use errRejected and assert only that exactly one
// sentinel is returned.

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
	"github.com/nofal82/warden-agent/internal/testproto/ordertest"
)

// errRejected marks a case that breaks more than one rule: the test asserts
// only that Check and Unmarshal reject it with exactly one sentinel.
var errRejected = errors.New("rejected by some rule (order unspecified)")

// runOrderCases is runCanonCases plus errRejected.
func runOrderCases(t *testing.T, cases []scanCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkErr := wirescan.CheckForTest(c.b, c.md)
			unErr := wirescan.Unmarshal(c.b, newMessage(c.md))
			if !errors.Is(c.want, errRejected) {
				assertSentinel(t, checkErr, c.want)
				assertSentinel(t, unErr, c.want)
				return
			}
			for name, err := range map[string]error{"Check": checkErr, "Unmarshal": unErr} {
				if err == nil {
					t.Fatalf("%s accepted an input that breaks several rules: %x", name, c.b)
				}
				if n := countSentinels(err); n != 1 {
					t.Fatalf("%s error %v wraps %d sentinels, want 1", name, err, n)
				}
			}
		})
	}
}

// splitRecords cuts b into its top-level records (tag plus value).
func splitRecords(tb testing.TB, b []byte) [][]byte {
	tb.Helper()
	var recs [][]byte
	for len(b) > 0 {
		_, _, n := protowire.ConsumeField(b)
		if n < 0 {
			tb.Fatalf("splitRecords: %v", protowire.ParseError(n))
		}
		recs = append(recs, b[:n:n])
		b = b[n:]
	}
	return recs
}

// recNum is the field number of a record.
func recNum(rec []byte) protowire.Number {
	num, _, _ := protowire.ConsumeTag(rec)
	return num
}

// withField returns b with every record of rec's field number replaced by
// rec, placed at its ascending position, so that only the rule under test
// is broken.
func withField(tb testing.TB, b, rec []byte) []byte {
	tb.Helper()
	num := recNum(rec)
	var out []byte
	placed := false
	for _, r := range splitRecords(tb, b) {
		n := recNum(r)
		if n == num {
			continue
		}
		if !placed && n > num {
			out, placed = append(out, rec...), true
		}
		out = append(out, r...)
	}
	if !placed {
		out = append(out, rec...)
	}
	return out
}

// reorder concatenates recs in the order given by idx.
func reorder(recs [][]byte, idx ...int) []byte {
	var out []byte
	for _, i := range idx {
		out = append(out, recs[i]...)
	}
	return out
}

// swapped is recs with records i and j exchanged.
func swapped(recs [][]byte, i, j int) []byte {
	idx := make([]int, len(recs))
	for k := range idx {
		idx[k] = k
	}
	idx[i], idx[j] = idx[j], idx[i]
	return reorder(recs, idx...)
}

// reversed is recs in reverse order.
func reversed(recs [][]byte) []byte {
	idx := make([]int, len(recs))
	for k := range idx {
		idx[k] = len(recs) - 1 - k
	}
	return reorder(recs, idx...)
}

// ascendingOK is a test-side oracle for R13 (k) that does not share code
// with the scanner: field numbers ascend record by record at every depth,
// and an equal number is allowed only for the next record of a repeated
// string, bytes or message field. It assumes b otherwise parses.
func ascendingOK(b []byte, md protoreflect.MessageDescriptor) bool {
	var prev protowire.Number
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return false
		}
		fd := md.Fields().ByNumber(num)
		if fd == nil {
			return false
		}
		sharesPosition := fd.IsList() && nativeWireType(fd) == protowire.BytesType
		if num < prev || (num == prev && !sharesPosition) {
			return false
		}
		prev = num
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return false
		}
		if fd.Kind() == protoreflect.MessageKind && typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(b[n:])
			if !ascendingOK(v, fd.Message()) {
				return false
			}
		}
		b = b[n+m:]
	}
	return true
}

// R13 (k) at the top level of EnvelopeBody: Go's deterministic encoding is
// accepted; every adjacent swap of two fields, the reversed body, and a
// field moved to the end are ErrNonCanonical (only (k) is broken).
func TestOrderBodyTopLevel(t *testing.T) {
	base := marshalDet(t, validBody())
	if !ascendingOK(base, bodyMD) {
		t.Fatalf("deterministic marshalling of validBody is not ascending; test premise broken")
	}
	recs := splitRecords(t, base)
	if len(recs) != 12 {
		t.Fatalf("validBody has %d records, want 12 (one per EnvelopeBody field)", len(recs))
	}
	cases := []scanCase{{"valid_deterministic", bodyMD, base, nil}}
	for i := 0; i+1 < len(recs); i++ {
		cases = append(cases, scanCase{
			fmt.Sprintf("swap_field_%d_and_%d", recNum(recs[i]), recNum(recs[i+1])),
			bodyMD, swapped(recs, i, i+1), wirescan.ErrNonCanonical,
		})
	}
	paramsLast := reorder(recs, 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 7)
	pdFirst := reorder(recs, 8, 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11)
	cases = append(cases, []scanCase{
		{"first_and_last_swapped", bodyMD, swapped(recs, 0, 11), wirescan.ErrNonCanonical},
		{"reversed", bodyMD, reversed(recs), wirescan.ErrNonCanonical},
		{"params_moved_last", bodyMD, paramsLast, wirescan.ErrNonCanonical},
		{"policy_decision_moved_first", bodyMD, pdFirst, wirescan.ErrNonCanonical},
		{"format_version_moved_last", bodyMD, reorder(recs, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0), wirescan.ErrNonCanonical},
		{"idempotency_key_moved_first", bodyMD, reorder(recs, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10), wirescan.ErrNonCanonical},

		// Two fields only.
		{"two_fields_ascending", bodyMD, cat(fVarint(nil, 1, 1), fBytes(nil, 2, []byte("a"))), nil},
		{"two_fields_descending", bodyMD, cat(fBytes(nil, 2, []byte("a")), fVarint(nil, 1, 1)), wirescan.ErrNonCanonical},
		{"ascending_with_gaps", bodyMD, cat(fVarint(nil, 1, 1), fVarint(nil, 10, 5), fBytes(nil, 12, []byte("k"))), nil},
		{"descending_with_gaps", bodyMD, cat(fBytes(nil, 12, []byte("k")), fVarint(nil, 10, 5), fVarint(nil, 1, 1)), wirescan.ErrNonCanonical},
		{"created_expires_swapped", bodyMD, cat(fVarint(nil, 11, 2), fVarint(nil, 10, 1)), wirescan.ErrNonCanonical},
		{"single_field", bodyMD, fBytes(nil, 12, []byte("k")), nil},

		// A non-repeated field encoded again after a higher one breaks both
		// (b) and (k): only rejection is contractual.
		{"non_repeated_1_2_1", bodyMD, cat(fVarint(nil, 1, 1), fBytes(nil, 2, []byte("a")), fVarint(nil, 1, 1)), errRejected},
		{"action_id_again_at_end", bodyMD, cat(base, fBytes(nil, 2, []byte("x"))), errRejected},
		{"policy_decision_again_after_created_at", bodyMD, reorder(recs, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 10, 11), errRejected},
		{"params_again_after_idempotency_key", bodyMD, cat(base, recs[7]), errRejected},
		// Two members of the params oneof in descending order: (b) and (k).
		{"oneof_members_descending", bodyMD, withField(t, base, fBytes(nil, 8, cat(
			fBytes(nil, 11, fBytes(nil, 1, []byte("nginx.service"))), fBytes(nil, 7, nil)))), errRejected},
		// A non-repeated field encoded twice in a row is a duplicate, not a
		// "repeated run" (the exception covers repeated fields only).
		{"non_repeated_twice_consecutive", bodyMD, reorder(recs, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11), errRejected},
	}...)
	runOrderCases(t, cases)
}

// R13 (k) one level down: inside policy_decision (field 9) and inside a
// params request (field 8 -> member 15), with the outer body in order.
func TestOrderBodyNested(t *testing.T) {
	base := marshalDet(t, validBody())
	pdMsg := validBody().PolicyDecision
	pdMsg.ApprovalId = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
	pd := marshalDet(t, pdMsg)
	pdRecs := splitRecords(t, pd)
	if len(pdRecs) != 4 {
		t.Fatalf("policy decision has %d records, want 4", len(pdRecs))
	}
	withPD := func(p []byte) []byte { return withField(t, base, fBytes(nil, 9, p)) }

	quota := marshalDet(t, &wardenv1.ServiceSetCpuQuotaRequest{
		Unit: "nginx.service", CpuQuotaPercent: 50, Pid: 4242, StartTimeTicks: 123456,
	})
	qRecs := splitRecords(t, quota)
	if len(qRecs) != 4 {
		t.Fatalf("cpu quota request has %d records, want 4", len(qRecs))
	}
	withQuota := func(q []byte) []byte { return withField(t, base, fBytes(nil, 8, fBytes(nil, 15, q))) }

	runOrderCases(t, []scanCase{
		{"pd_ascending", bodyMD, withPD(pd), nil},
		{"pd_swap_1_2", bodyMD, withPD(swapped(pdRecs, 0, 1)), wirescan.ErrNonCanonical},
		{"pd_swap_3_4", bodyMD, withPD(swapped(pdRecs, 2, 3)), wirescan.ErrNonCanonical},
		{"pd_reversed", bodyMD, withPD(reversed(pdRecs)), wirescan.ErrNonCanonical},
		{"pd_approval_first", bodyMD, withPD(reorder(pdRecs, 3, 0, 1, 2)), wirescan.ErrNonCanonical},
		{"pd_1_2_1", bodyMD, withPD(reorder(pdRecs, 0, 1, 0)), errRejected},
		{"pd_1_2_3_4_2", bodyMD, withPD(reorder(pdRecs, 0, 1, 2, 3, 1)), errRejected},

		{"request_ascending", bodyMD, withQuota(quota), nil},
		{"request_swap_pid_ticks", bodyMD, withQuota(swapped(qRecs, 2, 3)), wirescan.ErrNonCanonical},
		{"request_unit_last", bodyMD, withQuota(reorder(qRecs, 1, 2, 3, 0)), wirescan.ErrNonCanonical},
		{"request_reversed", bodyMD, withQuota(reversed(qRecs)), wirescan.ErrNonCanonical},
		{"request_1_2_3_4_1", bodyMD, withQuota(reorder(qRecs, 0, 1, 2, 3, 0)), errRejected},

		// The order state is per message: a nested message that starts at
		// field 1 after the parent reached field 8, and a parent that
		// continues at field 9 after a nested message reached field 4, are
		// both fine (validBody itself shows this; spelled out here).
		{"nested_restarts_at_1", bodyMD, withQuota(quota), nil},
	})
}

// R13 (k) and repeated fields in the contract: the repeated bytes field
// session_owner_digests (6) of DbTerminateSessionRequest is one position;
// its records must be consecutive. Tested directly and through a body.
func TestOrderRepeatedContract(t *testing.T) {
	d1, d2 := bytes.Repeat([]byte{0xd1}, 32), bytes.Repeat([]byte{0xd2}, 32)
	engine := fVarint(nil, 1, 1)
	instance := fBytes(nil, 2, []byte("mysql.service"))
	ids := fBytes(nil, 3, packedVarints(11, 12))
	starts := fBytes(nil, 4, packedVarints(0, 1_700_000_000))
	server := fVarint(nil, 5, 1_700_000_000)
	dg1, dg2 := fBytes(nil, 6, d1), fBytes(nil, 6, d2)
	idle := fVarint(nil, 7, 600)

	full := marshalDet(t, &wardenv1.DbTerminateSessionRequest{
		Engine: wardenv1.Engine_ENGINE_MYSQL, Instance: "mysql.service",
		SessionIds: []uint64{11, 12}, SessionStartedAt: []int64{0, 1_700_000_000},
		ServerStartedAt: 1_700_000_000, SessionOwnerDigests: [][]byte{d1, d2}, MinIdleSeconds: 600,
	})
	handmade := cat(engine, instance, ids, starts, server, dg1, dg2, idle)
	if !bytes.Equal(full, handmade) {
		t.Fatalf("hand-built record order differs from Go's deterministic encoding:\n go   %x\n hand %x", full, handmade)
	}

	type c struct {
		name string
		b    []byte
		want error
	}
	inner := []c{
		{"ascending_repeated_consecutive", handmade, nil},
		{"repeated_bytes_three_consecutive", cat(server, dg1, dg2, dg1, idle), nil},
		{"repeated_bytes_only", cat(dg1, dg2), nil},
		// A,B,A: two runs of field 6 separated by field 7.
		{"repeated_bytes_interleaved_with_higher", cat(dg1, idle, dg2), wirescan.ErrNonCanonical},
		// A,B,A with B lower: the B record already descends.
		{"repeated_bytes_interleaved_with_lower", cat(dg1, server, dg2), wirescan.ErrNonCanonical},
		{"repeated_bytes_before_lower_field", cat(dg1, dg2, server), wirescan.ErrNonCanonical},
		{"repeated_bytes_after_higher_field", cat(idle, dg1, dg2), wirescan.ErrNonCanonical},
		{"packed_fields_swapped", cat(engine, instance, starts, ids), wirescan.ErrNonCanonical},
		{"engine_after_instance", cat(instance, engine), wirescan.ErrNonCanonical},
		// Packed list split around another field: (i) and (k).
		{"packed_split_around_other_field", cat(fBytes(nil, 3, packedVarints(11)), starts, fBytes(nil, 3, packedVarints(12))), errRejected},
		// Packed record twice in a row: (i) only; equal number is not a
		// shared position for a packable field.
		{"packed_twice_consecutive", cat(fBytes(nil, 3, packedVarints(11)), fBytes(nil, 3, packedVarints(12))), wirescan.ErrNonCanonical},
		{"engine_twice_around_instance", cat(engine, instance, engine), errRejected},
	}
	var cases []scanCase
	base := marshalDet(t, validBody())
	for _, x := range inner {
		cases = append(cases,
			scanCase{"direct/" + x.name, dbTermMD, x.b, x.want},
			scanCase{"in_body/" + x.name, bodyMD, withField(t, base, fBytes(nil, 8, fBytes(nil, 22, x.b))), x.want},
		)
	}
	runOrderCases(t, cases)
}

// R13 (k) on the test-only descriptors: repeated message and string fields,
// state per message and per element, and depth.
func TestOrderTestOnlyDescriptors(t *testing.T) {
	// kindsMD: 1 i32, 3 u32, 8 u64, 11 str, 12 child, 13 ri32 (packed),
	// 21 rf32 (packed), 22 children.
	k1 := fVarint(nil, 1, 1)
	k2 := fVarint(nil, 2, 2) // sint32 zigzag 2 = 1
	k8 := fVarint(nil, 8, 8)
	k11 := fBytes(nil, 11, []byte("s"))
	k13 := fBytes(nil, 13, packedVarints(1, 2))
	k21 := fBytes(nil, 21, protowire.AppendFixed32(nil, 1))
	child := func(b []byte) []byte { return fBytes(nil, 12, b) }
	elem := func(b []byte) []byte { return fBytes(nil, 22, b) }
	nest := func(levels int, leaf []byte) []byte {
		for i := 0; i < levels; i++ {
			leaf = child(leaf)
		}
		return leaf
	}

	// presenceMD: 21 children, 22 rstr, 23 rbyt, 30.. oneof, 40.. optional.
	pc := func(b []byte) []byte { return fBytes(nil, pChildren, b) }
	ps := func(s string) []byte { return fBytes(nil, pRStr, []byte(s)) }
	pb := func(s string) []byte { return fBytes(nil, pRByt, []byte(s)) }

	cases := []scanCase{
		{"kinds/ascending", kindsMD, cat(k1, k2, k8, k11, child(k1), k13, k21, elem(k1), elem(k2)), nil},
		{"kinds/descending_pair", kindsMD, cat(k8, k1), wirescan.ErrNonCanonical},
		{"kinds/child_after_packed", kindsMD, cat(k13, child(k1)), wirescan.ErrNonCanonical},
		{"kinds/children_interleaved_with_lower", kindsMD, cat(elem(k1), k21, elem(k1)), wirescan.ErrNonCanonical},
		{"kinds/children_then_lower", kindsMD, cat(elem(k1), elem(k1), k21), wirescan.ErrNonCanonical},
		{"kinds/children_three_consecutive_empty", kindsMD, cat(elem(nil), elem(nil), elem(nil)), nil},

		// Order state is per message: a child's high field numbers do not
		// leak to the parent, the parent's do not leak into the child, and
		// each element of a repeated child starts afresh.
		{"kinds/child_high_then_parent_low", kindsMD, cat(child(cat(k21, elem(nil))), k13), nil},
		{"kinds/parent_high_then_child_low", kindsMD, cat(k11, child(k1), k13), nil},
		{"kinds/each_element_restarts", kindsMD, cat(elem(cat(k1, k8)), elem(cat(k1, k8)), elem(cat(k2, k11))), nil},
		{"kinds/element_internally_descending", kindsMD, cat(elem(cat(k1, k8)), elem(cat(k8, k1))), wirescan.ErrNonCanonical},
		{"kinds/child_internally_descending", kindsMD, child(cat(k11, k1)), wirescan.ErrNonCanonical},
		{"kinds/child_non_repeated_1_8_1", kindsMD, child(cat(k1, k8, k1)), errRejected},

		{"presence/repeated_consecutive", presenceMD, cat(pc(nil), pc(nil), ps("a"), ps("b"), pb("x"), pb("y")), nil},
		{"presence/repeated_string_interleaved_with_higher", presenceMD, cat(ps("a"), pb("x"), ps("b")), wirescan.ErrNonCanonical},
		{"presence/repeated_message_interleaved_with_higher", presenceMD, cat(pc(nil), ps("a"), pc(nil)), wirescan.ErrNonCanonical},
		{"presence/repeated_bytes_then_string", presenceMD, cat(pb("x"), ps("a")), wirescan.ErrNonCanonical},
		{"presence/oneof_member_then_lower", presenceMD, cat(fVarint(nil, pOI32, 1), pc(nil)), wirescan.ErrNonCanonical},
		{"presence/optional_then_oneof_member", presenceMD, cat(fVarint(nil, pOptU32, 0), fVarint(nil, pOEnum, 0)), wirescan.ErrNonCanonical},
		{"presence/oneof_member_then_optional", presenceMD, cat(fVarint(nil, pOEnum, 0), fVarint(nil, pOptU32, 0)), nil},
		{"presence/oneof_members_descending", presenceMD, cat(fVarint(nil, pOBool, 1), fVarint(nil, pOI32, 1)), errRejected},
	}
	for _, depth := range []int{1, 2, 5, 15} {
		cases = append(cases,
			scanCase{fmt.Sprintf("kinds/depth%02d_ascending", depth), kindsMD, nest(depth, cat(k1, k8)), nil},
			scanCase{fmt.Sprintf("kinds/depth%02d_descending", depth), kindsMD, nest(depth, cat(k8, k1)), wirescan.ErrNonCanonical},
			scanCase{fmt.Sprintf("kinds/depth%02d_children_interleaved", depth), kindsMD, nest(depth, cat(elem(nil), k21, elem(nil))), wirescan.ErrNonCanonical},
			scanCase{fmt.Sprintf("presence/depth%02d_repeated_string_interleaved", depth), presenceMD,
				func() []byte {
					leaf := cat(ps("a"), pb("x"), ps("b"))
					for i := 0; i < depth; i++ {
						leaf = fBytes(nil, pChild, leaf)
					}
					return leaf
				}(), wirescan.ErrNonCanonical},
		)
	}
	runOrderCases(t, cases)
}

// R13 (k) in the outer SignedEnvelope (MALFORMED in the verifier).
func TestOrderOuter(t *testing.T) {
	kid, body, sig := fBytes(nil, 1, make([]byte, 32)), fBytes(nil, 2, []byte{0x08, 0x01}), fBytes(nil, 3, make([]byte, 64))
	runOrderCases(t, []scanCase{
		{"ascending", outerMD, cat(kid, body, sig), nil},
		{"ascending_body_left_out", outerMD, cat(kid, sig), nil},
		{"body_key_id", outerMD, cat(body, kid, sig), wirescan.ErrNonCanonical},
		{"signature_first", outerMD, cat(sig, kid, body), wirescan.ErrNonCanonical},
		{"signature_before_body", outerMD, cat(kid, sig, body), wirescan.ErrNonCanonical},
		{"reversed", outerMD, cat(sig, body, kid), wirescan.ErrNonCanonical},
		{"two_fields_descending", outerMD, cat(sig, kid), wirescan.ErrNonCanonical},
		{"key_id_again_after_body", outerMD, cat(kid, body, kid), errRejected},
		{"body_again_after_signature", outerMD, cat(kid, body, sig, body), errRejected},
	})
}

// Go's own encoding of a valid body, then each pair of top-level fields
// swapped (not only adjacent ones): every permutation step is rejected.
func TestOrderEveryPairSwapped(t *testing.T) {
	recs := splitRecords(t, marshalDet(t, validBody()))
	var cases []scanCase
	for i := 0; i < len(recs); i++ {
		for j := i + 1; j < len(recs); j++ {
			cases = append(cases, scanCase{
				fmt.Sprintf("swap_%02d_%02d", recNum(recs[i]), recNum(recs[j])),
				bodyMD, swapped(recs, i, j), wirescan.ErrNonCanonical,
			})
		}
	}
	runOrderCases(t, cases)
}

// Literal reading of (k) for reflection-based marshalling. protobuf-go's
// slow path (dynamicpb) in Deterministic mode uses LegacyFieldOrder: fields
// outside a real oneof first, then oneof members, so a oneof member
// numbered below another set field is written after it. Generated code
// sorts the same way (TestOutOfOrderMarshalRejected); today's contract is
// not affected (AC8a) because its only oneof is a whole message. This pins
// that the scanner follows the encoding rule, not one particular
// marshaller, so a change in either is deliberate.
func TestOrderReflectionMarshalOneofLast(t *testing.T) {
	m := dynamicpb.NewMessage(presenceMD)
	m.Set(presenceMD.Fields().ByNumber(pOI32), protoreflect.ValueOfInt32(1))
	m.Set(presenceMD.Fields().ByNumber(pOptU32), protoreflect.ValueOfUint32(1))
	b := marshalDet(t, m)
	want := cat(fVarint(nil, pOptU32, 1), fVarint(nil, pOI32, 1))
	asc := cat(fVarint(nil, pOI32, 1), fVarint(nil, pOptU32, 1))
	assertSentinel(t, wirescan.CheckForTest(asc, presenceMD), nil)
	assertSentinel(t, wirescan.CheckForTest(want, presenceMD), wirescan.ErrNonCanonical)
	if !bytes.Equal(b, want) {
		t.Fatalf("protobuf-go's reflection marshaller changed its oneof order (got %x, want %x); review this pin and action-envelope OQ28", b, want)
	}
}

// ten is a 10-byte varint: nine continuation bytes (first) and the last byte.
func ten(first, last byte) []byte {
	b := bytes.Repeat([]byte{first | 0x80}, 9)
	return append(b, last)
}

// R13 (l): a 10-byte varint must end in 0x01, in a value, a tag, a length
// prefix and a packed element; the 10-byte form of -1 in an int32 field is
// valid. 0x00 as last byte is (e), not (l).
func TestVarintTenthByte(t *testing.T) {
	tagV := func(num protowire.Number) []byte { return protowire.AppendTag(nil, num, protowire.VarintType) }
	tagB := func(num protowire.Number) []byte { return protowire.AppendTag(nil, num, protowire.BytesType) }
	minus1 := ten(0xff, 0x01)
	if v, n := protowire.ConsumeVarint(minus1); n != 10 || v != math.MaxUint64 {
		t.Fatalf("ten(0xff, 0x01) is not the 10-byte -1")
	}

	base := marshalDet(t, validBody())
	pd := marshalDet(t, validBody().PolicyDecision)
	withPD := func(p []byte) []byte { return withField(t, base, fBytes(nil, 9, p)) }
	kid, sig := fBytes(nil, 1, make([]byte, 32)), fBytes(nil, 3, make([]byte, 64))
	abc := []byte("abc")

	cases := []scanCase{
		// value position, test-only kinds
		{"value/u64_last_0x02", kindsMD, cat(tagV(8), ten(0xff, 0x02)), wirescan.ErrMalformed},
		{"value/u64_last_0x7f", kindsMD, cat(tagV(8), ten(0xff, 0x7f)), wirescan.ErrMalformed},
		{"value/u64_2^64_exact", kindsMD, cat(tagV(8), ten(0x80, 0x02)), wirescan.ErrMalformed},
		{"value/u64_last_0x01_max", kindsMD, cat(tagV(8), ten(0xff, 0x01)), nil},
		{"value/u64_last_0x01_2^63", kindsMD, cat(tagV(8), ten(0x80, 0x01)), nil},
		{"value/u64_last_0x00_overlong", kindsMD, cat(tagV(8), ten(0xff, 0x00)), wirescan.ErrNonCanonical},
		{"value/i64_last_0x02", kindsMD, cat(tagV(6), ten(0xff, 0x02)), wirescan.ErrMalformed},
		{"value/i64_minus1", kindsMD, cat(tagV(6), minus1), nil},
		{"value/i32_last_0x02", kindsMD, cat(tagV(1), ten(0xff, 0x02)), wirescan.ErrMalformed},
		{"value/i32_last_0x7f", kindsMD, cat(tagV(1), ten(0xff, 0x7f)), wirescan.ErrMalformed},
		{"value/i32_minus1_ten_bytes", kindsMD, cat(tagV(1), minus1), nil},
		{"value/enum_minus1_ten_bytes", kindsMD, cat(tagV(5), minus1), nil},
		{"value/bool_last_0x02", kindsMD, cat(tagV(4), ten(0xff, 0x02)), wirescan.ErrMalformed},
		{"value/s64_last_0x7f", kindsMD, cat(tagV(7), ten(0xff, 0x7f)), wirescan.ErrMalformed},
		// i32 with 2^63 (10 bytes, last 0x01) is well-formed but out of range: (f).
		{"value/i32_2^63_out_of_range", kindsMD, cat(tagV(1), ten(0x80, 0x01)), wirescan.ErrNonCanonical},

		// packed element position
		{"packed/ru64_last_0x02", kindsMD, fBytes(nil, 20, cat(packedVarints(1), ten(0xff, 0x02))), wirescan.ErrMalformed},
		{"packed/ru64_last_0x7f", kindsMD, fBytes(nil, 20, ten(0xff, 0x7f)), wirescan.ErrMalformed},
		{"packed/ru64_last_0x01", kindsMD, fBytes(nil, 20, cat(ten(0xff, 0x01), packedVarints(1))), nil},
		{"packed/ri32_minus1_ten_bytes", kindsMD, fBytes(nil, 13, cat(minus1, minus1)), nil},
		{"packed/ri32_last_0x02", kindsMD, fBytes(nil, 13, ten(0xff, 0x02)), wirescan.ErrMalformed},
		{"packed/session_ids_last_0x02", dbTermMD, fBytes(nil, 3, cat(packedVarints(7), ten(0xff, 0x02))), wirescan.ErrMalformed},
		{"packed/session_started_at_last_0x7f", dbTermMD, fBytes(nil, 4, ten(0xff, 0x7f)), wirescan.ErrMalformed},
		{"packed/session_started_at_minus1", dbTermMD, fBytes(nil, 4, minus1), nil},

		// tag position
		{"tag/kinds_last_0x02", kindsMD, cat(ten(0xff, 0x02), []byte{0x01}), wirescan.ErrMalformed},
		{"tag/kinds_last_0x7f", kindsMD, cat(ten(0xff, 0x7f), []byte{0x01}), wirescan.ErrMalformed},
		{"tag/body_first_last_0x02", bodyMD, cat(ten(0x88, 0x02), []byte{0x01}), wirescan.ErrMalformed},
		{"tag/body_after_valid_last_0x7f", bodyMD, cat(base, ten(0xff, 0x7f), []byte{0x01}), wirescan.ErrMalformed},
		{"tag/in_pd_last_0x02", bodyMD, withPD(cat(pd, ten(0xff, 0x02), []byte{0x01})), wirescan.ErrMalformed},
		{"tag/outer_last_0x02", outerMD, cat(ten(0x8a, 0x02), fBytes(nil, 2, []byte{1})), wirescan.ErrMalformed},
		{"tag/outer_last_0x7f", outerMD, cat(kid, ten(0xff, 0x7f), sig), wirescan.ErrMalformed},

		// length-prefix position
		{"length/kinds_str_last_0x02", kindsMD, cat(tagB(11), ten(0x83, 0x02), abc), wirescan.ErrMalformed},
		{"length/kinds_str_last_0x7f", kindsMD, cat(tagB(11), ten(0x83, 0x7f), abc), wirescan.ErrMalformed},
		{"length/kinds_child_last_0x02", kindsMD, cat(tagB(12), ten(0x80, 0x02)), wirescan.ErrMalformed},
		{"length/body_action_id_last_0x02", bodyMD, withField(t, base, cat(tagB(2), ten(0x83, 0x02), abc)), wirescan.ErrMalformed},
		{"length/body_pd_last_0x7f", bodyMD, withField(t, base, cat(tagB(9), ten(0x80, 0x7f), pd)), wirescan.ErrMalformed},
		{"length/in_pd_decision_id_last_0x02", bodyMD, withPD(withField(t, pd, cat(tagB(1), ten(0x83, 0x02), abc))), wirescan.ErrMalformed},
		{"length/in_request_unit_last_0x7f", bodyMD, withField(t, base, fBytes(nil, 8, fBytes(nil, 11, cat(tagB(1), ten(0x83, 0x7f), abc)))), wirescan.ErrMalformed},
		{"length/outer_key_id_last_0x02", outerMD, cat(tagB(1), ten(0xa0, 0x02), make([]byte, 32)), wirescan.ErrMalformed},
		{"length/outer_body_last_0x7f", outerMD, cat(kid, tagB(2), ten(0x82, 0x7f), []byte{0x08, 0x01}, sig), wirescan.ErrMalformed},
		{"length/packed_last_0x02", dbTermMD, cat(tagB(3), ten(0x81, 0x02), []byte{0x01}), wirescan.ErrMalformed},

		// value position in the contract
		{"value/body_created_at_last_0x02", bodyMD, withField(t, base, cat(tagV(10), ten(0xff, 0x02))), wirescan.ErrMalformed},
		{"value/body_created_at_last_0x7f", bodyMD, withField(t, base, cat(tagV(10), ten(0xff, 0x7f))), wirescan.ErrMalformed},
		{"value/body_created_at_minus1", bodyMD, withField(t, base, cat(tagV(10), minus1)), nil},
		{"value/body_format_version_last_0x02", bodyMD, withField(t, base, cat(tagV(1), ten(0xff, 0x02))), wirescan.ErrMalformed},
		{"value/in_pd_autonomy_last_0x02", bodyMD, withPD(withField(t, pd, cat(tagV(2), ten(0xff, 0x02)))), wirescan.ErrMalformed},
		{"value/in_pd_autonomy_last_0x7f", bodyMD, withPD(withField(t, pd, cat(tagV(2), ten(0xff, 0x7f)))), wirescan.ErrMalformed},
		{"value/in_pd_autonomy_minus1", bodyMD, withPD(withField(t, pd, cat(tagV(2), minus1))), nil},
	}
	runOrderCases(t, cases)

	// Every last byte from 0x02 to 0x7f is rejected in a value position.
	var all []scanCase
	for last := 0x02; last <= 0x7f; last++ {
		all = append(all, scanCase{fmt.Sprintf("u64_last_%#02x", last), kindsMD, cat(tagV(8), ten(0xff, byte(last))), wirescan.ErrMalformed})
	}
	runOrderCases(t, all)
}

// R13 (f) semantics: a varint is a uint64 first, then range-checked.
func TestInt32RangeSemantics(t *testing.T) {
	tagV := func(num protowire.Number) []byte { return protowire.AppendTag(nil, num, protowire.VarintType) }
	five := []byte{0xff, 0xff, 0xff, 0xff, 0x0f}
	if v, n := protowire.ConsumeVarint(five); n != 5 || v != math.MaxUint32 {
		t.Fatalf("FF FF FF FF 0F is not 4,294,967,295")
	}
	minI32 := protowire.AppendVarint(nil, i64(math.MinInt32))
	belowMinI32 := protowire.AppendVarint(nil, i64(math.MinInt32-1))
	if len(minI32) != 10 || len(belowMinI32) != 10 {
		t.Fatalf("negative int32 encodings are not 10 bytes")
	}

	base := marshalDet(t, validBody())
	pd := marshalDet(t, validBody().PolicyDecision)
	withPD := func(p []byte) []byte { return withField(t, base, fBytes(nil, 9, p)) }
	largest := marshalDet(t, &wardenv1.FsLargestEntriesRequest{Path: "/var/log", MaxDepth: 3, TopN: 10, ModifiedWithinSeconds: 60})
	withLargest := func(req []byte) []byte { return withField(t, base, fBytes(nil, 8, fBytes(nil, 2, req))) }

	runOrderCases(t, []scanCase{
		// kindsMD singular fields
		{"five/int32", kindsMD, cat(tagV(1), five), wirescan.ErrNonCanonical},
		{"five/enum", kindsMD, cat(tagV(5), five), wirescan.ErrNonCanonical},
		{"five/uint64", kindsMD, cat(tagV(8), five), nil},
		{"five/int64", kindsMD, cat(tagV(6), five), nil},
		{"five/sint64", kindsMD, cat(tagV(7), five), nil},
		{"five/uint32_max", kindsMD, cat(tagV(3), five), nil},
		{"five/sint32_zigzag_max", kindsMD, cat(tagV(2), five), nil},
		{"five/bool", kindsMD, cat(tagV(4), five), wirescan.ErrNonCanonical},
		// packed elements
		{"five/packed_int32", kindsMD, fBytes(nil, 13, five), wirescan.ErrNonCanonical},
		{"five/packed_enum", kindsMD, fBytes(nil, 17, five), wirescan.ErrNonCanonical},
		{"five/packed_int64", kindsMD, fBytes(nil, 18, five), nil},
		{"five/packed_uint64", kindsMD, fBytes(nil, 20, five), nil},
		// in a nested child
		{"five/child_int32", kindsMD, fBytes(nil, 12, cat(tagV(1), five)), wirescan.ErrNonCanonical},
		{"five/child_uint64", kindsMD, fBytes(nil, 12, cat(tagV(8), five)), nil},

		// 10-byte -2^31 is the lowest int32; -2^31-1 is not an int32.
		{"min_int32/int32", kindsMD, cat(tagV(1), minI32), nil},
		{"min_int32/enum", kindsMD, cat(tagV(5), minI32), nil},
		{"min_int32_minus1/int32", kindsMD, cat(tagV(1), belowMinI32), wirescan.ErrNonCanonical},
		{"min_int32_minus1/enum", kindsMD, cat(tagV(5), belowMinI32), wirescan.ErrNonCanonical},
		{"min_int32_minus1/int64", kindsMD, cat(tagV(6), belowMinI32), nil},
		{"min_int32/packed_int32", kindsMD, fBytes(nil, 13, minI32), nil},
		{"min_int32_minus1/packed_int32", kindsMD, fBytes(nil, 13, belowMinI32), wirescan.ErrNonCanonical},
		{"max_int32/int32", kindsMD, cat(tagV(1), protowire.AppendVarint(nil, math.MaxInt32)), nil},
		{"max_int32_plus1/int32", kindsMD, cat(tagV(1), protowire.AppendVarint(nil, math.MaxInt32+1)), wirescan.ErrNonCanonical},

		// contract: autonomy_level (enum), min_size_bytes (uint64),
		// created_at (int64)
		{"five/body_pd_autonomy_enum", bodyMD, withPD(withField(t, pd, cat(tagV(2), five))), wirescan.ErrNonCanonical},
		{"min_int32/body_pd_autonomy_enum", bodyMD, withPD(withField(t, pd, cat(tagV(2), minI32))), nil},
		{"min_int32_minus1/body_pd_autonomy_enum", bodyMD, withPD(withField(t, pd, cat(tagV(2), belowMinI32))), wirescan.ErrNonCanonical},
		{"five/body_request_min_size_uint64", bodyMD, withLargest(withField(t, largest, cat(tagV(4), five))), nil},
		{"five/body_created_at_int64", bodyMD, withField(t, base, cat(tagV(10), five)), nil},
		{"five/body_format_version_uint32", bodyMD, withField(t, base, cat(tagV(1), five)), nil},
	})

	// The value decoded from FF FF FF FF 0F in a 64-bit field is
	// 4,294,967,295, never -1; the 10-byte -1 in an int32 field is -1.
	m := dynamicpb.NewMessage(kindsMD)
	assertSentinel(t, wirescan.Unmarshal(cat(tagV(1), ten(0xff, 0x01), tagV(6), five, tagV(8), five), m), nil)
	if got := m.Get(kindsMD.Fields().ByNumber(6)).Int(); got != math.MaxUint32 {
		t.Fatalf("int64 from FF FF FF FF 0F = %d, want 4294967295", got)
	}
	if got := m.Get(kindsMD.Fields().ByNumber(8)).Uint(); got != math.MaxUint32 {
		t.Fatalf("uint64 from FF FF FF FF 0F = %d, want 4294967295", got)
	}
	if got := m.Get(kindsMD.Fields().ByNumber(1)).Int(); got != -1 {
		t.Fatalf("int32 from 10-byte -1 = %d, want -1", got)
	}
}

// AC8a ---------------------------------------------------------------------

// oneofVariant picks, for each real oneof (by full name), the index of the
// member to set; a oneof not in the map gets its first member.
type oneofVariant map[protoreflect.FullName]int

// reachableOneofs lists every real oneof of md and of every message type
// reachable from it, each once.
func reachableOneofs(md protoreflect.MessageDescriptor) []protoreflect.OneofDescriptor {
	var out []protoreflect.OneofDescriptor
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		for i := 0; i < md.Oneofs().Len(); i++ {
			if od := md.Oneofs().Get(i); !od.IsSynthetic() {
				out = append(out, od)
			}
		}
		for i := 0; i < md.Fields().Len(); i++ {
			if fd := md.Fields().Get(i); fd.Kind() == protoreflect.MessageKind {
				walk(fd.Message())
			}
		}
	}
	walk(md)
	return out
}

// variantsOf is one variant per member of every reachable oneof (the other
// oneofs on their first member), or a single empty variant if there is none.
func variantsOf(md protoreflect.MessageDescriptor) (names []string, vs []oneofVariant) {
	for _, od := range reachableOneofs(md) {
		for i := 0; i < od.Fields().Len(); i++ {
			names = append(names, string(od.Name())+"="+string(od.Fields().Get(i).Name()))
			vs = append(vs, oneofVariant{od.FullName(): i})
		}
	}
	if len(vs) == 0 {
		return []string{"no_oneof"}, []oneofVariant{{}}
	}
	return names, vs
}

// chosen reports whether fd is to be set under v: every field outside a
// real oneof, and the picked member of each real oneof.
func (v oneofVariant) chosen(fd protoreflect.FieldDescriptor) bool {
	od := fd.ContainingOneof()
	if od == nil || od.IsSynthetic() {
		return true
	}
	return od.Fields().Get(v[od.FullName()]) == fd
}

// populateVariant is populate with the oneof member chosen by v: every
// chosen field non-default, every repeated field two elements.
func populateVariant(m protoreflect.Message, v oneofVariant) {
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if !v.chosen(fd) {
			continue
		}
		switch {
		case fd.IsList():
			l := m.Mutable(fd).List()
			for j := uint8(0); j < 2; j++ {
				if fd.Kind() == protoreflect.MessageKind {
					e := l.NewElement()
					populateVariant(e.Message(), v)
					l.Append(e)
				} else {
					l.Append(scalar(fd, j))
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			populateVariant(m.Mutable(fd).Message(), v)
		default:
			m.Set(fd, scalar(fd, 0))
		}
	}
}

// assertFull checks the AC8a premise on m: every chosen field is set, every
// repeated field holds at least two elements, recursively.
func assertFull(t *testing.T, m protoreflect.Message, v oneofVariant) {
	t.Helper()
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if !v.chosen(fd) {
			if m.Has(fd) {
				t.Fatalf("%s set although another oneof member was chosen", fd.FullName())
			}
			continue
		}
		if !m.Has(fd) {
			t.Fatalf("%s not set", fd.FullName())
		}
		switch {
		case fd.IsList():
			l := m.Get(fd).List()
			if l.Len() < 2 {
				t.Fatalf("%s has %d elements, want >= 2", fd.FullName(), l.Len())
			}
			if fd.Kind() == protoreflect.MessageKind {
				for j := 0; j < l.Len(); j++ {
					assertFull(t, l.Get(j).Message(), v)
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			assertFull(t, m.Get(fd).Message(), v)
		}
	}
}

// AC8a (R13 (k)): every message type of the contract, enumerated from the
// generated descriptors, with every field non-default, every repeated field
// at least two elements, and each oneof member in turn (also the oneof of
// a nested message, such as EnvelopeBody.params), marshalled
// deterministically, passes the complete scan and round-trips byte for
// byte.
func TestAC8aEveryMessageEveryOneofMember(t *testing.T) {
	mds := contractMessages()
	if len(mds) < 25 {
		t.Fatalf("found only %d message types", len(mds))
	}
	total, withOneof := 0, 0
	for _, md := range mds {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
		if err != nil {
			t.Fatalf("%s: %v", md.FullName(), err)
		}
		names, vs := variantsOf(md)
		if names[0] != "no_oneof" {
			withOneof++
		}
		for i, v := range vs {
			total++
			t.Run(string(md.Name())+"/"+names[i], func(t *testing.T) {
				m := mt.New()
				populateVariant(m, v)
				assertFull(t, m, v)
				b := marshalDet(t, m.Interface())
				if !ascendingOK(b, md) {
					t.Fatalf("deterministic encoding is not in ascending field order: %x", b)
				}
				assertSentinel(t, wirescan.CheckForTest(b, md), nil)
				out := mt.New().Interface()
				assertSentinel(t, wirescan.Unmarshal(b, out), nil)
				if !proto.Equal(out, m.Interface()) {
					t.Fatalf("Unmarshal result differs")
				}
				if re := marshalDet(t, out); !bytes.Equal(re, b) {
					t.Fatalf("re-marshalled bytes differ:\n in  %x\n out %x", b, re)
				}
			})
		}
	}
	// EnvelopeBody (through params) and TypedRequest each have one variant
	// per request member; guard against the walk finding nothing.
	od := paramsMD.Oneofs().ByName("request")
	if withOneof < 2 || total < len(mds)-2+2*od.Fields().Len() {
		t.Fatalf("too few variants: %d total, %d message types with a oneof", total, withOneof)
	}
}

// OQ28: protobuf-go writes the fields outside any oneof first, then the
// oneof, with or without Deterministic. A message whose oneof member is
// numbered below another set field therefore marshals out of order, and
// the scanner rejects it. SplitOneof breaks the contract's declaration rule
// (TestContractFieldOrder); OneofBelowField satisfies it and is still
// written out of order. Both live in a test-only package outside the
// contract. The same values written in ascending order are accepted, so
// the order alone causes the rejection.
func TestOutOfOrderMarshalRejected(t *testing.T) {
	cases := []struct {
		name string
		m, n proto.Message // n is an empty message of the same type
		asc  []byte
	}{
		{"split_oneof", &ordertest.SplitOneof{Choice: &ordertest.SplitOneof_First{First: "a"}, Second: "b"}, new(ordertest.SplitOneof),
			fBytes(fBytes(nil, 1, []byte("a")), 2, []byte("b"))},
		{"oneof_below_field", &ordertest.OneofBelowField{Choice: &ordertest.OneofBelowField_First{First: "a"}, Third: "c"}, new(ordertest.OneofBelowField),
			fBytes(fBytes(nil, 1, []byte("a")), 3, []byte("c"))},
	}
	for _, c := range cases {
		for _, opts := range []proto.MarshalOptions{{}, {Deterministic: true}} {
			t.Run(fmt.Sprintf("%s/deterministic=%t", c.name, opts.Deterministic), func(t *testing.T) {
				b, err := opts.Marshal(c.m)
				if err != nil {
					t.Fatal(err)
				}
				if ascendingOK(b, c.m.ProtoReflect().Descriptor()) {
					t.Fatalf("protobuf-go wrote %x in ascending order; review this test and action-envelope OQ28", b)
				}
				assertSentinel(t, wirescan.Unmarshal(b, proto.Clone(c.n)), wirescan.ErrNonCanonical)
				out := proto.Clone(c.n)
				assertSentinel(t, wirescan.Unmarshal(c.asc, out), nil)
				if !proto.Equal(out, c.m) {
					t.Fatalf("ascending bytes decode to %v, want %v", out, c.m)
				}
			})
		}
	}
}

// Fuzz ---------------------------------------------------------------------

// orderSeeds is one input for each (k), (l) and (f) case above.
func orderSeeds(tb testing.TB) [][]byte {
	base := marshalDet(tb, validBody())
	recs := splitRecords(tb, base)
	kid, body, sig := fBytes(nil, 1, make([]byte, 32)), fBytes(nil, 2, []byte{0x08, 0x01}), fBytes(nil, 3, make([]byte, 64))
	dg := fBytes(nil, 6, make([]byte, 32))
	five := []byte{0xff, 0xff, 0xff, 0xff, 0x0f}
	return [][]byte{
		swapped(recs, 0, 1),
		swapped(recs, 7, 8),
		reversed(recs),
		cat(base, recs[1]),
		cat(sig, kid, body),
		cat(kid, body, kid),
		withField(tb, base, fBytes(nil, 8, fBytes(nil, 22, cat(dg, fVarint(nil, 7, 1), dg)))),
		withField(tb, base, fBytes(nil, 8, fBytes(nil, 22, cat(dg, dg, fVarint(nil, 7, 1))))),
		cat(dg, fVarint(nil, 7, 1), dg),
		cat(fBytes(nil, 22, nil), fBytes(nil, 21, protowire.AppendFixed32(nil, 1)), fBytes(nil, 22, nil)),
		cat(fBytes(nil, 12, fBytes(nil, 21, protowire.AppendFixed32(nil, 1))), fBytes(nil, 13, packedVarints(1))),
		cat([]byte{0x40}, ten(0xff, 0x02)),
		cat([]byte{0x40}, ten(0xff, 0x7f)),
		cat([]byte{0x08}, ten(0xff, 0x01)),
		cat(ten(0xff, 0x02), []byte{0x01}),
		cat([]byte{0x12}, ten(0x83, 0x02), []byte("abc")),
		fBytes(nil, 20, ten(0xff, 0x02)),
		cat([]byte{0x08}, five),
		cat([]byte{0x28}, five),
		cat([]byte{0x30}, five),
		cat([]byte{0x40}, five),
		cat([]byte{0x08}, protowire.AppendVarint(nil, i64(math.MinInt32))),
		cat([]byte{0x08}, protowire.AppendVarint(nil, i64(math.MinInt32-1))),
	}
}

// FuzzOrder: with (k) the scanner accepts exactly Go's deterministic
// encoding, byte for byte (R13 (k)). For every contract message type and
// the test-only kindsMD (no oneof, no float, so protobuf-go's reflection
// marshaller emits ascending order and keeps bits exactly), an input that
// Unmarshal accepts re-marshals to the identical bytes.
func FuzzOrder(f *testing.F) {
	for _, s := range orderSeeds(f) {
		f.Add(s)
	}
	for _, md := range contractMessages() {
		_, vs := variantsOf(md)
		for _, v := range vs {
			m := newMessage(md).ProtoReflect()
			populateVariant(m, v)
			f.Add(marshalDet(f, m.Interface()))
		}
	}
	f.Add(marshalDet(f, dynamicKindsWithLists()))
	mds := append(contractMessages(), kindsMD)
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, md := range mds {
			m := newMessage(md)
			err := wirescan.Unmarshal(b, m)
			if err != nil {
				if countSentinels(err) != 1 {
					t.Fatalf("error %v wraps %d sentinels, want 1", err, countSentinels(err))
				}
				continue
			}
			if !ascendingOK(b, md) {
				t.Fatalf("accepted input out of field order (%s): %x", md.FullName(), b)
			}
			re, mErr := proto.MarshalOptions{Deterministic: true}.Marshal(m)
			if mErr != nil {
				t.Fatalf("re-marshal: %v", mErr)
			}
			if !bytes.Equal(re, b) {
				t.Fatalf("accepted input is not the canonical encoding (%s):\n in  %x\n out %x", md.FullName(), b, re)
			}
		}
	})
}
