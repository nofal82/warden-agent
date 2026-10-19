package wirescan_test

// Tests for action-envelope.md R13 (i) (Nofal 2026-10-16, signing-and-updates
// OQ37; one non-empty record, Nofal 2026-10-18): a repeated field of a
// numeric scalar or enum type MUST be exactly one non-empty packed record
// (wire type 2) per field per message. The unpacked encoding (one record
// per element, using the element's own varint, I32 or I64 wire type), a
// list split over two or more packed records, and an empty packed record
// (length 0, alone or next to a valid one) are each ErrNonCanonical:
// proto.Unmarshal reads all of them as the same list as the one-record
// form, so without this rule different signed byte strings decode to one
// value. An empty list is the field left out. Repeated string, bytes and
// message fields cannot be packed and are not affected.
//
// Check order pinned here (the spec orders none of these; the codes are
// the same either way): a record with a wire type that is neither the
// element's own nor 2 stays ErrWireType and a group stays ErrGroup, even
// after a valid packed record; a second packed record is ErrNonCanonical
// before its payload is parsed (like a duplicate non-repeated field today),
// so a second record holding a truncated element is ErrNonCanonical, not
// ErrMalformed.

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// fixedKindsMD is a test-only proto3 message with repeated I32 and I64
// kinds (neither kindsMD nor the contract has a repeated I64 field) and
// repeated string, bytes and message fields that the rule must not touch.
var fixedKindsMD = func() protoreflect.MessageDescriptor {
	type T = descriptorpb.FieldDescriptorProto_Type
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	field := func(name string, num int32, typ T, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(), Label: rep.Enum(),
		}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("wardentest/packed_kinds.proto"),
		Package: proto.String("wardentest"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("FixedKinds"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("rfixed32", 1, descriptorpb.FieldDescriptorProto_TYPE_FIXED32, ""),
				field("rsfixed32", 2, descriptorpb.FieldDescriptorProto_TYPE_SFIXED32, ""),
				field("rfloat", 3, descriptorpb.FieldDescriptorProto_TYPE_FLOAT, ""),
				field("rfixed64", 4, descriptorpb.FieldDescriptorProto_TYPE_FIXED64, ""),
				field("rsfixed64", 5, descriptorpb.FieldDescriptorProto_TYPE_SFIXED64, ""),
				field("rdouble", 6, descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, ""),
				field("rstr", 7, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
				field("rbytes", 8, descriptorpb.FieldDescriptorProto_TYPE_BYTES, ""),
				field("rchild", 9, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".wardentest.FixedKinds"),
			},
		}},
	}
	file, err := protodesc.NewFile(fdp, new(protoregistry.Files))
	if err != nil {
		panic(err)
	}
	return file.Messages().ByName("FixedKinds")
}()

var (
	locationMD     = (&descriptorpb.SourceCodeInfo_Location{}).ProtoReflect().Descriptor()
	fieldOptionsMD = (&descriptorpb.FieldOptions{}).ProtoReflect().Descriptor()
)

// elemWireType is the wire type of one element of a packable kind, or
// BytesType for kinds that cannot be packed.
func elemWireType(k protoreflect.Kind) protowire.Type {
	switch k {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind, protoreflect.GroupKind:
		return protowire.BytesType
	default:
		return protowire.VarintType
	}
}

// elem is the encoding (without tag) of one small element of wire type typ.
func elem(typ protowire.Type, v uint64) []byte {
	switch typ {
	case protowire.Fixed32Type:
		if v > math.MaxUint32 {
			panic("elem: fixed32 value too large")
		}
		return protowire.AppendFixed32(nil, uint32(v))
	case protowire.Fixed64Type:
		return protowire.AppendFixed64(nil, v)
	default:
		return protowire.AppendVarint(nil, v)
	}
}

// unpackedRec is one unpacked record: tag with the element wire type, then
// the element.
func unpackedRec(num protowire.Number, typ protowire.Type, v uint64) []byte {
	return append(protowire.AppendTag(nil, num, typ), elem(typ, v)...)
}

// packedRec is one packed record holding vals.
func packedRec(num protowire.Number, typ protowire.Type, vals ...uint64) []byte {
	var payload []byte
	for _, v := range vals {
		payload = append(payload, elem(typ, v)...)
	}
	return fBytes(nil, num, payload)
}

// otherScalarTypes are the two scalar wire types that are not typ.
func otherScalarTypes(typ protowire.Type) []protowire.Type {
	var out []protowire.Type
	for _, t := range []protowire.Type{protowire.VarintType, protowire.Fixed32Type, protowire.Fixed64Type} {
		if t != typ {
			out = append(out, t)
		}
	}
	return out
}

// packableLists returns every repeated numeric-scalar or enum field of md.
func packableLists(md protoreflect.MessageDescriptor) []protoreflect.FieldDescriptor {
	var out []protoreflect.FieldDescriptor
	for i := 0; i < md.Fields().Len(); i++ {
		fd := md.Fields().Get(i)
		if fd.IsList() && elemWireType(fd.Kind()) != protowire.BytesType {
			out = append(out, fd)
		}
	}
	return out
}

// Every repeated numeric or enum field of the contract and of the test
// schemas (proto3 and proto2, packed by default or not) rejects every
// unpacked form and accepts the same values packed.
func TestUnpackedRepeatedEveryField(t *testing.T) {
	mds := append(contractMessages(), kindsMD, fixedKindsMD, locationMD, fieldOptionsMD)
	checked := map[protowire.Type]int{}
	for _, md := range mds {
		for _, fd := range packableLists(md) {
			num, typ := fd.Number(), elemWireType(fd.Kind())
			checked[typ]++
			p := string(md.Name()) + "." + string(fd.Name()) + "/"
			cases := []scanCase{
				// accepted: packed
				{p + "packed_single_0", md, packedRec(num, typ, 0), nil},
				{p + "packed_single_1", md, packedRec(num, typ, 1), nil},
				{p + "packed_three", md, packedRec(num, typ, 1, 0, 1), nil},

				// rejected: unpacked (R13 (i))
				{p + "unpacked_single_0", md, unpackedRec(num, typ, 0), wirescan.ErrNonCanonical},
				{p + "unpacked_single_1", md, unpackedRec(num, typ, 1), wirescan.ErrNonCanonical},
				{p + "unpacked_two", md, cat(unpackedRec(num, typ, 1), unpackedRec(num, typ, 0)), wirescan.ErrNonCanonical},
				{p + "unpacked_same_value_twice", md, cat(unpackedRec(num, typ, 1), unpackedRec(num, typ, 1)), wirescan.ErrNonCanonical},
				{p + "packed_then_unpacked", md, cat(packedRec(num, typ, 1, 0), unpackedRec(num, typ, 1)), wirescan.ErrNonCanonical},
				{p + "unpacked_then_packed", md, cat(unpackedRec(num, typ, 1), packedRec(num, typ, 0, 1)), wirescan.ErrNonCanonical},
				{p + "packed_unpacked_packed", md, cat(packedRec(num, typ, 1), unpackedRec(num, typ, 0), packedRec(num, typ, 1)), wirescan.ErrNonCanonical},
				// Same list as packed_three, other encoding: must not be equivalent.
				{p + "unpacked_three", md, cat(unpackedRec(num, typ, 1), unpackedRec(num, typ, 0), unpackedRec(num, typ, 1)), wirescan.ErrNonCanonical},
			}
			// Check order: a wire type that is neither the element's own
			// nor 2 is a wire-type mismatch, not an unpacked element.
			for _, other := range otherScalarTypes(typ) {
				cases = append(cases,
					scanCase{fmt.Sprintf("%swire_type_%d", p, other), md, unpackedRec(num, other, 1), wirescan.ErrWireType},
					scanCase{fmt.Sprintf("%spacked_then_wire_type_%d", p, other), md, cat(packedRec(num, typ, 1), unpackedRec(num, other, 1)), wirescan.ErrWireType},
				)
			}
			// Check order: tag minimality and group come first.
			cases = append(cases,
				scanCase{p + "tag_overlong+unpacked", md, cat(overlong(rawTag(num, typ)), elem(typ, 1)), wirescan.ErrNonCanonical},
				scanCase{p + "group_on_repeated_number", md, fGroup(nil, num, nil), wirescan.ErrGroup},
				scanCase{p + "packed_then_group", md, cat(packedRec(num, typ, 1), fGroup(nil, num, nil)), wirescan.ErrGroup},
				// The empty record is complete and checked before the group.
				scanCase{p + "empty_packed_then_group", md, cat(fBytes(nil, num, nil), fGroup(nil, num, nil)), wirescan.ErrNonCanonical},
			)
			// R13 (i), 2026-10-18: exactly one non-empty packed record.
			truncated := []byte{0x80} // a varint cut short
			if typ != protowire.VarintType {
				truncated = []byte{0x01, 0x02, 0x03} // shorter than one fixed element
			}
			cases = append(cases,
				scanCase{p + "split_one_then_two", md, cat(packedRec(num, typ, 1), packedRec(num, typ, 0, 1)), wirescan.ErrNonCanonical},
				scanCase{p + "split_two_then_one", md, cat(packedRec(num, typ, 1, 0), packedRec(num, typ, 1)), wirescan.ErrNonCanonical},
				scanCase{p + "split_same_record_twice", md, cat(packedRec(num, typ, 1), packedRec(num, typ, 1)), wirescan.ErrNonCanonical},
				scanCase{p + "split_three_records", md, cat(packedRec(num, typ, 1), packedRec(num, typ, 0), packedRec(num, typ, 1)), wirescan.ErrNonCanonical},
				scanCase{p + "split_zero_elements", md, cat(packedRec(num, typ, 0), packedRec(num, typ, 0)), wirescan.ErrNonCanonical},
				scanCase{p + "empty_alone", md, fBytes(nil, num, nil), wirescan.ErrNonCanonical},
				scanCase{p + "empty_twice", md, cat(fBytes(nil, num, nil), fBytes(nil, num, nil)), wirescan.ErrNonCanonical},
				scanCase{p + "empty_before_valid", md, cat(fBytes(nil, num, nil), packedRec(num, typ, 1, 0, 1)), wirescan.ErrNonCanonical},
				scanCase{p + "empty_after_valid", md, cat(packedRec(num, typ, 1, 0, 1), fBytes(nil, num, nil)), wirescan.ErrNonCanonical},
				scanCase{p + "empty_then_unpacked", md, cat(fBytes(nil, num, nil), unpackedRec(num, typ, 1)), wirescan.ErrNonCanonical},
				// Check order: the second record is rejected before its
				// payload is parsed.
				scanCase{p + "second_record_truncated_element", md, cat(packedRec(num, typ, 1), fBytes(nil, num, truncated)), wirescan.ErrNonCanonical},
				// A truncated element in the only record stays ErrMalformed.
				scanCase{p + "only_record_truncated_element", md, fBytes(nil, num, truncated), wirescan.ErrMalformed},
			)
			runCanonCases(t, cases)
		}
	}
	if checked[protowire.VarintType] < 12 || checked[protowire.Fixed32Type] < 4 || checked[protowire.Fixed64Type] < 3 {
		t.Fatalf("too few repeated packable fields checked: %v", checked)
	}
}

// The contract's repeated numeric fields, as the issue names them:
// DbTerminateSessionRequest.session_ids (uint64) and session_started_at
// (int64), directly and through a whole EnvelopeBody (depth 2).
func TestUnpackedRepeatedContract(t *testing.T) {
	digest := make([]byte, 32)
	full := marshalDet(t, &wardenv1.DbTerminateSessionRequest{
		Engine: wardenv1.Engine_ENGINE_MYSQL, Instance: "mysql.service",
		SessionIds: []uint64{101, 202}, SessionStartedAt: []int64{0, 0},
		ServerStartedAt: 1_700_000_000, SessionOwnerDigests: [][]byte{digest, digest}, MinIdleSeconds: 600,
	})
	noLists := marshalDet(t, &wardenv1.DbTerminateSessionRequest{
		Engine: wardenv1.Engine_ENGINE_POSTGRESQL, Instance: "postgresql.service", MinIdleSeconds: 600,
	})
	app := func(b []byte, more ...[]byte) []byte {
		return cat(append([][]byte{append([]byte(nil), b...)}, more...)...)
	}
	// ins places records at their ascending position in noLists, so each
	// case breaks only the rule under test, not R13 (k).
	ins := func(recs ...[]byte) []byte { return withField(t, noLists, cat(recs...)) }
	noParams := func() []byte { b := validBody(); b.Params = nil; return marshalDet(t, b) }()
	inBody := func(req []byte) []byte { return withField(t, noParams, fBytes(nil, 8, fBytes(nil, 22, req))) }
	minus1 := uint64(math.MaxUint64)

	direct := []scanCase{
		{"full_deterministic", dbTermMD, full, nil},
		{"ids_packed_starts_packed", dbTermMD, ins(fBytes(nil, 3, packedVarints(1, 2)), fBytes(nil, 4, packedVarints(minus1, 5))), nil},
		{"digests_three_records", dbTermMD, ins(fBytes(nil, 6, digest), fBytes(nil, 6, digest), fBytes(nil, 6, digest)), nil},
		// session_owner_digests is repeated bytes: several records and
		// empty records stay valid (R13 (i) and (j) do not reach it).
		{"digests_empty_records", dbTermMD, ins(fBytes(nil, 6, nil), fBytes(nil, 6, nil)), nil},
		// MySQL P22: every session_started_at element is 0, as packed
		// elements (R13 (j) does not apply to repeated elements).
		{"starts_packed_zeros_mysql", dbTermMD, ins(fBytes(nil, 3, packedVarints(101, 202, 303)), fBytes(nil, 4, packedVarints(0, 0, 0))), nil},
		{"ids_packed_with_zero_element", dbTermMD, ins(fBytes(nil, 3, packedVarints(0))), nil},

		// R13 (i), 2026-10-18: one non-empty packed record per field.
		{"ids_split_one_then_two", dbTermMD, ins(fBytes(nil, 3, packedVarints(101)), fBytes(nil, 3, packedVarints(202, 303))), wirescan.ErrNonCanonical},
		{"ids_split_far_apart", dbTermMD, ins(fBytes(nil, 3, packedVarints(101)), fBytes(nil, 4, packedVarints(0, 0)), fBytes(nil, 3, packedVarints(202))), wirescan.ErrNonCanonical},
		{"ids_split_across_head", dbTermMD, app(ins(fBytes(nil, 3, packedVarints(101))), fBytes(nil, 3, packedVarints(202))), wirescan.ErrNonCanonical},
		{"ids_split_after_full", dbTermMD, app(full, fBytes(nil, 3, packedVarints(303))), wirescan.ErrNonCanonical},
		{"ids_empty_alone", dbTermMD, ins(fBytes(nil, 3, nil)), wirescan.ErrNonCanonical},
		{"ids_empty_before_valid", dbTermMD, ins(fBytes(nil, 3, nil), fBytes(nil, 3, packedVarints(101, 202, 303))), wirescan.ErrNonCanonical},
		{"ids_empty_after_valid", dbTermMD, ins(fBytes(nil, 3, packedVarints(101, 202, 303)), fBytes(nil, 3, nil)), wirescan.ErrNonCanonical},
		{"ids_empty_then_unpacked", dbTermMD, ins(fBytes(nil, 3, nil), fVarint(nil, 3, 101)), wirescan.ErrNonCanonical},
		{"starts_split_one_then_two", dbTermMD, ins(fBytes(nil, 4, packedVarints(0)), fBytes(nil, 4, packedVarints(0, 0))), wirescan.ErrNonCanonical},
		{"starts_split_negative", dbTermMD, ins(fBytes(nil, 4, packedVarints(minus1)), fBytes(nil, 4, packedVarints(minus1, 5))), wirescan.ErrNonCanonical},
		{"starts_split_after_full", dbTermMD, app(full, fBytes(nil, 4, packedVarints(0))), wirescan.ErrNonCanonical},
		{"starts_empty_alone", dbTermMD, ins(fBytes(nil, 4, nil)), wirescan.ErrNonCanonical},
		{"starts_empty_before_valid", dbTermMD, ins(fBytes(nil, 4, nil), fBytes(nil, 4, packedVarints(0, 0, 0))), wirescan.ErrNonCanonical},
		{"starts_empty_after_valid", dbTermMD, ins(fBytes(nil, 4, packedVarints(0, 0, 0)), fBytes(nil, 4, nil)), wirescan.ErrNonCanonical},
		{"both_empty", dbTermMD, ins(fBytes(nil, 3, nil), fBytes(nil, 4, nil)), wirescan.ErrNonCanonical},

		{"ids_unpacked_single", dbTermMD, ins(fVarint(nil, 3, 101)), wirescan.ErrNonCanonical},
		{"ids_unpacked_single_zero", dbTermMD, ins(fVarint(nil, 3, 0)), wirescan.ErrNonCanonical},
		{"ids_unpacked_max", dbTermMD, ins(fVarint(nil, 3, math.MaxUint64)), wirescan.ErrNonCanonical},
		{"ids_unpacked_first", dbTermMD, cat(fVarint(nil, 3, 101), noLists), wirescan.ErrNonCanonical},
		{"ids_unpacked_after_full", dbTermMD, app(full, fVarint(nil, 3, 303)), wirescan.ErrNonCanonical},
		{"ids_unpacked_then_packed", dbTermMD, ins(fVarint(nil, 3, 1), fBytes(nil, 3, packedVarints(2))), wirescan.ErrNonCanonical},
		{"starts_unpacked_single", dbTermMD, ins(fVarint(nil, 4, 1_700_000_000_000_000)), wirescan.ErrNonCanonical},
		{"starts_unpacked_minus1", dbTermMD, ins(fVarint(nil, 4, minus1)), wirescan.ErrNonCanonical},
		{"starts_unpacked_min_int64", dbTermMD, ins(fVarint(nil, 4, 1<<63)), wirescan.ErrNonCanonical},
		{"starts_unpacked_after_full", dbTermMD, app(full, fVarint(nil, 4, 0)), wirescan.ErrNonCanonical},
		{"ids_packed_starts_unpacked", dbTermMD, ins(fBytes(nil, 3, packedVarints(1)), fVarint(nil, 4, 0)), wirescan.ErrNonCanonical},
		{"ids_unpacked_starts_packed", dbTermMD, ins(fVarint(nil, 3, 1), fBytes(nil, 4, packedVarints(0))), wirescan.ErrNonCanonical},

		// Check order: wire-type mismatch before unpacked (as today).
		{"ids_i32", dbTermMD, ins(fFixed32(nil, 3, 1)), wirescan.ErrWireType},
		{"ids_i64", dbTermMD, ins(fFixed64(nil, 3, 1)), wirescan.ErrWireType},
		{"starts_i32", dbTermMD, ins(fFixed32(nil, 4, 1)), wirescan.ErrWireType},
		{"starts_i64", dbTermMD, ins(fFixed64(nil, 4, 1)), wirescan.ErrWireType},
		// Check order: unpacked before value minimality.
		{"ids_unpacked+value_overlong", dbTermMD, ins(fVarintOverlong(nil, 3, 1)), wirescan.ErrNonCanonical},
		{"ids_unpacked+tag_overlong", dbTermMD, ins(fOverlongTagVarint(nil, 3, 1)), wirescan.ErrNonCanonical},
	}
	runCanonCases(t, direct)

	var body []scanCase
	for _, c := range direct {
		body = append(body, scanCase{"in_body/" + c.name, bodyMD, inBody(c.b), c.want})
	}
	runCanonCases(t, body)
}

// Thousands of unpacked or split records are rejected (not slowly
// accepted), and the same count in one packed record is accepted.
func TestUnpackedRepeatedMany(t *testing.T) {
	const n = 10_000
	var unpacked, onePerRecord []byte
	vals := make([]uint64, n)
	for i := range vals {
		vals[i] = uint64(i)
		unpacked = fVarint(unpacked, 3, uint64(i))
		onePerRecord = fBytes(onePerRecord, 3, packedVarints(uint64(i)))
	}
	runCanonCases(t, []scanCase{
		{"packed_10000", dbTermMD, fBytes(nil, 3, packedVarints(vals...)), nil},
		{"unpacked_10000", dbTermMD, unpacked, wirescan.ErrNonCanonical},
		{"packed_10000_then_one_unpacked", dbTermMD, cat(fBytes(nil, 3, packedVarints(vals...)), fVarint(nil, 3, 1)), wirescan.ErrNonCanonical},
		// R13 (i): the same list split in two, one packed record per
		// element, and thousands of empty packed records are rejected too.
		{"packed_10000_split_in_two", dbTermMD, cat(fBytes(nil, 3, packedVarints(vals[:n/2]...)), fBytes(nil, 3, packedVarints(vals[n/2:]...))), wirescan.ErrNonCanonical},
		{"one_packed_record_per_element_10000", dbTermMD, onePerRecord, wirescan.ErrNonCanonical},
		{"empty_packed_10000", dbTermMD, bytes.Repeat(fBytes(nil, 3, nil), n), wirescan.ErrNonCanonical},
	})
}

// Repeated string, bytes and message fields cannot be packed: several
// records stay valid, in every schema.
func TestRepeatedNonPackableUnaffected(t *testing.T) {
	listValueMD := (&structpb.ListValue{}).ProtoReflect().Descriptor()
	fileMD := (&descriptorpb.FileDescriptorProto{}).ProtoReflect().Descriptor()
	lv, err := structpb.NewList([]any{1.0, "x", true, nil, []any{2.0}})
	if err != nil {
		t.Fatal(err)
	}
	fileB := marshalDet(t, &descriptorpb.FileDescriptorProto{
		Name: proto.String("a.proto"), Dependency: []string{"b.proto", "c.proto"},
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("A")}, {Name: proto.String("B")}},
	})
	runCanonCases(t, []scanCase{
		{"listvalue_values_five_records", listValueMD, marshalDet(t, lv), nil},
		{"listvalue_values_empty_records", listValueMD, cat(fBytes(nil, 1, nil), fBytes(nil, 1, nil)), nil},
		{"file_dependency_and_message_type", fileMD, fileB, nil},
		{"kinds_children_three_records", kindsMD, cat(fBytes(nil, 22, nil), fBytes(nil, 22, fVarint(nil, 1, 1)), fBytes(nil, 22, nil)), nil},
		{"fixed_kinds_strings", fixedKindsMD, cat(fBytes(nil, 7, []byte("a")), fBytes(nil, 7, []byte("b"))), nil},
		{"fixed_kinds_bytes", fixedKindsMD, cat(fBytes(nil, 8, []byte{0xff}), fBytes(nil, 8, nil)), nil},
		{"fixed_kinds_children", fixedKindsMD, cat(fBytes(nil, 9, nil), fBytes(nil, 9, packedRec(4, protowire.Fixed64Type, 1))), nil},
		// The rule still applies inside a repeated message element.
		{"fixed_kinds_child_unpacked", fixedKindsMD, cat(fBytes(nil, 9, nil), fBytes(nil, 9, fFixed64(nil, 4, 1))), wirescan.ErrNonCanonical},
		// R13 (i) counts records per field per message: one packed record in
		// each of two repeated children, and one in a child plus one in its
		// parent, are each one record per message.
		{"one_packed_record_in_each_child", kindsMD, cat(fBytes(nil, 22, fBytes(nil, 15, packedVarints(1, 2))), fBytes(nil, 22, fBytes(nil, 15, packedVarints(3)))), nil},
		{"one_packed_record_parent_and_child", kindsMD, cat(fBytes(nil, 12, fBytes(nil, 15, packedVarints(2))), fBytes(nil, 15, packedVarints(1))), nil},
		{"fixed_one_packed_record_in_each_child", fixedKindsMD, cat(fBytes(nil, 9, packedRec(4, protowire.Fixed64Type, 1)), fBytes(nil, 9, packedRec(4, protowire.Fixed64Type, 2))), nil},
		{"split_inside_one_child", kindsMD, cat(fBytes(nil, 22, fBytes(nil, 15, packedVarints(1))), fBytes(nil, 22, cat(fBytes(nil, 15, packedVarints(2)), fBytes(nil, 15, packedVarints(3))))), wirescan.ErrNonCanonical},
		{"empty_packed_inside_child", kindsMD, fBytes(nil, 12, fBytes(nil, 17, nil)), wirescan.ErrNonCanonical},
		{"listvalue_nested_ok", listValueMD, fBytes(nil, 1, fBytes(nil, 6, fBytes(nil, 1, fVarint(nil, 4, 1)))), nil},
	})
}

// Deterministic Go marshalling writes proto3 repeated scalars packed, so it
// passes; for a proto2 field not declared packed it writes one record per
// element, and R13 (i) rejects that, whatever the schema says.
func TestUnpackedFromGoMarshal(t *testing.T) {
	m := dynamicKindsWithLists()
	assertSentinel(t, wirescan.CheckForTest(marshalDet(t, m), kindsMD), nil)

	opts := &descriptorpb.FieldOptions{Targets: []descriptorpb.FieldOptions_OptionTargetType{
		descriptorpb.FieldOptions_TARGET_TYPE_FILE, descriptorpb.FieldOptions_TARGET_TYPE_FIELD,
	}}
	targets := fieldOptionsMD.Fields().ByName("targets")
	if targets == nil || targets.IsPacked() {
		t.Fatalf("descriptorpb.FieldOptions.targets is no longer an unpacked repeated enum; pick another proto2 field")
	}
	unpacked := marshalDet(t, opts)
	assertSentinel(t, wirescan.CheckForTest(unpacked, fieldOptionsMD), wirescan.ErrNonCanonical)
	assertSentinel(t, wirescan.Unmarshal(unpacked, new(descriptorpb.FieldOptions)), wirescan.ErrNonCanonical)
	packed := packedRec(targets.Number(), protowire.VarintType,
		uint64(descriptorpb.FieldOptions_TARGET_TYPE_FILE), uint64(descriptorpb.FieldOptions_TARGET_TYPE_FIELD))
	var out descriptorpb.FieldOptions
	assertSentinel(t, wirescan.Unmarshal(packed, &out), nil)
	if !proto.Equal(&out, opts) {
		t.Fatalf("packed targets decode to %v, want %v", &out, opts)
	}
}

// dynamicKindsWithLists is a kindsMD message with two elements in every
// repeated scalar list.
func dynamicKindsWithLists() proto.Message {
	m := newMessage(kindsMD).ProtoReflect()
	for _, fd := range packableLists(kindsMD) {
		l := m.Mutable(fd).List()
		l.Append(scalar(fd, 0))
		l.Append(scalar(fd, 1))
	}
	return m.Interface()
}
