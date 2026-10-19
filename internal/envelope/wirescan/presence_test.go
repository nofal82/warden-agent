package wirescan_test

// Tests for action-envelope.md R13 (j) (Nofal, 2026-10-18, signing-and-updates
// OQ37) and the matching AC8 cases: an explicitly encoded proto3 default
// value (varint 0, false, enum 0, an empty string or bytes, all-zero bits
// for a fixed-width kind) in a non-repeated scalar or enum field with
// implicit presence is ErrNonCanonical. Deterministic Go marshalling never
// writes it, and proto.Unmarshal reads it as the field left out, so
// accepting it would let two different signed byte strings stand for one
// value. Exempt, because the default is a value of its own there or the
// rule does not reach them: oneof members and proto3 `optional` fields
// (explicit presence), proto2 singular fields (always have presence),
// message-typed fields (an empty sub-message), and elements of repeated
// fields.

import (
	"fmt"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// Field numbers of presenceMD.
const (
	pU32  = 1  // uint32, implicit presence
	pI64  = 2  // int64, implicit presence
	pEnum = 3  // enum, implicit presence
	pBool = 4  // bool, implicit presence
	pStr  = 5  // string, implicit presence
	pByt  = 6  // bytes, implicit presence
	pF32  = 7  // fixed32, implicit presence
	pF64  = 8  // fixed64, implicit presence
	pFlt  = 9  // float, implicit presence
	pDbl  = 10 // double, implicit presence
	pS32  = 11 // sint32, implicit presence
	pI32  = 12 // int32, implicit presence

	pChild    = 20 // Presence, message
	pChildren = 21 // repeated Presence
	pRStr     = 22 // repeated string
	pRByt     = 23 // repeated bytes
	pRU32     = 24 // repeated uint32 (packed)
	pREnum    = 25 // repeated enum (packed)

	// oneof choice: scalar members of several kinds, plus a message.
	pOI32  = 30
	pOU32  = 31
	pOBool = 32
	pOEnum = 33
	pOStr  = 34
	pOByt  = 35
	pOF32  = 36
	pOF64  = 37
	pODbl  = 38
	pOMsg  = 39

	// proto3 optional (synthetic oneofs).
	pOptU32  = 40
	pOptI64  = 41
	pOptBool = 42
	pOptEnum = 43
	pOptStr  = 44
	pOptByt  = 45
	pOptDbl  = 46
	pOptF32  = 47
)

// presenceMD is a test-only proto3 message (never added to the contract,
// AC8) with implicit-presence singular fields of every kind R13 (j) names
// plus the fixed-width kinds, a scalar oneof with members of several kinds,
// proto3 optional fields, a nested and a repeated child, and repeated
// fields. The contract has no scalar oneof member and no optional field.
var presenceMD = func() protoreflect.MessageDescriptor {
	type T = descriptorpb.FieldDescriptorProto_Type
	type L = descriptorpb.FieldDescriptorProto_Label
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	field := func(name string, num int32, typ T, label L, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(), Label: label.Enum(),
		}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	inOneof := func(f *descriptorpb.FieldDescriptorProto, idx int32, synthetic bool) *descriptorpb.FieldDescriptorProto {
		f.OneofIndex = proto.Int32(idx)
		if synthetic {
			f.Proto3Optional = proto.Bool(true)
		}
		return f
	}
	const (
		tI32  = descriptorpb.FieldDescriptorProto_TYPE_INT32
		tS32  = descriptorpb.FieldDescriptorProto_TYPE_SINT32
		tU32  = descriptorpb.FieldDescriptorProto_TYPE_UINT32
		tI64  = descriptorpb.FieldDescriptorProto_TYPE_INT64
		tBool = descriptorpb.FieldDescriptorProto_TYPE_BOOL
		tEnum = descriptorpb.FieldDescriptorProto_TYPE_ENUM
		tStr  = descriptorpb.FieldDescriptorProto_TYPE_STRING
		tByt  = descriptorpb.FieldDescriptorProto_TYPE_BYTES
		tF32  = descriptorpb.FieldDescriptorProto_TYPE_FIXED32
		tF64  = descriptorpb.FieldDescriptorProto_TYPE_FIXED64
		tFlt  = descriptorpb.FieldDescriptorProto_TYPE_FLOAT
		tDbl  = descriptorpb.FieldDescriptorProto_TYPE_DOUBLE
		tMsg  = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	)
	const self, shade = ".wardentest.Presence", ".wardentest.Shade"
	fields := []*descriptorpb.FieldDescriptorProto{
		field("u32", pU32, tU32, opt, ""),
		field("i64", pI64, tI64, opt, ""),
		field("e", pEnum, tEnum, opt, shade),
		field("b", pBool, tBool, opt, ""),
		field("str", pStr, tStr, opt, ""),
		field("byt", pByt, tByt, opt, ""),
		field("f32", pF32, tF32, opt, ""),
		field("f64", pF64, tF64, opt, ""),
		field("flt", pFlt, tFlt, opt, ""),
		field("dbl", pDbl, tDbl, opt, ""),
		field("s32", pS32, tS32, opt, ""),
		field("i32", pI32, tI32, opt, ""),
		field("child", pChild, tMsg, opt, self),
		field("children", pChildren, tMsg, rep, self),
		field("rstr", pRStr, tStr, rep, ""),
		field("rbyt", pRByt, tByt, rep, ""),
		field("ru32", pRU32, tU32, rep, ""),
		field("re", pREnum, tEnum, rep, shade),
		inOneof(field("o_i32", pOI32, tI32, opt, ""), 0, false),
		inOneof(field("o_u32", pOU32, tU32, opt, ""), 0, false),
		inOneof(field("o_b", pOBool, tBool, opt, ""), 0, false),
		inOneof(field("o_e", pOEnum, tEnum, opt, shade), 0, false),
		inOneof(field("o_str", pOStr, tStr, opt, ""), 0, false),
		inOneof(field("o_byt", pOByt, tByt, opt, ""), 0, false),
		inOneof(field("o_f32", pOF32, tF32, opt, ""), 0, false),
		inOneof(field("o_f64", pOF64, tF64, opt, ""), 0, false),
		inOneof(field("o_dbl", pODbl, tDbl, opt, ""), 0, false),
		inOneof(field("o_msg", pOMsg, tMsg, opt, self), 0, false),
	}
	oneofs := []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}}
	// Synthetic oneofs must follow every real one (protodesc rule).
	next := int32(1) // index 0 is choice
	for _, o := range []struct {
		name string
		num  int32
		typ  T
		tn   string
	}{
		{"opt_u32", pOptU32, tU32, ""}, {"opt_i64", pOptI64, tI64, ""}, {"opt_b", pOptBool, tBool, ""},
		{"opt_e", pOptEnum, tEnum, shade}, {"opt_str", pOptStr, tStr, ""}, {"opt_byt", pOptByt, tByt, ""},
		{"opt_dbl", pOptDbl, tDbl, ""}, {"opt_f32", pOptF32, tF32, ""},
	} {
		oneofs = append(oneofs, &descriptorpb.OneofDescriptorProto{Name: proto.String("_" + o.name)})
		fields = append(fields, inOneof(field(o.name, o.num, o.typ, opt, o.tn), next, true))
		next++
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("wardentest/presence.proto"),
		Package: proto.String("wardentest"),
		Syntax:  proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Shade"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("SHADE_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("SHADE_ON"), Number: proto.Int32(1)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Presence"), Field: fields, OneofDecl: oneofs,
		}},
	}
	file, err := protodesc.NewFile(fdp, new(protoregistry.Files))
	if err != nil {
		panic(err)
	}
	return file.Messages().ByName("Presence")
}()

// The descriptor is what the tests below assume: implicit presence on the
// plain singular fields, explicit presence on oneof members and optional
// fields. A protobuf-go change here would silently void the tests.
func TestPresenceDescriptorShape(t *testing.T) {
	implicit := []protowire.Number{pU32, pI64, pEnum, pBool, pStr, pByt, pF32, pF64, pFlt, pDbl, pS32, pI32}
	explicit := []protowire.Number{
		pOI32, pOU32, pOBool, pOEnum, pOStr, pOByt, pOF32, pOF64, pODbl,
		pOptU32, pOptI64, pOptBool, pOptEnum, pOptStr, pOptByt, pOptDbl, pOptF32,
	}
	for _, n := range implicit {
		if fd := presenceMD.Fields().ByNumber(n); fd == nil || fd.HasPresence() || fd.IsList() {
			t.Errorf("field %d: want an implicit-presence singular field", n)
		}
	}
	for _, n := range explicit {
		if fd := presenceMD.Fields().ByNumber(n); fd == nil || !fd.HasPresence() || fd.ContainingOneof() == nil {
			t.Errorf("field %d: want an explicit-presence oneof or optional field", n)
		}
	}
	if fd := presenceMD.Fields().ByNumber(pOptU32); !fd.ContainingOneof().IsSynthetic() {
		t.Errorf("opt_u32 is not a proto3 optional field")
	}
}

// defaultRecord is fd's proto3 default written explicitly: varint 0, an
// all-zero fixed-width value, or a length-delimited record of length 0.
func defaultRecord(fd protoreflect.FieldDescriptor) []byte {
	num := fd.Number()
	switch nativeWireType(fd) {
	case protowire.Fixed32Type:
		return fFixed32(nil, num, 0)
	case protowire.Fixed64Type:
		return fFixed64(nil, num, 0)
	case protowire.BytesType:
		return fBytes(nil, num, nil)
	default:
		return fVarint(nil, num, 0)
	}
}

// nonDefaultRecord is fd holding a small valid value other than its default.
func nonDefaultRecord(fd protoreflect.FieldDescriptor) []byte {
	num := fd.Number()
	switch nativeWireType(fd) {
	case protowire.Fixed32Type:
		return fFixed32(nil, num, 1)
	case protowire.Fixed64Type:
		return fFixed64(nil, num, 1)
	case protowire.BytesType:
		return fBytes(nil, num, []byte("a"))
	default:
		return fVarint(nil, num, 1)
	}
}

// R13 (j), every field of every schema: for a non-repeated, non-message
// field the explicit default is ErrNonCanonical exactly when the field has
// implicit presence; message-typed fields accept an empty record, repeated
// numeric fields a packed element 0, repeated string/bytes an empty record.
// The non-default value and the field left out are accepted throughout.
func TestExplicitDefaultEveryField(t *testing.T) {
	mds := append(contractMessages(), kindsMD, fixedKindsMD, presenceMD, locationMD, fieldOptionsMD)
	rejected, exempt := 0, 0
	for _, md := range mds {
		cases := []scanCase{{string(md.Name()) + "/all_fields_left_out", md, nil, nil}}
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			p := string(md.Name()) + "." + string(fd.Name()) + "/"
			num := fd.Number()
			switch {
			case fd.IsList() && elemWireType(fd.Kind()) != protowire.BytesType:
				typ := elemWireType(fd.Kind())
				cases = append(cases,
					scanCase{p + "packed_element_0", md, packedRec(num, typ, 0), nil},
					scanCase{p + "packed_elements_0_0_0", md, packedRec(num, typ, 0, 0, 0), nil},
				)
			case fd.IsList() && fd.Kind() != protoreflect.MessageKind:
				cases = append(cases,
					scanCase{p + "repeated_empty_record", md, fBytes(nil, num, nil), nil},
					scanCase{p + "repeated_two_empty_records", md, cat(fBytes(nil, num, nil), fBytes(nil, num, nil)), nil},
				)
			case fd.Kind() == protoreflect.MessageKind:
				cases = append(cases, scanCase{p + "empty_message", md, fBytes(nil, num, nil), nil})
			default:
				want := error(nil)
				if !fd.HasPresence() {
					want = wirescan.ErrNonCanonical
					rejected++
				} else {
					exempt++
				}
				cases = append(cases,
					scanCase{p + "explicit_default", md, defaultRecord(fd), want},
					scanCase{p + "non_default", md, nonDefaultRecord(fd), nil},
				)
			}
		}
		runCanonCases(t, cases)
	}
	// Guard against the walk finding nothing: the contract alone has more
	// than 60 implicit-presence scalar fields; presenceMD has 17 exempt ones,
	// and descriptorpb's proto2 FieldOptions several more.
	if rejected < 60 || exempt < 17 {
		t.Fatalf("too few fields checked: %d rejected, %d exempt", rejected, exempt)
	}
}

// AC8 named cases on the test-only message: each implicit-presence kind
// explicitly encoded with its default is rejected, left out is accepted;
// zero-valued oneof members and optional fields pass the scan.
func TestExplicitDefaultPresenceCases(t *testing.T) {
	md := presenceMD
	negZero32 := math.Float32bits(float32(math.Copysign(0, -1)))
	negZero64 := math.Float64bits(math.Copysign(0, -1))
	runCanonCases(t, []scanCase{
		{"left_out", md, nil, nil},

		// implicit presence: rejected (R13 (j))
		{"uint32_0", md, fVarint(nil, pU32, 0), wirescan.ErrNonCanonical},
		{"int64_0", md, fVarint(nil, pI64, 0), wirescan.ErrNonCanonical},
		{"enum_0", md, fVarint(nil, pEnum, 0), wirescan.ErrNonCanonical},
		{"bool_false", md, fVarint(nil, pBool, 0), wirescan.ErrNonCanonical},
		{"string_empty", md, fBytes(nil, pStr, nil), wirescan.ErrNonCanonical},
		{"bytes_empty", md, fBytes(nil, pByt, nil), wirescan.ErrNonCanonical},
		{"fixed32_0", md, fFixed32(nil, pF32, 0), wirescan.ErrNonCanonical},
		{"fixed64_0", md, fFixed64(nil, pF64, 0), wirescan.ErrNonCanonical},
		{"float_+0", md, fFixed32(nil, pFlt, 0), wirescan.ErrNonCanonical},
		{"double_+0", md, fFixed64(nil, pDbl, 0), wirescan.ErrNonCanonical},
		{"sint32_0", md, fVarint(nil, pS32, 0), wirescan.ErrNonCanonical},
		{"int32_0", md, fVarint(nil, pI32, 0), wirescan.ErrNonCanonical},
		{"default_after_valid_fields", md, cat(fVarint(nil, pU32, 7), fBytes(nil, pStr, []byte("x")), fVarint(nil, pBool, 0)), wirescan.ErrNonCanonical},
		{"default_before_valid_fields", md, cat(fBytes(nil, pByt, nil), fVarint(nil, pU32, 7)), wirescan.ErrNonCanonical},

		// implicit presence, non-default values: accepted
		{"uint32_1", md, fVarint(nil, pU32, 1), nil},
		{"uint32_max", md, fVarint(nil, pU32, math.MaxUint32), nil},
		{"int64_minus1", md, fVarint(nil, pI64, math.MaxUint64), nil},
		{"enum_1", md, fVarint(nil, pEnum, 1), nil},
		{"bool_true", md, fVarint(nil, pBool, 1), nil},
		{"string_one_byte", md, fBytes(nil, pStr, []byte("a")), nil},
		{"bytes_one_zero_byte", md, fBytes(nil, pByt, []byte{0}), nil},
		{"fixed32_1", md, fFixed32(nil, pF32, 1), nil},
		{"fixed64_high_bit", md, fFixed64(nil, pF64, 1<<63), nil},
		// -0.0 is not the proto3 default (its bits are not all zero) and Go
		// marshals it, so it stays valid.
		{"float_-0", md, fFixed32(nil, pFlt, negZero32), nil},
		{"double_-0", md, fFixed64(nil, pDbl, negZero64), nil},
		{"float_nan", md, fFixed32(nil, pFlt, 0x7fc00000), nil},
		{"sint32_zigzag_2^32-1", md, fVarint(nil, pS32, math.MaxUint32), nil},

		// R13 (g): sint32's ZigZag varint above 2^32-1 stays rejected.
		{"sint32_zigzag_2^32", md, fVarint(nil, pS32, 1<<32), wirescan.ErrNonCanonical},

		// oneof members: explicit presence, zero passes the scan
		{"oneof_int32_0", md, fVarint(nil, pOI32, 0), nil},
		{"oneof_uint32_0", md, fVarint(nil, pOU32, 0), nil},
		{"oneof_bool_false", md, fVarint(nil, pOBool, 0), nil},
		{"oneof_enum_0", md, fVarint(nil, pOEnum, 0), nil},
		{"oneof_string_empty", md, fBytes(nil, pOStr, nil), nil},
		{"oneof_bytes_empty", md, fBytes(nil, pOByt, nil), nil},
		{"oneof_fixed32_0", md, fFixed32(nil, pOF32, 0), nil},
		{"oneof_fixed64_0", md, fFixed64(nil, pOF64, 0), nil},
		{"oneof_double_+0", md, fFixed64(nil, pODbl, 0), nil},
		{"oneof_message_empty", md, fBytes(nil, pOMsg, nil), nil},
		// The oneof rule itself still applies to zero members.
		{"oneof_two_zero_members", md, cat(fVarint(nil, pOI32, 0), fVarint(nil, pOBool, 0)), wirescan.ErrDuplicateField},
		{"oneof_same_zero_member_twice", md, cat(fVarint(nil, pOU32, 0), fVarint(nil, pOU32, 0)), wirescan.ErrDuplicateField},
		// R13 (e)-(h) still apply to oneof members.
		{"oneof_zero_overlong", md, append(protowire.AppendTag(nil, pOU32, protowire.VarintType), 0x80, 0x00), wirescan.ErrNonCanonical},
		{"oneof_bool_2", md, fVarint(nil, pOBool, 2), wirescan.ErrNonCanonical},
		{"oneof_uint32_2^32", md, fVarint(nil, pOU32, 1<<32), wirescan.ErrNonCanonical},

		// proto3 optional: explicit presence, zero passes the scan
		{"optional_uint32_0", md, fVarint(nil, pOptU32, 0), nil},
		{"optional_int64_0", md, fVarint(nil, pOptI64, 0), nil},
		{"optional_bool_false", md, fVarint(nil, pOptBool, 0), nil},
		{"optional_enum_0", md, fVarint(nil, pOptEnum, 0), nil},
		{"optional_string_empty", md, fBytes(nil, pOptStr, nil), nil},
		{"optional_bytes_empty", md, fBytes(nil, pOptByt, nil), nil},
		{"optional_double_+0", md, fFixed64(nil, pOptDbl, 0), nil},
		{"optional_fixed32_0", md, fFixed32(nil, pOptF32, 0), nil},
		{"all_optionals_zero_together", md, cat(fVarint(nil, pOptU32, 0), fVarint(nil, pOptI64, 0), fVarint(nil, pOptBool, 0),
			fVarint(nil, pOptEnum, 0), fBytes(nil, pOptStr, nil), fBytes(nil, pOptByt, nil), fFixed64(nil, pOptDbl, 0), fFixed32(nil, pOptF32, 0)), nil},
		{"optional_zero_and_oneof_zero", md, cat(fVarint(nil, pOEnum, 0), fVarint(nil, pOptU32, 0)), nil},
		{"optional_zero_twice", md, cat(fVarint(nil, pOptU32, 0), fVarint(nil, pOptU32, 0)), wirescan.ErrDuplicateField},
		{"optional_zero_overlong", md, append(protowire.AppendTag(nil, pOptU32, protowire.VarintType), 0x80, 0x00), wirescan.ErrNonCanonical},

		// message-typed and repeated fields: not affected
		{"child_empty", md, fBytes(nil, pChild, nil), nil},
		{"children_empty_records", md, cat(fBytes(nil, pChildren, nil), fBytes(nil, pChildren, nil)), nil},
		{"repeated_string_empty_records", md, cat(fBytes(nil, pRStr, nil), fBytes(nil, pRStr, []byte("a")), fBytes(nil, pRStr, nil)), nil},
		{"repeated_bytes_empty_record", md, fBytes(nil, pRByt, nil), nil},
		{"repeated_uint32_packed_0", md, fBytes(nil, pRU32, packedVarints(0)), nil},
		{"repeated_enum_packed_0_0", md, fBytes(nil, pREnum, packedVarints(0, 0)), nil},
	})
}

// R13 (j) applies at every depth: a nested child and an element of a
// repeated child (AC8 "at any depth").
func TestExplicitDefaultNested(t *testing.T) {
	nest := func(levels int, leaf []byte) []byte {
		for i := 0; i < levels; i++ {
			leaf = fBytes(nil, pChild, leaf)
		}
		return leaf
	}
	inList := func(leaf []byte) []byte {
		return cat(fBytes(nil, pChildren, fVarint(nil, pU32, 1)), fBytes(nil, pChildren, leaf))
	}
	leaves := []struct {
		name string
		b    []byte
		want error
	}{
		{"uint32_0", fVarint(nil, pU32, 0), wirescan.ErrNonCanonical},
		{"int64_0", fVarint(nil, pI64, 0), wirescan.ErrNonCanonical},
		{"enum_0", fVarint(nil, pEnum, 0), wirescan.ErrNonCanonical},
		{"bool_false", fVarint(nil, pBool, 0), wirescan.ErrNonCanonical},
		{"string_empty", fBytes(nil, pStr, nil), wirescan.ErrNonCanonical},
		{"bytes_empty", fBytes(nil, pByt, nil), wirescan.ErrNonCanonical},
		{"double_+0", fFixed64(nil, pDbl, 0), wirescan.ErrNonCanonical},
		{"left_out", nil, nil},
		{"uint32_1", fVarint(nil, pU32, 1), nil},
		{"oneof_bool_false", fVarint(nil, pOBool, 0), nil},
		{"optional_string_empty", fBytes(nil, pOptStr, nil), nil},
		{"packed_element_0", fBytes(nil, pRU32, packedVarints(0)), nil},
		{"sint32_zigzag_2^32-1", fVarint(nil, pS32, math.MaxUint32), nil},
		{"sint32_zigzag_2^32", fVarint(nil, pS32, 1<<32), wirescan.ErrNonCanonical},
	}
	var cases []scanCase
	for _, depth := range []int{0, 1, 2, 5, 15} {
		for _, l := range leaves {
			name := fmt.Sprintf("depth%02d_%s", depth, l.name)
			cases = append(cases,
				scanCase{name, presenceMD, nest(depth, l.b), l.want},
				scanCase{name + "/in_repeated_child", presenceMD, nest(depth, inList(l.b)), l.want},
			)
		}
	}
	runCanonCases(t, cases)
}

// Go's own marshalling of the test-only message agrees with the rule: a
// zero implicit-presence field is left out, a zero optional or oneof member
// is written and accepted, and -0.0 is written and accepted.
func TestExplicitDefaultFromGoMarshal(t *testing.T) {
	set := func(m *dynamicpb.Message, num protowire.Number, v protoreflect.Value) {
		m.Set(presenceMD.Fields().ByNumber(num), v)
	}
	zeros := dynamicpb.NewMessage(presenceMD)
	set(zeros, pOptU32, protoreflect.ValueOfUint32(0))
	set(zeros, pOptStr, protoreflect.ValueOfString(""))
	b := marshalDet(t, zeros)
	if len(b) == 0 {
		t.Fatalf("Go did not write the zero optional fields")
	}
	assertSentinel(t, wirescan.Check(b, presenceMD), nil)
	// The oneof member gets its own message: Go's reflection marshaller
	// writes oneof members after the other fields, which R13 (k) rejects
	// when a lower-numbered member follows them
	// (TestOrderReflectionMarshalOneofLast).
	oneofZero := dynamicpb.NewMessage(presenceMD)
	set(oneofZero, pOBool, protoreflect.ValueOfBool(false))
	ob := marshalDet(t, oneofZero)
	if len(ob) == 0 {
		t.Fatalf("Go did not write the zero oneof member")
	}
	assertSentinel(t, wirescan.Check(ob, presenceMD), nil)

	negZero := dynamicpb.NewMessage(presenceMD)
	set(negZero, pFlt, protoreflect.ValueOfFloat32(float32(math.Copysign(0, -1))))
	set(negZero, pDbl, protoreflect.ValueOfFloat64(math.Copysign(0, -1)))
	nb := marshalDet(t, negZero)
	if len(nb) != 5+9 {
		t.Fatalf("Go wrote %d bytes for -0.0 float and double, want 14", len(nb))
	}
	assertSentinel(t, wirescan.Check(nb, presenceMD), nil)
	out := dynamicpb.NewMessage(presenceMD)
	assertSentinel(t, wirescan.Unmarshal(nb, out), nil)
	if !proto.Equal(out, negZero) {
		t.Fatalf("-0.0 round trip differs")
	}

	// +0.0 is the default: Go leaves it out.
	posZero := dynamicpb.NewMessage(presenceMD)
	set(posZero, pDbl, protoreflect.ValueOfFloat64(0))
	if pb := marshalDet(t, posZero); len(pb) != 0 {
		t.Fatalf("Go wrote +0.0 double: %x", pb)
	}
}

// Well-known wrapper types are proto3 messages whose `value` field has
// implicit presence, so an explicit default there is non-canonical like any
// other; the proto2 descriptor messages have presence on every singular
// field and are exempt.
func TestExplicitDefaultWellKnown(t *testing.T) {
	desc := func(m proto.Message) protoreflect.MessageDescriptor { return m.ProtoReflect().Descriptor() }
	fdpMD := desc(&descriptorpb.FieldDescriptorProto{})
	explicitProto2 := marshalDet(t, &descriptorpb.FieldDescriptorProto{Name: proto.String(""), Number: proto.Int32(0)})
	if len(explicitProto2) == 0 {
		t.Fatalf("Go left out proto2 fields that are set to their zero value")
	}
	runCanonCases(t, []scanCase{
		{"int32value_0", desc(&wrapperspb.Int32Value{}), fVarint(nil, 1, 0), wirescan.ErrNonCanonical},
		{"uint32value_0", desc(&wrapperspb.UInt32Value{}), fVarint(nil, 1, 0), wirescan.ErrNonCanonical},
		{"int64value_0", desc(&wrapperspb.Int64Value{}), fVarint(nil, 1, 0), wirescan.ErrNonCanonical},
		{"uint64value_0", desc(&wrapperspb.UInt64Value{}), fVarint(nil, 1, 0), wirescan.ErrNonCanonical},
		{"boolvalue_false", desc(&wrapperspb.BoolValue{}), fVarint(nil, 1, 0), wirescan.ErrNonCanonical},
		{"stringvalue_empty", desc(&wrapperspb.StringValue{}), fBytes(nil, 1, nil), wirescan.ErrNonCanonical},
		{"bytesvalue_empty", desc(&wrapperspb.BytesValue{}), fBytes(nil, 1, nil), wirescan.ErrNonCanonical},
		{"floatvalue_+0", desc(&wrapperspb.FloatValue{}), fFixed32(nil, 1, 0), wirescan.ErrNonCanonical},
		{"doublevalue_+0", desc(&wrapperspb.DoubleValue{}), fFixed64(nil, 1, 0), wirescan.ErrNonCanonical},
		{"boolvalue_left_out", desc(&wrapperspb.BoolValue{}), nil, nil},
		{"floatvalue_-0", desc(&wrapperspb.FloatValue{}), marshalDet(t, wrapperspb.Float(float32(math.Copysign(0, -1)))), nil},
		{"doublevalue_-0", desc(&wrapperspb.DoubleValue{}), marshalDet(t, wrapperspb.Double(math.Copysign(0, -1))), nil},

		// proto2: explicit presence, the zero value is a value.
		{"proto2_field_name_empty_and_number_0", fdpMD, explicitProto2, nil},
		{"proto2_bool_false", desc(&descriptorpb.FieldOptions{}), fVarint(nil, 2, 0), nil},
	})
}

// Map entries are implicit-presence proto3 messages, and Go always writes a
// map entry's key and value even when they are zero. The contract has no
// map. Read literally, R13 (j) rejects a zero key written explicitly inside
// an entry; this test pins that literal reading so a change is deliberate.
// A Go-marshalled map with an empty key so fails the scan. Nofal decided
// (2026-10-18) that the contract never contains maps (TestContractHasNoMaps
// in api/proto/warden/v1) and that the scanner stays as it is.
func TestExplicitDefaultMapEntryLiteral(t *testing.T) {
	structMD := (&structpb.Struct{}).ProtoReflect().Descriptor()
	trueValue := fVarint(nil, 4, 1) // Value.bool_value = true (a oneof member)
	entry := func(key []byte, withKey bool) []byte {
		var e []byte
		if withKey {
			e = fBytes(e, 1, key)
		}
		return fBytes(nil, 1, fBytes(e, 2, trueValue))
	}
	goEmptyKey, err := structpb.NewStruct(map[string]any{"": true})
	if err != nil {
		t.Fatal(err)
	}
	runCanonCases(t, []scanCase{
		{"key_a_accepted", structMD, entry([]byte("a"), true), nil},
		{"key_empty_explicit_rejected", structMD, entry(nil, true), wirescan.ErrNonCanonical},
		{"key_empty_left_out_accepted", structMD, entry(nil, false), nil},
		{"go_marshal_empty_key_rejected", structMD, marshalDet(t, goEmptyKey), wirescan.ErrNonCanonical},
	})
}
