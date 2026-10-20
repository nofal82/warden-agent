package wirescan_test

// Tests for the canonical-encoding rule of the strict wire scanner
// (action-envelope.md R13, Nofal 2026-10-16): every varint (tag, length
// prefix, value, packed element) must be minimally encoded, and every
// int32/enum, uint32/sint32 and bool value must be within the range of its
// type. Otherwise two decoders could read the same signed bytes differently
// (for example format_version 2^32+1 truncating to 1, or autonomy_level
// 2^32+4 truncating to AUTONOMY_LEVEL_L3). Violations are ErrNonCanonical.

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
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// kindsMD is a test-only proto3 message with one field of every scalar kind
// the rule distinguishes, the same kinds repeated (packed by default), and
// itself as a nested and repeated child. The warden contract has no int32
// or sint32 field and no repeated enum/bool/uint32, so these are covered
// here.
var kindsMD = func() protoreflect.MessageDescriptor {
	type T = descriptorpb.FieldDescriptorProto_Type
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	field := func(name string, num int32, typ T, label descriptorpb.FieldDescriptorProto_Label, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(), Label: label.Enum(),
		}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	const (
		tI32  = descriptorpb.FieldDescriptorProto_TYPE_INT32
		tS32  = descriptorpb.FieldDescriptorProto_TYPE_SINT32
		tU32  = descriptorpb.FieldDescriptorProto_TYPE_UINT32
		tBool = descriptorpb.FieldDescriptorProto_TYPE_BOOL
		tEnum = descriptorpb.FieldDescriptorProto_TYPE_ENUM
		tI64  = descriptorpb.FieldDescriptorProto_TYPE_INT64
		tS64  = descriptorpb.FieldDescriptorProto_TYPE_SINT64
		tU64  = descriptorpb.FieldDescriptorProto_TYPE_UINT64
		tF32  = descriptorpb.FieldDescriptorProto_TYPE_FIXED32
		tSF64 = descriptorpb.FieldDescriptorProto_TYPE_SFIXED64
		tStr  = descriptorpb.FieldDescriptorProto_TYPE_STRING
		tMsg  = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	)
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("wardentest/canonical_kinds.proto"),
		Package: proto.String("wardentest"),
		Syntax:  proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Color"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("COLOR_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("COLOR_RED"), Number: proto.Int32(1)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Kinds"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("i32", 1, tI32, opt, ""),
				field("s32", 2, tS32, opt, ""),
				field("u32", 3, tU32, opt, ""),
				field("b", 4, tBool, opt, ""),
				field("e", 5, tEnum, opt, ".wardentest.Color"),
				field("i64", 6, tI64, opt, ""),
				field("s64", 7, tS64, opt, ""),
				field("u64", 8, tU64, opt, ""),
				field("f32", 9, tF32, opt, ""),
				field("sf64", 10, tSF64, opt, ""),
				field("str", 11, tStr, opt, ""),
				field("child", 12, tMsg, opt, ".wardentest.Kinds"),
				field("ri32", 13, tI32, rep, ""),
				field("rs32", 14, tS32, rep, ""),
				field("ru32", 15, tU32, rep, ""),
				field("rb", 16, tBool, rep, ""),
				field("re", 17, tEnum, rep, ".wardentest.Color"),
				field("ri64", 18, tI64, rep, ""),
				field("rs64", 19, tS64, rep, ""),
				field("ru64", 20, tU64, rep, ""),
				field("rf32", 21, tF32, rep, ""),
				field("children", 22, tMsg, rep, ".wardentest.Kinds"),
			},
		}},
	}
	file, err := protodesc.NewFile(fdp, new(protoregistry.Files))
	if err != nil {
		panic(err)
	}
	return file.Messages().ByName("Kinds")
}()

// wantExplicitDefault is ErrNonCanonical for a varint 0 written explicitly
// in a non-repeated field with implicit presence (R13 (j)), and nil for
// any other field or value.
func wantExplicitDefault(fd protoreflect.FieldDescriptor, v uint64) error {
	if v == 0 && !fd.IsList() && !fd.HasPresence() {
		return wirescan.ErrNonCanonical
	}
	return nil
}

// wantIfList is want for a repeated field and nil for any other.
func wantIfList(fd protoreflect.FieldDescriptor, want error) error {
	if fd.IsList() {
		return want
	}
	return nil
}

// newMessage returns an empty message for md: the generated type when one is
// registered, otherwise a dynamic message.
func newMessage(md protoreflect.MessageDescriptor) proto.Message {
	if mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName()); err == nil {
		return mt.New().Interface()
	}
	return dynamicpb.NewMessage(md)
}

// runCanonCases is runScanCases for descriptors that need not be registered.
func runCanonCases(t *testing.T, cases []scanCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSentinel(t, wirescan.CheckForTest(c.b, c.md), c.want)
			assertSentinel(t, wirescan.Unmarshal(c.b, newMessage(c.md)), c.want)
		})
	}
}

// contractMessages is every message type in the warden contract: every
// registered file of the contract's package, so a new .proto file is
// covered without a test change (AC8a).
func contractMessages() []protoreflect.MessageDescriptor {
	pkg := wardenv1.File_warden_v1_envelope_proto.Package()
	var mds []protoreflect.MessageDescriptor
	protoregistry.GlobalFiles.RangeFilesByPackage(pkg, func(file protoreflect.FileDescriptor) bool {
		for i := 0; i < file.Messages().Len(); i++ {
			mds = append(mds, file.Messages().Get(i))
		}
		return true
	})
	return mds
}

type wireVal struct {
	name string
	v    uint64
}

// Values that are out of range for each 32-bit or bool kind, each minimally
// encoded so the range rule is the only one broken.
func badValues(k protoreflect.Kind) []wireVal {
	switch k {
	case protoreflect.Int32Kind, protoreflect.EnumKind:
		return []wireVal{
			{"2^31", 1 << 31},
			{"2^32-1_five_bytes", 1<<32 - 1}, // ff ff ff ff 0f
			{"2^32", 1 << 32},
			{"2^32+1", 1<<32 + 1},
			{"2^32+4_truncates_to_4", 1<<32 + 4},
			{"minInt32-1", i64(math.MinInt32 - 1)},
			{"minInt64", 1 << 63},
			{"maxInt64", math.MaxInt64},
		}
	case protoreflect.Uint32Kind, protoreflect.Sint32Kind:
		return []wireVal{
			{"2^32", 1 << 32},
			{"2^32+1_truncates_to_1", 1<<32 + 1},
			{"2^63", 1 << 63},
			{"maxUint64", math.MaxUint64},
		}
	case protoreflect.BoolKind:
		return []wireVal{
			{"2", 2},
			{"127", 127},
			{"128", 128},
			{"255", 255},
			{"2^32", 1 << 32},
			{"2^32+1", 1<<32 + 1},
			{"maxUint64", math.MaxUint64},
		}
	}
	return nil
}

// Boundary values that are in range for each varint kind.
func goodValues(k protoreflect.Kind) []wireVal {
	switch k {
	case protoreflect.Int32Kind, protoreflect.EnumKind:
		return []wireVal{
			{"0", 0}, {"1", 1}, {"maxInt32", math.MaxInt32},
			{"-1_ten_bytes", math.MaxUint64}, {"minInt32_ten_bytes", i64(math.MinInt32)},
		}
	case protoreflect.Uint32Kind, protoreflect.Sint32Kind:
		return []wireVal{{"0", 0}, {"1", 1}, {"2^31", 1 << 31}, {"maxUint32", math.MaxUint32}}
	case protoreflect.BoolKind:
		return []wireVal{{"0", 0}, {"1", 1}}
	case protoreflect.Int64Kind, protoreflect.Uint64Kind, protoreflect.Sint64Kind:
		return []wireVal{
			{"0", 0}, {"2^32+1", 1<<32 + 1}, {"maxInt64", math.MaxInt64},
			{"2^63", 1 << 63}, {"maxUint64", math.MaxUint64},
		}
	}
	return nil
}

func isVarintKind(k protoreflect.Kind) bool {
	switch k {
	case protoreflect.BoolKind, protoreflect.EnumKind,
		protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Uint32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		return true
	}
	return false
}

// Every varint field of every contract message (and of kindsMD) rejects an
// out-of-range value and accepts boundary in-range values, as a single
// field and, for repeated fields, packed (bad element first, in the middle
// and alone). A repeated field written unpacked is rejected whatever its
// values (R13 (i)), so range coverage for repeated fields lives in the
// packed cases. The in-range value 0 written explicitly in a singular
// implicit-presence field is the proto3 default and is rejected (R13 (j));
// as a packed element it stays valid.
func TestCanonicalRangeEveryField(t *testing.T) {
	mds := append(contractMessages(), kindsMD)
	checked := 0
	for _, md := range mds {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			if !isVarintKind(fd.Kind()) {
				continue
			}
			checked++
			num := fd.Number()
			var cases []scanCase
			for _, bad := range badValues(fd.Kind()) {
				name := string(md.Name()) + "." + string(fd.Name()) + "=" + bad.name
				if fd.IsList() {
					cases = append(cases,
						scanCase{name + "/packed", md, fBytes(nil, num, packedVarints(1, bad.v, 1)), wirescan.ErrNonCanonical},
						scanCase{name + "/packed_only", md, fBytes(nil, num, packedVarints(bad.v)), wirescan.ErrNonCanonical},
						scanCase{name + "/packed_first", md, fBytes(nil, num, packedVarints(bad.v, 1)), wirescan.ErrNonCanonical},
						// Rejected as unpacked (R13 (i)) before the value is looked at.
						scanCase{name + "/unpacked", md, cat(fVarint(nil, num, 1), fVarint(nil, num, bad.v)), wirescan.ErrNonCanonical},
					)
					continue
				}
				cases = append(cases, scanCase{name, md, fVarint(nil, num, bad.v), wirescan.ErrNonCanonical})
			}
			for _, good := range goodValues(fd.Kind()) {
				name := string(md.Name()) + "." + string(fd.Name()) + "=" + good.name
				if fd.IsList() {
					cases = append(cases,
						scanCase{name + "/packed", md, fBytes(nil, num, packedVarints(1, good.v, 1)), nil},
						scanCase{name + "/packed_only", md, fBytes(nil, num, packedVarints(good.v)), nil},
						// R13 (i): in-range values written unpacked are still rejected.
						scanCase{name + "/unpacked", md, cat(fVarint(nil, num, good.v), fVarint(nil, num, good.v)), wirescan.ErrNonCanonical},
						scanCase{name + "/unpacked_single", md, fVarint(nil, num, good.v), wirescan.ErrNonCanonical},
					)
					continue
				}
				cases = append(cases, scanCase{name, md, fVarint(nil, num, good.v), wantExplicitDefault(fd, good.v)})
			}
			runCanonCases(t, cases)
		}
	}
	// Guard against the schema walk silently finding nothing: the contract
	// alone has 14 enum fields, 19 uint32, 1 bool and several 64-bit ones.
	if checked < 40 {
		t.Fatalf("only %d varint fields checked", checked)
	}
}

// Every field of every contract message (and of kindsMD) rejects an
// overlong tag, and an overlong value or length prefix.
func TestCanonicalOverlongEveryField(t *testing.T) {
	mds := append(contractMessages(), kindsMD)
	checked := 0
	for _, md := range mds {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			num := fd.Number()
			prefix := string(md.Name()) + "." + string(fd.Name()) + "/"
			var cases []scanCase
			add := func(name string, b []byte, want error) {
				cases = append(cases, scanCase{prefix + name, md, b, want})
			}
			tagOver := func(typ protowire.Type, total int) []byte {
				return overlongN(rawTag(num, typ), total)
			}
			switch {
			case isVarintKind(fd.Kind()):
				// A repeated field's single unpacked record is non-canonical
				// (R13 (i)); its minimal form is the packed one below.
				add("minimal", fVarint(nil, num, 1), wantIfList(fd, wirescan.ErrNonCanonical))
				add("tag_overlong", fOverlongTagVarint(nil, num, 1), wirescan.ErrNonCanonical)
				add("tag_overlong_10_bytes", cat(tagOver(protowire.VarintType, 10), []byte{0x01}), wirescan.ErrNonCanonical)
				add("value_1_as_81_00", fVarintOverlong(nil, num, 1), wirescan.ErrNonCanonical)
				add("value_0_as_80_00", fVarintOverlong(nil, num, 0), wirescan.ErrNonCanonical)
				add("value_1_10_bytes", cat(protowire.AppendTag(nil, num, protowire.VarintType), overlongN(1, 10)), wirescan.ErrNonCanonical)
				if fd.IsList() {
					add("packed_minimal", fBytes(nil, num, packedVarints(1, 0, 1)), nil)
					add("packed_len_overlong", fBytesOverlongLen(nil, num, packedVarints(1, 0, 1)), wirescan.ErrNonCanonical)
					add("packed_empty_len_overlong", fBytesOverlongLen(nil, num, nil), wirescan.ErrNonCanonical)
					add("packed_tag_overlong", fOverlongTagBytes(nil, num, packedVarints(1)), wirescan.ErrNonCanonical)
					add("packed_elem_first_overlong", fBytes(nil, num, cat(overlong(1), packedVarints(0, 1))), wirescan.ErrNonCanonical)
					add("packed_elem_middle_overlong", fBytes(nil, num, cat(packedVarints(1), overlong(0), packedVarints(1))), wirescan.ErrNonCanonical)
					add("packed_elem_last_overlong", fBytes(nil, num, cat(packedVarints(1, 0), overlong(1))), wirescan.ErrNonCanonical)
					add("packed_elem_10_bytes", fBytes(nil, num, overlongN(1, 10)), wirescan.ErrNonCanonical)
				}
			case fd.Kind() == protoreflect.MessageKind:
				add("empty_minimal", fBytes(nil, num, nil), nil)
				add("tag_overlong", fOverlongTagBytes(nil, num, nil), wirescan.ErrNonCanonical)
				add("empty_len_as_80_00", fBytesOverlongLen(nil, num, nil), wirescan.ErrNonCanonical)
				add("empty_len_10_bytes", cat(protowire.AppendTag(nil, num, protowire.BytesType), overlongN(0, 10)), wirescan.ErrNonCanonical)
			case fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind:
				add("minimal", fBytes(nil, num, []byte("abc")), nil)
				add("tag_overlong", fOverlongTagBytes(nil, num, []byte("abc")), wirescan.ErrNonCanonical)
				add("len_3_as_83_00", fBytesOverlongLen(nil, num, []byte("abc")), wirescan.ErrNonCanonical)
				add("len_0_as_80_00", fBytesOverlongLen(nil, num, nil), wirescan.ErrNonCanonical)
				add("len_200_overlong", fBytesOverlongLen(nil, num, bytes.Repeat([]byte("a"), 200)), wirescan.ErrNonCanonical)
			case fd.Kind() == protoreflect.Fixed32Kind:
				add("minimal", fFixed32(nil, num, math.MaxUint32), wantIfList(fd, wirescan.ErrNonCanonical))
				add("tag_overlong", cat(overlong(rawTag(num, protowire.Fixed32Type)), protowire.AppendFixed32(nil, 1)), wirescan.ErrNonCanonical)
				if fd.IsList() {
					add("packed_minimal", fBytes(nil, num, cat(protowire.AppendFixed32(nil, math.MaxUint32), protowire.AppendFixed32(nil, 0))), nil)
					add("packed_len_overlong", fBytesOverlongLen(nil, num, protowire.AppendFixed32(nil, 1)), wirescan.ErrNonCanonical)
					add("packed_tag_overlong", fOverlongTagBytes(nil, num, protowire.AppendFixed32(nil, 1)), wirescan.ErrNonCanonical)
				}
			case fd.Kind() == protoreflect.Sfixed64Kind:
				add("minimal", fFixed64(nil, num, math.MaxUint64), nil)
				add("tag_overlong", cat(overlong(rawTag(num, protowire.Fixed64Type)), protowire.AppendFixed64(nil, 1)), wirescan.ErrNonCanonical)
			default:
				t.Fatalf("%s: kind %v not covered by this test", fd.FullName(), fd.Kind())
			}
			checked++
			runCanonCases(t, cases)
		}
	}
	if checked < 80 {
		t.Fatalf("only %d fields checked", checked)
	}
}

// The examples and attacks named in the requirement, through a whole
// EnvelopeBody, at depths 0 to 3.
func TestCanonicalBodyCases(t *testing.T) {
	base := marshalDet(t, validBody())
	without := func(m func(b *wardenv1.EnvelopeBody)) []byte { b := validBody(); m(b); return marshalDet(t, b) }
	noFV := without(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })
	noCreated := without(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 })
	noExpires := without(func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = 0 })
	noAction := without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" })
	noDigest := without(func(b *wardenv1.EnvelopeBody) { b.PlaybookDigest = nil })
	noParams := without(func(b *wardenv1.EnvelopeBody) { b.Params = nil })
	noPD := without(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil })
	pd := marshalDet(t, validBody().PolicyDecision)
	pdNoLevel := func() []byte {
		p := proto.Clone(validBody().PolicyDecision).(*wardenv1.PolicyDecision)
		p.AutonomyLevel = 0
		return marshalDet(t, p)
	}()
	pdNoDecision := func() []byte {
		p := proto.Clone(validBody().PolicyDecision).(*wardenv1.PolicyDecision)
		p.DecisionId = ""
		return marshalDet(t, p)
	}()
	restart := marshalDet(t, &wardenv1.ServiceRestartRequest{Unit: "nginx.service"})
	app := func(b []byte, more ...[]byte) []byte {
		return cat(append([][]byte{append([]byte(nil), b...)}, more...)...)
	}
	// Insert at the field's ascending position so only the rule under
	// test is broken (R13 (k)).
	withParams := func(tr []byte) []byte { return withField(t, noParams, fBytes(nil, 8, tr)) }
	withPD := func(p []byte) []byte { return withField(t, noPD, fBytes(nil, 9, p)) }
	withLevel := func(v uint64) []byte { return withPD(withField(t, pdNoLevel, fVarint(nil, 2, v))) }
	fileDelete := marshalDet(t, &wardenv1.FileDeleteByAgeRequest{
		Root: wardenv1.FileDeleteRoot(1), MinAgeDays: 7, MaxFiles: 10, MaxBytes: 1 << 30,
	})
	withDryRun := func(v uint64) []byte {
		return withParams(fBytes(nil, 17, withField(t, fileDelete, fVarint(nil, 5, v))))
	}

	runCanonCases(t, []scanCase{
		{"valid", bodyMD, base, nil},
		{"format_version_maxuint32", bodyMD, withField(t, noFV, fVarint(nil, 1, math.MaxUint32)), nil},
		{"autonomy_minus1_ten_bytes", bodyMD, withLevel(math.MaxUint64), nil},
		{"autonomy_minInt32_ten_bytes", bodyMD, withLevel(i64(math.MinInt32)), nil},
		{"autonomy_maxInt32", bodyMD, withLevel(math.MaxInt32), nil},
		{"dry_run_true", bodyMD, withDryRun(1), nil},

		// R13 (j), AC8: explicit proto3 defaults at depths 0 to 2. These two
		// were accepted before 2026-10-18. Each "left out" counterpart
		// passes the scan (the verifier may still refuse it later, as
		// check 5 or 6).
		{"autonomy_explicit_zero", bodyMD, withLevel(0), wirescan.ErrNonCanonical},
		{"dry_run_explicit_false", bodyMD, withDryRun(0), wirescan.ErrNonCanonical},
		{"autonomy_left_out", bodyMD, withPD(pdNoLevel), nil},
		{"dry_run_left_out", bodyMD, withParams(fBytes(nil, 17, fileDelete)), nil},
		{"format_version_explicit_0", bodyMD, fVarint(app(noFV), 1, 0), wirescan.ErrNonCanonical},
		{"format_version_explicit_0_first", bodyMD, cat(fVarint(nil, 1, 0), noFV), wirescan.ErrNonCanonical},
		{"format_version_left_out", bodyMD, noFV, nil},
		{"created_at_explicit_0", bodyMD, fVarint(app(noCreated), 10, 0), wirescan.ErrNonCanonical},
		{"created_at_left_out", bodyMD, noCreated, nil},
		{"action_id_explicit_empty", bodyMD, fBytes(app(noAction), 2, nil), wirescan.ErrNonCanonical},
		{"playbook_digest_explicit_empty", bodyMD, fBytes(app(noDigest), 6, nil), wirescan.ErrNonCanonical},
		{"approval_id_explicit_empty", bodyMD, withPD(fBytes(app(pd), 4, nil)), wirescan.ErrNonCanonical},
		{"approval_id_left_out", bodyMD, withPD(pd), nil},
		{"decision_id_explicit_empty", bodyMD, withPD(fBytes(app(pdNoDecision), 1, nil)), wirescan.ErrNonCanonical},
		{"unit_explicit_empty", bodyMD, withParams(fBytes(nil, 11, fBytes(nil, 1, nil))), wirescan.ErrNonCanonical},
		{"unit_left_out", bodyMD, withParams(fBytes(nil, 11, nil)), nil},
		{"min_age_days_explicit_0", bodyMD, withParams(fBytes(nil, 17, fVarint(nil, 2, 0))), wirescan.ErrNonCanonical},
		{"db_engine_explicit_0", bodyMD, withParams(fBytes(nil, 22, fVarint(nil, 1, 0))), wirescan.ErrNonCanonical},
		{"db_server_started_at_explicit_0", bodyMD, withParams(fBytes(nil, 22, fVarint(nil, 5, 0))), wirescan.ErrNonCanonical},
		{"db_starts_packed_zeros", bodyMD, withParams(fBytes(nil, 22, cat(fBytes(nil, 3, packedVarints(1, 2)), fBytes(nil, 4, packedVarints(0, 0))))), nil},
		// An empty params member (message-typed) is not a proto3 default.
		{"empty_member_message", bodyMD, withParams(fBytes(nil, 7, nil)), nil},

		// overlong varints at depth 0
		{"format_version_1_as_81_00", bodyMD, app(noFV, []byte{0x08, 0x81, 0x00}), wirescan.ErrNonCanonical},
		{"format_version_1_10_bytes", bodyMD, app(noFV, []byte{0x08}, overlongN(1, 10)), wirescan.ErrNonCanonical},
		{"format_version_tag_as_88_00", bodyMD, app(noFV, []byte{0x88, 0x00, 0x01}), wirescan.ErrNonCanonical},
		{"created_at_overlong", bodyMD, app(noCreated, []byte{0x50}, overlong(1_800_000_000)), wirescan.ErrNonCanonical},
		{"created_at_10_bytes", bodyMD, app(noCreated, []byte{0x50}, overlongN(1_800_000_000, 10)), wirescan.ErrNonCanonical},
		{"created_at_tag_overlong", bodyMD, fOverlongTagVarint(app(noCreated), 10, 1_800_000_000), wirescan.ErrNonCanonical},
		{"expires_at_overlong", bodyMD, fVarintOverlong(app(noExpires), 11, 1_800_000_300), wirescan.ErrNonCanonical},
		{"action_id_len_overlong", bodyMD, fBytesOverlongLen(app(noAction), 2, []byte(validBody().ActionId)), wirescan.ErrNonCanonical},
		{"action_id_tag_overlong", bodyMD, fOverlongTagBytes(app(noAction), 2, []byte(validBody().ActionId)), wirescan.ErrNonCanonical},
		{"digest_len_32_as_a0_00", bodyMD, app(noDigest, []byte{0x32, 0xa0, 0x00}, make([]byte, 32)), wirescan.ErrNonCanonical},
		{"pd_len_overlong", bodyMD, fBytesOverlongLen(app(noPD), 9, pd), wirescan.ErrNonCanonical},
		{"pd_tag_overlong", bodyMD, fOverlongTagBytes(app(noPD), 9, pd), wirescan.ErrNonCanonical},
		{"params_len_overlong", bodyMD, fBytesOverlongLen(app(noParams), 8, fBytes(nil, 11, restart)), wirescan.ErrNonCanonical},
		{"params_tag_overlong", bodyMD, fOverlongTagBytes(app(noParams), 8, fBytes(nil, 11, restart)), wirescan.ErrNonCanonical},

		// depth 1 (policy_decision, params)
		{"autonomy_3_overlong", bodyMD, withPD(fVarintOverlong(app(pdNoLevel), 2, 3)), wirescan.ErrNonCanonical},
		{"autonomy_tag_overlong", bodyMD, withPD(fOverlongTagVarint(app(pdNoLevel), 2, 3)), wirescan.ErrNonCanonical},
		{"decision_id_len_overlong", bodyMD, withPD(fBytesOverlongLen(app(pdNoDecision), 1, []byte(validBody().PolicyDecision.DecisionId))), wirescan.ErrNonCanonical},
		{"member_len_overlong", bodyMD, withParams(fBytesOverlongLen(nil, 11, restart)), wirescan.ErrNonCanonical},
		{"member_tag_overlong", bodyMD, withParams(fOverlongTagBytes(nil, 11, restart)), wirescan.ErrNonCanonical},
		{"empty_member_len_as_80_00", bodyMD, withParams([]byte{0x3a, 0x80, 0x00}), wirescan.ErrNonCanonical},
		// field 16 needs a two-byte tag (0x82 0x01); a three-byte one is overlong.
		{"two_byte_tag_minimal", bodyMD, withParams(fBytes(nil, 16, nil)), nil},
		{"two_byte_tag_overlong", bodyMD, withParams([]byte{0x82, 0x81, 0x00, 0x00}), wirescan.ErrNonCanonical},

		// depth 2 (inside the typed request)
		{"unit_len_overlong", bodyMD, withParams(fBytes(nil, 11, fBytesOverlongLen(nil, 1, []byte("nginx.service")))), wirescan.ErrNonCanonical},
		{"unit_tag_overlong", bodyMD, withParams(fBytes(nil, 11, fOverlongTagBytes(nil, 1, []byte("nginx.service")))), wirescan.ErrNonCanonical},
		{"dry_run_overlong", bodyMD, withParams(fBytes(nil, 17, fVarintOverlong(app(fileDelete), 5, 1))), wirescan.ErrNonCanonical},

		// out-of-range values
		{"format_version_2^32", bodyMD, fVarint(app(noFV), 1, 1<<32), wirescan.ErrNonCanonical},
		{"format_version_2^32+1_truncates_to_1", bodyMD, fVarint(app(noFV), 1, 1<<32+1), wirescan.ErrNonCanonical},
		{"format_version_maxuint64", bodyMD, fVarint(app(noFV), 1, math.MaxUint64), wirescan.ErrNonCanonical},
		{"autonomy_2^31", bodyMD, withLevel(1 << 31), wirescan.ErrNonCanonical},
		{"autonomy_2^32+3_truncates_to_L2", bodyMD, withLevel(1<<32 + 3), wirescan.ErrNonCanonical},
		{"autonomy_2^32+4_truncates_to_L3", bodyMD, withLevel(1<<32 + 4), wirescan.ErrNonCanonical},
		{"autonomy_minInt32-1", bodyMD, withLevel(i64(math.MinInt32 - 1)), wirescan.ErrNonCanonical},
		{"autonomy_ff_ff_ff_ff_0f", bodyMD, withPD(app(pdNoLevel, []byte{0x10, 0xff, 0xff, 0xff, 0xff, 0x0f})), wirescan.ErrNonCanonical},
		{"dry_run_2", bodyMD, withDryRun(2), wirescan.ErrNonCanonical},
		{"dry_run_255", bodyMD, withDryRun(255), wirescan.ErrNonCanonical},
		{"dry_run_2^32", bodyMD, withDryRun(1 << 32), wirescan.ErrNonCanonical},
		{"min_age_days_2^32+7", bodyMD, withParams(fBytes(nil, 17, fVarint(nil, 2, 1<<32+7))), wirescan.ErrNonCanonical},
		{"file_root_2^32+1", bodyMD, withParams(fBytes(nil, 17, fVarint(nil, 1, 1<<32+1))), wirescan.ErrNonCanonical},
		{"pid_2^32+1", bodyMD, withParams(fBytes(nil, 16, fVarint(nil, 1, 1<<32+1))), wirescan.ErrNonCanonical},
		{"keep_days_2^32+7", bodyMD, withParams(fBytes(nil, 18, fVarint(nil, 1, 1<<32+7))), wirescan.ErrNonCanonical},
		{"db_engine_2^32+1", bodyMD, withParams(fBytes(nil, 22, fVarint(nil, 1, 1<<32+1))), wirescan.ErrNonCanonical},
	})
}

func TestCanonicalOuterCases(t *testing.T) {
	kid, body, sig := make([]byte, 32), []byte{0x08, 0x01}, make([]byte, 64)
	runCanonCases(t, []scanCase{
		{"valid", outerMD, cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, sig)), nil},
		{"key_id_tag_overlong", outerMD, cat(fOverlongTagBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"body_tag_overlong", outerMD, cat(fBytes(nil, 1, kid), fOverlongTagBytes(nil, 2, body), fBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"signature_tag_overlong", outerMD, cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fOverlongTagBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"key_id_len_32_as_a0_00", outerMD, cat([]byte{0x0a, 0xa0, 0x00}, kid, fBytes(nil, 2, body), fBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"body_len_overlong", outerMD, cat(fBytes(nil, 1, kid), fBytesOverlongLen(nil, 2, body), fBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"body_len_10_bytes", outerMD, cat(fBytes(nil, 1, kid), []byte{0x12}, overlongN(uint64(len(body)), 10), body, fBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"signature_len_64_as_c0_00", outerMD, cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), []byte{0x1a, 0xc0, 0x00}, sig), wirescan.ErrNonCanonical},
		// R13 (j) in the outer SignedEnvelope (AC8): an explicit empty bytes
		// field, including one whose zero length is itself overlong.
		{"key_id_explicit_empty", outerMD, cat(fBytes(nil, 1, nil), fBytes(nil, 2, body), fBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"body_explicit_empty", outerMD, cat(fBytes(nil, 1, kid), fBytes(nil, 2, nil), fBytes(nil, 3, sig)), wirescan.ErrNonCanonical},
		{"signature_explicit_empty", outerMD, cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, nil)), wirescan.ErrNonCanonical},
		{"signature_explicit_empty_len_80_00", outerMD, cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), []byte{0x1a, 0x80, 0x00}), wirescan.ErrNonCanonical},
		{"key_id_left_out", outerMD, cat(fBytes(nil, 2, body), fBytes(nil, 3, sig)), nil},
	})
	// The outer scan treats body as opaque bytes: a non-canonical encoding
	// inside body is for the body scan (check 5), not the outer one.
	inner := []byte{0x08, 0x81, 0x00}
	assertSentinel(t, wirescan.CheckForTest(cat(fBytes(nil, 1, kid), fBytes(nil, 2, inner), fBytes(nil, 3, sig)), outerMD), nil)
}

// Repeated 64-bit fields: only minimality applies, inside and outside packed
// payloads.
func TestCanonicalPacked64(t *testing.T) {
	digest := make([]byte, 32)
	runCanonCases(t, []scanCase{
		{"ids_extremes", dbTermMD, fBytes(nil, 3, packedVarints(0, 1<<63, math.MaxUint64)), nil},
		{"starts_negative", dbTermMD, fBytes(nil, 4, packedVarints(math.MaxUint64, 1<<63, i64(math.MinInt32))), nil},
		{"full_message_negative_starts", dbTermMD, marshalDet(t, &wardenv1.DbTerminateSessionRequest{
			Engine: wardenv1.Engine(1), Instance: "mysql.service", SessionIds: []uint64{math.MaxUint64, 0},
			SessionStartedAt: []int64{-1, math.MinInt64, math.MaxInt64}, ServerStartedAt: -1,
			SessionOwnerDigests: [][]byte{digest}, MinIdleSeconds: math.MaxUint32,
		}), nil},
		{"ids_elem_overlong", dbTermMD, fBytes(nil, 3, cat(packedVarints(5), overlong(300), packedVarints(7))), wirescan.ErrNonCanonical},
		{"ids_elem_2^56_as_10_bytes", dbTermMD, fBytes(nil, 3, overlongN(1<<56, 10)), wirescan.ErrNonCanonical},
		{"starts_elem_overlong", dbTermMD, fBytes(nil, 4, cat(packedVarints(math.MaxUint64), overlong(1_700_000_000))), wirescan.ErrNonCanonical},
		{"ids_len_overlong", dbTermMD, fBytesOverlongLen(nil, 3, packedVarints(1, 2)), wirescan.ErrNonCanonical},
		// Since R13 (i) the first, minimal unpacked record is already
		// rejected; the overlong value and tag are covered packed below.
		{"ids_unpacked_value_overlong", dbTermMD, cat(fVarint(nil, 3, 1), fVarintOverlong(nil, 3, 2)), wirescan.ErrNonCanonical},
		{"ids_unpacked_tag_overlong", dbTermMD, cat(fVarint(nil, 3, 1), fOverlongTagVarint(nil, 3, 2)), wirescan.ErrNonCanonical},
		{"ids_packed_elem_2_overlong_alone", dbTermMD, fBytes(nil, 3, overlong(2)), wirescan.ErrNonCanonical},
		{"ids_packed_tag_overlong", dbTermMD, fOverlongTagBytes(nil, 3, packedVarints(1, 2)), wirescan.ErrNonCanonical},
		{"starts_packed_tag_overlong", dbTermMD, fOverlongTagBytes(nil, 4, packedVarints(math.MaxUint64)), wirescan.ErrNonCanonical},
		{"second_packed_run_overlong", dbTermMD, cat(fBytes(nil, 3, packedVarints(1)), fBytes(nil, 3, overlong(2))), wirescan.ErrNonCanonical},
		{"digests_second_len_overlong", dbTermMD, cat(fBytes(nil, 6, digest), fBytesOverlongLen(nil, 6, digest)), wirescan.ErrNonCanonical},
		{"server_started_overlong", dbTermMD, fVarintOverlong(nil, 5, 1_700_000_000), wirescan.ErrNonCanonical},
	})
}

// Well-known wrappers give real generated int32, uint32, bool and 64-bit
// fields (the contract has no int32).
func TestCanonicalWellKnownWrappers(t *testing.T) {
	i32 := (&wrapperspb.Int32Value{}).ProtoReflect().Descriptor()
	u32 := (&wrapperspb.UInt32Value{}).ProtoReflect().Descriptor()
	b := (&wrapperspb.BoolValue{}).ProtoReflect().Descriptor()
	i64d := (&wrapperspb.Int64Value{}).ProtoReflect().Descriptor()
	u64 := (&wrapperspb.UInt64Value{}).ProtoReflect().Descriptor()
	loc := (&descriptorpb.SourceCodeInfo_Location{}).ProtoReflect().Descriptor() // packed int32 path (proto2)
	cases := []scanCase{
		{"int32_minus1", i32, marshalDet(t, wrapperspb.Int32(-1)), nil},
		{"int32_min", i32, marshalDet(t, wrapperspb.Int32(math.MinInt32)), nil},
		{"int32_max", i32, marshalDet(t, wrapperspb.Int32(math.MaxInt32)), nil},
		{"uint32_max", u32, marshalDet(t, wrapperspb.UInt32(math.MaxUint32)), nil},
		{"bool_true", b, marshalDet(t, wrapperspb.Bool(true)), nil},
		{"int64_min", i64d, marshalDet(t, wrapperspb.Int64(math.MinInt64)), nil},
		{"uint64_max", u64, marshalDet(t, wrapperspb.UInt64(math.MaxUint64)), nil},
		{"location_path_extremes", loc, marshalDet(t, &descriptorpb.SourceCodeInfo_Location{Path: []int32{-1, 0, math.MinInt32, math.MaxInt32}}), nil},

		{"int32_2^31", i32, fVarint(nil, 1, 1<<31), wirescan.ErrNonCanonical},
		{"int32_five_byte_ff", i32, []byte{0x08, 0xff, 0xff, 0xff, 0xff, 0x0f}, wirescan.ErrNonCanonical},
		{"int32_2^32+4", i32, fVarint(nil, 1, 1<<32+4), wirescan.ErrNonCanonical},
		{"int32_minInt32-1", i32, fVarint(nil, 1, i64(math.MinInt32-1)), wirescan.ErrNonCanonical},
		{"int32_5_overlong", i32, []byte{0x08, 0x85, 0x00}, wirescan.ErrNonCanonical},
		{"uint32_2^32", u32, fVarint(nil, 1, 1<<32), wirescan.ErrNonCanonical},
		{"uint32_maxuint64", u32, fVarint(nil, 1, math.MaxUint64), wirescan.ErrNonCanonical},
		{"bool_2", b, fVarint(nil, 1, 2), wirescan.ErrNonCanonical},
		{"bool_255", b, fVarint(nil, 1, 255), wirescan.ErrNonCanonical},
		{"bool_2^32", b, fVarint(nil, 1, 1<<32), wirescan.ErrNonCanonical},
		{"bool_1_overlong", b, fVarintOverlong(nil, 1, 1), wirescan.ErrNonCanonical},
		{"int64_1_overlong", i64d, fVarintOverlong(nil, 1, 1), wirescan.ErrNonCanonical},
		{"uint64_2^56_10_bytes", u64, cat([]byte{0x08}, overlongN(1<<56, 10)), wirescan.ErrNonCanonical},
		{"location_path_elem_2^32+4", loc, fBytes(nil, 1, packedVarints(1, 1<<32+4)), wirescan.ErrNonCanonical},
		{"location_path_elem_overlong", loc, fBytes(nil, 1, cat(packedVarints(1), overlong(2))), wirescan.ErrNonCanonical},
		// R13 (i) applies to any schema, not only the warden contract.
		{"location_path_unpacked", loc, fVarint(nil, 1, 1), wirescan.ErrNonCanonical},
		{"location_span_unpacked", loc, cat(fBytes(nil, 2, packedVarints(1, 2)), fVarint(nil, 2, 3)), wirescan.ErrNonCanonical},
	}
	runCanonCases(t, cases)
}

// Range and minimality are enforced at every depth of a nested message.
func TestCanonicalNestedKinds(t *testing.T) {
	nest := func(levels int, leaf []byte) []byte {
		for i := 0; i < levels; i++ {
			leaf = fBytes(nil, 12, leaf)
		}
		return leaf
	}
	inList := func(leaf []byte) []byte {
		return cat(fBytes(nil, 22, fVarint(nil, 1, 1)), fBytes(nil, 22, leaf))
	}
	var cases []scanCase
	for _, depth := range []int{0, 1, 2, 5, 15} {
		d := fmt.Sprintf("%02d", depth)
		cases = append(cases,
			scanCase{"depth" + d + "_valid_extremes", kindsMD, nest(depth, cat(
				fVarint(nil, 1, i64(math.MinInt32)), fVarint(nil, 2, math.MaxUint32), fVarint(nil, 3, math.MaxUint32),
				fVarint(nil, 4, 1), fVarint(nil, 5, math.MaxUint64), fBytes(nil, 16, packedVarints(0)))), nil},
			scanCase{"depth" + d + "_unpacked_bool", kindsMD, nest(depth, fVarint(nil, 16, 0)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_unpacked_enum", kindsMD, nest(depth, fVarint(nil, 17, 1)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_unpacked_fixed32", kindsMD, nest(depth, fFixed32(nil, 21, 1)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_unpacked_in_repeated_child", kindsMD, nest(depth, inList(fVarint(nil, 20, 1))), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_int32_2^31", kindsMD, nest(depth, fVarint(nil, 1, 1<<31)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_sint32_2^32", kindsMD, nest(depth, fVarint(nil, 2, 1<<32)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_bool_2", kindsMD, nest(depth, fVarint(nil, 4, 2)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_enum_2^32+1", kindsMD, nest(depth, fVarint(nil, 5, 1<<32+1)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_packed_bool_2", kindsMD, nest(depth, fBytes(nil, 16, packedVarints(0, 1, 2))), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_tag_overlong", kindsMD, nest(depth, fOverlongTagVarint(nil, 6, 1)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_child_len_overlong", kindsMD, nest(depth, fBytesOverlongLen(nil, 12, nil)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_in_repeated_child", kindsMD, nest(depth, inList(fVarint(nil, 3, 1<<32))), wirescan.ErrNonCanonical},
			// R13 (g): sint32 ZigZag varint 2^32-1 is the largest accepted.
			scanCase{"depth" + d + "_sint32_2^32-1", kindsMD, nest(depth, fVarint(nil, 2, math.MaxUint32)), nil},
			// R13 (j): explicit defaults at this depth (AC8 "at any depth").
			scanCase{"depth" + d + "_uint32_explicit_0", kindsMD, nest(depth, fVarint(nil, 3, 0)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_int64_explicit_0", kindsMD, nest(depth, fVarint(nil, 6, 0)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_enum_explicit_0", kindsMD, nest(depth, fVarint(nil, 5, 0)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_bool_explicit_false", kindsMD, nest(depth, fVarint(nil, 4, 0)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_string_explicit_empty", kindsMD, nest(depth, fBytes(nil, 11, nil)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_fixed32_explicit_0", kindsMD, nest(depth, fFixed32(nil, 9, 0)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_explicit_0_in_repeated_child", kindsMD, nest(depth, inList(fVarint(nil, 3, 0))), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_left_out", kindsMD, nest(depth, nil), nil},
			// R13 (i): split and empty packed records at this depth.
			scanCase{"depth" + d + "_packed_split", kindsMD, nest(depth, cat(fBytes(nil, 15, packedVarints(1)), fBytes(nil, 15, packedVarints(2, 3)))), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_packed_empty", kindsMD, nest(depth, fBytes(nil, 17, nil)), wirescan.ErrNonCanonical},
			scanCase{"depth" + d + "_packed_element_0", kindsMD, nest(depth, fBytes(nil, 15, packedVarints(0))), nil},
		)
	}
	runCanonCases(t, cases)
}

// A deterministic marshal of extreme in-range values of every kind passes.
func TestCanonicalValidExtremesKinds(t *testing.T) {
	m := dynamicpb.NewMessage(kindsMD)
	set := func(name string, v protoreflect.Value) { m.Set(kindsMD.Fields().ByName(protoreflect.Name(name)), v) }
	set("i32", protoreflect.ValueOfInt32(math.MinInt32))
	set("s32", protoreflect.ValueOfInt32(math.MinInt32))
	set("u32", protoreflect.ValueOfUint32(math.MaxUint32))
	set("b", protoreflect.ValueOfBool(true))
	set("e", protoreflect.ValueOfEnum(math.MinInt32))
	set("i64", protoreflect.ValueOfInt64(math.MinInt64))
	set("s64", protoreflect.ValueOfInt64(math.MinInt64))
	set("u64", protoreflect.ValueOfUint64(math.MaxUint64))
	set("f32", protoreflect.ValueOfUint32(math.MaxUint32))
	set("sf64", protoreflect.ValueOfInt64(math.MinInt64))
	set("str", protoreflect.ValueOfString("x"))
	lists := map[string][]protoreflect.Value{
		"ri32": {protoreflect.ValueOfInt32(-1), protoreflect.ValueOfInt32(math.MaxInt32), protoreflect.ValueOfInt32(math.MinInt32)},
		"rs32": {protoreflect.ValueOfInt32(-1), protoreflect.ValueOfInt32(math.MaxInt32), protoreflect.ValueOfInt32(math.MinInt32)},
		"ru32": {protoreflect.ValueOfUint32(0), protoreflect.ValueOfUint32(math.MaxUint32)},
		"rb":   {protoreflect.ValueOfBool(true), protoreflect.ValueOfBool(false)},
		"re":   {protoreflect.ValueOfEnum(-1), protoreflect.ValueOfEnum(math.MaxInt32)},
		"ri64": {protoreflect.ValueOfInt64(math.MinInt64), protoreflect.ValueOfInt64(-1)},
		"rs64": {protoreflect.ValueOfInt64(math.MinInt64), protoreflect.ValueOfInt64(math.MaxInt64)},
		"ru64": {protoreflect.ValueOfUint64(math.MaxUint64)},
		"rf32": {protoreflect.ValueOfUint32(math.MaxUint32)},
	}
	for name, vals := range lists {
		l := m.Mutable(kindsMD.Fields().ByName(protoreflect.Name(name))).List()
		for _, v := range vals {
			l.Append(v)
		}
	}
	child := proto.Clone(m).(*dynamicpb.Message)
	m.Set(kindsMD.Fields().ByName("child"), protoreflect.ValueOfMessage(child))
	m.Mutable(kindsMD.Fields().ByName("children")).List().Append(protoreflect.ValueOfMessage(proto.Clone(child).(*dynamicpb.Message)))

	b := marshalDet(t, m)
	assertSentinel(t, wirescan.CheckForTest(b, kindsMD), nil)
	out := dynamicpb.NewMessage(kindsMD)
	assertSentinel(t, wirescan.Unmarshal(b, out), nil)
	if !proto.Equal(out, m) {
		t.Fatalf("round trip differs")
	}
	// A non-deterministic marshal may order fields differently; R13 (k)
	// accepts it only when it is byte for byte the deterministic encoding.
	nb, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nb, b) {
		assertSentinel(t, wirescan.CheckForTest(nb, kindsMD), nil)
	} else {
		assertSentinel(t, wirescan.CheckForTest(nb, kindsMD), wirescan.ErrNonCanonical)
	}
}

// Check order inside one field: tag minimality, group, known field,
// duplicate, wire type, value (minimality, range). Each case breaks exactly
// two rules; the earlier one decides the sentinel.
func TestCanonicalCheckOrder(t *testing.T) {
	base := marshalDet(t, validBody())
	without := func(m func(b *wardenv1.EnvelopeBody)) []byte { b := validBody(); m(b); return marshalDet(t, b) }
	noFV := without(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })
	noCreated := without(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 })
	app := func(b []byte, more ...[]byte) []byte {
		return cat(append([][]byte{append([]byte(nil), b...)}, more...)...)
	}
	runCanonCases(t, []scanCase{
		// tag minimality first
		{"tag_overlong+unknown", bodyMD, app(base, overlong(rawTag(99, protowire.VarintType)), []byte{0x01}), wirescan.ErrNonCanonical},
		{"tag_overlong+start_group", bodyMD, app(base, overlong(rawTag(99, protowire.StartGroupType)), protowire.AppendTag(nil, 99, protowire.EndGroupType)), wirescan.ErrNonCanonical},
		{"tag_overlong+end_group", bodyMD, app(base, overlong(rawTag(7, protowire.EndGroupType))), wirescan.ErrNonCanonical},
		{"tag_overlong+duplicate", bodyMD, app(base, overlong(rawTag(1, protowire.VarintType)), []byte{0x01}), wirescan.ErrNonCanonical},
		{"tag_overlong+wire_type", bodyMD, app(noFV, overlong(rawTag(1, protowire.BytesType)), []byte{0x01, 0x01}), wirescan.ErrNonCanonical},
		{"tag_overlong+value_out_of_range", bodyMD, app(noFV, overlong(rawTag(1, protowire.VarintType)), protowire.AppendVarint(nil, 1<<32+1)), wirescan.ErrNonCanonical},

		// group before value
		{"group+overlong_content", bodyMD, fGroup(app(base), 99, []byte{0x08, 0x81, 0x00}), wirescan.ErrGroup},
		// known field before value
		{"unknown+value_overlong", bodyMD, fVarintOverlong(app(base), 99, 1), wirescan.ErrUnknownField},
		{"unknown+len_overlong", bodyMD, fBytesOverlongLen(app(base), 99, []byte("x")), wirescan.ErrUnknownField},
		{"unknown_in_pd+value_overlong", bodyMD, fBytes(without(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil }), 9, fVarintOverlong(nil, 50, 1)), wirescan.ErrUnknownField},
		// duplicate before value
		{"duplicate+value_overlong", bodyMD, fVarintOverlong(app(base), 1, 1), wirescan.ErrDuplicateField},
		{"duplicate+value_out_of_range", bodyMD, fVarint(app(base), 1, 1<<32+1), wirescan.ErrDuplicateField},
		{"duplicate+len_overlong", bodyMD, fBytesOverlongLen(app(base), 2, []byte("x")), wirescan.ErrDuplicateField},
		// wire type before value
		{"wire_type+len_overlong", bodyMD, fBytesOverlongLen(app(noCreated), 10, []byte{1}), wirescan.ErrWireType},
		{"wire_type_varint_for_string+value_overlong", bodyMD, fVarintOverlong(without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2, 1), wirescan.ErrWireType},
		{"non_repeated_packed+len_overlong", dbTermMD, fBytesOverlongLen(nil, 1, packedVarints(1)), wirescan.ErrWireType},

		// R13 (j) runs on the value, after the field-level checks above.
		{"explicit_default+value_overlong_80_00", bodyMD, app(noFV, []byte{0x08, 0x80, 0x00}), wirescan.ErrNonCanonical},
		{"explicit_default+len_overlong_80_00", bodyMD, app(without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), []byte{0x12, 0x80, 0x00}), wirescan.ErrNonCanonical},
		{"explicit_default+tag_overlong", bodyMD, app(noFV, overlong(rawTag(1, protowire.VarintType)), []byte{0x00}), wirescan.ErrNonCanonical},
		{"unknown+explicit_default", bodyMD, fVarint(app(base), 99, 0), wirescan.ErrUnknownField},
		{"duplicate+explicit_default", bodyMD, fVarint(app(base), 1, 0), wirescan.ErrDuplicateField},
		{"duplicate_string+explicit_empty", bodyMD, fBytes(app(base), 2, nil), wirescan.ErrDuplicateField},
		{"wire_type+empty_payload", bodyMD, fBytes(app(noCreated), 10, nil), wirescan.ErrWireType},
		{"wire_type_varint_0_for_string", bodyMD, fVarint(without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2, 0), wirescan.ErrWireType},

		// Not decodable at all stays ErrMalformed.
		{"overlong_then_truncated", bodyMD, app(noFV, []byte{0x08, 0x81, 0x80}), wirescan.ErrMalformed},
		{"overlong_11_bytes", bodyMD, app(noFV, []byte{0x08, 0x81}, bytes.Repeat([]byte{0x80}, 9), []byte{0x00}), wirescan.ErrMalformed},
		{"ten_bytes_last_byte_2_overflows", bodyMD, app(noCreated, []byte{0x50}, bytes.Repeat([]byte{0xff}, 9), []byte{0x02}), wirescan.ErrMalformed},
		{"tag_overlong_truncated", bodyMD, app(base, []byte{0x88, 0x80}), wirescan.ErrMalformed},
	})
}
