package wirescan_test

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

var sentinels = map[string]error{
	"ErrMalformed":      wirescan.ErrMalformed,
	"ErrUnknownField":   wirescan.ErrUnknownField,
	"ErrDuplicateField": wirescan.ErrDuplicateField,
	"ErrGroup":          wirescan.ErrGroup,
	"ErrWireType":       wirescan.ErrWireType,
	"ErrTooDeep":        wirescan.ErrTooDeep,
	"ErrNonCanonical":   wirescan.ErrNonCanonical,
}

// assertSentinel checks err wraps want and no other sentinel.
func assertSentinel(t testing.TB, err, want error) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("no error; want %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error %v does not wrap %v", err, want)
	}
	for name, s := range sentinels {
		if !errors.Is(s, want) && errors.Is(err, s) {
			t.Fatalf("error %v also wraps %s; want exactly one sentinel", err, name)
		}
	}
}

// countSentinels returns how many sentinels err wraps.
func countSentinels(err error) int {
	n := 0
	for _, s := range sentinels {
		if errors.Is(err, s) {
			n++
		}
	}
	return n
}

var (
	bodyMD   = (&wardenv1.EnvelopeBody{}).ProtoReflect().Descriptor()
	outerMD  = (&wardenv1.SignedEnvelope{}).ProtoReflect().Descriptor()
	paramsMD = (&wardenv1.TypedRequest{}).ProtoReflect().Descriptor()
	dbTermMD = (&wardenv1.DbTerminateSessionRequest{}).ProtoReflect().Descriptor()
)

func marshalDet(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func fVarint(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func fBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func fFixed32(b []byte, num protowire.Number, v uint32) []byte {
	b = protowire.AppendTag(b, num, protowire.Fixed32Type)
	return protowire.AppendFixed32(b, v)
}

func fFixed64(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.Fixed64Type)
	return protowire.AppendFixed64(b, v)
}

func fGroup(b []byte, num protowire.Number, inner []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.StartGroupType)
	b = append(b, inner...)
	return protowire.AppendTag(b, num, protowire.EndGroupType)
}

func packedVarints(vals ...uint64) []byte {
	var b []byte
	for _, v := range vals {
		b = protowire.AppendVarint(b, v)
	}
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// populate sets every field of m to a non-default value. For a oneof only the
// first member is set.
func populate(m protoreflect.Message) {
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if od := fd.ContainingOneof(); od != nil && m.WhichOneof(od) != nil {
			continue
		}
		if fd.IsList() {
			l := m.Mutable(fd).List()
			for j := uint8(0); j < 2; j++ {
				if fd.Kind() == protoreflect.MessageKind {
					e := l.NewElement()
					populate(e.Message())
					l.Append(e)
				} else {
					l.Append(scalar(fd, j))
				}
			}
			continue
		}
		if fd.Kind() == protoreflect.MessageKind {
			populate(m.Mutable(fd).Message())
			continue
		}
		m.Set(fd, scalar(fd, 0))
	}
}

func scalar(fd protoreflect.FieldDescriptor, j uint8) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		return protoreflect.ValueOfEnum(protoreflect.EnumNumber(1 + int32(j)))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(-7 - int32(j))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(-1) << 40 >> j)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(4_000_000_000 + uint32(j))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(1)<<62 + uint64(j))
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(1.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(2.5)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("svc-" + string(rune('a')+rune(j)) + ".service")
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(make([]byte, 32))
	}
	panic("unhandled kind " + fd.Kind().String())
}

// Non-canonical encodings (R13 canonical-encoding rule) --------------------

// overlongN returns a non-minimal varint encoding of v that is exactly total
// bytes long: the minimal encoding with continuation bits set, padded with
// 0x80 bytes and closed by 0x00. It decodes to v with protowire.ConsumeVarint.
func overlongN(v uint64, total int) []byte {
	b := protowire.AppendVarint(nil, v)
	if total <= len(b) || total > 10 {
		panic("overlongN: impossible length")
	}
	b[len(b)-1] |= 0x80
	for len(b) < total-1 {
		b = append(b, 0x80)
	}
	return append(b, 0x00)
}

// overlong is v encoded one byte longer than necessary.
func overlong(v uint64) []byte { return overlongN(v, protowire.SizeVarint(v)+1) }

// rawTag is the varint value of a field tag.
func rawTag(num protowire.Number, typ protowire.Type) uint64 {
	return protowire.EncodeTag(num, typ)
}

// fVarintOverlong is a varint field whose value is not minimally encoded.
func fVarintOverlong(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return append(b, overlong(v)...)
}

// fBytesOverlongLen is a length-delimited field whose length prefix is not
// minimally encoded.
func fBytesOverlongLen(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	b = append(b, overlong(uint64(len(v)))...)
	return append(b, v...)
}

// fOverlongTagVarint is a varint field whose tag is not minimally encoded.
func fOverlongTagVarint(b []byte, num protowire.Number, v uint64) []byte {
	b = append(b, overlong(rawTag(num, protowire.VarintType))...)
	return protowire.AppendVarint(b, v)
}

// fOverlongTagBytes is a length-delimited field whose tag is not minimally
// encoded.
func fOverlongTagBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = append(b, overlong(rawTag(num, protowire.BytesType))...)
	return protowire.AppendBytes(b, v)
}

// i64 is the two's-complement wire value of a signed integer.
// i64 is the two's complement uint64 that a varint carries for v.
func i64(v int64) uint64 {
	if v >= 0 {
		return uint64(v)
	}
	// For v < 0, m = -(v+1) is in 0 … MaxInt64 (no overflow, even for
	// MinInt64), and ^m = 2^64 - 1 - m = 2^64 + v.
	if m := -(v + 1); m >= 0 {
		return ^uint64(m)
	}
	panic("unreachable")
}
