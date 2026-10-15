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
		if s != want && errors.Is(err, s) {
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
	pdMD     = (&wardenv1.PolicyDecision{}).ProtoReflect().Descriptor()
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
			for j := 0; j < 2; j++ {
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

func scalar(fd protoreflect.FieldDescriptor, j int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		return protoreflect.ValueOfEnum(protoreflect.EnumNumber(1 + j))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(-7 - j))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(-1) << 40 >> j)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(4_000_000_000 + j))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(1)<<62 + uint64(j))
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(1.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(2.5)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("svc-" + string(rune('a'+j)) + ".service")
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(make([]byte, 32))
	}
	panic("unhandled kind " + fd.Kind().String())
}
