package wirescan

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// Warden's contract uses only varint and length-delimited kinds. The
// scanner is generic, so these tests pin its behaviour for the other kinds
// with well-known types.
func TestScalarWireTypeAllKinds(t *testing.T) {
	cases := map[protoreflect.Kind]protowire.Type{
		protoreflect.BoolKind:     protowire.VarintType,
		protoreflect.Sint64Kind:   protowire.VarintType,
		protoreflect.Fixed32Kind:  protowire.Fixed32Type,
		protoreflect.FloatKind:    protowire.Fixed32Type,
		protoreflect.Sfixed64Kind: protowire.Fixed64Type,
		protoreflect.DoubleKind:   protowire.Fixed64Type,
		protoreflect.StringKind:   protowire.BytesType,
		protoreflect.MessageKind:  protowire.BytesType,
		protoreflect.GroupKind:    protowire.StartGroupType,
	}
	for k, want := range cases {
		if got := scalarWireType(k); got != want {
			t.Errorf("scalarWireType(%v) = %v, want %v", k, got, want)
		}
	}
}

func TestFixedWidthKinds(t *testing.T) {
	ok := []proto.Message{wrapperspb.Float(1.5), wrapperspb.Double(2.5)}
	for _, m := range ok {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := Unmarshal(b, m.ProtoReflect().New().Interface()); err != nil {
			t.Errorf("%T: %v", m, err)
		}
	}
	// FloatValue.value as varint: wrong wire type.
	b := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1)
	if err := check(b, wrapperspb.Float(0).ProtoReflect().Descriptor(), 0); err == nil {
		t.Error("float encoded as varint accepted")
	}
}

func TestMapsAndRepeatedMessages(t *testing.T) {
	v, err := structpb.NewStruct(map[string]any{"a": []any{1.0, "x", map[string]any{"b": true}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := Unmarshal(b, new(structpb.Struct)); err != nil {
		t.Fatalf("valid Struct rejected: %v", err)
	}
}

func TestHasUnknownNested(t *testing.T) {
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1)

	inList := structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewBoolValue(true)}})
	inList.GetListValue().GetValues()[0].ProtoReflect().SetUnknown(unknown)

	inMap, err := structpb.NewStruct(map[string]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	inMap.GetFields()["k"].ProtoReflect().SetUnknown(unknown)

	single := structpb.NewStructValue(&structpb.Struct{})
	single.GetStructValue().ProtoReflect().SetUnknown(unknown)

	for name, m := range map[string]proto.Message{"list": inList, "map": inMap, "single": single} {
		if !hasUnknown(m.ProtoReflect()) {
			t.Errorf("%s: nested unknown field not found", name)
		}
	}
	clean, err := structpb.NewValue(map[string]any{"k": []any{"v"}})
	if err != nil {
		t.Fatal(err)
	}
	if hasUnknown(clean.ProtoReflect()) {
		t.Error("clean message reported unknown fields")
	}
}

// R13 (l) is checked by checkVarintEnd itself, not left to protowire, so
// these cases pin it without going through protowire.ConsumeVarint.
func TestCheckVarintEnd(t *testing.T) {
	nine := bytes.Repeat([]byte{0xff}, 9)
	ten := func(last byte) []byte { return append(append([]byte(nil), nine...), last) }
	cases := []struct {
		name string
		b    []byte
		bad  bool
	}{
		{"empty", nil, false},
		{"one_byte", []byte{0x01}, false},
		{"truncated", []byte{0x80}, false}, // left to protowire
		{"nine_bytes", append(append([]byte(nil), nine[:8]...), 0x7f), false},
		{"ten_last_00", ten(0x00), false}, // non-minimal: R13 (e)
		{"ten_last_01", ten(0x01), false},
		{"ten_last_01_then_more", append(ten(0x01), 0xff), false},
		{"ten_last_02", ten(0x02), true},
		{"ten_last_7f", ten(0x7f), true},
		{"eleven_bytes", append(ten(0x80), 0x01), true},
		{"ten_continuation_bytes_only", ten(0x80), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkVarintEnd(c.b)
			if c.bad != (err != nil) {
				t.Fatalf("checkVarintEnd(%x) = %v, want error %v", c.b, err, c.bad)
			}
			if err != nil && !errors.Is(err, ErrMalformed) {
				t.Fatalf("error %v does not wrap ErrMalformed", err)
			}
		})
	}
}

// Every split packed record also breaks R13 (k), so this pins the (i)
// check in markSeen on its own: it stays as defence in depth.
func TestMarkSeenSplitPackedRecord(t *testing.T) {
	fd := (&wardenv1.DbTerminateSessionRequest{}).ProtoReflect().Descriptor().Fields().ByName("session_ids")
	seen, seenOneof := map[protowire.Number]bool{}, map[int]bool{}
	if err := markSeen(fd, protowire.BytesType, seen, seenOneof); err != nil {
		t.Fatalf("first packed record: %v", err)
	}
	err := markSeen(fd, protowire.BytesType, seen, seenOneof)
	if !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("second packed record: got %v, want ErrNonCanonical", err)
	}
}
