package wirescan

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	if err := Check(b, wrapperspb.Float(0).ProtoReflect().Descriptor()); err == nil {
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
