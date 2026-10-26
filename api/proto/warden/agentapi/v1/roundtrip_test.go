package agentapiv1_test

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// scalarValue is a non-zero value of fd's kind; k varies it between list
// elements, and k = 2 gives signed kinds a negative value so the scanner's
// sign-extension rules are exercised.
func scalarValue(fd protoreflect.FieldDescriptor, k uint8) protoreflect.Value {
	sign := int32(1)
	if k == 2 {
		sign = -1
	}
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		vals := fd.Enum().Values()
		return protoreflect.ValueOfEnum(vals.Get(1 + (int(k)-1)%(vals.Len()-1)).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(sign * 3 * int32(k))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(sign) * 1_700_000_000_000 * int64(k))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(7 * k))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(k) << 40)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(k) + 0.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(float64(sign)*float64(k) + 0.25)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(fmt.Sprintf("value-%d-é", k))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte{byte(k), 0x00, 0xff})
	}
	panic(fmt.Sprintf("%s: kind %v not handled", fd.FullName(), fd.Kind()))
}

// populate sets every field of m to a non-zero value, two elements in each
// list, recursing into messages. In each oneof it sets member
// variant mod n, so variants 0 … 21 together set every member of every
// oneof (TypedResult, the largest, has 21).
func populate(m protoreflect.Message, variant, depth int) {
	if depth > 8 {
		panic("contract nests deeper than 8 levels: " + string(m.Descriptor().FullName()))
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() {
			if od.Fields().Get(variant%od.Fields().Len()) != fd {
				continue
			}
		}
		switch {
		case fd.IsList():
			l := m.Mutable(fd).List()
			for k := uint8(1); k <= 2; k++ {
				if fd.Message() != nil {
					e := l.NewElement()
					populate(e.Message(), variant+int(k), depth+1)
					l.Append(e)
				} else {
					l.Append(scalarValue(fd, k))
				}
			}
		case fd.Message() != nil:
			populate(m.Mutable(fd).Message(), variant, depth+1)
		default:
			m.Set(fd, scalarValue(fd, 1))
		}
	}
}

// TestFullyPopulatedRoundTrip: a fully populated instance of every message
// of both packages, with every oneof member in turn, marshals
// deterministically, passes the strict scanner (R12 for agentapi,
// R13 for warden.v1) and decodes to an equal message.
func TestFullyPopulatedRoundTrip(t *testing.T) {
	files := append(packageFiles(t, agentapiPkg), packageFiles(t, wardenPkg)...)
	for _, md := range allMessages(files) {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
		if err != nil {
			t.Errorf("%s: %v", md.FullName(), err)
			continue
		}
		for variant := 0; variant < 22; variant++ {
			m := mt.New()
			populate(m, variant, 0)
			b, err := deterministic.Marshal(m.Interface())
			if err != nil {
				t.Fatalf("%s/%d: %v", md.FullName(), variant, err)
			}
			again, err := deterministic.Marshal(m.Interface())
			if err != nil || string(again) != string(b) {
				t.Errorf("%s/%d: marshalling is not deterministic", md.FullName(), variant)
			}
			got := mt.New().Interface()
			if err := wirescan.Unmarshal(b, got); err != nil {
				t.Errorf("%s/%d: strict scan: %v", md.FullName(), variant, err)
				continue
			}
			if !proto.Equal(got, m.Interface()) {
				t.Errorf("%s/%d: round trip changed the message", md.FullName(), variant)
			}
		}
	}
}

// TestPopulateCoversEveryOneofMember guards the round-trip test: over the
// 22 variants, every member of every oneof is set at least once.
func TestPopulateCoversEveryOneofMember(t *testing.T) {
	files := append(packageFiles(t, agentapiPkg), packageFiles(t, wardenPkg)...)
	for _, md := range allMessages(files) {
		for i := 0; i < md.Oneofs().Len(); i++ {
			od := md.Oneofs().Get(i)
			if od.IsSynthetic() {
				continue
			}
			if od.Fields().Len() > 22 {
				t.Errorf("%s: %d members, more than the 22 variants", od.FullName(), od.Fields().Len())
			}
		}
	}
}

// TestEndDetailFitsAny (R45): an EndDetail with the largest EndReason,
// packed as a google.protobuf.Any, is at most 128 bytes, with type URL
// exactly type.googleapis.com/warden.agentapi.v1.EndDetail; so is every
// other reason. The detail itself passes the strict scanner.
func TestEndDetailFitsAny(t *testing.T) {
	ed := agentapiv1.EndReason(0).Descriptor()
	largest := ed.Values().Get(0).Number()
	for i := 0; i < ed.Values().Len(); i++ {
		largest = max(largest, ed.Values().Get(i).Number())
	}
	if largest != 18 {
		t.Errorf("largest EndReason is %d, want 18 (DUPLICATE_IDENTITY)", largest)
	}
	if agentapiv1.EndReason_END_REASON_DUPLICATE_IDENTITY != agentapiv1.EndReason(largest) {
		t.Error("END_REASON_DUPLICATE_IDENTITY is not the largest value")
	}
	for n := protoreflect.EnumNumber(1); n <= largest; n++ {
		detail := &agentapiv1.EndDetail{Reason: agentapiv1.EndReason(n)}
		a, err := anypb.New(detail)
		if err != nil {
			t.Fatal(err)
		}
		if a.GetTypeUrl() != "type.googleapis.com/warden.agentapi.v1.EndDetail" {
			t.Errorf("type URL %q", a.GetTypeUrl())
		}
		if size := proto.Size(a); size > 128 {
			t.Errorf("reason %d: Any is %d bytes, over 128", n, size)
		}
		got := &agentapiv1.EndDetail{}
		if err := wirescan.Unmarshal(a.GetValue(), got); err != nil || got.GetReason() != detail.GetReason() {
			t.Errorf("reason %d: strict decode: %v, %v", n, err, got.GetReason())
		}
	}
}
