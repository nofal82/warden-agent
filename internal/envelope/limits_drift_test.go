package envelope

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// The verifier hard-codes the limits that envelope.proto also states as
// options, so that the hot path never reads descriptors. These tests fail
// when the two copies drift, or when an option is dropped from the
// contract.

func fieldOpts(t *testing.T, m protoreflect.MessageDescriptor, name protoreflect.Name) *descriptorpb.FieldOptions {
	t.Helper()
	fd := m.Fields().ByName(name)
	if fd == nil {
		t.Fatalf("%s has no field %q", m.FullName(), name)
	}
	o, ok := fd.Options().(*descriptorpb.FieldOptions)
	if !ok || o == nil {
		t.Fatalf("%s.%s has no field options", m.FullName(), name)
	}
	return o
}

func extUint64(t *testing.T, o proto.Message, xt protoreflect.ExtensionType, where string) uint64 {
	t.Helper()
	opt := string(xt.TypeDescriptor().FullName())
	if !proto.HasExtension(o, xt) {
		t.Fatalf("%s: option (%s) is not set", where, opt)
	}
	switch v := proto.GetExtension(o, xt).(type) {
	case uint64:
		return v
	case uint32:
		return uint64(v)
	default:
		t.Fatalf("%s: option (%s) has unexpected type %T", where, opt, v)
		return 0
	}
}

func extInt64(t *testing.T, o proto.Message, xt protoreflect.ExtensionType, where string) int64 {
	t.Helper()
	opt := string(xt.TypeDescriptor().FullName())
	if !proto.HasExtension(o, xt) {
		t.Fatalf("%s: option (%s) is not set", where, opt)
	}
	v, ok := proto.GetExtension(o, xt).(int64)
	if !ok {
		t.Fatalf("%s: option (%s) is not int64", where, opt)
	}
	return v
}

func TestLimitsDriftEnvelopeCounter(t *testing.T) {
	body := (&wardenv1.EnvelopeBody{}).ProtoReflect().Descriptor()
	fd := body.Fields().ByName("envelope_counter")
	if fd == nil || fd.Number() != 13 {
		t.Fatalf("EnvelopeBody.envelope_counter is missing or not field 13")
	}
	o := fieldOpts(t, body, "envelope_counter")
	where := "EnvelopeBody.envelope_counter"
	if got := extUint64(t, o, wardenv1.E_MinUint, where); got != minEnvelopeCounter {
		t.Errorf("minEnvelopeCounter = %d, but %s (min_uint) = %d", uint64(minEnvelopeCounter), where, got)
	}
	if got := extUint64(t, o, wardenv1.E_MaxUint, where); got != maxEnvelopeCounter {
		t.Errorf("maxEnvelopeCounter = %d, but %s (max_uint) = %d", uint64(maxEnvelopeCounter), where, got)
	}
}

func TestLimitsDriftEnvelopeBytes(t *testing.T) {
	const want = 16384 // action-envelope R11
	if MaxEnvelopeBytes != want {
		t.Errorf("MaxEnvelopeBytes = %d, want %d (R11)", MaxEnvelopeBytes, want)
	}
	se := (&wardenv1.SignedEnvelope{}).ProtoReflect().Descriptor()
	mo, ok := se.Options().(*descriptorpb.MessageOptions)
	if !ok || mo == nil {
		t.Fatal("SignedEnvelope has no message options")
	}
	msgMax := extUint64(t, mo, wardenv1.E_MaxMessageBytes, "SignedEnvelope")
	if msgMax != MaxEnvelopeBytes {
		t.Errorf("MaxEnvelopeBytes = %d, but SignedEnvelope (max_message_bytes) = %d", MaxEnvelopeBytes, msgMax)
	}
	bodyMax := extUint64(t, fieldOpts(t, se, "body"), wardenv1.E_MaxBytes, "SignedEnvelope.body")
	if bodyMax != MaxEnvelopeBytes {
		t.Errorf("MaxEnvelopeBytes = %d, but SignedEnvelope.body (max_bytes) = %d", MaxEnvelopeBytes, bodyMax)
	}
}

func TestLimitsDriftUnixTime(t *testing.T) {
	body := (&wardenv1.EnvelopeBody{}).ProtoReflect().Descriptor()
	for _, name := range []protoreflect.Name{"created_at", "expires_at"} {
		where := "EnvelopeBody." + string(name)
		o := fieldOpts(t, body, name)
		if got := extInt64(t, o, wardenv1.E_MinInt, where); got != minUnixTime {
			t.Errorf("minUnixTime = %d, but %s (min_int) = %d", int64(minUnixTime), where, got)
		}
		if got := extInt64(t, o, wardenv1.E_MaxInt, where); got != maxUnixTime {
			t.Errorf("maxUnixTime = %d, but %s (max_int) = %d", int64(maxUnixTime), where, got)
		}
	}
}
