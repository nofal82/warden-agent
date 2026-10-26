package agentapiv1_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// fuzzRoots are the messages decoded from untrusted bytes: everything the
// control plane receives from an agent (agent-api R12), everything the
// agent receives from the control plane (§4.5), the EndDetail reader
// (R45), and the executor bodies and typed result the agent decodes
// (executor-ipc §4.6, §4.7; typed-action-catalog §4.8).
var fuzzRoots = []protoreflect.FullName{
	"warden.agentapi.v1.EnrollRequest",
	"warden.agentapi.v1.EnrollResponse",
	"warden.agentapi.v1.RenewRequest",
	"warden.agentapi.v1.RenewResponse",
	"warden.agentapi.v1.AgentMessage",
	"warden.agentapi.v1.ControlMessage",
	"warden.agentapi.v1.TelemetryBatch",
	"warden.agentapi.v1.TelemetryAck",
	"warden.agentapi.v1.EndDetail",
	"warden.agentapi.v1.AdminToolRecord",
	"warden.v1.PrimitiveResult",
	"warden.v1.IpcRefusal",
	"warden.v1.ExecutorResultBody",
	"warden.v1.TrustInstallResultBody",
	"warden.v1.ExecutorStatusBody",
}

// FuzzStrictDecodeContract: for any bytes and any root message, the strict
// decoder never panics, and bytes it accepts are the canonical encoding:
// deterministic re-marshalling gives them back byte for byte
// (action-envelope R13 (k): the scanner accepts exactly the canonical
// encoding). A schema shape the scanner mishandles (an optional field, a
// oneof, a packed enum list, a double) would break this.
func FuzzStrictDecodeContract(f *testing.F) {
	types := make([]protoreflect.MessageType, len(fuzzRoots))
	for i, name := range fuzzRoots {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(name)
		if err != nil {
			f.Fatalf("%s: %v", name, err)
		}
		types[i] = mt
	}
	for i, mt := range types {
		for variant := 0; variant < 22; variant++ {
			m := mt.New()
			populate(m, variant, 0)
			b, err := deterministic.Marshal(m.Interface())
			if err != nil {
				f.Fatal(err)
			}
			f.Add(uint8(i), b)
		}
		// Attack seeds: an explicit default, an unknown field, a
		// truncated record, a duplicate field and an overlong varint.
		f.Add(uint8(i), []byte{0x08, 0x00})
		f.Add(uint8(i), []byte{0xf8, 0x06, 0x01})
		f.Add(uint8(i), []byte{0x0a, 0x05, 0x01})
		f.Add(uint8(i), []byte{0x08, 0x01, 0x08, 0x01})
		f.Add(uint8(i), []byte{0x08, 0x81, 0x00})
	}
	f.Fuzz(func(t *testing.T, which uint8, b []byte) {
		mt := types[int(which)%len(types)]
		m := mt.New().Interface()
		if err := wirescan.Unmarshal(b, m); err != nil {
			return
		}
		again, err := deterministic.Marshal(m)
		if err != nil {
			t.Fatalf("%s: accepted message does not re-marshal: %v", mt.Descriptor().FullName(), err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("%s: accepted non-canonical bytes\n in: %x\nout: %x", mt.Descriptor().FullName(), b, again)
		}
		// The decoded message is stable across a second strict decode.
		m2 := mt.New().Interface()
		if err := wirescan.Unmarshal(again, m2); err != nil || !proto.Equal(m, m2) {
			t.Fatalf("%s: re-decode differs: %v", mt.Descriptor().FullName(), err)
		}
	})
}
