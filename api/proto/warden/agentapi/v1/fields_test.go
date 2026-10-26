package agentapiv1_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// TestAgentapiFieldNumbers: every message of agent-api §4 has exactly the
// spec's fields, numbers, types and oneof, and nothing else (R52: final
// wire numbers).
func TestAgentapiFieldNumbers(t *testing.T) {
	for _, v := range shapeViolations(agentapiPkg, allMessages(packageFiles(t, agentapiPkg)), agentapiTable) {
		t.Error(v)
	}
}

// TestNewV1FieldNumbers: the same for the warden.v1 messages of
// typed-action-catalog §4.8, §4.8.1 and executor-ipc §4.3, §4.6, §4.7.
func TestNewV1FieldNumbers(t *testing.T) {
	for _, v := range shapeViolations(wardenPkg, allMessages(newV1Files(t)), v1Table) {
		t.Error(v)
	}
}

// TestNewV1MessagesTopLevel: executor-ipc §4.5 declares every message and
// enum of §4.5–§4.9 at the top level of the package, never nested.
func TestNewV1MessagesTopLevel(t *testing.T) {
	files := newV1Files(t)
	for _, md := range allMessages(files) {
		if _, ok := md.Parent().(protoreflect.FileDescriptor); !ok {
			t.Errorf("%s is nested", md.FullName())
		}
	}
	for _, ed := range allEnums(files) {
		if _, ok := ed.Parent().(protoreflect.FileDescriptor); !ok {
			t.Errorf("%s is nested", ed.FullName())
		}
	}
}

// TestStatusBodyHasNoCounterFields: ExecutorStatusBody fields 31 boot_id
// and 32 highest_envelope_counter arrive with the M2 envelope change
// (agent-api R52a); in M1 they are neither declared nor reserved.
func TestStatusBodyHasNoCounterFields(t *testing.T) {
	md := (&wardenv1.ExecutorStatusBody{}).ProtoReflect().Descriptor()
	for _, n := range []protoreflect.FieldNumber{31, 32} {
		if fd := md.Fields().ByNumber(n); fd != nil {
			t.Errorf("ExecutorStatusBody declares field %d (%s)", n, fd.Name())
		}
		if md.ReservedRanges().Has(n) {
			t.Errorf("ExecutorStatusBody reserves field %d", n)
		}
	}
	for _, name := range []protoreflect.Name{"boot_id", "highest_envelope_counter"} {
		if md.Fields().ByName(name) != nil || md.ReservedNames().Has(name) {
			t.Errorf("ExecutorStatusBody declares or reserves %s", name)
		}
	}
	if got := md.Fields().Len(); got != 30 {
		t.Errorf("ExecutorStatusBody has %d fields, want 30", got)
	}
}

// TestTypedResultReservesP20: TypedResult mirrors TypedRequest: P20
// (cert.renew) was removed, its number and name stay reserved
// (typed-action-catalog §4.8).
func TestTypedResultReservesP20(t *testing.T) {
	md := (&wardenv1.TypedResult{}).ProtoReflect().Descriptor()
	if !md.ReservedRanges().Has(20) || !md.ReservedNames().Has("cert_renew") {
		t.Error("TypedResult does not reserve 20 and cert_renew")
	}
	req := (&wardenv1.TypedRequest{}).ProtoReflect().Descriptor().Oneofs().ByName("request")
	res := md.Oneofs().ByName("result")
	if req == nil || res == nil {
		t.Fatal("TypedRequest.request or TypedResult.result missing")
	}
	if req.Fields().Len() != res.Fields().Len() {
		t.Fatalf("TypedResult has %d members, TypedRequest %d", res.Fields().Len(), req.Fields().Len())
	}
	for i := 0; i < req.Fields().Len(); i++ {
		q := req.Fields().Get(i)
		r := res.Fields().ByNumber(q.Number())
		if r == nil || r.Name() != q.Name() {
			t.Errorf("request member %s (%d) has no result member of the same name and number", q.Name(), q.Number())
		}
	}
}

// TestDbQueryDataMatchesDbQuery: each DbQueryData member's number equals
// the request's DbQuery value for that query, so the executor's match is a
// number comparison (typed-action-catalog §4.8.1, ruling (a)).
func TestDbQueryDataMatchesDbQuery(t *testing.T) {
	od := (&wardenv1.DbQueryData{}).ProtoReflect().Descriptor().Oneofs().ByName("query")
	ed := wardenv1.DbQuery(0).Descriptor()
	if od == nil {
		t.Fatal("DbQueryData has no oneof query")
	}
	if od.Fields().Len() != ed.Values().Len()-1 {
		t.Fatalf("DbQueryData has %d members, DbQuery %d non-zero values", od.Fields().Len(), ed.Values().Len()-1)
	}
	for i := 0; i < od.Fields().Len(); i++ {
		fd := od.Fields().Get(i)
		v := ed.Values().ByNumber(protoreflect.EnumNumber(fd.Number()))
		if v == nil || string(v.Name()) != "DB_QUERY_"+strings.ToUpper(string(fd.Name())) {
			t.Errorf("member %s (%d) does not match a DbQuery value of the same number", fd.Name(), fd.Number())
		}
	}
}

// TestImportedTypesResolveToWardenV1 (AC36): PrimitiveResult,
// IpcRefusalCode and TrustKind are the warden.v1 types, and no type of
// warden.agentapi.v1 re-declares a warden.v1 type name.
func TestImportedTypesResolveToWardenV1(t *testing.T) {
	checks := []struct {
		field protoreflect.FieldDescriptor
		want  protoreflect.FullName
	}{
		{(&agentapiv1.SignedReplyReport{}).ProtoReflect().Descriptor().Fields().ByName("primitive_result"), "warden.v1.PrimitiveResult"},
		{(&agentapiv1.EnvelopeAdvisory{}).ProtoReflect().Descriptor().Fields().ByName("last_ipc_refusal"), "warden.v1.IpcRefusalCode"},
		{(&agentapiv1.TrustDocument{}).ProtoReflect().Descriptor().Fields().ByName("kind"), "warden.v1.TrustKind"},
		{(&agentapiv1.TrustDocumentOversize{}).ProtoReflect().Descriptor().Fields().ByName("kind"), "warden.v1.TrustKind"},
	}
	for _, c := range checks {
		if c.field == nil {
			t.Errorf("field for %s missing", c.want)
			continue
		}
		var got protoreflect.FullName
		switch {
		case c.field.Message() != nil:
			got = c.field.Message().FullName()
		case c.field.Enum() != nil:
			got = c.field.Enum().FullName()
		}
		if got != c.want {
			t.Errorf("%s has type %s, want %s", c.field.FullName(), got, c.want)
		}
	}
	// The Go types are the warden.v1 ones, assignable without conversion.
	_ = &agentapiv1.SignedReplyReport{PrimitiveResult: &wardenv1.PrimitiveResult{}}
	_ = &agentapiv1.TrustDocument{Kind: wardenv1.TrustKind_TRUST_KIND_KEYSET}
	_ = &agentapiv1.EnvelopeAdvisory{LastIpcRefusal: wardenv1.IpcRefusalCode_IPC_REFUSAL_CODE_BUSY.Enum()}

	for _, v := range duplicateTypeNames(packageFiles(t, wardenPkg), packageFiles(t, agentapiPkg)) {
		t.Error(v)
	}
}

// duplicateTypeNames reports every message or enum of b whose short name
// is also a message or enum of a (AC36: no type of §4 declared twice).
func duplicateTypeNames(a, b []protoreflect.FileDescriptor) []string {
	names := map[protoreflect.Name]protoreflect.FullName{}
	for _, md := range allMessages(a) {
		names[md.Name()] = md.FullName()
	}
	for _, ed := range allEnums(a) {
		names[ed.Name()] = ed.FullName()
	}
	var out []string
	check := func(n protoreflect.Name, full protoreflect.FullName) {
		if other, ok := names[n]; ok {
			out = append(out, fmt.Sprintf("%s re-declares %s", full, other))
		}
	}
	for _, md := range allMessages(b) {
		check(md.Name(), md.FullName())
	}
	for _, ed := range allEnums(b) {
		check(ed.Name(), ed.FullName())
	}
	return out
}

// TestDuplicateTypeNamesDetects: a test-only package declaring its own
// TrustKind and PrimitiveResult is caught.
func TestDuplicateTypeNamesDetects(t *testing.T) {
	f, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:        proto.String("wardentest/dup.proto"),
		Package:     proto.String("wardentest.dup"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("PrimitiveResult")}},
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name:  proto.String("TrustKind"),
			Value: []*descriptorpb.EnumValueDescriptorProto{{Name: proto.String("X_UNSPECIFIED"), Number: proto.Int32(0)}},
		}},
	}, new(protoregistry.Files))
	if err != nil {
		t.Fatal(err)
	}
	got := duplicateTypeNames(packageFiles(t, wardenPkg), []protoreflect.FileDescriptor{f})
	want := []string{
		"wardentest.dup.PrimitiveResult re-declares warden.v1.PrimitiveResult",
		"wardentest.dup.TrustKind re-declares warden.v1.TrustKind",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestShapeViolationsDetects feeds the shape check a wrong table: a
// renumbered field, a wrong type, a lost optional, a field with no row, a
// row with no field, a message with no row and a row with no message.
func TestShapeViolationsDetects(t *testing.T) {
	bad := msgTable{}
	for k, v := range agentapiTable {
		bad[k] = msgSpec{oneof: v.oneof, opts: v.opts, fields: slices.Clone(v.fields)}
	}
	hello := bad["Hello"]
	hello.fields[0].num = 7         // contract_version_min
	hello.fields[1].typ = "uint64"  // contract_version_max
	hello.fields = hello.fields[:5] // executor_available has no row
	hello.fields = append(hello.fields, fieldSpec{9, "extra", "bool", none})
	bad["Hello"] = hello
	sr := bad["SignedReplyReport"]
	sr.fields[4].typ = "uint64" // advisory_document_sequence without optional
	bad["SignedReplyReport"] = sr
	delete(bad, "Label")
	bad["NoSuchMessage"] = msgSpec{opts: none}
	ack := bad["DeliveryAck"]
	ack.oneof = "body"
	bad["DeliveryAck"] = ack

	// Violations of the real table are reported by
	// TestAgentapiFieldNumbers; only the injected ones are counted here.
	mds := allMessages(packageFiles(t, agentapiPkg))
	baseline := shapeViolations(agentapiPkg, mds, agentapiTable)
	got := slices.DeleteFunc(shapeViolations(agentapiPkg, mds, bad), func(v string) bool {
		return slices.Contains(baseline, v)
	})
	for _, want := range []string{
		"warden.agentapi.v1.Hello.contract_version_min: number 1, want 7",
		`warden.agentapi.v1.Hello.contract_version_max: type "uint32", want "uint64"`,
		"warden.agentapi.v1.Hello.executor_available: field has no row",
		"warden.agentapi.v1.Hello.extra: row has no field",
		`warden.agentapi.v1.SignedReplyReport.advisory_document_sequence: type "optional uint64", want "uint64"`,
		"warden.agentapi.v1.Label: message has no row",
		"warden.agentapi.v1.NoSuchMessage: row has no message",
		"warden.agentapi.v1.DeliveryAck: want exactly one oneof body, have 0",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing violation %q in\n%s", want, strings.Join(got, "\n"))
		}
	}
	if len(got) != 8 {
		t.Errorf("got %d violations, want 8:\n%s", len(got), strings.Join(got, "\n"))
	}
}

// TestServices: agent-api §4.1, the two services and their RPCs with the
// stream flags, in the descriptors and in the generated gRPC code.
func TestServices(t *testing.T) {
	type rpc struct {
		in, out                  protoreflect.FullName
		clientStream, serverStrm bool
	}
	want := map[protoreflect.FullName]map[protoreflect.Name]rpc{
		"warden.agentapi.v1.AgentEnrollment": {
			"Enroll": {"warden.agentapi.v1.EnrollRequest", "warden.agentapi.v1.EnrollResponse", false, false},
		},
		"warden.agentapi.v1.AgentControl": {
			"Connect":         {"warden.agentapi.v1.AgentMessage", "warden.agentapi.v1.ControlMessage", true, true},
			"Renew":           {"warden.agentapi.v1.RenewRequest", "warden.agentapi.v1.RenewResponse", false, false},
			"UploadTelemetry": {"warden.agentapi.v1.TelemetryBatch", "warden.agentapi.v1.TelemetryAck", false, false},
		},
	}
	seen := map[protoreflect.FullName]bool{}
	for _, f := range packageFiles(t, agentapiPkg) {
		for i := 0; i < f.Services().Len(); i++ {
			sd := f.Services().Get(i)
			methods, ok := want[sd.FullName()]
			if !ok {
				t.Errorf("unexpected service %s", sd.FullName())
				continue
			}
			seen[sd.FullName()] = true
			if sd.Methods().Len() != len(methods) {
				t.Errorf("%s has %d methods, want %d", sd.FullName(), sd.Methods().Len(), len(methods))
			}
			for name, w := range methods {
				m := sd.Methods().ByName(name)
				if m == nil {
					t.Errorf("%s has no method %s", sd.FullName(), name)
					continue
				}
				got := rpc{m.Input().FullName(), m.Output().FullName(), m.IsStreamingClient(), m.IsStreamingServer()}
				if got != w {
					t.Errorf("%s.%s = %+v, want %+v", sd.FullName(), name, got, w)
				}
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("service %s not declared", name)
		}
	}

	// Generated gRPC code (protoc-gen-go-grpc): method paths and stream
	// shapes.
	paths := map[string]string{
		agentapiv1.AgentEnrollment_Enroll_FullMethodName:       "/warden.agentapi.v1.AgentEnrollment/Enroll",
		agentapiv1.AgentControl_Connect_FullMethodName:         "/warden.agentapi.v1.AgentControl/Connect",
		agentapiv1.AgentControl_Renew_FullMethodName:           "/warden.agentapi.v1.AgentControl/Renew",
		agentapiv1.AgentControl_UploadTelemetry_FullMethodName: "/warden.agentapi.v1.AgentControl/UploadTelemetry",
	}
	for got, want := range paths {
		if got != want {
			t.Errorf("method path %s, want %s", got, want)
		}
	}
	ctl := agentapiv1.AgentControl_ServiceDesc
	if ctl.ServiceName != "warden.agentapi.v1.AgentControl" || len(ctl.Methods) != 2 || len(ctl.Streams) != 1 {
		t.Fatalf("AgentControl_ServiceDesc = %s, %d unary, %d streams", ctl.ServiceName, len(ctl.Methods), len(ctl.Streams))
	}
	if s := ctl.Streams[0]; s.StreamName != "Connect" || !s.ClientStreams || !s.ServerStreams {
		t.Errorf("Connect stream = %+v, want bidirectional", s)
	}
	enr := agentapiv1.AgentEnrollment_ServiceDesc
	if enr.ServiceName != "warden.agentapi.v1.AgentEnrollment" || len(enr.Methods) != 1 || len(enr.Streams) != 0 {
		t.Errorf("AgentEnrollment_ServiceDesc = %s, %d unary, %d streams", enr.ServiceName, len(enr.Methods), len(enr.Streams))
	}
}
