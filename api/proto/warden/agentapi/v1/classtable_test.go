package agentapiv1_test

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// The contract files the mutation cases edit, by their registered path.
var (
	ctEnrollment = agentapiv1.File_warden_agentapi_v1_enrollment_proto
	ctErrors     = agentapiv1.File_warden_agentapi_v1_errors_proto
	ctOutbox     = agentapiv1.File_warden_agentapi_v1_outbox_proto
	ctService    = agentapiv1.File_warden_agentapi_v1_service_proto
	ctStream     = agentapiv1.File_warden_agentapi_v1_stream_proto
	ctTelemetry  = agentapiv1.File_warden_agentapi_v1_telemetry_proto
	ctPrimitive  = wardenv1.File_warden_v1_primitive_result_proto
	ctExecutor   = wardenv1.File_warden_v1_executor_proto
)

// inboundRootNames are the control-plane-to-agent roots of agent-api
// §4.10.1 reading 3.
var inboundRootNames = []protoreflect.FullName{
	"warden.agentapi.v1.ControlMessage",
	"warden.agentapi.v1.EndDetail",
	"warden.agentapi.v1.EnrollResponse",
	"warden.agentapi.v1.RenewResponse",
	"warden.agentapi.v1.TelemetryAck",
}

// The violation lines generateClassTable reports.
func vNoClass(f string) string      { return f + ": no redact_class" }
func vUnspecified(f string) string  { return f + ": redact_class UNSPECIFIED" }
func vInbound(f string) string      { return f + ": redact_class on a control-plane-to-agent field" }
func vBoth(m string) string         { return m + ": reached from both directions" }
func vMessageTyped(f string) string { return f + ": redact_class on a message-typed field" }
func vNonString(f string, c wardenv1.RedactFieldClass) string {
	return f + ": class " + c.String() + " on a non-string field outside §4.1"
}

// The difference lines classTableDiff reports.
func dExtra(f string) string   { return f + ": in the compiled table, not in a fresh generation" }
func dMissing(f string) string { return f + ": missing from the compiled table" }
func dChanged(f string, compiled, fresh wardenv1.RedactFieldClass) string {
	return f + ": compiled " + compiled.String() + ", fresh " + fresh.String()
}

type fileProtos = map[string]*descriptorpb.FileDescriptorProto

func ctFile(t *testing.T, files fileProtos, fd protoreflect.FileDescriptor) *descriptorpb.FileDescriptorProto {
	t.Helper()
	fp, ok := files[fd.Path()]
	if !ok {
		t.Fatalf("contractFiles: no %s in the edit map", fd.Path())
	}
	return fp
}

// ctMsg finds a message of a file by its name relative to the package;
// a dotted name reaches a nested message.
func ctMsg(t *testing.T, files fileProtos, fd protoreflect.FileDescriptor, name string) *descriptorpb.DescriptorProto {
	t.Helper()
	parts := strings.Split(name, ".")
	list := ctFile(t, files, fd).MessageType
	var m *descriptorpb.DescriptorProto
	for _, p := range parts {
		m = nil
		for _, c := range list {
			if c.GetName() == p {
				m = c
			}
		}
		if m == nil {
			t.Fatalf("%s: no message %s", fd.Path(), name)
		}
		list = m.NestedType
	}
	return m
}

func ctField(t *testing.T, m *descriptorpb.DescriptorProto, name string) *descriptorpb.FieldDescriptorProto {
	t.Helper()
	for _, f := range m.Field {
		if f.GetName() == name {
			return f
		}
	}
	t.Fatalf("%s: no field %s", m.GetName(), name)
	return nil
}

func ctNewField(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:     proto.String(name),
		Number:   proto.Int32(num),
		Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		Type:     typ.Enum(),
		JsonName: proto.String(name),
	}
}

func ctMsgField(name string, num int32, typeName string) *descriptorpb.FieldDescriptorProto {
	f := ctNewField(name, num, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE)
	f.TypeName = proto.String(typeName)
	return f
}

func ctSetClass(f *descriptorpb.FieldDescriptorProto, c wardenv1.RedactFieldClass) {
	if f.Options == nil {
		f.Options = &descriptorpb.FieldOptions{}
	}
	proto.SetExtension(f.Options, wardenv1.E_RedactClass, c)
}

func entryMap(entries []classEntry) map[protoreflect.FullName]wardenv1.RedactFieldClass {
	m := make(map[protoreflect.FullName]wardenv1.RedactFieldClass, len(entries))
	for _, e := range entries {
		m[e.field] = e.class
	}
	return m
}

func names(mds []protoreflect.MessageDescriptor) []protoreflect.FullName {
	out := make([]protoreflect.FullName, 0, len(mds))
	for _, md := range mds {
		out = append(out, md.FullName())
	}
	slices.Sort(out)
	return out
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// R5, §4.5, OQ4: the committed table is a fresh generation.

// TestClassTableGenerated is R5 and AC1: the class table generated from
// the redact_class options of the contract has no violation, equals the
// committed classtable_gen.go byte for byte and the compiled table entry
// for entry, and generating it twice gives identical bytes (AC49).
// With -update-class-table it rewrites the committed file instead.
func TestClassTableGenerated(t *testing.T) {
	entries, violations := generateClassTable(contractFiles(t, nil))
	for _, v := range violations {
		t.Error(v)
	}
	got, err := renderClassTable(entries)
	if err != nil {
		t.Fatal(err)
	}
	if *updateClassTable {
		if len(violations) > 0 {
			t.Fatalf("not writing %s: the contract has %d R5 violations", classTableFile, len(violations))
		}
		if err := os.WriteFile(classTableFile, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(classTableFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from a fresh generation; run go test -run TestClassTableGenerated -update-class-table", classTableFile)
	}
	for _, d := range classTableDiff(agentapiv1.CompiledFieldClasses(), entries) {
		t.Error(d)
	}
	again, _ := generateClassTable(contractFiles(t, nil))
	twice, err := renderClassTable(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, twice) {
		t.Error("generating the class table twice gives different bytes")
	}
}

// TestClassTableEntries is R5 and §4.1: the table has one entry per
// non-message field reachable from the agent-to-control-plane roots,
// sorted, each a defined class other than UNSPECIFIED, the redact_class
// option where set and X for an unmarked non-string field. A string or
// bytes field always carries its class as an option.
func TestClassTableEntries(t *testing.T) {
	files := contractFiles(t, nil)
	entries, _ := generateClassTable(files)
	if len(entries) == 0 {
		t.Fatal("the generated class table is empty")
	}
	for i, e := range entries {
		if i > 0 && entries[i-1].field >= e.field {
			t.Errorf("entries not strictly sorted: %s before %s", entries[i-1].field, e.field)
		}
		if _, ok := wardenv1.RedactFieldClass_name[int32(e.class)]; !ok || e.class == wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED {
			t.Errorf("%s: class %v is not a class of §4.1", e.field, e.class)
		}
		d, err := files.FindDescriptorByName(e.field)
		if err != nil {
			t.Errorf("%s: %v", e.field, err)
			continue
		}
		fd, ok := d.(protoreflect.FieldDescriptor)
		if !ok {
			t.Errorf("%s is a %T, not a field", e.field, d)
			continue
		}
		if fd.Message() != nil {
			t.Errorf("%s: message-typed field has an entry", e.field)
		}
	}

	// An independent oracle: the R5 walk of helpers_test.go from r5Roots.
	var roots []protoreflect.MessageDescriptor
	for _, name := range r5Roots {
		roots = append(roots, messageByName(t, name))
	}
	want := map[protoreflect.FullName]wardenv1.RedactFieldClass{}
	for name := range reachable(roots) {
		md := messageByName(t, name)
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			switch {
			case fd.Message() != nil:
			case proto.HasExtension(fd.Options(), wardenv1.E_RedactClass):
				want[fd.FullName()] = proto.GetExtension(fd.Options(), wardenv1.E_RedactClass).(wardenv1.RedactFieldClass)
			case isStringOrBytes(fd):
				t.Errorf("%s: string or bytes field in R5 scope without redact_class", fd.FullName())
			default:
				want[fd.FullName()] = clsX
			}
		}
	}
	got := entryMap(entries)
	for name, c := range want {
		if g, ok := got[name]; !ok {
			t.Errorf("%s: no entry, want %v", name, c)
		} else if g != c {
			t.Errorf("%s: entry %v, want %v", name, g, c)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: entry for a field outside R5's scope", name)
		}
	}
}

// TestCompiledClassTableWellFormed: the compiled table is not empty, every
// class is defined and none is UNSPECIFIED, and CompiledFieldClasses
// returns a copy, so nothing at run time changes FieldClass (R43).
func TestCompiledClassTableWellFormed(t *testing.T) {
	compiled := agentapiv1.CompiledFieldClasses()
	if len(compiled) == 0 {
		t.Error("the compiled class table is empty")
	}
	for name, c := range compiled {
		if _, ok := wardenv1.RedactFieldClass_name[int32(c)]; !ok || c == wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED {
			t.Errorf("%s: compiled class %v is not a class of §4.1", name, c)
		}
		if got, ok := agentapiv1.FieldClass(name); !ok || got != c {
			t.Errorf("FieldClass(%s) = %v, %v; want %v, true", name, got, ok, c)
		}
	}
	const extract = "warden.agentapi.v1.LogEvent.extract"
	compiled[extract] = clsS
	compiled["warden.agentapi.v1.LogEvent.injected"] = clsX
	delete(compiled, "warden.agentapi.v1.Label.value")
	if c, ok := agentapiv1.FieldClass(extract); ok && c != clsEText {
		t.Errorf("FieldClass(%s) = %v after editing the copy", extract, c)
	}
	if _, ok := agentapiv1.FieldClass("warden.agentapi.v1.LogEvent.injected"); ok {
		t.Error("an entry added to the copy reached FieldClass")
	}
	if fresh := agentapiv1.CompiledFieldClasses(); fresh[extract] == clsS {
		t.Error("CompiledFieldClasses returned the table itself, not a copy")
	}
}

// ---------------------------------------------------------------------------
// R5 roots and agent-api §4.10.1 reading 3.

// TestClassTableRoots: the outbound roots are the request types of the
// services and the three executor bodies (exactly r5Roots), the inbound
// roots are exactly the response types and EndDetail, both taken from the
// given files; the outbound walk reaches every PrimitiveResult variant,
// every DbQueryData member and every executor body message (MA2), and
// every warden.agentapi.v1 message is reached from exactly one direction.
func TestClassTableRoots(t *testing.T) {
	files := contractFiles(t, nil)
	out, err := outboundRoots(files)
	if err != nil {
		t.Fatal(err)
	}
	in, err := inboundRoots(files)
	if err != nil {
		t.Fatal(err)
	}
	wantOut := slices.Clone(r5Roots)
	slices.Sort(wantOut)
	if got := names(out); !slices.Equal(got, wantOut) {
		t.Errorf("outbound roots = %v, want %v", got, wantOut)
	}
	if got := names(in); !slices.Equal(got, inboundRootNames) {
		t.Errorf("inbound roots = %v, want %v", got, inboundRootNames)
	}
	for _, md := range append(slices.Clone(out), in...) {
		if d, err := files.FindDescriptorByName(md.FullName()); err != nil || d != md {
			t.Errorf("%s: root not taken from the given files", md.FullName())
		}
	}

	seenOut, seenIn := reachable(out), reachable(in)
	for name := range v1Table {
		full := protoreflect.FullName("warden.v1." + name)
		if name == "IpcRefusal" {
			if seenOut[full] || seenIn[full] {
				t.Errorf("%s: an unsigned transport answer is reached by a walk", full)
			}
			continue
		}
		if !seenOut[full] {
			t.Errorf("%s is not reached from the outbound roots", full)
		}
		if seenIn[full] {
			t.Errorf("%s is reached from the inbound roots", full)
		}
	}
	for _, md := range allMessages(packageFiles(t, agentapiPkg)) {
		if seenOut[md.FullName()] == seenIn[md.FullName()] {
			t.Errorf("%s: reached outbound %v, inbound %v; want exactly one", md.FullName(),
				seenOut[md.FullName()], seenIn[md.FullName()])
		}
	}
}

// addProbeService adds ProbeRequest (an unclassified string) and
// ProbeResponse (a string marked X) to service.proto and a method using
// them, to AgentControl or to a new service.
func addProbeService(t *testing.T, files fileProtos, newService bool) {
	t.Helper()
	fp := ctFile(t, files, ctService)
	note := ctNewField("note", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING)
	ctSetClass(note, clsX)
	fp.MessageType = append(fp.MessageType,
		&descriptorpb.DescriptorProto{Name: proto.String("ProbeRequest"),
			Field: []*descriptorpb.FieldDescriptorProto{ctNewField("text", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING)}},
		&descriptorpb.DescriptorProto{Name: proto.String("ProbeResponse"),
			Field: []*descriptorpb.FieldDescriptorProto{note}})
	method := &descriptorpb.MethodDescriptorProto{
		Name:       proto.String("Probe"),
		InputType:  proto.String(".warden.agentapi.v1.ProbeRequest"),
		OutputType: proto.String(".warden.agentapi.v1.ProbeResponse"),
	}
	if newService {
		fp.Service = append(fp.Service, &descriptorpb.ServiceDescriptorProto{
			Name: proto.String("ProbeService"), Method: []*descriptorpb.MethodDescriptorProto{method}})
		return
	}
	for _, s := range fp.Service {
		if s.GetName() == "AgentControl" {
			s.Method = append(s.Method, method)
			return
		}
	}
	t.Fatal("service.proto: no AgentControl")
}

// TestClassTableRootsFollowServices: a method added to a service, or a new
// service, adds its request type to the outbound roots and its response
// type to the inbound roots; nothing is hard-coded.
func TestClassTableRootsFollowServices(t *testing.T) {
	for _, newService := range []bool{false, true} {
		files := contractFiles(t, func(m fileProtos) { addProbeService(t, m, newService) })
		out, err := outboundRoots(files)
		if err != nil {
			t.Fatal(err)
		}
		in, err := inboundRoots(files)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(names(out), "warden.agentapi.v1.ProbeRequest") {
			t.Errorf("new service %v: ProbeRequest not an outbound root: %v", newService, names(out))
		}
		if !slices.Contains(names(in), "warden.agentapi.v1.ProbeResponse") {
			t.Errorf("new service %v: ProbeResponse not an inbound root: %v", newService, names(in))
		}
	}
}

// ---------------------------------------------------------------------------
// FieldClass against §4.1.

// TestFieldClassSpotChecks: the compiled table gives the §4.1 class of
// fields in every part of R5's scope.
func TestFieldClassSpotChecks(t *testing.T) {
	for _, c := range []struct {
		field protoreflect.FullName
		want  wardenv1.RedactFieldClass
	}{
		{"warden.agentapi.v1.EnrollRequest.format_version", clsI},
		{"warden.agentapi.v1.EnrollRequest.token", clsI},
		{"warden.agentapi.v1.EnrollRequest.csr", clsI},
		{"warden.agentapi.v1.RenewRequest.format_version", clsI},
		{"warden.agentapi.v1.RenewRequest.csr", clsI},
		{"warden.agentapi.v1.Hello.server_id", clsX},
		{"warden.agentapi.v1.Hello.agent_version", clsX},
		{"warden.agentapi.v1.DeliveryAck.delivery_id", clsX},
		{"warden.agentapi.v1.HealthReport.outbox_messages", clsX},
		{"warden.agentapi.v1.HealthReport.conditions", clsX},
		{"warden.agentapi.v1.HealthReport.controlplane_ca_sha256", clsX},
		{"warden.agentapi.v1.RedactDropCount.class", clsX},
		{"warden.agentapi.v1.SignedReplyReport.kind", clsX},
		{"warden.agentapi.v1.SignedReplyReport.signed", clsS},
		{"warden.agentapi.v1.SignedReplyReport.unsigned_body", clsU},
		{"warden.agentapi.v1.SignedReplyReport.unsigned_body_withheld", clsX},
		{"warden.agentapi.v1.EnvelopeAdvisory.envelope_sha256", clsX},
		{"warden.agentapi.v1.RecoveryReport.recovery_id", clsX},
		{"warden.agentapi.v1.TrustDocumentOversize.received_size", clsX},
		{"warden.agentapi.v1.AdminToolRecord.record_id", clsX},
		{"warden.agentapi.v1.AdminToolRecord.release_version", clsNPatterned},
		{"warden.agentapi.v1.AdminToolRecord.signed_replies", clsS},
		{"warden.agentapi.v1.TelemetryBatch.server_id", clsX},
		{"warden.agentapi.v1.MetricSample.name", clsX},
		{"warden.agentapi.v1.MetricSample.value", clsX},
		{"warden.agentapi.v1.Label.key", clsX},
		{"warden.agentapi.v1.Label.value", clsLValue},
		{"warden.agentapi.v1.LogEvent.rule_id", clsX},
		{"warden.agentapi.v1.LogEvent.unit_id", clsNPatterned},
		{"warden.agentapi.v1.LogEvent.count", clsX},
		{"warden.agentapi.v1.LogEvent.extract", clsEText},
		{"warden.v1.PrimitiveResult.status", clsX},
		{"warden.v1.FsUsageResult.fs_type", clsTName},
		{"warden.v1.FsLargestEntry.path", clsTPath},
		{"warden.v1.WebConfigTestResult.messages", clsTText},
		{"warden.v1.CertificateInfo.subject_cn", clsTName},
		{"warden.v1.CertificateInfo.dns_names", clsTName},
		{"warden.v1.CertificateInfo.serial_hex", clsTName},
		{"warden.v1.ProcessInfo.comm", clsTName},
		{"warden.v1.ProcessInfo.unit", clsTName},
		{"warden.v1.ContainerInspectResult.name", clsTName},
		{"warden.v1.DbServerStatus.version", clsTName},
		{"warden.v1.DbSession.user", clsTName},
		{"warden.v1.DbSession.database", clsTName},
		{"warden.v1.DbSession.owner_digest", clsX},
		{"warden.v1.DbSession.session_id", clsX},
		{"warden.v1.DbReplsetMember.name", clsTName},
		{"warden.v1.DbBackupVerifyResult.newest_name", clsTName},
		{"warden.v1.ExecutorResultBody.action_id", clsX},
		{"warden.v1.ExecutorResultBody.stored_action_id", clsX},
		{"warden.v1.TrustInstallResultBody.document_sha256", clsX},
		{"warden.v1.InstalledDocument.hash", clsX},
		{"warden.v1.ExecutorStatusBody.server_id", clsX},
		{"warden.v1.ExecutorStatusBody.installed_release_version", clsNPatterned},
		{"warden.v1.ExecutorStatusBody.keyset_signed_bytes", clsS},
		{"warden.v1.ExecutorStatusBody.healthy", clsX},
		{"warden.v1.FrozenPlaybook.playbook_id", clsX},
		{"warden.v1.DbInstanceHealth.unit_id", clsNPatterned},
	} {
		got, ok := agentapiv1.FieldClass(c.field)
		if !ok || got != c.want {
			t.Errorf("FieldClass(%s) = %v, %v; want %v, true", c.field, got, ok, c.want)
		}
	}
}

// TestFieldClassOutOfScope: FieldClass has no entry for a control-plane-
// to-agent field (§4.10.1 reading 3), a message-typed field, a message
// that is never sent (IpcRefusal), a pre-M1 warden.v1 field, or a name
// that is not a field.
func TestFieldClassOutOfScope(t *testing.T) {
	for _, name := range []protoreflect.FullName{
		"warden.agentapi.v1.ControlMessage.welcome",
		"warden.agentapi.v1.Welcome.contract_version",
		"warden.agentapi.v1.Delivery.delivery_id",
		"warden.agentapi.v1.EnvelopeDelivery.signed_envelope",
		"warden.agentapi.v1.TrustDocument.document",
		"warden.agentapi.v1.StatusRequest.challenge",
		"warden.agentapi.v1.MessageAck.message_seq",
		"warden.agentapi.v1.EnrollResponse.certificate",
		"warden.agentapi.v1.RenewResponse.certificate",
		"warden.agentapi.v1.RenewResponse.refusal",
		"warden.agentapi.v1.TelemetryAck.batch_seq",
		"warden.agentapi.v1.EndDetail.reason",
		"warden.agentapi.v1.SignedReplyReport.primitive_result",
		"warden.agentapi.v1.HealthReport.redact_drops",
		"warden.agentapi.v1.AgentMessage.health",
		"warden.agentapi.v1.TelemetryBatch.log_events",
		"warden.v1.TypedResult.fs_usage",
		"warden.v1.DbQueryData.sessions_top_idle",
		"warden.v1.IpcRefusal.code",
		"warden.v1.SignedEnvelope.body",
		"",
		".",
		"warden.agentapi.v1.LogEvent",
		"warden.agentapi.v1.LogEvent.made_up",
		"LogEvent.extract",
		".warden.agentapi.v1.LogEvent.extract",
		"warden.agentapi.v1.LogEvent.extract ",
		"warden.agentapi.v1.LogEvent.extract\x00",
		"WARDEN.AGENTAPI.V1.LOGEVENT.EXTRACT",
		"warden.agentapi.v1.LogEvent.extrаct", // Cyrillic а
		"warden.agentapi.v1.LogEvent.extract/../rule_id",
		protoreflect.FullName(strings.Repeat("a.", 5000) + "extract"),
	} {
		if c, ok := agentapiv1.FieldClass(name); ok {
			t.Errorf("FieldClass(%q) = %v, true; want no entry", name, c)
		}
	}
}

// ---------------------------------------------------------------------------
// AC1, MA2: a contract edit that breaks R5 or reading 3 fails the test.

type classMutation struct {
	name    string
	edit    func(*testing.T, fileProtos)
	want    []string
	absent  []protoreflect.FullName
	present map[protoreflect.FullName]wardenv1.RedactFieldClass
}

// addProbe adds an unclassified field probe = 999 of typ to a message.
func addProbe(fd protoreflect.FileDescriptor, msg string, typ descriptorpb.FieldDescriptorProto_Type, label descriptorpb.FieldDescriptorProto_Label) func(*testing.T, fileProtos) {
	return func(t *testing.T, m fileProtos) {
		f := ctNewField("probe", 999, typ)
		f.Label = label.Enum()
		md := ctMsg(t, m, fd, msg)
		md.Field = append(md.Field, f)
	}
}

// addOneofProbe adds an unclassified string member probe = 999 to the
// first oneof of a message.
func addOneofProbe(fd protoreflect.FileDescriptor, msg string) func(*testing.T, fileProtos) {
	return func(t *testing.T, m fileProtos) {
		md := ctMsg(t, m, fd, msg)
		if len(md.OneofDecl) == 0 {
			t.Fatalf("%s has no oneof", msg)
		}
		f := ctNewField("probe", 999, descriptorpb.FieldDescriptorProto_TYPE_STRING)
		f.OneofIndex = proto.Int32(0)
		md.Field = append(md.Field, f)
	}
}

func setClassOn(fd protoreflect.FileDescriptor, msg, field string, c wardenv1.RedactFieldClass) func(*testing.T, fileProtos) {
	return func(t *testing.T, m fileProtos) {
		ctSetClass(ctField(t, ctMsg(t, m, fd, msg), field), c)
	}
}

func classMutations() []classMutation {
	const (
		str = descriptorpb.FieldDescriptorProto_TYPE_STRING
		byt = descriptorpb.FieldDescriptorProto_TYPE_BYTES
		opt = descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
		rep = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	)
	var cases []classMutation

	// An unclassified string at every depth of R5's scope (AC1 a, b, e–h).
	for _, p := range []struct {
		file protoreflect.FileDescriptor
		msg  string
	}{
		{ctStream, "HealthReport"}, // R14
		{ctStream, "Hello"},
		{ctStream, "DeliveryAck"},
		{ctStream, "RedactDropCount"},
		{ctOutbox, "OutboxMessage"},
		{ctOutbox, "SignedReplyReport"},
		{ctOutbox, "EnvelopeAdvisory"},      // R15
		{ctOutbox, "TrustDocumentOversize"}, // R15
		{ctOutbox, "RecoveryReport"},        // R15
		{ctOutbox, "AdminToolRecord"},
		{ctEnrollment, "EnrollRequest"},
		{ctEnrollment, "RenewRequest"},
		{ctTelemetry, "TelemetryBatch"},
		{ctTelemetry, "MetricSample"},
		{ctTelemetry, "Label"},
		{ctTelemetry, "LogEvent"},
		{ctPrimitive, "PrimitiveResult"},
		{ctPrimitive, "FsLargestEntry"},
		{ctPrimitive, "MemStatusResult"},
		{ctPrimitive, "DbSession"}, // behind the DbQueryData oneof
		{ctPrimitive, "DbReplsetMember"},
		{ctPrimitive, "DbSessionOutcome"},
		{ctExecutor, "ExecutorResultBody"},
		{ctExecutor, "TrustInstallResultBody"},
		{ctExecutor, "InstalledDocument"},
		{ctExecutor, "ExecutorStatusBody"}, // AC1
		{ctExecutor, "FrozenPlaybook"},
		{ctExecutor, "DbInstanceHealth"},
	} {
		full := string(p.file.Package()) + "." + p.msg + ".probe"
		cases = append(cases, classMutation{
			name:   "unclassified string in " + p.msg,
			edit:   addProbe(p.file, p.msg, str, opt),
			want:   []string{vNoClass(full)},
			absent: []protoreflect.FullName{protoreflect.FullName(full)},
		})
	}

	cases = append(cases,
		classMutation{
			name:   "unclassified bytes in LogEvent",
			edit:   addProbe(ctTelemetry, "LogEvent", byt, opt),
			want:   []string{vNoClass("warden.agentapi.v1.LogEvent.probe")},
			absent: []protoreflect.FullName{"warden.agentapi.v1.LogEvent.probe"},
		},
		classMutation{
			name: "unclassified repeated string in ExecutorResultBody",
			edit: addProbe(ctExecutor, "ExecutorResultBody", str, rep),
			want: []string{vNoClass("warden.v1.ExecutorResultBody.probe")},
		},
		classMutation{
			name: "unclassified repeated bytes in ExecutorStatusBody",
			edit: addProbe(ctExecutor, "ExecutorStatusBody", byt, rep),
			want: []string{vNoClass("warden.v1.ExecutorStatusBody.probe")},
		},
		classMutation{
			name: "unclassified string member of the nested DbQueryData oneof",
			edit: addOneofProbe(ctPrimitive, "DbQueryData"),
			want: []string{vNoClass("warden.v1.DbQueryData.probe")},
		},
		classMutation{
			name: "unclassified string member of the TypedResult oneof",
			edit: addOneofProbe(ctPrimitive, "TypedResult"),
			want: []string{vNoClass("warden.v1.TypedResult.probe")},
		},
		classMutation{
			name: "unclassified string member of the AgentMessage oneof",
			edit: addOneofProbe(ctStream, "AgentMessage"),
			want: []string{vNoClass("warden.agentapi.v1.AgentMessage.probe")},
		},
		classMutation{
			name: "unclassified string member of the OutboxPayload oneof",
			edit: addOneofProbe(ctOutbox, "OutboxPayload"),
			want: []string{vNoClass("warden.agentapi.v1.OutboxPayload.probe")},
		},
		classMutation{
			name: "new nested message inside a PrimitiveResult variant",
			edit: func(t *testing.T, m fileProtos) {
				md := ctMsg(t, m, ctPrimitive, "FsUsageResult")
				md.NestedType = append(md.NestedType, &descriptorpb.DescriptorProto{
					Name: proto.String("Probe"),
					Field: []*descriptorpb.FieldDescriptorProto{
						ctNewField("text", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING),
						ctNewField("count", 2, descriptorpb.FieldDescriptorProto_TYPE_UINT64),
					},
				})
				md.Field = append(md.Field, ctMsgField("probe", 999, ".warden.v1.FsUsageResult.Probe"))
			},
			want:    []string{vNoClass("warden.v1.FsUsageResult.Probe.text")},
			absent:  []protoreflect.FullName{"warden.v1.FsUsageResult.Probe.text", "warden.v1.FsUsageResult.probe"},
			present: map[protoreflect.FullName]wardenv1.RedactFieldClass{"warden.v1.FsUsageResult.Probe.count": clsX},
		},
		classMutation{
			name: "map field in HealthReport",
			edit: func(t *testing.T, m fileProtos) {
				md := ctMsg(t, m, ctStream, "HealthReport")
				md.NestedType = append(md.NestedType, &descriptorpb.DescriptorProto{
					Name:    proto.String("ProbeEntry"),
					Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
					Field: []*descriptorpb.FieldDescriptorProto{
						ctNewField("key", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING),
						ctNewField("value", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING),
					},
				})
				f := ctMsgField("probe", 999, ".warden.agentapi.v1.HealthReport.ProbeEntry")
				f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
				md.Field = append(md.Field, f)
			},
			want: []string{
				vNoClass("warden.agentapi.v1.HealthReport.ProbeEntry.key"),
				vNoClass("warden.agentapi.v1.HealthReport.ProbeEntry.value"),
			},
		},
		classMutation{
			name: "self-referential message terminates and reports once",
			edit: func(t *testing.T, m fileProtos) {
				md := ctMsg(t, m, ctStream, "HealthReport")
				md.NestedType = append(md.NestedType, &descriptorpb.DescriptorProto{
					Name: proto.String("Node"),
					Field: []*descriptorpb.FieldDescriptorProto{
						ctMsgField("next", 1, ".warden.agentapi.v1.HealthReport.Node"),
						ctNewField("text", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING),
					},
				})
				md.Field = append(md.Field,
					ctMsgField("probe", 999, ".warden.agentapi.v1.HealthReport.Node"),
					ctMsgField("probe2", 998, ".warden.agentapi.v1.HealthReport.Node"))
			},
			want: []string{vNoClass("warden.agentapi.v1.HealthReport.Node.text")},
		},
		classMutation{
			name: "new service method with an unclassified request and a classified response",
			edit: func(t *testing.T, m fileProtos) { addProbeService(t, m, false) },
			want: []string{
				vNoClass("warden.agentapi.v1.ProbeRequest.text"),
				vInbound("warden.agentapi.v1.ProbeResponse.note"),
			},
		},
		classMutation{
			name: "new service with an unclassified request and a classified response",
			edit: func(t *testing.T, m fileProtos) { addProbeService(t, m, true) },
			want: []string{
				vNoClass("warden.agentapi.v1.ProbeRequest.text"),
				vInbound("warden.agentapi.v1.ProbeResponse.note"),
			},
		},
		classMutation{
			name: "class removed from an existing string field",
			edit: func(t *testing.T, m fileProtos) {
				proto.ClearExtension(ctField(t, ctMsg(t, m, ctTelemetry, "LogEvent"), "extract").Options, wardenv1.E_RedactClass)
			},
			want:   []string{vNoClass("warden.agentapi.v1.LogEvent.extract")},
			absent: []protoreflect.FullName{"warden.agentapi.v1.LogEvent.extract"},
		},
		classMutation{
			name: "class removed from a nested warden.v1 bytes field",
			edit: func(t *testing.T, m fileProtos) {
				proto.ClearExtension(ctField(t, ctMsg(t, m, ctExecutor, "ExecutorStatusBody"), "keyset_signed_bytes").Options, wardenv1.E_RedactClass)
			},
			want: []string{vNoClass("warden.v1.ExecutorStatusBody.keyset_signed_bytes")},
		},
		classMutation{
			name:   "UNSPECIFIED class on LogEvent.extract",
			edit:   setClassOn(ctTelemetry, "LogEvent", "extract", wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED),
			want:   []string{vUnspecified("warden.agentapi.v1.LogEvent.extract")},
			absent: []protoreflect.FullName{"warden.agentapi.v1.LogEvent.extract"},
		},
		classMutation{
			name: "UNSPECIFIED class on DbSession.user",
			edit: setClassOn(ctPrimitive, "DbSession", "user", wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED),
			want: []string{vUnspecified("warden.v1.DbSession.user")},
		},
		classMutation{
			name: "unclassified string in a control-plane-to-agent message is not R5's",
			edit: addProbe(ctTelemetry, "TelemetryAck", str, opt),
			absent: []protoreflect.FullName{"warden.agentapi.v1.TelemetryAck.probe",
				"warden.agentapi.v1.TelemetryAck.batch_seq"},
		},
		classMutation{
			name:   "unclassified string in IpcRefusal, which is never forwarded",
			edit:   addProbe(ctExecutor, "IpcRefusal", str, opt),
			absent: []protoreflect.FullName{"warden.v1.IpcRefusal.probe", "warden.v1.IpcRefusal.code"},
		},
		classMutation{
			name:    "I on EnrollRequest.format_version stays allowed",
			edit:    setClassOn(ctEnrollment, "EnrollRequest", "format_version", clsI),
			present: map[protoreflect.FullName]wardenv1.RedactFieldClass{"warden.agentapi.v1.EnrollRequest.format_version": clsI},
		},
		classMutation{
			name:    "I on RenewRequest.format_version stays allowed",
			edit:    setClassOn(ctEnrollment, "RenewRequest", "format_version", clsI),
			present: map[protoreflect.FullName]wardenv1.RedactFieldClass{"warden.agentapi.v1.RenewRequest.format_version": clsI},
		},
		classMutation{
			name: "T_NAME on EnrollRequest.format_version",
			edit: setClassOn(ctEnrollment, "EnrollRequest", "format_version", clsTName),
			want: []string{vNonString("warden.agentapi.v1.EnrollRequest.format_version", clsTName)},
		},
		classMutation{
			name: "T_NAME on a numeric HealthReport field",
			edit: setClassOn(ctStream, "HealthReport", "outbox_messages", clsTName),
			want: []string{vNonString("warden.agentapi.v1.HealthReport.outbox_messages", clsTName)},
		},
		classMutation{
			name: "L_VALUE on a repeated enum HealthReport field",
			edit: setClassOn(ctStream, "HealthReport", "conditions", clsLValue),
			want: []string{vNonString("warden.agentapi.v1.HealthReport.conditions", clsLValue)},
		},
		classMutation{
			name: "I on a numeric field outside EnrollRequest and RenewRequest",
			edit: setClassOn(ctTelemetry, "LogEvent", "count", clsI),
			want: []string{vNonString("warden.agentapi.v1.LogEvent.count", clsI)},
		},
		classMutation{
			name: "T_TEXT on a numeric warden.v1 field",
			edit: setClassOn(ctPrimitive, "DbSession", "session_id", clsTText),
			want: []string{vNonString("warden.v1.DbSession.session_id", clsTText)},
		},
		classMutation{
			name: "S on a bool in an executor body",
			edit: setClassOn(ctExecutor, "ExecutorStatusBody", "healthy", clsS),
			want: []string{vNonString("warden.v1.ExecutorStatusBody.healthy", clsS)},
		},
		classMutation{
			name: "inbound Welcome carries the outbound DeliveryAck",
			edit: func(t *testing.T, m fileProtos) {
				md := ctMsg(t, m, ctStream, "Welcome")
				md.Field = append(md.Field, ctMsgField("probe", 999, ".warden.agentapi.v1.DeliveryAck"))
			},
			want: []string{vBoth("warden.agentapi.v1.DeliveryAck")},
		},
		classMutation{
			name: "HealthReport carries the inbound MessageAck",
			edit: func(t *testing.T, m fileProtos) {
				md := ctMsg(t, m, ctStream, "HealthReport")
				md.Field = append(md.Field, ctMsgField("probe", 999, ".warden.agentapi.v1.MessageAck"))
			},
			want: []string{vBoth("warden.agentapi.v1.MessageAck")},
		},
	)

	// A redact_class on a message-typed field fails whatever its value: a
	// message field has no class of its own, its fields carry theirs
	// (agent-api §4.10.1 rule 3; Nofal, 2026-10-27). The field gets no
	// entry, and the message's own fields keep theirs.
	for _, p := range []struct {
		file       protoreflect.FileDescriptor
		msg, field string
		class      wardenv1.RedactFieldClass
	}{
		{ctStream, "HealthReport", "redact_drops", clsX},
		{ctStream, "HealthReport", "redact_drops", clsI},
		{ctStream, "AgentMessage", "health", clsX},
		{ctStream, "AgentMessage", "health", clsU},
		{ctOutbox, "SignedReplyReport", "primitive_result", clsX},
		{ctOutbox, "SignedReplyReport", "primitive_result", clsTText},
		{ctOutbox, "SignedReplyReport", "primitive_result", clsS},
		{ctTelemetry, "TelemetryBatch", "log_events", clsEText},
		{ctTelemetry, "TelemetryBatch", "log_events", clsX},
		{ctTelemetry, "MetricSample", "labels", clsLValue},
		{ctPrimitive, "PrimitiveResult", "result", clsTName},
		{ctPrimitive, "TypedResult", "fs_usage", clsX},
		{ctPrimitive, "TypedResult", "fs_usage", clsNPatterned},
		{ctStream, "HealthReport", "redact_drops", wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED},
	} {
		full := string(p.file.Package()) + "." + p.msg + "." + p.field
		cases = append(cases, classMutation{
			name:   p.class.String() + " on message-typed " + p.msg + "." + p.field,
			edit:   setClassOn(p.file, p.msg, p.field, p.class),
			want:   []string{vMessageTyped(full)},
			absent: []protoreflect.FullName{protoreflect.FullName(full)},
		})
	}
	cases = append(cases, classMutation{
		name: "X on message-typed HealthReport.redact_drops keeps the nested classes",
		edit: setClassOn(ctStream, "HealthReport", "redact_drops", clsX),
		want: []string{vMessageTyped("warden.agentapi.v1.HealthReport.redact_drops")},
		present: map[protoreflect.FullName]wardenv1.RedactFieldClass{
			"warden.agentapi.v1.RedactDropCount.dropped": clsX,
		},
	})

	// redact_class on control-plane-to-agent fields, at every depth
	// (§4.10.1 reading 3).
	for _, p := range []struct {
		file       protoreflect.FileDescriptor
		msg, field string
	}{
		{ctStream, "Welcome", "contract_version"},
		{ctStream, "Delivery", "delivery_id"},
		{ctStream, "EnvelopeDelivery", "signed_envelope"},
		{ctStream, "TrustDocument", "document"},
		{ctStream, "StatusRequest", "challenge"},
		{ctStream, "MessageAck", "outcome"},
		{ctEnrollment, "EnrollResponse", "certificate"},
		{ctEnrollment, "RenewResponse", "certificate"},
		{ctEnrollment, "RenewResponse", "refusal"},
		{ctTelemetry, "TelemetryAck", "batch_seq"},
		{ctErrors, "EndDetail", "reason"},
	} {
		full := string(p.file.Package()) + "." + p.msg + "." + p.field
		cases = append(cases, classMutation{
			name:   "X on control-plane-to-agent " + p.msg + "." + p.field,
			edit:   setClassOn(p.file, p.msg, p.field, clsX),
			want:   []string{vInbound(full)},
			absent: []protoreflect.FullName{protoreflect.FullName(full)},
		})
	}
	return cases
}

// TestClassTableMutations is AC1 and MA2: each contract edit makes the
// generator report exactly the expected violations, and the table gets
// no entry for an unclassified or out-of-scope field.
func TestClassTableMutations(t *testing.T) {
	for _, c := range classMutations() {
		t.Run(c.name, func(t *testing.T) {
			files := contractFiles(t, func(m fileProtos) { c.edit(t, m) })
			entries, got := generateClassTable(files)
			if got, want := sortedCopy(got), sortedCopy(c.want); !slices.Equal(got, want) {
				t.Errorf("violations =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			table := entryMap(entries)
			for _, name := range c.absent {
				if cl, ok := table[name]; ok {
					t.Errorf("%s: entry %v, want none", name, cl)
				}
			}
			for name, want := range c.present {
				if cl, ok := table[name]; !ok || cl != want {
					t.Errorf("%s: entry %v, %v; want %v", name, cl, ok, want)
				}
			}
		})
	}
}

// TestClassTableUndefinedClass: a redact_class value outside the enum is
// not a class of §4.1 (R5 "exactly one class in §4.1"): the field is
// reported and gets no entry. Only the field-name prefix is fixed; the
// message wording is the implementation's.
func TestClassTableUndefinedClass(t *testing.T) {
	const field = "warden.agentapi.v1.LogEvent.extract"
	files := contractFiles(t, setClassOnT(t, ctTelemetry, "LogEvent", "extract", wardenv1.RedactFieldClass(99)))
	entries, got := generateClassTable(files)
	if !slices.ContainsFunc(got, func(v string) bool { return strings.HasPrefix(v, field+": ") }) {
		t.Errorf("violations = %q, want one for %s", got, field)
	}
	if c, ok := entryMap(entries)[field]; ok {
		t.Errorf("%s: entry %v for an undefined class", field, c)
	}
}

func setClassOnT(t *testing.T, fd protoreflect.FileDescriptor, msg, field string, c wardenv1.RedactFieldClass) func(fileProtos) {
	return func(m fileProtos) { setClassOn(fd, msg, field, c)(t, m) }
}

// TestClassTableContractFilesIsolated: contractFiles hands out every
// contract file and a private copy: an edit changes neither the
// registered descriptors, the compiled table, nor the next copy.
func TestClassTableContractFilesIsolated(t *testing.T) {
	const field protoreflect.FullName = "warden.agentapi.v1.LogEvent.extract"
	var keys []string
	edited := contractFiles(t, func(m fileProtos) {
		for k := range m {
			keys = append(keys, k)
		}
		setClassOn(ctTelemetry, "LogEvent", "extract", clsS)(t, m)
	})
	for _, fd := range []protoreflect.FileDescriptor{ctEnrollment, ctErrors, ctOutbox, ctService,
		ctStream, ctTelemetry, ctPrimitive, ctExecutor, wardenv1.File_warden_v1_options_proto} {
		if !slices.Contains(keys, fd.Path()) {
			t.Errorf("edit map has no %s (has %v)", fd.Path(), keys)
		}
	}
	classOf := func(d protoreflect.Descriptor, err error) wardenv1.RedactFieldClass {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return proto.GetExtension(d.Options(), wardenv1.E_RedactClass).(wardenv1.RedactFieldClass)
	}
	if c := classOf(edited.FindDescriptorByName(field)); c != clsS {
		t.Errorf("edited copy: %s class %v, want S", field, c)
	}
	if c := classOf(messageByName(t, "warden.agentapi.v1.LogEvent").Fields().ByName("extract"), nil); c != clsEText {
		t.Errorf("registered descriptor changed: %s class %v", field, c)
	}
	if c := classOf(contractFiles(t, nil).FindDescriptorByName(field)); c != clsEText {
		t.Errorf("a later copy sees the edit: %s class %v", field, c)
	}
	if c, ok := agentapiv1.FieldClass(field); ok && c != clsEText {
		t.Errorf("compiled table changed: FieldClass(%s) = %v", field, c)
	}
}

// ---------------------------------------------------------------------------
// R5: a stale committed table fails the build.

// TestClassTableStaleDiff: classTableDiff reports an entry for a removed
// field, a changed class and a missing entry, each with its line, and
// nothing for equal tables.
func TestClassTableStaleDiff(t *testing.T) {
	const (
		extract = "warden.agentapi.v1.LogEvent.extract"
		ruleID  = "warden.agentapi.v1.LogEvent.rule_id"
		value   = "warden.agentapi.v1.Label.value"
		removed = "warden.agentapi.v1.HealthReport.removed_field"
	)
	fresh := []classEntry{{value, clsLValue}, {extract, clsEText}, {ruleID, clsX}}
	type table = map[protoreflect.FullName]wardenv1.RedactFieldClass
	for _, c := range []struct {
		name     string
		compiled table
		fresh    []classEntry
		want     []string
	}{
		{"equal", table{value: clsLValue, extract: clsEText, ruleID: clsX}, fresh, nil},
		{"both empty", nil, nil, nil},
		{"entry for a removed field", table{value: clsLValue, extract: clsEText, ruleID: clsX, removed: clsX}, fresh,
			[]string{dExtra(removed)}},
		{"changed class", table{value: clsLValue, extract: clsTText, ruleID: clsX}, fresh,
			[]string{dChanged(extract, clsTText, clsEText)}},
		{"compiled UNSPECIFIED", table{value: clsLValue, extract: wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED, ruleID: clsX}, fresh,
			[]string{dChanged(extract, wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED, clsEText)}},
		{"missing entry", table{value: clsLValue, extract: clsEText}, fresh, []string{dMissing(ruleID)}},
		{"empty compiled table", nil, fresh, []string{dMissing(value), dMissing(extract), dMissing(ruleID)}},
		{"empty fresh generation", table{value: clsLValue}, nil, []string{dExtra(value)}},
		{"all three", table{value: clsLValue, extract: clsTText, removed: clsX}, fresh,
			[]string{dExtra(removed), dChanged(extract, clsTText, clsEText), dMissing(ruleID)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, want := sortedCopy(classTableDiff(c.compiled, c.fresh)), sortedCopy(c.want)
			if !slices.Equal(got, want) {
				t.Errorf("diff =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// TestClassTableStaleAfterContractEdit is AC1: once a field is removed,
// reclassified, added or unreached in the .proto, the committed table no
// longer matches a fresh generation, and the difference names the field.
func TestClassTableStaleAfterContractEdit(t *testing.T) {
	const extract = "warden.agentapi.v1.LogEvent.extract"
	for _, c := range []struct {
		name string
		edit func(*testing.T, fileProtos)
		want []string
	}{{
		name: "field removed",
		edit: func(t *testing.T, m fileProtos) {
			md := ctMsg(t, m, ctTelemetry, "LogEvent")
			md.Field = slices.DeleteFunc(md.Field, func(f *descriptorpb.FieldDescriptorProto) bool { return f.GetName() == "extract" })
		},
		want: []string{dExtra(extract)},
	}, {
		name: "class changed",
		edit: setClassOn(ctTelemetry, "LogEvent", "extract", clsTText),
		want: []string{dChanged(extract, clsEText, clsTText)},
	}, {
		name: "classified field added",
		edit: func(t *testing.T, m fileProtos) {
			f := ctNewField("probe", 999, descriptorpb.FieldDescriptorProto_TYPE_STRING)
			ctSetClass(f, clsX)
			md := ctMsg(t, m, ctTelemetry, "LogEvent")
			md.Field = append(md.Field, f)
		},
		want: []string{dMissing("warden.agentapi.v1.LogEvent.probe")},
	}, {
		name: "message no longer reached",
		edit: func(t *testing.T, m fileProtos) {
			md := ctMsg(t, m, ctStream, "HealthReport")
			md.Field = slices.DeleteFunc(md.Field, func(f *descriptorpb.FieldDescriptorProto) bool { return f.GetName() == "redact_drops" })
		},
		want: []string{
			dExtra("warden.agentapi.v1.RedactDropCount.class"),
			dExtra("warden.agentapi.v1.RedactDropCount.dropped"),
		},
	}} {
		t.Run(c.name, func(t *testing.T) {
			fresh, violations := generateClassTable(contractFiles(t, func(m fileProtos) { c.edit(t, m) }))
			if len(violations) != 0 {
				t.Errorf("violations: %q", violations)
			}
			got, want := sortedCopy(classTableDiff(agentapiv1.CompiledFieldClasses(), fresh)), sortedCopy(c.want)
			if !slices.Equal(got, want) {
				t.Errorf("diff =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// renderClassTable: gofmt-ed Go source whose map round-trips its entries.

var generatedHeader = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

// parseRendered parses rendered source and returns the fieldClasses map
// literal as field name -> wardenv1 identifier, failing on any other
// top-level declaration (a field name must never inject code).
func parseRendered(t *testing.T, src []byte) map[string]string {
	t.Helper()
	if first, _, _ := strings.Cut(string(src), "\n"); !generatedHeader.MatchString(first) {
		t.Errorf("first line %q is not a generated-code header", first)
	}
	formatted, err := format.Source(src)
	if err != nil {
		t.Fatalf("rendered source does not parse: %v\n%s", err, src)
	}
	if !bytes.Equal(formatted, src) {
		t.Errorf("rendered source is not gofmt-ed")
	}
	f, err := parser.ParseFile(token.NewFileSet(), classTableFile, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name.Name != "agentapiv1" {
		t.Errorf("package %s, want agentapiv1", f.Name.Name)
	}
	out := map[string]string{}
	vars := 0
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			t.Errorf("unexpected declaration %T", decl)
			continue
		}
		if gd.Tok == token.IMPORT {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || gd.Tok != token.VAR || len(vs.Names) != 1 || vs.Names[0].Name != "fieldClasses" || len(vs.Values) != 1 {
				t.Errorf("unexpected declaration in rendered source")
				continue
			}
			vars++
			lit, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("fieldClasses is a %T, not a literal", vs.Values[0])
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					t.Fatalf("map element %T", elt)
				}
				key := kv.Key
				if call, ok := key.(*ast.CallExpr); ok && len(call.Args) == 1 {
					key = call.Args[0]
				}
				bl, ok := key.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					t.Fatalf("map key %T is not a string literal", kv.Key)
				}
				name, err := strconv.Unquote(bl.Value)
				if err != nil {
					t.Fatal(err)
				}
				sel, ok := kv.Value.(*ast.SelectorExpr)
				if !ok {
					t.Fatalf("%s: value %T is not a wardenv1 constant", name, kv.Value)
				}
				if _, dup := out[name]; dup {
					t.Errorf("%s: duplicate key", name)
				}
				out[name] = sel.Sel.Name
			}
		}
	}
	if vars != 1 {
		t.Errorf("%d fieldClasses declarations, want 1", vars)
	}
	return out
}

func checkRendered(t *testing.T, entries []classEntry) {
	t.Helper()
	src, err := renderClassTable(entries)
	if err != nil {
		t.Fatal(err)
	}
	got := parseRendered(t, src)
	if len(got) != len(entries) {
		t.Errorf("rendered %d entries, want %d", len(got), len(entries))
	}
	for _, e := range entries {
		if want := "RedactFieldClass_" + e.class.String(); got[string(e.field)] != want {
			t.Errorf("%q: rendered %s, want %s", e.field, got[string(e.field)], want)
		}
	}
}

// TestRenderClassTable: the rendered table is gofmt-ed, carries the
// generated-code header, declares only fieldClasses and round-trips every
// entry, an empty table included; a hostile name stays a string literal.
func TestRenderClassTable(t *testing.T) {
	checkRendered(t, nil)
	checkRendered(t, []classEntry{
		{"warden.agentapi.v1.Label.value", clsLValue},
		{"warden.agentapi.v1.LogEvent.extract", clsEText},
		{"warden.v1.ExecutorStatusBody.keyset_signed_bytes", clsS},
	})
	checkRendered(t, []classEntry{
		{"x\"}\nfunc init() { panic(1) }\nvar _ = map[string]int{\"", clsX},
		{"`raw` \\   \x00 ü", clsI},
	})
}

// ---------------------------------------------------------------------------
// Fuzz tests.

// FuzzFieldClass: FieldClass never panics, and answers from the compiled
// table only, with a defined class other than UNSPECIFIED.
func FuzzFieldClass(f *testing.F) {
	for _, s := range []string{
		"warden.agentapi.v1.LogEvent.extract", "warden.v1.DbSession.user",
		"warden.agentapi.v1.EnrollRequest.format_version", "warden.agentapi.v1.TelemetryAck.batch_seq",
		"warden.agentapi.v1.SignedReplyReport.primitive_result", "warden.v1.IpcRefusal.code",
		"", ".", "..", "../etc/shadow", "warden.agentapi.v1.LogEvent.extract\x00",
		"warden.agentapi.v1.LogEvent.extrаct", "$(id)", "a;b|c&&d", "--config=/tmp/x",
		strings.Repeat("A", 10240),
	} {
		f.Add(s)
	}
	compiled := agentapiv1.CompiledFieldClasses()
	f.Fuzz(func(t *testing.T, name string) {
		c, ok := agentapiv1.FieldClass(protoreflect.FullName(name))
		want, inTable := compiled[protoreflect.FullName(name)]
		if ok != inTable || c != want {
			t.Fatalf("FieldClass(%q) = %v, %v; table has %v, %v", name, c, ok, want, inTable)
		}
		if ok {
			if _, defined := wardenv1.RedactFieldClass_name[int32(c)]; !defined || c == wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED {
				t.Fatalf("FieldClass(%q) = %v", name, c)
			}
		}
	})
}

// FuzzRenderClassTable: whatever the field name, a rendered table is
// valid, gofmt-ed Go that declares only fieldClasses, with the name as a
// string literal that round-trips. A renderer may refuse a name with an
// error; it must never emit code from it.
func FuzzRenderClassTable(f *testing.F) {
	for _, s := range []string{
		"warden.agentapi.v1.LogEvent.extract", "", "\"", "`", "\\", "\n}", "\x00",
		"x\"}\nfunc init() { panic(1) }\nvar _ = map[string]int{\"",
		"*/ /*", "// comment", "  ", "\xff\xfe", strings.Repeat("é", 4096),
	} {
		f.Add(s, uint8(2))
	}
	f.Fuzz(func(t *testing.T, name string, class uint8) {
		c := wardenv1.RedactFieldClass(1 + int32(class)%10) // S … N_PATTERNED
		src, err := renderClassTable([]classEntry{{protoreflect.FullName(name), c}})
		if err != nil {
			return
		}
		got := parseRendered(t, src)
		if len(got) != 1 || got[name] != "RedactFieldClass_"+c.String() {
			t.Fatalf("name %q class %v rendered as %v", name, c, got)
		}
	})
}
