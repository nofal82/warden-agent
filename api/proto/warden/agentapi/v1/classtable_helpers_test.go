package agentapiv1_test

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"sort"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// classTableFile is the committed, generated class table (redaction.md R5).
const classTableFile = "classtable_gen.go"

var updateClassTable = flag.Bool("update-class-table", false, "rewrite "+classTableFile+" from the redact_class options")

// executorBodies are the executor bodies the agent forwards or scans
// (redaction.md R5; executor-ipc §4.6, §4.7). They travel as bytes inside
// SignedReplyReport, so no descriptor walk reaches them: they are roots.
var executorBodies = []protoreflect.FullName{
	"warden.v1.ExecutorResultBody",
	"warden.v1.TrustInstallResultBody",
	"warden.v1.ExecutorStatusBody",
}

// endDetail is the one control-plane-to-agent message that is not a
// method's response: it travels as a gRPC status detail (agent-api R45,
// §4.10.1 reading 3).
const endDetail protoreflect.FullName = "warden.agentapi.v1.EndDetail"

// nonStringClassAllowed lists the messages where §4.1 gives every field,
// numbers included, a class other than X: EnrollRequest and RenewRequest,
// class I.
// Stricter than §4.10.1 reading 2 on purpose, as is the "reached from
// both directions" rule in generateClassTable (Go reviewer, PR #16; a
// warden spec PR records both).
var nonStringClassAllowed = map[protoreflect.FullName]wardenv1.RedactFieldClass{
	"warden.agentapi.v1.EnrollRequest": clsI,
	"warden.agentapi.v1.RenewRequest":  clsI,
}

// classEntry is one row of the class table.
type classEntry struct {
	field protoreflect.FullName
	class wardenv1.RedactFieldClass
}

// contractFiles returns a private copy of the registered contract files
// (warden.v1, warden.agentapi.v1 and their imports), after edit has
// changed their descriptor protos (keyed by file path). edit may be nil.
func contractFiles(t *testing.T, edit func(map[string]*descriptorpb.FileDescriptorProto)) *protoregistry.Files {
	t.Helper()
	fdps := map[string]*descriptorpb.FileDescriptorProto{}
	var add func(f protoreflect.FileDescriptor)
	add = func(f protoreflect.FileDescriptor) {
		if _, ok := fdps[f.Path()]; ok {
			return
		}
		fdps[f.Path()] = protodesc.ToFileDescriptorProto(f)
		for i := 0; i < f.Imports().Len(); i++ {
			add(f.Imports().Get(i).FileDescriptor)
		}
	}
	for _, pkg := range []protoreflect.FullName{wardenPkg, agentapiPkg} {
		for _, f := range packageFiles(t, pkg) {
			add(f)
		}
	}
	if edit != nil {
		edit(fdps)
	}
	set := &descriptorpb.FileDescriptorSet{}
	for _, fdp := range fdps {
		set.File = append(set.File, fdp)
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatalf("building the contract copy: %v", err)
	}
	return files
}

// outboundRoots returns the agent-to-control-plane roots of the R5 walk:
// the request type of every method of every warden.agentapi.v1 service
// and the three executor bodies.
func outboundRoots(files *protoregistry.Files) ([]protoreflect.MessageDescriptor, error) {
	roots, err := methodTypes(files, protoreflect.MethodDescriptor.Input)
	if err != nil {
		return nil, err
	}
	return addRoots(files, roots, executorBodies...)
}

// inboundRoots returns the control-plane-to-agent roots: the response
// type of every service method and EndDetail (agent-api §4.10.1 reading 3).
func inboundRoots(files *protoregistry.Files) ([]protoreflect.MessageDescriptor, error) {
	roots, err := methodTypes(files, protoreflect.MethodDescriptor.Output)
	if err != nil {
		return nil, err
	}
	return addRoots(files, roots, endDetail)
}

// methodTypes collects one side of every method of every service of
// warden.agentapi.v1, so a new method cannot escape the walk.
func methodTypes(files *protoregistry.Files, side func(protoreflect.MethodDescriptor) protoreflect.MessageDescriptor) ([]protoreflect.MessageDescriptor, error) {
	var out []protoreflect.MessageDescriptor
	services := 0
	files.RangeFilesByPackage(agentapiPkg, func(f protoreflect.FileDescriptor) bool {
		for i := 0; i < f.Services().Len(); i++ {
			services++
			ms := f.Services().Get(i).Methods()
			for j := 0; j < ms.Len(); j++ {
				out = append(out, side(ms.Get(j)))
			}
		}
		return true
	})
	if services == 0 {
		return nil, fmt.Errorf("no service in %s", agentapiPkg)
	}
	return out, nil
}

// addRoots appends the named messages to roots and returns them without
// duplicates, sorted by name.
func addRoots(files *protoregistry.Files, roots []protoreflect.MessageDescriptor, names ...protoreflect.FullName) ([]protoreflect.MessageDescriptor, error) {
	for _, name := range names {
		d, err := files.FindDescriptorByName(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		md, ok := d.(protoreflect.MessageDescriptor)
		if !ok {
			return nil, fmt.Errorf("%s is a %T, not a message", name, d)
		}
		roots = append(roots, md)
	}
	byName := map[protoreflect.FullName]protoreflect.MessageDescriptor{}
	for _, md := range roots {
		byName[md.FullName()] = md
	}
	out := make([]protoreflect.MessageDescriptor, 0, len(byName))
	for _, md := range byName {
		out = append(out, md)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out, nil
}

// reachableMessages is reachable, keeping the descriptors, sorted by name.
func reachableMessages(roots []protoreflect.MessageDescriptor) []protoreflect.MessageDescriptor {
	seen := map[protoreflect.FullName]protoreflect.MessageDescriptor{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if _, ok := seen[md.FullName()]; ok {
			return
		}
		seen[md.FullName()] = md
		for i := 0; i < md.Fields().Len(); i++ {
			if m := md.Fields().Get(i).Message(); m != nil {
				walk(m)
			}
		}
	}
	for _, md := range roots {
		walk(md)
	}
	out := make([]protoreflect.MessageDescriptor, 0, len(seen))
	for _, md := range seen {
		out = append(out, md)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

// generateClassTable walks files from the roots and returns the class
// table sorted by field name, and every violation of R5 and §4.10.1.
func generateClassTable(files *protoregistry.Files) ([]classEntry, []string) {
	out, err := outboundRoots(files)
	if err != nil {
		return nil, []string{"outbound roots: " + err.Error()}
	}
	in, err := inboundRoots(files)
	if err != nil {
		return nil, []string{"inbound roots: " + err.Error()}
	}
	var entries []classEntry
	var violations []string
	outbound := map[protoreflect.FullName]bool{}
	for _, md := range reachableMessages(out) {
		outbound[md.FullName()] = true
		for i := 0; i < md.Fields().Len(); i++ {
			e, v := classifyField(md.Fields().Get(i))
			if v != "" {
				violations = append(violations, v)
			} else if e != nil {
				entries = append(entries, *e)
			}
		}
	}
	for _, md := range reachableMessages(in) {
		if outbound[md.FullName()] {
			violations = append(violations, fmt.Sprintf("%s: reached from both directions", md.FullName()))
		}
		for i := 0; i < md.Fields().Len(); i++ {
			if fd := md.Fields().Get(i); proto.HasExtension(fd.Options(), wardenv1.E_RedactClass) {
				violations = append(violations, fmt.Sprintf("%s: redact_class on a control-plane-to-agent field", fd.FullName()))
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].field < entries[j].field })
	return entries, violations
}

// classifyField returns the table entry of one outbound field, nil for a
// message-typed field (its own fields carry the class), or a violation.
func classifyField(fd protoreflect.FieldDescriptor) (*classEntry, string) {
	if fd.Message() != nil {
		return nil, ""
	}
	has := proto.HasExtension(fd.Options(), wardenv1.E_RedactClass)
	class := clsX // §4.10: a numeric, bool or enum field without the option
	if has {
		class = proto.GetExtension(fd.Options(), wardenv1.E_RedactClass).(wardenv1.RedactFieldClass)
	}
	switch {
	case isStringOrBytes(fd) && !has:
		return nil, fmt.Sprintf("%s: no redact_class", fd.FullName())
	case class == wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED:
		return nil, fmt.Sprintf("%s: redact_class UNSPECIFIED", fd.FullName())
	case wardenv1.RedactFieldClass_name[int32(class)] == "":
		return nil, fmt.Sprintf("%s: redact_class %d is not a class of §4.1", fd.FullName(), class)
	case !isStringOrBytes(fd) && class != clsX && nonStringClassAllowed[fd.ContainingMessage().FullName()] != class:
		return nil, fmt.Sprintf("%s: class %s on a non-string field outside §4.1", fd.FullName(), class)
	}
	return &classEntry{field: fd.FullName(), class: class}, ""
}

// renderClassTable writes entries as the gofmt-ed source of classTableFile.
func renderClassTable(entries []classEntry) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`// Code generated by TestClassTableGenerated (go test -run TestClassTableGenerated -update-class-table); DO NOT EDIT.

package agentapiv1

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// fieldClasses is the redaction class (redaction.md §4.1) of every
// non-message field the agent sends, generated from the redact_class
// options of the .proto files (redaction.md R5, agent-api R52c).
var fieldClasses = map[protoreflect.FullName]wardenv1.RedactFieldClass{
`)
	for _, e := range entries {
		fmt.Fprintf(&b, "%q: wardenv1.RedactFieldClass_%s,\n", e.field, e.class)
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}

// classTableDiff compares a compiled table with a fresh generation, both
// ways.
func classTableDiff(compiled map[protoreflect.FullName]wardenv1.RedactFieldClass, fresh []classEntry) []string {
	var out []string
	inFresh := map[protoreflect.FullName]bool{}
	for _, e := range fresh {
		inFresh[e.field] = true
		c, ok := compiled[e.field]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: missing from the compiled table", e.field))
		case c != e.class:
			out = append(out, fmt.Sprintf("%s: compiled %s, fresh %s", e.field, c, e.class))
		}
	}
	for name := range compiled {
		if !inFresh[name] {
			out = append(out, fmt.Sprintf("%s: in the compiled table, not in a fresh generation", name))
		}
	}
	sort.Strings(out)
	return out
}

// structuralOnly are the messages redaction R14 and R15 keep free of
// text: HealthReport carries enums, numbers and SHA-256 values only (R14),
// the advisory reports have no string fields (R15). The rule is kept as a
// field-type rule beside R5's classes (Go reviewer, PR #16), so a string
// added with class X still fails.
var structuralOnly = []protoreflect.FullName{
	"warden.agentapi.v1.HealthReport",
	"warden.agentapi.v1.EnvelopeAdvisory",
	"warden.agentapi.v1.TrustDocumentOversize",
	"warden.agentapi.v1.RecoveryReport",
}

// sha256Only are the structuralOnly roots whose bytes fields must be
// SHA-256 values: exactly 32 bytes by their options (R14).
var sha256Only = map[protoreflect.FullName]bool{"warden.agentapi.v1.HealthReport": true}

// structuralViolations reports each string field reachable from a
// structuralOnly message, and each bytes field under HealthReport whose
// options do not fix it at 32 bytes.
func structuralViolations(files *protoregistry.Files) []string {
	var out []string
	for _, name := range structuralOnly {
		roots, err := addRoots(files, nil, name)
		if err != nil {
			out = append(out, err.Error())
			continue
		}
		for _, md := range reachableMessages(roots) {
			for i := 0; i < md.Fields().Len(); i++ {
				fd := md.Fields().Get(i)
				switch {
				case fd.Kind() == protoreflect.StringKind:
					out = append(out, fmt.Sprintf("%s: string field under %s (R14, R15)", fd.FullName(), name))
				case fd.Kind() == protoreflect.BytesKind && sha256Only[name] && !exactly32(fd):
					out = append(out, fmt.Sprintf("%s: bytes field under %s that is not a 32-byte SHA-256 (R14)", fd.FullName(), name))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func exactly32(fd protoreflect.FieldDescriptor) bool {
	opts := fd.Options()
	return proto.HasExtension(opts, wardenv1.E_MinBytes) && proto.HasExtension(opts, wardenv1.E_MaxBytes) &&
		proto.GetExtension(opts, wardenv1.E_MinBytes).(uint32) == 32 &&
		proto.GetExtension(opts, wardenv1.E_MaxBytes).(uint32) == 32
}
