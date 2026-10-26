package agentapiv1_test

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// The two contract packages. Referencing a generated symbol of each makes
// sure their files are registered before the tests range over them.
const (
	agentapiPkg protoreflect.FullName = "warden.agentapi.v1"
	wardenPkg   protoreflect.FullName = "warden.v1"
)

var (
	_ = agentapiv1.File_warden_agentapi_v1_service_proto
	_ = wardenv1.File_warden_v1_options_proto
)

// preM1Files are the warden.v1 files that existed before issue #12. They
// are not touched by it and carry no option (agent-api §4.10.1).
var preM1Files = map[string]bool{
	"warden/v1/envelope.proto":      true,
	"warden/v1/typed_request.proto": true,
}

// packageFiles returns every registered file of pkg.
func packageFiles(t *testing.T, pkg protoreflect.FullName) []protoreflect.FileDescriptor {
	t.Helper()
	var files []protoreflect.FileDescriptor
	protoregistry.GlobalFiles.RangeFilesByPackage(pkg, func(f protoreflect.FileDescriptor) bool {
		files = append(files, f)
		return true
	})
	if len(files) == 0 {
		t.Fatalf("no registered file in package %s", pkg)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path() < files[j].Path() })
	return files
}

// newV1Files returns the warden.v1 files added by issue #12: options,
// PrimitiveResult and the executor bodies.
func newV1Files(t *testing.T) []protoreflect.FileDescriptor {
	t.Helper()
	var out []protoreflect.FileDescriptor
	for _, f := range packageFiles(t, wardenPkg) {
		if !preM1Files[f.Path()] {
			out = append(out, f)
		}
	}
	if len(out) < 2 {
		t.Fatalf("found %d new warden.v1 files, want options.proto plus the result and executor files", len(out))
	}
	return out
}

// allMessages lists every message of files, nested ones included, in
// declaration order.
func allMessages(files []protoreflect.FileDescriptor) []protoreflect.MessageDescriptor {
	var out []protoreflect.MessageDescriptor
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			if md.IsMapEntry() {
				continue
			}
			out = append(out, md)
			walk(md.Messages())
		}
	}
	for _, f := range files {
		walk(f.Messages())
	}
	return out
}

// allEnums lists every enum of files, nested ones included.
func allEnums(files []protoreflect.FileDescriptor) []protoreflect.EnumDescriptor {
	var out []protoreflect.EnumDescriptor
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			for j := 0; j < md.Enums().Len(); j++ {
				out = append(out, md.Enums().Get(j))
			}
			walk(md.Messages())
		}
	}
	for _, f := range files {
		for j := 0; j < f.Enums().Len(); j++ {
			out = append(out, f.Enums().Get(j))
		}
		walk(f.Messages())
	}
	return out
}

// relName is a descriptor's name relative to its package, so a table row
// names a nested message as "Outer.Inner".
func relName(pkg, full protoreflect.FullName) string {
	return strings.TrimPrefix(string(full), string(pkg)+".")
}

// ---------------------------------------------------------------------------
// Option sets (agent-api §4.10). An optSet maps an option name to its value,
// with the Go type proto.GetExtension returns for it, so a value of the
// wrong type never compares equal.

type optSet map[string]any

// none states explicitly that a field or message carries no option
// (R52c rule 1: "an empty set stated where a field has none").
var none = optSet{}

func minB(n uint32) optSet     { return optSet{"min_bytes": n} }
func maxB(n uint32) optSet     { return optSet{"max_bytes": n} }
func exactB(n uint32) optSet   { return optSet{"min_bytes": n, "max_bytes": n} }
func maxC(n uint32) optSet     { return optSet{"max_count": n} }
func minU(n uint64) optSet     { return optSet{"min_uint": n} }
func maxU(n uint64) optSet     { return optSet{"max_uint": n} }
func minI(n int64) optSet      { return optSet{"min_int": n} }
func pat(re string) optSet     { return optSet{"pattern": re} }
func sortedBy(f string) optSet { return optSet{"sorted_by": f} }
func maxMsg(n uint32) optSet   { return optSet{"max_message_bytes": n} }
func rc(c wardenv1.RedactFieldClass) optSet {
	return optSet{"redact_class": c}
}

var (
	sorted = optSet{"sorted": true}
	req    = optSet{"required": true}
)

// o merges option sets; a name given twice is a mistake in the table.
func o(sets ...optSet) optSet {
	out := optSet{}
	for _, s := range sets {
		for k, v := range s {
			if _, dup := out[k]; dup {
				panic("option " + k + " given twice")
			}
			out[k] = v
		}
	}
	return out
}

// Redaction classes of redaction.md §4.1.
const (
	clsS          = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_S
	clsX          = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_X
	clsI          = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_I
	clsU          = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_U
	clsTName      = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_T_NAME
	clsTPath      = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_T_PATH
	clsTText      = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_T_TEXT
	clsEText      = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_E_TEXT
	clsLValue     = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_L_VALUE
	clsNPatterned = wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_N_PATTERNED
)

type namedExt struct {
	name string
	xt   protoreflect.ExtensionType
}

// fieldOptionExts is every FieldOptions extension of §4.10, in number
// order (50001–50013).
var fieldOptionExts = []namedExt{
	{"min_bytes", wardenv1.E_MinBytes},
	{"max_bytes", wardenv1.E_MaxBytes},
	{"min_count", wardenv1.E_MinCount},
	{"max_count", wardenv1.E_MaxCount},
	{"min_uint", wardenv1.E_MinUint},
	{"max_uint", wardenv1.E_MaxUint},
	{"min_int", wardenv1.E_MinInt},
	{"max_int", wardenv1.E_MaxInt},
	{"pattern", wardenv1.E_Pattern},
	{"sorted", wardenv1.E_Sorted},
	{"sorted_by", wardenv1.E_SortedBy},
	{"required", wardenv1.E_Required},
	{"redact_class", wardenv1.E_RedactClass},
}

// messageOptionExts is every MessageOptions extension of §4.10 (50101).
var messageOptionExts = []namedExt{
	{"max_message_bytes", wardenv1.E_MaxMessageBytes},
}

// readOptions returns the warden options set on opts, read with
// proto.HasExtension (R52c rule 3: never a zero check, so an option
// explicitly set to 0 or UNSPECIFIED is seen), and a text form of any
// other option (a standard one such as deprecated, or an unknown
// extension), which the contract never uses.
func readOptions(opts proto.Message, exts []namedExt) (optSet, string) {
	got := optSet{}
	if opts == nil || !opts.ProtoReflect().IsValid() {
		return got, ""
	}
	rest := proto.Clone(opts)
	for _, e := range exts {
		if proto.HasExtension(opts, e.xt) {
			got[e.name] = proto.GetExtension(opts, e.xt)
		}
		proto.ClearExtension(rest, e.xt)
	}
	if proto.Size(rest) == 0 {
		return got, ""
	}
	other := prototext.MarshalOptions{}.Format(rest)
	if other == "" {
		other = fmt.Sprintf("%d unknown bytes", len(rest.ProtoReflect().GetUnknown()))
	}
	return got, other
}

// diffOptions compares one descriptor's options with its golden set and
// describes each difference: missing, extra or different.
func diffOptions(name protoreflect.FullName, got, want optSet, exts []namedExt) []string {
	var out []string
	for _, e := range exts {
		g, gok := got[e.name]
		w, wok := want[e.name]
		switch {
		case gok && !wok:
			out = append(out, fmt.Sprintf("%s: extra option %s = %v", name, e.name, g))
		case !gok && wok:
			out = append(out, fmt.Sprintf("%s: missing option %s = %v", name, e.name, w))
		case gok && wok && g != w:
			out = append(out, fmt.Sprintf("%s: option %s = %v (%T), want %v (%T)", name, e.name, g, g, w, w))
		}
	}
	for k := range want {
		if !slices.ContainsFunc(exts, func(e namedExt) bool { return e.name == k }) {
			out = append(out, fmt.Sprintf("%s: golden row names unknown option %s", name, k))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Message tables: one hand-written row per message and per field, written
// from the spec text. The same rows drive the field-number and type check
// and the golden option check, so a row states a field's number, type and
// complete option set once.

type fieldSpec struct {
	num  protoreflect.FieldNumber
	name protoreflect.Name
	// typ is "[repeated |optional ]<type>", where <type> is a scalar kind
	// name (uint32, int64, string, bytes, bool, double, …), "E:<enum>" or
	// "M:<message>". A name without a dot is in the table's package.
	typ  string
	opts optSet
}

type msgSpec struct {
	// oneof, when set, names the one oneof that holds every field
	// (action-envelope §4.1a).
	oneof  protoreflect.Name
	opts   optSet
	fields []fieldSpec
}

type msgTable map[string]msgSpec

// typeOf renders fd in the fieldSpec.typ form.
func typeOf(fd protoreflect.FieldDescriptor) string {
	var b strings.Builder
	switch {
	case fd.IsList():
		b.WriteString("repeated ")
	case fd.HasOptionalKeyword():
		b.WriteString("optional ")
	}
	switch fd.Kind() {
	case protoreflect.EnumKind:
		b.WriteString("E:" + string(fd.Enum().FullName()))
	case protoreflect.MessageKind, protoreflect.GroupKind:
		b.WriteString("M:" + string(fd.Message().FullName()))
	default:
		b.WriteString(fd.Kind().String())
	}
	return b.String()
}

// qualify expands a table type to full names within pkg.
func qualify(pkg protoreflect.FullName, typ string) string {
	prefix := ""
	for _, p := range []string{"repeated ", "optional "} {
		if strings.HasPrefix(typ, p) {
			prefix, typ = p, strings.TrimPrefix(typ, p)
		}
	}
	for _, k := range []string{"E:", "M:"} {
		if name, ok := strings.CutPrefix(typ, k); ok && !strings.Contains(name, ".") {
			typ = k + string(pkg) + "." + name
		}
	}
	return prefix + typ
}

// shapeViolations compares mds with table both ways: every message and
// field has a row with the same number, type, cardinality and oneof, and
// every row matches a declared message or field.
func shapeViolations(pkg protoreflect.FullName, mds []protoreflect.MessageDescriptor, table msgTable) []string {
	var out []string
	seen := map[string]bool{}
	for _, md := range mds {
		key := relName(pkg, md.FullName())
		spec, ok := table[key]
		if !ok {
			out = append(out, fmt.Sprintf("%s: message has no row", md.FullName()))
			continue
		}
		seen[key] = true
		out = append(out, oneofViolations(md, spec)...)
		rows := map[protoreflect.Name]fieldSpec{}
		for _, f := range spec.fields {
			rows[f.name] = f
		}
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			row, ok := rows[fd.Name()]
			if !ok {
				out = append(out, fmt.Sprintf("%s: field has no row", fd.FullName()))
				continue
			}
			delete(rows, fd.Name())
			if fd.Number() != row.num {
				out = append(out, fmt.Sprintf("%s: number %d, want %d", fd.FullName(), fd.Number(), row.num))
			}
			if got, want := typeOf(fd), qualify(pkg, row.typ); got != want {
				out = append(out, fmt.Sprintf("%s: type %q, want %q", fd.FullName(), got, want))
			}
		}
		for _, f := range spec.fields {
			if _, left := rows[f.name]; left {
				out = append(out, fmt.Sprintf("%s.%s: row has no field", md.FullName(), f.name))
			}
		}
	}
	for _, key := range sortedKeys(table) {
		if !seen[key] {
			out = append(out, fmt.Sprintf("%s.%s: row has no message", pkg, key))
		}
	}
	return out
}

func oneofViolations(md protoreflect.MessageDescriptor, spec msgSpec) []string {
	var real []protoreflect.OneofDescriptor
	for i := 0; i < md.Oneofs().Len(); i++ {
		if od := md.Oneofs().Get(i); !od.IsSynthetic() {
			real = append(real, od)
		}
	}
	switch {
	case spec.oneof == "" && len(real) > 0:
		return []string{fmt.Sprintf("%s: unexpected oneof %s", md.FullName(), real[0].Name())}
	case spec.oneof == "":
		return nil
	case len(real) != 1 || real[0].Name() != spec.oneof:
		return []string{fmt.Sprintf("%s: want exactly one oneof %s, have %d", md.FullName(), spec.oneof, len(real))}
	case real[0].Fields().Len() != md.Fields().Len():
		return []string{fmt.Sprintf("%s: fields outside oneof %s", md.FullName(), spec.oneof)}
	}
	return nil
}

// optionViolations is the golden-table comparison of R52c rule 1, both
// ways: a missing, extra or different option on any message or field, a
// non-warden option, a message or field with no row, and a row with no
// message or field each produce one line.
func optionViolations(pkg protoreflect.FullName, mds []protoreflect.MessageDescriptor, table msgTable) []string {
	var out []string
	seen := map[string]bool{}
	for _, md := range mds {
		key := relName(pkg, md.FullName())
		spec, ok := table[key]
		if !ok {
			out = append(out, fmt.Sprintf("%s: no golden row", md.FullName()))
			continue
		}
		seen[key] = true
		if spec.opts == nil {
			out = append(out, fmt.Sprintf("%s: golden row states no option set (use none)", md.FullName()))
		}
		got, other := readOptions(md.Options(), messageOptionExts)
		out = append(out, diffOptions(md.FullName(), got, spec.opts, messageOptionExts)...)
		if other != "" {
			out = append(out, fmt.Sprintf("%s: non-warden option %s", md.FullName(), other))
		}
		rows := map[protoreflect.Name]fieldSpec{}
		for _, f := range spec.fields {
			rows[f.name] = f
		}
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			row, ok := rows[fd.Name()]
			if !ok {
				out = append(out, fmt.Sprintf("%s: no golden row", fd.FullName()))
				continue
			}
			delete(rows, fd.Name())
			if row.opts == nil {
				out = append(out, fmt.Sprintf("%s: golden row states no option set (use none)", fd.FullName()))
			}
			got, other := readOptions(fd.Options(), fieldOptionExts)
			out = append(out, diffOptions(fd.FullName(), got, row.opts, fieldOptionExts)...)
			if other != "" {
				out = append(out, fmt.Sprintf("%s: non-warden option %s", fd.FullName(), other))
			}
		}
		for _, f := range spec.fields {
			if _, left := rows[f.name]; left {
				out = append(out, fmt.Sprintf("%s.%s: golden row matches no field", md.FullName(), f.name))
			}
		}
	}
	for _, key := range sortedKeys(table) {
		if !seen[key] {
			out = append(out, fmt.Sprintf("%s.%s: golden row matches no message", pkg, key))
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// R52c rule 2 checks, reusable on test-only descriptors.

func isStringOrBytes(fd protoreflect.FieldDescriptor) bool {
	return fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind
}

// boundViolations reports every string or bytes field without max_bytes
// and every repeated field without max_count, except the exempt fields
// (R52c rule 2; agent-api §4.10.1 names exactly two).
func boundViolations(mds []protoreflect.MessageDescriptor, exempt map[protoreflect.FullName]bool) []string {
	var out []string
	for _, md := range mds {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if exempt[fd.FullName()] {
				continue
			}
			if isStringOrBytes(fd) && !proto.HasExtension(fd.Options(), wardenv1.E_MaxBytes) {
				out = append(out, fmt.Sprintf("%s: %s field without max_bytes", fd.FullName(), fd.Kind()))
			}
			if fd.IsList() && !proto.HasExtension(fd.Options(), wardenv1.E_MaxCount) {
				out = append(out, fmt.Sprintf("%s: repeated field without max_count", fd.FullName()))
			}
		}
	}
	return out
}

// exemptions reports, both ways, whether the fields left without a bound
// by name are exactly bounded nowhere: an exempt field that gained a
// length option is no longer the documented exemption.
func exemptionViolations(mds []protoreflect.MessageDescriptor, exempt map[protoreflect.FullName]bool) []string {
	var out []string
	found := map[protoreflect.FullName]bool{}
	for _, md := range mds {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if !exempt[fd.FullName()] {
				continue
			}
			found[fd.FullName()] = true
			for _, e := range []namedExt{fieldOptionExts[0], fieldOptionExts[1], fieldOptionExts[2], fieldOptionExts[3]} {
				if proto.HasExtension(fd.Options(), e.xt) {
					out = append(out, fmt.Sprintf("%s: exempt field carries %s", fd.FullName(), e.name))
				}
			}
		}
	}
	for name := range exempt {
		if !found[name] {
			out = append(out, fmt.Sprintf("%s: exempt field not declared", name))
		}
	}
	sort.Strings(out)
	return out
}

// messageLimitViolations reports each named message that lacks
// max_message_bytes (R52c rule 2, §4.2).
func messageLimitViolations(mds []protoreflect.MessageDescriptor, limited map[protoreflect.FullName]bool) []string {
	var out []string
	found := map[protoreflect.FullName]bool{}
	for _, md := range mds {
		if !limited[md.FullName()] {
			continue
		}
		found[md.FullName()] = true
		if !proto.HasExtension(md.Options(), wardenv1.E_MaxMessageBytes) {
			out = append(out, fmt.Sprintf("%s: §4.2 message without max_message_bytes", md.FullName()))
		}
	}
	var missing []string
	for name := range limited {
		if !found[name] {
			missing = append(missing, fmt.Sprintf("%s: §4.2 message not declared", name))
		}
	}
	sort.Strings(missing)
	return append(out, missing...)
}

// redactViolations walks every message reachable from roots, through
// nested messages, every oneof member and imported types (redaction.md R5),
// and reports each string or bytes field whose redact_class is missing or
// UNSPECIFIED.
func redactViolations(roots []protoreflect.MessageDescriptor) []string {
	var out []string
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			switch {
			case fd.Message() != nil:
				walk(fd.Message())
			case isStringOrBytes(fd) && !proto.HasExtension(fd.Options(), wardenv1.E_RedactClass):
				out = append(out, fmt.Sprintf("%s: no redact_class", fd.FullName()))
			case isStringOrBytes(fd) && proto.GetExtension(fd.Options(), wardenv1.E_RedactClass).(wardenv1.RedactFieldClass) == wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED:
				out = append(out, fmt.Sprintf("%s: redact_class UNSPECIFIED", fd.FullName()))
			}
		}
	}
	for _, md := range roots {
		walk(md)
	}
	return out
}

// reachable returns the full names of every message reachable from roots.
func reachable(roots []protoreflect.MessageDescriptor) map[protoreflect.FullName]bool {
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		for i := 0; i < md.Fields().Len(); i++ {
			if m := md.Fields().Get(i).Message(); m != nil {
				walk(m)
			}
		}
	}
	for _, md := range roots {
		walk(md)
	}
	return seen
}

// ---------------------------------------------------------------------------
// R52b allow-list check, reusable on test-only descriptors.

// optionalViolations compares the fields declared proto3 optional
// (HasOptionalKeyword, a synthetic oneof) with allow, both ways.
func optionalViolations(mds []protoreflect.MessageDescriptor, allow []protoreflect.FullName) []string {
	var out []string
	byName := map[protoreflect.FullName]protoreflect.FieldDescriptor{}
	for _, md := range mds {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			byName[fd.FullName()] = fd
			if fd.HasOptionalKeyword() && !slices.Contains(allow, fd.FullName()) {
				out = append(out, fmt.Sprintf("%s: optional field not in the R52b allow-list", fd.FullName()))
			}
		}
	}
	for _, name := range allow {
		fd, ok := byName[name]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: allow-listed field not declared", name))
		case !fd.HasOptionalKeyword():
			out = append(out, fmt.Sprintf("%s: allow-listed field declared without optional", name))
		}
	}
	return out
}

// messageByName finds a message of pkg's registered files.
func messageByName(t *testing.T, name protoreflect.FullName) protoreflect.MessageDescriptor {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("%s is a %T, not a message", name, d)
	}
	return md
}
