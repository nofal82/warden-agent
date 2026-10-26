package agentapiv1_test

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// TestGoldenOptionsAgentapi is R52c rule 1: the complete option set of
// every message and field of warden.agentapi.v1 equals the hand-written
// golden table, both ways.
func TestGoldenOptionsAgentapi(t *testing.T) {
	for _, v := range optionViolations(agentapiPkg, allMessages(packageFiles(t, agentapiPkg)), agentapiTable) {
		t.Error(v)
	}
}

// TestGoldenOptionsNewV1: every warden.v1 message added by issue #12
// carries exactly the redact_class options of the golden table and nothing
// else (agent-api §4.10.1: in M1 only redact_class, on R5's scope).
func TestGoldenOptionsNewV1(t *testing.T) {
	for _, v := range optionViolations(wardenPkg, allMessages(newV1Files(t)), v1Table) {
		t.Error(v)
	}
}

// TestWardenV1CarriesOnlyRedactClass: no warden.v1 message carries a
// message option and no warden.v1 field carries an option other than
// redact_class, in every file of the package, envelope.proto and
// typed_request.proto included (agent-api §4.10.1, R52c: warden.v1 limits
// stay hand-written until the M2 envelope change).
func TestWardenV1CarriesOnlyRedactClass(t *testing.T) {
	for _, md := range allMessages(packageFiles(t, wardenPkg)) {
		if got, other := readOptions(md.Options(), messageOptionExts); len(got) > 0 || other != "" {
			t.Errorf("%s: message options %v %s", md.FullName(), got, other)
		}
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			got, other := readOptions(fd.Options(), fieldOptionExts)
			delete(got, "redact_class")
			if len(got) > 0 || other != "" {
				t.Errorf("%s: options %v %s", fd.FullName(), got, other)
			}
		}
	}
}

// TestPreM1FilesCarryNoOption: envelope.proto and typed_request.proto are
// not touched by issue #12 and carry no option at all; their messages are
// outside redaction R5's scope.
func TestPreM1FilesCarryNoOption(t *testing.T) {
	var files []protoreflect.FileDescriptor
	for _, f := range packageFiles(t, wardenPkg) {
		if preM1Files[f.Path()] {
			files = append(files, f)
		}
	}
	if len(files) != len(preM1Files) {
		t.Fatalf("found %d of the %d pre-M1 files", len(files), len(preM1Files))
	}
	for _, md := range allMessages(files) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if got, other := readOptions(fd.Options(), fieldOptionExts); len(got) > 0 || other != "" {
				t.Errorf("%s: options %v %s", fd.FullName(), got, other)
			}
		}
	}
}

// TestEveryGoldenRowStatesItsSet: a nil option set in a row would read as
// "not written"; R52c rule 1 wants an empty set stated where a field has
// none.
func TestEveryGoldenRowStatesItsSet(t *testing.T) {
	for _, table := range []msgTable{agentapiTable, v1Table} {
		for name, m := range table {
			if m.opts == nil {
				t.Errorf("%s: message row has no option set", name)
			}
			for _, f := range m.fields {
				if f.opts == nil {
					t.Errorf("%s.%s: field row has no option set", name, f.name)
				}
			}
		}
	}
}

// TestBoundOptions is R52c rule 2 for lengths and counts: every string,
// bytes and repeated field of warden.agentapi.v1 has max_bytes or
// max_count, except the two exemptions of §4.10.1, which carry no length
// option at all.
func TestBoundOptions(t *testing.T) {
	mds := allMessages(packageFiles(t, agentapiPkg))
	for _, v := range boundViolations(mds, boundExempt) {
		t.Error(v)
	}
	for _, v := range exemptionViolations(mds, boundExempt) {
		t.Error(v)
	}
}

// TestMessageSizeOptions is R52c rule 2 for §4.2: each message with a
// per-type limit has max_message_bytes, and no other message has it.
func TestMessageSizeOptions(t *testing.T) {
	mds := allMessages(packageFiles(t, agentapiPkg))
	for _, v := range messageLimitViolations(mds, sizeLimitedMessages) {
		t.Error(v)
	}
	for _, md := range mds {
		if !sizeLimitedMessages[md.FullName()] && proto.HasExtension(md.Options(), wardenv1.E_MaxMessageBytes) {
			t.Errorf("%s: max_message_bytes on a message §4.2 gives no limit", md.FullName())
		}
	}
}

// TestNoZeroBound: a bound of 0 never means "unlimited" (R52c rule 3); no
// option of the contract states a maximum of 0.
func TestNoZeroBound(t *testing.T) {
	maxima := []namedExt{fieldOptionExts[1], fieldOptionExts[3], fieldOptionExts[5]}
	for _, md := range allMessages(packageFiles(t, agentapiPkg)) {
		if proto.HasExtension(md.Options(), wardenv1.E_MaxMessageBytes) &&
			proto.GetExtension(md.Options(), wardenv1.E_MaxMessageBytes).(uint32) == 0 {
			t.Errorf("%s: max_message_bytes 0", md.FullName())
		}
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			for _, e := range maxima {
				if !proto.HasExtension(fd.Options(), e.xt) {
					continue
				}
				switch v := proto.GetExtension(fd.Options(), e.xt).(type) {
				case uint32:
					if v == 0 {
						t.Errorf("%s: %s 0", fd.FullName(), e.name)
					}
				case uint64:
					if v == 0 {
						t.Errorf("%s: %s 0", fd.FullName(), e.name)
					}
				}
			}
		}
	}
}

// TestRequiredOptionExactlyTen: option 50012 is set on exactly the ten
// fields of §4.10.1, and on no other field of either package.
func TestRequiredOptionExactlyTen(t *testing.T) {
	var got []protoreflect.FullName
	files := append(packageFiles(t, agentapiPkg), packageFiles(t, wardenPkg)...)
	for _, md := range allMessages(files) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if proto.HasExtension(fd.Options(), wardenv1.E_Required) {
				got = append(got, fd.FullName())
				if !proto.GetExtension(fd.Options(), wardenv1.E_Required).(bool) {
					t.Errorf("%s: required = false", fd.FullName())
				}
			}
		}
	}
	want := slices.Clone(requiredFields)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("required on %v, want %v", got, want)
	}
}

// TestRedactClassInR5Scope is R52c rule 2 for redaction.md R5: every
// string and bytes field reachable from the agent-to-control-plane
// messages and the three executor bodies, through nested messages, oneof
// members and imported warden.v1 types, has a redact_class other than
// UNSPECIFIED.
func TestRedactClassInR5Scope(t *testing.T) {
	var roots []protoreflect.MessageDescriptor
	for _, name := range r5Roots {
		roots = append(roots, messageByName(t, name))
	}
	for _, v := range redactViolations(roots) {
		t.Error(v)
	}
	// The walk must reach every PrimitiveResult variant and every message
	// of the executor bodies, or the check above proves nothing for them.
	seen := reachable(roots)
	for name := range v1Table {
		if name == "IpcRefusal" { // an unsigned transport answer, not forwarded
			continue
		}
		if !seen[protoreflect.FullName("warden.v1."+name)] {
			t.Errorf("warden.v1.%s is not reached by the R5 walk", name)
		}
	}
	for _, name := range []string{"Hello", "DeliveryAck", "HealthReport", "RedactDropCount",
		"OutboxMessage", "OutboxPayload", "SignedReplyReport", "EnvelopeAdvisory",
		"TrustDocumentOversize", "RecoveryReport", "AdminToolRecord", "MetricSample",
		"Label", "LogEvent"} {
		if !seen[protoreflect.FullName("warden.agentapi.v1."+name)] {
			t.Errorf("warden.agentapi.v1.%s is not reached by the R5 walk", name)
		}
	}
}

// TestNoRedactClassControlPlaneToAgent: §4.10.1 reading 3, control-plane-
// to-agent messages are outside R5's scope and carry no redact_class.
func TestNoRedactClassControlPlaneToAgent(t *testing.T) {
	var roots []protoreflect.MessageDescriptor
	for _, name := range []protoreflect.FullName{
		"warden.agentapi.v1.ControlMessage", "warden.agentapi.v1.EnrollResponse",
		"warden.agentapi.v1.RenewResponse", "warden.agentapi.v1.TelemetryAck",
	} {
		roots = append(roots, messageByName(t, name))
	}
	for name := range reachable(roots) {
		md := messageByName(t, name)
		for i := 0; i < md.Fields().Len(); i++ {
			if fd := md.Fields().Get(i); proto.HasExtension(fd.Options(), wardenv1.E_RedactClass) {
				t.Errorf("%s: redact_class on a control-plane-to-agent field", fd.FullName())
			}
		}
	}
}

// TestGoldenPatterns: every pattern of the tables is a valid RE2
// expression anchored with ^ and $ (§4.10), and the SemVer patterns behave
// as §4.10.1 states: 0.0.0-redacted matches both, the empty value only the
// optional one.
func TestGoldenPatterns(t *testing.T) {
	for _, table := range []msgTable{agentapiTable, v1Table} {
		for name, m := range table {
			for _, f := range m.fields {
				p, ok := f.opts["pattern"].(string)
				if !ok {
					continue
				}
				if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
					t.Errorf("%s.%s: pattern %q not anchored", name, f.name, p)
				}
				if _, err := regexp.Compile(p); err != nil {
					t.Errorf("%s.%s: %v", name, f.name, err)
				}
			}
		}
	}
	strict := regexp.MustCompile(semverPattern)
	empty := regexp.MustCompile(semverOrEmptyPattern)
	for _, c := range []struct {
		v             string
		strict, empty bool
	}{
		{"0.0.0-redacted", true, true},
		{"1.2.3", true, true},
		{"1.2.3-rc.1", true, true},
		{"", false, true},
		{"01.2.3", false, false},
		{"1.2.3+build", false, false},
		{"1.2", false, false},
		{"1.2.3-01", false, false},
		{"v1.2.3", false, false},
		{"1.2.3\n", false, false},
	} {
		if strict.MatchString(c.v) != c.strict || empty.MatchString(c.v) != c.empty {
			t.Errorf("%q: strict %v, optional %v; want %v, %v", c.v,
				strict.MatchString(c.v), empty.MatchString(c.v), c.strict, c.empty)
		}
	}
	// §4.10.1 reading 4: max_bytes derived from the pattern's own bound.
	for _, c := range []struct {
		re  string
		max int
	}{{metricNamePattern, 128}, {labelKeyPattern, 64}, {ruleIDPattern, 63}} {
		re := regexp.MustCompile(c.re)
		if !re.MatchString("a" + strings.Repeat("b", c.max-1)) {
			t.Errorf("%s: rejects a %d-byte value", c.re, c.max)
		}
		if re.MatchString("a" + strings.Repeat("b", c.max)) {
			t.Errorf("%s: accepts a %d-byte value", c.re, c.max+1)
		}
	}
}

// ---------------------------------------------------------------------------
// AC49: the checks above fail on test-only descriptors that break them.

func setExt(opts proto.Message, xt protoreflect.ExtensionType, v any) {
	proto.SetExtension(opts, xt, v)
}

// probeFileProto is a test-only file, outside the contract, whose options
// exactly match probeTable.
func probeFileProto() *descriptorpb.FileDescriptorProto {
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	field := func(name string, num int32, label *descriptorpb.FieldDescriptorProto_Label, typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num), Label: label, Type: typ.Enum(),
			Options: &descriptorpb.FieldOptions{},
		}
	}
	name := field("name", 1, opt, descriptorpb.FieldDescriptorProto_TYPE_STRING)
	setExt(name.Options, wardenv1.E_MaxBytes, uint32(32))
	setExt(name.Options, wardenv1.E_Pattern, "^[a-z]+$")
	setExt(name.Options, wardenv1.E_RedactClass, clsX)
	items := field("items", 2, rep, descriptorpb.FieldDescriptorProto_TYPE_BYTES)
	setExt(items.Options, wardenv1.E_MaxCount, uint32(2))
	setExt(items.Options, wardenv1.E_MinBytes, uint32(16))
	setExt(items.Options, wardenv1.E_MaxBytes, uint32(16))
	setExt(items.Options, wardenv1.E_Sorted, true)
	setExt(items.Options, wardenv1.E_RedactClass, clsS)
	seq := field("seq", 3, opt, descriptorpb.FieldDescriptorProto_TYPE_UINT64)
	setExt(seq.Options, wardenv1.E_MinUint, uint64(1))
	setExt(seq.Options, wardenv1.E_MaxUint, uint64(10))
	kind := field("kind", 4, opt, descriptorpb.FieldDescriptorProto_TYPE_INT32)
	setExt(kind.Options, wardenv1.E_Required, true)
	inner := field("inner", 5, opt, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE)
	inner.TypeName = proto.String(".wardentest.golden.Inner")
	inner.Options = nil
	text := field("text", 1, opt, descriptorpb.FieldDescriptorProto_TYPE_STRING)
	setExt(text.Options, wardenv1.E_MaxBytes, uint32(8))
	setExt(text.Options, wardenv1.E_RedactClass, clsTText)

	probeOpts := &descriptorpb.MessageOptions{}
	setExt(probeOpts, wardenv1.E_MaxMessageBytes, uint32(64))
	return &descriptorpb.FileDescriptorProto{
		Name:    proto.String("wardentest/golden.proto"),
		Package: proto.String("wardentest.golden"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Probe"), Options: probeOpts,
				Field: []*descriptorpb.FieldDescriptorProto{name, items, seq, kind, inner}},
			{Name: proto.String("Inner"), Field: []*descriptorpb.FieldDescriptorProto{text}},
		},
	}
}

const probePkg protoreflect.FullName = "wardentest.golden"

func probeTable() msgTable {
	return msgTable{
		"Probe": {opts: maxMsg(64), fields: []fieldSpec{
			{1, "name", "string", o(maxB(32), pat("^[a-z]+$"), rc(clsX))},
			{2, "items", "repeated bytes", o(maxC(2), exactB(16), sorted, rc(clsS))},
			{3, "seq", "uint64", o(minU(1), maxU(10))},
			{4, "kind", "int32", req},
			{5, "inner", "M:Inner", none},
		}},
		"Inner": {opts: none, fields: []fieldSpec{
			{1, "text", "string", o(maxB(8), rc(clsTText))},
		}},
	}
}

func buildProbe(t *testing.T, fdp *descriptorpb.FileDescriptorProto) []protoreflect.MessageDescriptor {
	t.Helper()
	f, err := protodesc.NewFile(fdp, new(protoregistry.Files))
	if err != nil {
		t.Fatal(err)
	}
	return allMessages([]protoreflect.FileDescriptor{f})
}

func probeField(fdp *descriptorpb.FileDescriptorProto, msg, field string) *descriptorpb.FieldDescriptorProto {
	for _, m := range fdp.MessageType {
		if m.GetName() != msg {
			continue
		}
		for _, f := range m.Field {
			if f.GetName() == field {
				return f
			}
		}
	}
	panic("no field " + msg + "." + field)
}

// probeChecks runs every check of this file on the probe and returns the
// violations, sorted.
func probeChecks(t *testing.T, fdp *descriptorpb.FileDescriptorProto, table msgTable) []string {
	t.Helper()
	mds := buildProbe(t, fdp)
	var probe protoreflect.MessageDescriptor
	for _, md := range mds {
		if md.Name() == "Probe" {
			probe = md
		}
	}
	var out []string
	out = append(out, optionViolations(probePkg, mds, table)...)
	out = append(out, shapeViolations(probePkg, mds, table)...)
	out = append(out, boundViolations(mds, nil)...)
	out = append(out, messageLimitViolations(mds, map[protoreflect.FullName]bool{"wardentest.golden.Probe": true})...)
	out = append(out, redactViolations([]protoreflect.MessageDescriptor{probe})...)
	sort.Strings(out)
	return out
}

func TestProbeBaselinePasses(t *testing.T) {
	if got := probeChecks(t, probeFileProto(), probeTable()); len(got) != 0 {
		t.Errorf("baseline probe has violations:\n%s", strings.Join(got, "\n"))
	}
}

// TestChecksDetectViolations (AC49): each broken descriptor or table makes
// the checks report exactly the expected lines.
func TestChecksDetectViolations(t *testing.T) {
	cases := []struct {
		name  string
		file  func(*descriptorpb.FileDescriptorProto)
		table func(msgTable)
		want  []string
	}{{
		name: "string field lacking max_bytes",
		file: func(f *descriptorpb.FileDescriptorProto) {
			proto.ClearExtension(probeField(f, "Probe", "name").Options, wardenv1.E_MaxBytes)
		},
		table: func(m msgTable) { m["Probe"].fields[0].opts = o(pat("^[a-z]+$"), rc(clsX)) },
		want:  []string{"wardentest.golden.Probe.name: string field without max_bytes"},
	}, {
		name: "repeated field lacking max_count",
		file: func(f *descriptorpb.FileDescriptorProto) {
			proto.ClearExtension(probeField(f, "Probe", "items").Options, wardenv1.E_MaxCount)
		},
		table: func(m msgTable) { m["Probe"].fields[1].opts = o(exactB(16), sorted, rc(clsS)) },
		want:  []string{"wardentest.golden.Probe.items: repeated field without max_count"},
	}, {
		name: "§4.2 message lacking max_message_bytes",
		file: func(f *descriptorpb.FileDescriptorProto) { f.MessageType[0].Options = nil },
		table: func(m msgTable) {
			p := m["Probe"]
			p.opts = none
			m["Probe"] = p
		},
		want: []string{"wardentest.golden.Probe: §4.2 message without max_message_bytes"},
	}, {
		name: "R5-scope string lacking redact_class",
		file: func(f *descriptorpb.FileDescriptorProto) {
			proto.ClearExtension(probeField(f, "Inner", "text").Options, wardenv1.E_RedactClass)
		},
		table: func(m msgTable) { m["Inner"].fields[0].opts = maxB(8) },
		want:  []string{"wardentest.golden.Inner.text: no redact_class"},
	}, {
		name: "R5-scope string with redact_class UNSPECIFIED",
		file: func(f *descriptorpb.FileDescriptorProto) {
			setExt(probeField(f, "Inner", "text").Options, wardenv1.E_RedactClass, wardenv1.RedactFieldClass_REDACT_FIELD_CLASS_UNSPECIFIED)
		},
		want: []string{
			"wardentest.golden.Inner.text: option redact_class = REDACT_FIELD_CLASS_UNSPECIFIED (wardenv1.RedactFieldClass), want REDACT_FIELD_CLASS_T_TEXT (wardenv1.RedactFieldClass)",
			"wardentest.golden.Inner.text: redact_class UNSPECIFIED",
		},
	}, {
		name: "golden: dropped required",
		file: func(f *descriptorpb.FileDescriptorProto) {
			proto.ClearExtension(probeField(f, "Probe", "kind").Options, wardenv1.E_Required)
		},
		want: []string{"wardentest.golden.Probe.kind: missing option required = true"},
	}, {
		name: "golden: dropped pattern",
		file: func(f *descriptorpb.FileDescriptorProto) {
			proto.ClearExtension(probeField(f, "Probe", "name").Options, wardenv1.E_Pattern)
		},
		want: []string{"wardentest.golden.Probe.name: missing option pattern = ^[a-z]+$"},
	}, {
		name: "golden: dropped range option",
		file: func(f *descriptorpb.FileDescriptorProto) {
			proto.ClearExtension(probeField(f, "Probe", "seq").Options, wardenv1.E_MinUint)
		},
		want: []string{"wardentest.golden.Probe.seq: missing option min_uint = 1"},
	}, {
		name: "golden: max_bytes changed tenfold",
		file: func(f *descriptorpb.FileDescriptorProto) {
			setExt(probeField(f, "Probe", "name").Options, wardenv1.E_MaxBytes, uint32(320))
		},
		want: []string{"wardentest.golden.Probe.name: option max_bytes = 320 (uint32), want 32 (uint32)"},
	}, {
		name: "golden: extra option",
		file: func(f *descriptorpb.FileDescriptorProto) {
			setExt(probeField(f, "Probe", "seq").Options, wardenv1.E_Sorted, true)
		},
		want: []string{"wardentest.golden.Probe.seq: extra option sorted = true"},
	}, {
		name: "golden: extra message option",
		file: func(f *descriptorpb.FileDescriptorProto) {
			f.MessageType[1].Options = &descriptorpb.MessageOptions{}
			setExt(f.MessageType[1].Options, wardenv1.E_MaxMessageBytes, uint32(64))
		},
		want: []string{"wardentest.golden.Inner: extra option max_message_bytes = 64"},
	}, {
		name: "golden: field with no row",
		file: func(f *descriptorpb.FileDescriptorProto) {
			opts := &descriptorpb.FieldOptions{}
			setExt(opts, wardenv1.E_MaxBytes, uint32(4))
			setExt(opts, wardenv1.E_RedactClass, clsX)
			f.MessageType[0].Field = append(f.MessageType[0].Field, &descriptorpb.FieldDescriptorProto{
				Name: proto.String("added"), Number: proto.Int32(6),
				Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Options: opts,
			})
		},
		want: []string{
			"wardentest.golden.Probe.added: field has no row",
			"wardentest.golden.Probe.added: no golden row",
		},
	}, {
		name: "golden: row with no field",
		table: func(m msgTable) {
			p := m["Probe"]
			p.fields = append(p.fields, fieldSpec{6, "ghost", "bool", none})
			m["Probe"] = p
		},
		want: []string{
			"wardentest.golden.Probe.ghost: golden row matches no field",
			"wardentest.golden.Probe.ghost: row has no field",
		},
	}, {
		name: "golden: message with no row",
		table: func(m msgTable) {
			delete(m, "Inner")
		},
		want: []string{
			"wardentest.golden.Inner: message has no row",
			"wardentest.golden.Inner: no golden row",
		},
	}, {
		name:  "golden: row with no message",
		table: func(m msgTable) { m["Ghost"] = msgSpec{opts: none} },
		want: []string{
			"wardentest.golden.Ghost: golden row matches no message",
			"wardentest.golden.Ghost: row has no message",
		},
	}, {
		name:  "golden: row with an unstated option set",
		table: func(m msgTable) { m["Probe"].fields[4].opts = nil },
		want:  []string{"wardentest.golden.Probe.inner: golden row states no option set (use none)"},
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fdp := probeFileProto()
			table := probeTable()
			if c.file != nil {
				c.file(fdp)
			}
			if c.table != nil {
				c.table(table)
			}
			got := probeChecks(t, fdp, table)
			if !slices.Equal(got, c.want) {
				t.Errorf("violations =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// TestChecksDetectNonWardenOption: a standard option (here deprecated) or
// an unknown extension is reported as an extra option the contract does
// not use. The text form of the option is not stable, so only the prefix
// is compared.
func TestChecksDetectNonWardenOption(t *testing.T) {
	fdp := probeFileProto()
	probeField(fdp, "Probe", "seq").Options.Deprecated = proto.Bool(true)
	got := probeChecks(t, fdp, probeTable())
	if len(got) != 1 || !strings.HasPrefix(got[0], "wardentest.golden.Probe.seq: non-warden option ") {
		t.Errorf("violations = %q, want one non-warden option on seq", got)
	}
}

// TestExemptionViolationsDetects: an exempt field that gains a length
// option, or an exemption naming no field, is reported.
func TestExemptionViolationsDetects(t *testing.T) {
	mds := buildProbe(t, probeFileProto())
	got := exemptionViolations(mds, map[protoreflect.FullName]bool{
		"wardentest.golden.Probe.name":  true,
		"wardentest.golden.Probe.ghost": true,
	})
	want := []string{
		"wardentest.golden.Probe.ghost: exempt field not declared",
		"wardentest.golden.Probe.name: exempt field carries max_bytes",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := boundViolations(mds, map[protoreflect.FullName]bool{"wardentest.golden.Probe.name": true}); len(got) != 0 {
		t.Errorf("exempt field still reported: %q", got)
	}
}

// TestRedactWalkFollowsOneofsAndImports: the R5 walk reaches a string
// field that sits only behind a oneof member in another file.
func TestRedactWalkFollowsOneofsAndImports(t *testing.T) {
	files := new(protoregistry.Files)
	leaf, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("wardentest/leaf.proto"),
		Package: proto.String("wardentest.leaf"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Leaf"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name: proto.String("secret_text"), Number: proto.Int32(1),
				Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(),
			}},
		}},
	}, files)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.RegisterFile(leaf); err != nil {
		t.Fatal(err)
	}
	root, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:       proto.String("wardentest/root.proto"),
		Package:    proto.String("wardentest.root"),
		Syntax:     proto.String("proto3"),
		Dependency: []string{"wardentest/leaf.proto"},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Root"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name: proto.String("leaf"), Number: proto.Int32(1),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
				TypeName: proto.String(".wardentest.leaf.Leaf"), OneofIndex: proto.Int32(0),
			}},
			OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}},
		}},
	}, files)
	if err != nil {
		t.Fatal(err)
	}
	got := redactViolations([]protoreflect.MessageDescriptor{root.Messages().Get(0)})
	if want := []string{"wardentest.leaf.Leaf.secret_text: no redact_class"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
