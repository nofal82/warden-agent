package agentapiv1_test

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// TestStructuralOnlyMessages is redaction R14 and R15 as a field-type rule:
// HealthReport and the advisory reports carry no string field at any
// depth, and HealthReport's bytes fields are 32-byte SHA-256 values.
func TestStructuralOnlyMessages(t *testing.T) {
	for _, v := range structuralViolations(contractFiles(t, nil)) {
		t.Error(v)
	}
}

// TestStructuralOnlyDetects: a string field fails even with class X (the
// R5 check alone would accept it), at the top and nested, and a bytes
// field under HealthReport fails unless it is fixed at 32 bytes.
func TestStructuralOnlyDetects(t *testing.T) {
	const (
		str = descriptorpb.FieldDescriptorProto_TYPE_STRING
		byt = descriptorpb.FieldDescriptorProto_TYPE_BYTES
	)
	classedX := func(name string, typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
		f := ctNewField(name, 999, typ)
		ctSetClass(f, clsX)
		return f
	}
	withLen := func(f *descriptorpb.FieldDescriptorProto, min, max uint32) *descriptorpb.FieldDescriptorProto {
		proto.SetExtension(f.Options, wardenv1.E_MinBytes, min)
		proto.SetExtension(f.Options, wardenv1.E_MaxBytes, max)
		return f
	}
	cases := []struct {
		name  string
		file  protoreflect.FileDescriptor
		msg   string
		field func() *descriptorpb.FieldDescriptorProto
		want  []string
	}{
		{"string with class X in HealthReport", ctStream, "HealthReport",
			func() *descriptorpb.FieldDescriptorProto { return classedX("probe", str) },
			[]string{"warden.agentapi.v1.HealthReport.probe: string field under warden.agentapi.v1.HealthReport (R14, R15)"}},
		{"string nested in RedactDropCount", ctStream, "RedactDropCount",
			func() *descriptorpb.FieldDescriptorProto { return classedX("probe", str) },
			[]string{"warden.agentapi.v1.RedactDropCount.probe: string field under warden.agentapi.v1.HealthReport (R14, R15)"}},
		{"string in EnvelopeAdvisory", ctOutbox, "EnvelopeAdvisory",
			func() *descriptorpb.FieldDescriptorProto { return classedX("probe", str) },
			[]string{"warden.agentapi.v1.EnvelopeAdvisory.probe: string field under warden.agentapi.v1.EnvelopeAdvisory (R14, R15)"}},
		{"string in TrustDocumentOversize", ctOutbox, "TrustDocumentOversize",
			func() *descriptorpb.FieldDescriptorProto { return classedX("probe", str) },
			[]string{"warden.agentapi.v1.TrustDocumentOversize.probe: string field under warden.agentapi.v1.TrustDocumentOversize (R14, R15)"}},
		{"string in RecoveryReport", ctOutbox, "RecoveryReport",
			func() *descriptorpb.FieldDescriptorProto { return classedX("probe", str) },
			[]string{"warden.agentapi.v1.RecoveryReport.probe: string field under warden.agentapi.v1.RecoveryReport (R14, R15)"}},
		{"unbounded bytes in HealthReport", ctStream, "HealthReport",
			func() *descriptorpb.FieldDescriptorProto { return classedX("probe", byt) },
			[]string{"warden.agentapi.v1.HealthReport.probe: bytes field under warden.agentapi.v1.HealthReport that is not a 32-byte SHA-256 (R14)"}},
		{"33-byte bytes in HealthReport", ctStream, "HealthReport",
			func() *descriptorpb.FieldDescriptorProto { return withLen(classedX("probe", byt), 33, 33) },
			[]string{"warden.agentapi.v1.HealthReport.probe: bytes field under warden.agentapi.v1.HealthReport that is not a 32-byte SHA-256 (R14)"}},
		{"32-byte bytes in HealthReport", ctStream, "HealthReport",
			func() *descriptorpb.FieldDescriptorProto { return withLen(classedX("probe", byt), 32, 32) },
			nil},
		{"string in Hello is not this rule's", ctStream, "Hello",
			func() *descriptorpb.FieldDescriptorProto { return classedX("probe", str) },
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := contractFiles(t, func(m fileProtos) {
				md := ctMsg(t, m, c.file, c.msg)
				md.Field = append(md.Field, c.field())
			})
			if got := structuralViolations(files); !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
