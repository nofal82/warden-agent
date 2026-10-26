package agentapiv1_test

import (
	"errors"
	"flag"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// classTableFile is the committed, generated class table (redaction.md R5).
const classTableFile = "classtable_gen.go"

var updateClassTable = flag.Bool("update-class-table", false, "rewrite "+classTableFile+" from the redact_class options")

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
	t.Fatal("not implemented")
	return nil
}

// outboundRoots returns the agent-to-control-plane roots of the R5 walk:
// the request type of every method of every warden.agentapi.v1 service
// and the three executor bodies.
func outboundRoots(files *protoregistry.Files) ([]protoreflect.MessageDescriptor, error) {
	return nil, errors.New("not implemented")
}

// inboundRoots returns the control-plane-to-agent roots: the response
// type of every service method and EndDetail (agent-api §4.10.1 reading 3).
func inboundRoots(files *protoregistry.Files) ([]protoreflect.MessageDescriptor, error) {
	return nil, errors.New("not implemented")
}

// generateClassTable walks files from the roots and returns the class
// table sorted by field name, and every violation of R5 and §4.10.1.
func generateClassTable(files *protoregistry.Files) ([]classEntry, []string) {
	return nil, []string{"not implemented"}
}

// renderClassTable writes entries as the gofmt-ed source of classTableFile.
func renderClassTable(entries []classEntry) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// classTableDiff compares a compiled table with a fresh generation, both
// ways.
func classTableDiff(compiled map[protoreflect.FullName]wardenv1.RedactFieldClass, fresh []classEntry) []string {
	return []string{"not implemented"}
}
