package agentapiv1

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// FieldClass returns the redaction class (redaction.md §4.1) of a field
// the agent sends, by its full protobuf name, and false for a field
// outside redaction.md R5's scope. Message-typed fields have no entry:
// their own fields carry the class.
//
// The table behind it is generated from the redact_class options of the
// .proto files and compiled in (R5, R43); nothing at run time can add,
// remove or change an entry.
func FieldClass(name protoreflect.FullName) (wardenv1.RedactFieldClass, bool) {
	c, ok := fieldClasses[name]
	return c, ok
}
