package agentapiv1

import (
	"maps"

	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// CompiledFieldClasses returns a copy of the compiled class table, for the
// contract test's comparison with a fresh generation.
func CompiledFieldClasses() map[protoreflect.FullName]wardenv1.RedactFieldClass {
	return maps.Clone(fieldClasses)
}
