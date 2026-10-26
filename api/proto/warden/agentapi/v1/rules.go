package agentapiv1

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// unitIDRule is LogEvent.unit_id's pattern and length, read once from the
// field's options so no second copy of either value exists (agent-api
// R52c rule 3: a missing bound stops the program instead of leaving the
// field unchecked). It is built on first use because package variables are
// set before the generated init functions register the descriptors.
var unitIDRule = sync.OnceValue(func() stringRule {
	return mustStringRule((&LogEvent{}).ProtoReflect().Descriptor().Fields().ByName("unit_id"))
})

type stringRule struct {
	maxBytes int
	pattern  *regexp.Regexp
}

func mustStringRule(fd protoreflect.FieldDescriptor) stringRule {
	opts := fd.Options()
	if !proto.HasExtension(opts, wardenv1.E_MaxBytes) || !proto.HasExtension(opts, wardenv1.E_Pattern) {
		panic(fmt.Sprintf("%s: max_bytes or pattern option missing", fd.FullName()))
	}
	maxBytes := proto.GetExtension(opts, wardenv1.E_MaxBytes).(uint32)
	if maxBytes == 0 {
		panic(fmt.Sprintf("%s: max_bytes is 0", fd.FullName()))
	}
	return stringRule{
		maxBytes: int(maxBytes),
		pattern:  regexp.MustCompile(proto.GetExtension(opts, wardenv1.E_Pattern).(string)),
	}
}

// ValidUnitID reports whether s is a valid LogEvent.unit_id: within the
// field's max_bytes, matching its pattern, and never containing "..". The
// last rule is typed-action-catalog §4.2's ("no `..`"), which the RE2
// pattern cannot state, so it stays hand-written beside the options
// (agent-api R52c; Nofal, PR #13).
func ValidUnitID(s string) bool {
	rule := unitIDRule()
	return len(s) <= rule.maxBytes &&
		rule.pattern.MatchString(s) &&
		!strings.Contains(s, "..")
}
