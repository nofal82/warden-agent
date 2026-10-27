package agentapiv1

import (
	"errors"
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
// R52c). It is built on first use because package variables are set
// before the generated init functions register the descriptors. A missing
// or zero bound is an error, never a panic: Warden failing must not crash
// the agent (Go reviewer, PR #16), so ValidUnitID refuses every item and
// CheckRules lets start-up refuse to start (R52c rule 3).
var unitIDRule = sync.OnceValues(newRuleSource(func() protoreflect.FieldDescriptor {
	return (&LogEvent{}).ProtoReflect().Descriptor().Fields().ByName("unit_id")
}))

type stringRule struct {
	maxBytes int
	pattern  *regexp.Regexp
}

// newRuleSource builds the rule of the field fd returns. A panic while
// reading the descriptor becomes an error too, so no caller ever sees one.
func newRuleSource(fd func() protoreflect.FieldDescriptor) func() (stringRule, error) {
	return func() (rule stringRule, err error) {
		defer func() {
			if r := recover(); r != nil {
				rule, err = stringRule{}, errors.New("agentapiv1: building a field rule panicked")
			}
		}()
		return stringRuleFor(fd())
	}
}

func stringRuleFor(fd protoreflect.FieldDescriptor) (stringRule, error) {
	if fd == nil {
		return stringRule{}, errors.New("agentapiv1: field rule: no such field")
	}
	opts := fd.Options()
	if !proto.HasExtension(opts, wardenv1.E_MaxBytes) || !proto.HasExtension(opts, wardenv1.E_Pattern) {
		return stringRule{}, fmt.Errorf("%s: max_bytes or pattern option missing", fd.FullName())
	}
	maxBytes := proto.GetExtension(opts, wardenv1.E_MaxBytes).(uint32)
	if maxBytes == 0 {
		return stringRule{}, fmt.Errorf("%s: max_bytes is 0", fd.FullName())
	}
	pattern, err := regexp.Compile(proto.GetExtension(opts, wardenv1.E_Pattern).(string))
	if err != nil {
		return stringRule{}, fmt.Errorf("%s: pattern does not compile: %w", fd.FullName(), err)
	}
	return stringRule{maxBytes: int(maxBytes), pattern: pattern}, nil
}

// CheckRules builds every option-derived rule of this package and returns
// the first error. A program calls it at start-up and refuses to start on
// an error (agent-api R52c rule 3); without that call, a broken rule only
// makes each validation refuse its item.
func CheckRules() error {
	_, err := unitIDRule()
	return err
}

// ValidUnitID reports whether s is a valid LogEvent.unit_id: within the
// field's max_bytes, matching its pattern, and never containing "..". The
// last rule is typed-action-catalog §4.2's ("no `..`"), which the RE2
// pattern cannot state, so it stays hand-written beside the options
// (agent-api R52c; Nofal, PR #13). If the rule cannot be built, every
// value is refused.
func ValidUnitID(s string) bool {
	return validUnitID(unitIDRule, s)
}

func validUnitID(source func() (stringRule, error), s string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false // refuse this item, keep the agent running
		}
	}()
	rule, err := source()
	if err != nil {
		return false
	}
	return len(s) <= rule.maxBytes &&
		rule.pattern.MatchString(s) &&
		!strings.Contains(s, "..")
}
