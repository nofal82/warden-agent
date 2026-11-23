package agentapiv1_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// ac8aVariants is the number of populate variants; TestFullyPopulatedRoundTrip
// documents why 22 sets every member of every oneof.
const ac8aVariants = 22

// assertFullyPopulated reports, at every depth of m, a singular field that is
// unset or default, a repeated or map field with fewer than two elements, and
// a oneof with no member set (AC8a). Set oneof members are added to seen.
func assertFullyPopulated(t *testing.T, where string, m protoreflect.Message, seen map[protoreflect.FullName]bool) {
	t.Helper()
	md := m.Descriptor()
	for i := 0; i < md.Oneofs().Len(); i++ {
		od := md.Oneofs().Get(i)
		if od.IsSynthetic() {
			continue
		}
		if fd := m.WhichOneof(od); fd == nil {
			t.Errorf("%s: oneof %s has no member set", where, od.Name())
		} else {
			seen[fd.FullName()] = true
		}
	}
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		at := where + "." + string(fd.Name())
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() && m.WhichOneof(od) != fd {
			continue
		}
		switch {
		case fd.IsList():
			l := m.Get(fd).List()
			if l.Len() < 2 {
				t.Errorf("%s: repeated field has %d elements, want >= 2", at, l.Len())
			}
			for k := 0; fd.Message() != nil && k < l.Len(); k++ {
				assertFullyPopulated(t, at, l.Get(k).Message(), seen)
			}
		case fd.IsMap():
			if n := m.Get(fd).Map().Len(); n < 2 {
				t.Errorf("%s: map field has %d entries, want >= 2", at, n)
			}
		case !m.Has(fd):
			t.Errorf("%s: singular field is unset or default", at)
		case fd.Message() != nil:
			assertFullyPopulated(t, at, m.Get(fd).Message(), seen)
		case m.Get(fd).Equal(fd.Default()):
			t.Errorf("%s: singular field holds its default value", at)
		}
	}
}

// TestAC8aAgentapiCanonical applies action-envelope.md AC8a (R13 (k)) to
// warden.agentapi.v1, which internal/envelope/wirescan cannot import: every
// message enumerated from the descriptors, every field non-default, every
// repeated field at least two elements, each oneof member in turn,
// marshalled Deterministic, passes the complete strict scan and re-marshals
// to identical bytes. A last check proves every oneof member was covered.
func TestAC8aAgentapiCanonical(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	msgs := allMessages(packageFiles(t, agentapiPkg))
	if len(msgs) == 0 {
		t.Fatal("no warden.agentapi.v1 messages found")
	}
	for _, md := range msgs {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
		if err != nil {
			t.Errorf("%s: %v", md.FullName(), err)
			continue
		}
		for variant := 0; variant < ac8aVariants; variant++ {
			name := string(md.FullName())
			m := mt.New()
			populate(m, variant, 0)
			assertFullyPopulated(t, name, m, seen)
			b, err := deterministic.Marshal(m.Interface())
			if err != nil {
				t.Fatalf("%s/%d: marshal: %v", name, variant, err)
			}
			got := mt.New().Interface()
			if err := wirescan.Unmarshal(b, got); err != nil {
				t.Errorf("%s/%d: R13 scan rejected the canonical encoding: %v", name, variant, err)
				continue
			}
			again, err := proto.MarshalOptions{Deterministic: true}.Marshal(got)
			if err != nil {
				t.Fatalf("%s/%d: re-marshal: %v", name, variant, err)
			}
			if !bytes.Equal(again, b) {
				t.Errorf("%s/%d: re-marshal is not byte-identical (%d vs %d bytes)", name, variant, len(again), len(b))
			}
		}
	}
	for _, md := range msgs {
		for i := 0; i < md.Oneofs().Len(); i++ {
			od := md.Oneofs().Get(i)
			for j := 0; !od.IsSynthetic() && j < od.Fields().Len(); j++ {
				if fd := od.Fields().Get(j); !seen[fd.FullName()] {
					t.Errorf("oneof member %s is never set by any variant", fd.FullName())
				}
			}
		}
	}
}
