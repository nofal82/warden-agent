package agentapiv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

func withOpts(set func(*descriptorpb.FieldOptions)) *descriptorpb.FieldOptions {
	o := &descriptorpb.FieldOptions{}
	set(o)
	return o
}

// brokenRuleCases are field options a rule must refuse to build from: a
// missing or zero bound, or a pattern that does not compile.
var brokenRuleCases = map[string]*descriptorpb.FieldOptions{
	"no options": {},
	"no pattern": withOpts(func(o *descriptorpb.FieldOptions) {
		proto.SetExtension(o, wardenv1.E_MaxBytes, uint32(256))
	}),
	"no max_bytes": withOpts(func(o *descriptorpb.FieldOptions) {
		proto.SetExtension(o, wardenv1.E_Pattern, "^x$")
	}),
	"max_bytes 0": withOpts(func(o *descriptorpb.FieldOptions) {
		proto.SetExtension(o, wardenv1.E_MaxBytes, uint32(0))
		proto.SetExtension(o, wardenv1.E_Pattern, "^x$")
	}),
	"bad pattern": withOpts(func(o *descriptorpb.FieldOptions) {
		proto.SetExtension(o, wardenv1.E_MaxBytes, uint32(256))
		proto.SetExtension(o, wardenv1.E_Pattern, "^(x$")
	}),
}

func ruleField(t *testing.T, opts *descriptorpb.FieldOptions) protoreflect.FieldDescriptor {
	t.Helper()
	f, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("wardentest/rule.proto"),
		Package: proto.String("wardentest"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("M"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name: proto.String("s"), Number: proto.Int32(1),
				Label:   descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:    descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
				Options: opts,
			}},
		}},
	}, new(protoregistry.Files))
	if err != nil {
		t.Fatal(err)
	}
	return f.Messages().Get(0).Fields().Get(0)
}

// TestBrokenRuleRefusesEveryItem: a field without max_bytes or pattern,
// with max_bytes 0 or a pattern that does not compile, never leaves the
// field unchecked and never crashes the agent: building the rule returns
// an error (for start-up to refuse, R52c rule 3) and validation refuses
// each item, a valid unit name included (Go reviewer, PR #16).
func TestBrokenRuleRefusesEveryItem(t *testing.T) {
	for name, opts := range brokenRuleCases {
		t.Run(name, func(t *testing.T) {
			fd := ruleField(t, opts)
			if _, err := stringRuleFor(fd); err == nil {
				t.Error("stringRuleFor accepted a broken field")
			}
			source := newRuleSource(func() protoreflect.FieldDescriptor { return fd })
			if _, err := source(); err == nil {
				t.Error("rule source accepted a broken field")
			}
			for _, s := range []string{"nginx.service", "x", ""} {
				if validUnitID(source, s) {
					t.Errorf("validUnitID(%q) = true with a broken rule", s)
				}
			}
		})
	}
}

// TestRuleSourcePanicIsRefused: a panic while reading the descriptor (here
// a nil field, as ByName returns for a renamed field, and a source that
// panics itself) becomes an error and a refused item, not a crash.
func TestRuleSourcePanicIsRefused(t *testing.T) {
	sources := map[string]func() (stringRule, error){
		"nil field": newRuleSource(func() protoreflect.FieldDescriptor { return nil }),
		"panicking descriptor": newRuleSource(func() protoreflect.FieldDescriptor {
			panic("descriptor unavailable")
		}),
		"panicking rule source": func() (stringRule, error) { panic("rule unavailable") },
		"nil pattern":           func() (stringRule, error) { return stringRule{maxBytes: 256}, nil },
	}
	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			if validUnitID(source, "nginx.service") {
				t.Error("validUnitID accepted an item without a usable rule")
			}
		})
	}
	for _, name := range []string{"nil field", "panicking descriptor"} {
		if _, err := sources[name](); err == nil {
			t.Errorf("%s: rule source returned no error", name)
		}
	}
}

// TestCheckRulesOnContract: the real contract's rules build, so start-up
// proceeds and the good rule is the one ValidUnitID uses.
func TestCheckRulesOnContract(t *testing.T) {
	if err := CheckRules(); err != nil {
		t.Fatalf("CheckRules() = %v", err)
	}
	rule, err := unitIDRule()
	if err != nil || rule.maxBytes != 256 || rule.pattern == nil {
		t.Fatalf("unitIDRule() = %+v, %v", rule, err)
	}
}

// TestRefusedItemsCounted: every item refused because its rule cannot be
// built (the source returns an error, or panics) is counted, so a broken
// rule shows as refusals in the local health output, never as silence
// (agent-api §4.10.1 M1 limitation; Nofal, 2026-10-27). A valid value and
// an ordinary invalid value under a good rule are not refusals of this
// kind and are not counted.
func TestRefusedItemsCounted(t *testing.T) {
	broken := map[string]func() (stringRule, error){
		"nil field": newRuleSource(func() protoreflect.FieldDescriptor { return nil }),
		"panicking descriptor": newRuleSource(func() protoreflect.FieldDescriptor {
			panic("descriptor unavailable")
		}),
		"panicking rule source": func() (stringRule, error) { panic("rule unavailable") },
	}
	for name, opts := range brokenRuleCases {
		fd := ruleField(t, opts)
		broken["options: "+name] = newRuleSource(func() protoreflect.FieldDescriptor { return fd })
	}
	for name, source := range broken {
		t.Run(name, func(t *testing.T) {
			for i, s := range []string{"nginx.service", "", "../x"} {
				before := RefusedItems()
				if validUnitID(source, s) {
					t.Fatalf("validUnitID(%q) = true with a broken rule", s)
				}
				if got := RefusedItems() - before; got != 1 {
					t.Errorf("item %d: RefusedItems grew by %d, want 1", i, got)
				}
			}
		})
	}

	good := unitIDRule
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"nginx.service", true},
		{"getty@tty1.service", true},
		{"../etc/shadow", false},
		{"", false},
		{"a;b.service", false},
		{string(make([]byte, 300)), false},
	} {
		before := RefusedItems()
		if got := validUnitID(good, c.in); got != c.want {
			t.Errorf("validUnitID(%q) = %v, want %v", c.in, got, c.want)
		}
		if d := RefusedItems() - before; d != 0 {
			t.Errorf("validUnitID(%q) with a good rule grew RefusedItems by %d", c.in, d)
		}
	}
	before := RefusedItems()
	_ = ValidUnitID("nginx.service")
	_ = ValidUnitID("../x")
	if d := RefusedItems() - before; d != 0 {
		t.Errorf("ValidUnitID with the contract's rule grew RefusedItems by %d", d)
	}
}

// TestRefusedItemsConcurrent: the count is exact under concurrent
// refusals (the agent validates on more than one goroutine).
func TestRefusedItemsConcurrent(t *testing.T) {
	source := newRuleSource(func() protoreflect.FieldDescriptor { return nil })
	const workers, each = 16, 200
	before := RefusedItems()
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < each; i++ {
				validUnitID(source, "nginx.service")
			}
		}()
	}
	for w := 0; w < workers; w++ {
		<-done
	}
	if got := RefusedItems() - before; got != workers*each {
		t.Errorf("RefusedItems grew by %d, want %d", got, workers*each)
	}
}
