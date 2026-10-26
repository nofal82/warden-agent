package agentapiv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// TestMustStringRuleRefusesMissingBound: a field without max_bytes or
// pattern, or with max_bytes 0, stops the program instead of leaving the
// field unchecked (agent-api R52c rule 3).
func TestMustStringRuleRefusesMissingBound(t *testing.T) {
	withOpts := func(set func(*descriptorpb.FieldOptions)) *descriptorpb.FieldOptions {
		o := &descriptorpb.FieldOptions{}
		set(o)
		return o
	}
	cases := map[string]*descriptorpb.FieldOptions{
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
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
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
			defer func() {
				if recover() == nil {
					t.Error("mustStringRule did not panic")
				}
			}()
			mustStringRule(f.Messages().Get(0).Fields().Get(0))
		})
	}
}
