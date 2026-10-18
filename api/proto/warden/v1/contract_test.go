package wardenv1_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// primitiveNumbers pins every params member to its catalog number
// (typed-action-catalog §4.4). A renumbered member would change the signed
// wire format.
var primitiveNumbers = map[protoreflect.Name]protoreflect.FieldNumber{
	"fs_usage": 1, "fs_largest_entries": 2, "service_status": 3,
	"web_config_test": 4, "cert_inspect": 5, "process_top": 6,
	"mem_status": 7, "container_inspect": 8, "db_query_readonly": 9,
	"db_backup_verify": 10, "service_restart": 11, "service_reset_failed": 12,
	"service_reload": 13, "service_start": 14, "service_set_cpu_quota": 15,
	"process_signal": 16, "file_delete_by_age": 17, "journal_vacuum": 18,
	"pkg_cache_clean": 19, "container_restart": 21, "db_terminate_session": 22,
}

func paramsOneof(t *testing.T) protoreflect.OneofDescriptor {
	t.Helper()
	md := (&wardenv1.TypedRequest{}).ProtoReflect().Descriptor()
	od := md.Oneofs().ByName("request")
	if od == nil {
		t.Fatal("TypedRequest has no oneof named request")
	}
	if md.Fields().Len() != od.Fields().Len() {
		t.Fatalf("TypedRequest has %d fields outside the oneof", md.Fields().Len()-od.Fields().Len())
	}
	return od
}

func TestParamsMembersMatchCatalogNumbers(t *testing.T) {
	od := paramsOneof(t)
	if od.Fields().Len() != len(primitiveNumbers) {
		t.Fatalf("params has %d members, want %d (21 primitives)", od.Fields().Len(), len(primitiveNumbers))
	}
	for i := 0; i < od.Fields().Len(); i++ {
		fd := od.Fields().Get(i)
		want, ok := primitiveNumbers[fd.Name()]
		if !ok || fd.Number() != want {
			t.Errorf("member %s has number %d, want %d (known: %v)", fd.Name(), fd.Number(), want, ok)
		}
		if fd.Kind() != protoreflect.MessageKind {
			t.Errorf("member %s is not a message", fd.Name())
		}
	}
	md := (&wardenv1.TypedRequest{}).ProtoReflect().Descriptor()
	if !md.ReservedRanges().Has(20) || !md.ReservedNames().Has("cert_renew") {
		t.Error("P20 (cert_renew) is not reserved")
	}
}

// TestRequestsHaveNoMessageFields enforces typed-action-catalog R3a: every
// params member holds only scalars, enums and repeated scalars, so no
// request can be nested or recursive.
func TestRequestsHaveNoMessageFields(t *testing.T) {
	od := paramsOneof(t)
	for i := 0; i < od.Fields().Len(); i++ {
		req := od.Fields().Get(i).Message()
		for j := 0; j < req.Fields().Len(); j++ {
			fd := req.Fields().Get(j)
			if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind || fd.IsMap() {
				t.Errorf("%s.%s is message-typed", req.Name(), fd.Name())
			}
		}
	}
}

// TestEnumsStartUnspecified checks that every enum's zero value is
// *_UNSPECIFIED, which validators always reject (§4.1).
func TestEnumsStartUnspecified(t *testing.T) {
	files := []protoreflect.FileDescriptor{
		wardenv1.File_warden_v1_envelope_proto,
		wardenv1.File_warden_v1_typed_request_proto,
	}
	for _, f := range files {
		for i := 0; i < f.Enums().Len(); i++ {
			ed := f.Enums().Get(i)
			zero := ed.Values().ByNumber(0)
			if zero == nil || len(zero.Name()) < len("_UNSPECIFIED") ||
				string(zero.Name()[len(zero.Name())-len("_UNSPECIFIED"):]) != "_UNSPECIFIED" {
				t.Errorf("enum %s: value 0 is not *_UNSPECIFIED", ed.Name())
			}
		}
	}
}

// contractFiles is every registered file of package warden.v1, so a contract
// file added later is covered without editing these tests.
func contractFiles(t *testing.T) []protoreflect.FileDescriptor {
	t.Helper()
	var files []protoreflect.FileDescriptor
	protoregistry.GlobalFiles.RangeFilesByPackage("warden.v1", func(f protoreflect.FileDescriptor) bool {
		files = append(files, f)
		return true
	})
	if len(files) < 2 {
		t.Fatalf("found %d warden.v1 files, want at least envelope.proto and typed_request.proto", len(files))
	}
	return files
}

// mapFields returns every map field declared in f, nested messages included.
func mapFields(f protoreflect.FileDescriptor) []protoreflect.FullName {
	var out []protoreflect.FullName
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			for j := 0; j < md.Fields().Len(); j++ {
				if fd := md.Fields().Get(j); fd.IsMap() {
					out = append(out, fd.FullName())
				}
			}
			walk(md.Messages())
		}
	}
	walk(f.Messages())
	return out
}

// TestContractHasNoMaps: map fields are never allowed in the contract. Go
// always writes a map entry's key and value, even when zero, which the
// strict scanner's R13 (j) rule rejects, and duplicate keys silently keep
// the last entry (Nofal, 2026-10-18).
func TestContractHasNoMaps(t *testing.T) {
	for _, f := range contractFiles(t) {
		for _, name := range mapFields(f) {
			t.Errorf("%s: map field %s; the contract must never contain map fields", f.Path(), name)
		}
	}
}

// TestContractIsProto3: every contract file is proto3. The R13 (i) and (j)
// rules assume proto3: repeated scalars packed by default and implicit
// presence for plain scalars (Nofal, 2026-10-18).
func TestContractIsProto3(t *testing.T) {
	for _, f := range contractFiles(t) {
		if f.Syntax() != protoreflect.Proto3 {
			t.Errorf("%s has syntax %v, want proto3", f.Path(), f.Syntax())
		}
	}
}

// The two checks above would catch a violation: a proto2 file with a map
// nested one level deep fails both.
func TestContractChecksDetectViolations(t *testing.T) {
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum()
	entry := &descriptorpb.DescriptorProto{
		Name: proto.String("LabelsEntry"),
		Field: []*descriptorpb.FieldDescriptorProto{
			{Name: proto.String("key"), Number: proto.Int32(1), Label: opt, Type: str},
			{Name: proto.String("value"), Number: proto.Int32(2), Label: opt, Type: str},
		},
		Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
	}
	f, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("wardentest/bad_contract.proto"),
		Package: proto.String("wardentest"),
		Syntax:  proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Outer"),
			NestedType: []*descriptorpb.DescriptorProto{{
				Name:       proto.String("Inner"),
				Field:      []*descriptorpb.FieldDescriptorProto{{Name: proto.String("labels"), Number: proto.Int32(1), Label: rep, Type: msg, TypeName: proto.String(".wardentest.Outer.Inner.LabelsEntry")}},
				NestedType: []*descriptorpb.DescriptorProto{entry},
			}},
		}},
	}, new(protoregistry.Files))
	if err != nil {
		t.Fatal(err)
	}
	if got := mapFields(f); len(got) != 1 || got[0] != "wardentest.Outer.Inner.labels" {
		t.Errorf("mapFields = %v, want [wardentest.Outer.Inner.labels]", got)
	}
	if f.Syntax() == protoreflect.Proto3 {
		t.Error("test file should be proto2")
	}
}
