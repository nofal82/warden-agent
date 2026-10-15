package wardenv1_test

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

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
