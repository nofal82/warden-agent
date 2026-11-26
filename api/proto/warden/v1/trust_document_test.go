package wardenv1_test

// Contract tests for the trust-document messages of signing-and-updates
// §4.1–§4.7 (issue #68). The messages are looked up by name at run time,
// never through generated Go types, so these tests compile before the
// .proto exists and fail until it does.

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// TestPrimitiveEnumMirrorsTypedRequest (signing-and-updates §4.5,
// CatalogStep.allowed_primitives): every Primitive value other than 0 is
// PRIMITIVE_ plus the upper-case name of a TypedRequest oneof member and
// has that member's field number, every member has its value, and 20
// (P20, removed) is reserved by number and by the name TypedRequest
// reserves for it, so it can never be reused.
func TestPrimitiveEnumMirrorsTypedRequest(t *testing.T) {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName("warden.v1.Primitive")
	if err != nil {
		t.Fatalf("warden.v1.Primitive: %v (signing-and-updates §4.5, issue #68)", err)
	}
	ed, ok := d.(protoreflect.EnumDescriptor)
	if !ok {
		t.Fatalf("warden.v1.Primitive is a %T, not an enum", d)
	}
	if z := ed.Values().ByNumber(0); z == nil || z.Name() != "PRIMITIVE_UNSPECIFIED" {
		t.Errorf("value 0 is %v, want PRIMITIVE_UNSPECIFIED", z)
	}
	od := paramsOneof(t)
	want := map[protoreflect.EnumNumber]protoreflect.Name{}
	for i := 0; i < od.Fields().Len(); i++ {
		fd := od.Fields().Get(i)
		want[protoreflect.EnumNumber(fd.Number())] = protoreflect.Name("PRIMITIVE_" + strings.ToUpper(string(fd.Name())))
	}
	got := map[protoreflect.EnumNumber]protoreflect.Name{}
	for i := 0; i < ed.Values().Len(); i++ {
		if v := ed.Values().Get(i); v.Number() != 0 {
			got[v.Number()] = v.Name()
		}
	}
	for n, name := range want {
		if got[n] != name {
			t.Errorf("Primitive value %d = %q, want %q", n, got[n], name)
		}
	}
	for n, name := range got {
		if _, ok := want[n]; !ok {
			t.Errorf("Primitive value %s = %d has no TypedRequest member", name, n)
		}
	}
	if !ed.ReservedRanges().Has(20) {
		t.Error("Primitive does not reserve 20")
	}
	tr := od.Parent().(protoreflect.MessageDescriptor)
	if tr.ReservedNames().Len() != 1 {
		t.Fatalf("TypedRequest reserves %d names, want 1", tr.ReservedNames().Len())
	}
	p20 := protoreflect.Name("PRIMITIVE_" + strings.ToUpper(string(tr.ReservedNames().Get(0))))
	if !ed.ReservedNames().Has(p20) {
		t.Errorf("Primitive does not reserve the name %s", p20)
	}
}

// docMsg is a registered, empty message of the given warden.v1 name.
func docMsg(t *testing.T, name string) protoreflect.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName("warden.v1." + name))
	if err != nil {
		t.Fatalf("warden.v1.%s: %v (signing-and-updates §4, issue #68)", name, err)
	}
	return mt.New()
}

func field(t *testing.T, m protoreflect.Message, name string) protoreflect.FieldDescriptor {
	t.Helper()
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(name))
	if fd == nil {
		t.Fatalf("%s has no field %s", m.Descriptor().FullName(), name)
	}
	return fd
}

// set sets a scalar field; v is uint32, uint64, int64, string, []byte or
// an enum value name.
func set(t *testing.T, m protoreflect.Message, name string, v any) {
	t.Helper()
	fd := field(t, m, name)
	m.Set(fd, value(t, fd, v))
}

func value(t *testing.T, fd protoreflect.FieldDescriptor, v any) protoreflect.Value {
	t.Helper()
	if fd.Kind() == protoreflect.EnumKind {
		ev := fd.Enum().Values().ByName(protoreflect.Name(v.(string)))
		if ev == nil {
			t.Fatalf("%s: enum %s has no value %v", fd.FullName(), fd.Enum().FullName(), v)
		}
		return protoreflect.ValueOfEnum(ev.Number())
	}
	return protoreflect.ValueOf(v)
}

// add appends scalar values to a repeated field.
func add(t *testing.T, m protoreflect.Message, name string, vs ...any) {
	t.Helper()
	fd := field(t, m, name)
	l := m.Mutable(fd).List()
	for _, v := range vs {
		l.Append(value(t, fd, v))
	}
}

// addMsg appends a new element to a repeated message field and returns it.
func addMsg(t *testing.T, m protoreflect.Message, name string) protoreflect.Message {
	t.Helper()
	l := m.Mutable(field(t, m, name)).List()
	e := l.NewElement()
	l.Append(e)
	return e.Message()
}

func detMarshal(t *testing.T, m protoreflect.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m.Interface())
	if err != nil {
		t.Fatalf("marshal %s: %v", m.Descriptor().FullName(), err)
	}
	return b
}

// Largest values of the shared document fields (§4.3a–§4.6).
const (
	maxDocSequence = uint64(1)<<63 - 1
	maxDocTime     = int64(1)<<40 - 1
)

// fake is a fixed fake byte pattern of length n, never a key.
func fake(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// longID is a playbook or step id of 63 characters, the most the
// action-envelope §4.2 patterns allow, ending in a two-digit index.
func longID(i int) string { return "p" + strings.Repeat("a", 60) + fmt.Sprintf("%02d", i) }

// longUnit is a service unit name of 249 characters, the most the
// typed-action-catalog §4.2 pattern allows, with a two-digit index.
func longUnit(i int) string {
	return "u" + strings.Repeat("a", 238) + fmt.Sprintf("%02d", i) + ".service"
}

func docHeader(t *testing.T, m protoreflect.Message, timeField string) {
	t.Helper()
	set(t, m, "format_version", uint32(1))
	set(t, m, "sequence", maxDocSequence)
	set(t, m, timeField, maxDocTime)
}

func largestKeyset(t *testing.T) protoreflect.Message {
	m := docMsg(t, "KeysetBody")
	docHeader(t, m, "signed_at")
	for i, role := range []string{"KEY_ROLE_ENVELOPE", "KEY_ROLE_ENVELOPE", "KEY_ROLE_MANIFEST", "KEY_ROLE_MANIFEST"} {
		k := addMsg(t, m, "keys")
		set(t, k, "role", role)
		set(t, k, "public_key", fake(byte(0x10+i), 32))
		set(t, k, "not_before", maxDocTime)
		set(t, k, "not_after", maxDocTime)
	}
	for _, list := range []string{"controlplane_cas", "audit_checkpoint_keys"} {
		for i := 0; i < 2; i++ {
			e := addMsg(t, m, list)
			set(t, e, "fingerprint", fake(byte(0x20+i), 32))
			set(t, e, "not_before", maxDocTime)
			set(t, e, "not_after", maxDocTime)
		}
	}
	add(t, m, "release_keys", fake(0x30, 91), fake(0x31, 91))
	return m
}

func largestStatement(t *testing.T) protoreflect.Message {
	m := docMsg(t, "ReleaseKeyStatementBody")
	docHeader(t, m, "issued_at")
	add(t, m, "release_keys", fake(0x30, 91), fake(0x31, 91))
	return m
}

func largestCatalog(t *testing.T) protoreflect.Message {
	m := docMsg(t, "CatalogBody")
	docHeader(t, m, "published_at")
	for i := 0; i < 64; i++ {
		e := addMsg(t, m, "entries")
		set(t, e, "playbook_id", longID(i))
		set(t, e, "version", "1.2.3-"+strings.Repeat("a", 26)) // 32 characters
		set(t, e, "digest", fake(0x40, 32))
		for j := 0; j < 32; j++ {
			s := addMsg(t, e, "steps")
			set(t, s, "step_id", longID(j))
			add(t, s, "allowed_primitives", "PRIMITIVE_SERVICE_START", "PRIMITIVE_SERVICE_SET_CPU_QUOTA",
				"PRIMITIVE_PROCESS_SIGNAL", "PRIMITIVE_FILE_DELETE_BY_AGE", "PRIMITIVE_JOURNAL_VACUUM",
				"PRIMITIVE_PKG_CACHE_CLEAN", "PRIMITIVE_CONTAINER_RESTART", "PRIMITIVE_DB_TERMINATE_SESSION")
			set(t, s, "rollback_kind", "ROLLBACK_KIND_IMPOSSIBLE")
		}
		set(t, e, "max_risk", "RISK_HIGH")
		set(t, e, "autonomy_ceiling", "AUTONOMY_LEVEL_L3")
		set(t, e, "max_act_steps_per_hour", uint32(60))
		add(t, e, "unit_categories", "UNIT_CATEGORY_WEB", "UNIT_CATEGORY_DATABASE", "UNIT_CATEGORY_ADMIN_LISTED")
		add(t, e, "renewal_units", longUnit(0), longUnit(1), longUnit(2), longUnit(3))
	}
	return m
}

func largestManifest(t *testing.T) protoreflect.Message {
	m := docMsg(t, "ManifestBody")
	set(t, m, "format_version", uint32(1))
	set(t, m, "server_id", "4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f")
	set(t, m, "sequence", maxDocSequence)
	set(t, m, "issued_at", maxDocTime)
	set(t, m, "post_recovery", fake(0x50, 24))
	for i := 0; i < 64; i++ {
		p := addMsg(t, m, "playbooks")
		set(t, p, "playbook_id", longID(i))
		set(t, p, "autonomy_ceiling", "AUTONOMY_LEVEL_L3")
		set(t, p, "max_act_steps_per_hour", uint32(60))
		add(t, m, "unfreeze", longID(i))
	}
	for i := 0; i < 32; i++ {
		if i < 8 {
			add(t, m, "backup_units", longUnit(i))
		}
		add(t, m, "admin_listed_units", longUnit(i))
	}
	return m
}

// largestRelease is a §4.7 release manifest at every limit: 16 artifacts,
// a 32-character version and the greatest number in every field. Only
// 4 × 2 (component, arch) pairs exist, so 16 artifacts repeat pairs;
// "one per pair" is the verifier's rule, not a size bound.
func largestRelease(t *testing.T) protoreflect.Message {
	m := docMsg(t, "ReleaseBody")
	set(t, m, "format_version", uint32(1))
	set(t, m, "product", "warden-agent")
	set(t, m, "version", "1.2.3-"+strings.Repeat("a", 26)) // 32 characters
	set(t, m, "release_sequence", maxDocSequence)
	set(t, m, "released_at", maxDocTime)
	for i := 0; i < 16; i++ {
		a := addMsg(t, m, "artifacts")
		set(t, a, "component", "ARTIFACT_COMPONENT_ADMIN_TOOL")
		set(t, a, "arch", "ARTIFACT_ARCH_ARM64")
		set(t, a, "sha256", fake(byte(0x80+i), 32))
		set(t, a, "size", uint64(67108864))
	}
	return m
}

// TestLargestDocumentSizeBounds is signing-and-updates §4.2's size-bound
// list: the largest valid body of each kind marshals under the stated
// bound, and the SignedDocument carrying it, with a 32-byte key id and
// the longest (72-byte) signature, stays within the kind's raw limit.
func TestLargestDocumentSizeBounds(t *testing.T) {
	cases := []struct {
		name      string
		build     func(*testing.T) protoreflect.Message
		bodyUnder int // §4.2 size bound for the body
		kindLimit int // §4.2 max raw size of the whole SignedDocument
	}{
		{"keyset", largestKeyset, 1024, 4096},
		{"catalog", largestCatalog, 251 * 1024, 262144},
		{"manifest", largestManifest, 20 * 1024, 32768},
		{"release_key_statement", largestStatement, 4096, 4096},
		{"release", largestRelease, 4096, 16384},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := detMarshal(t, c.build(t))
			if len(body) >= c.bodyUnder {
				t.Errorf("largest %s body is %d bytes, want under %d", c.name, len(body), c.bodyUnder)
			}
			doc := docMsg(t, "SignedDocument")
			set(t, doc, "key_id", fake(0x60, 32))
			set(t, doc, "body", body)
			set(t, doc, "signature", fake(0x70, 72))
			if n := len(detMarshal(t, doc)); n > c.kindLimit {
				t.Errorf("SignedDocument with the largest %s body is %d bytes, kind limit %d", c.name, n, c.kindLimit)
			}
		})
	}
}
