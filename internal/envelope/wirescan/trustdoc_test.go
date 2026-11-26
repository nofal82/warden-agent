package wirescan_test

// Strict-decoder attack cases against the trust-document messages of
// signing-and-updates §4.1–§4.6 (issue #68), which R1–R7 there decode with
// the same R13 scanner as the envelope. The descriptors are looked up by
// name at run time, so this file compiles before trust_document.proto
// exists and fails until it does.

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// trustDocRoots are the top-level trust-document messages the scanner
// must accept as roots (signing-and-updates §4.1, §4.3a–§4.6).
var trustDocRoots = func() []protoreflect.FullName {
	var out []protoreflect.FullName
	for _, n := range []string{"SignedDocument", "ReleaseKeyStatementBody", "KeysetBody", "CatalogBody", "ManifestBody"} {
		out = append(out, protoreflect.FullName("warden.v1."+n))
	}
	return out
}()

// trustMD is the registered descriptor of a warden.v1 message.
func trustMD(tb testing.TB, name protoreflect.FullName) protoreflect.MessageDescriptor {
	tb.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
	if err != nil {
		tb.Fatalf("%s: %v (signing-and-updates §4, issue #68)", name, err)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		tb.Fatalf("%s is a %T, not a message", name, d)
	}
	return md
}

// populatedDoc is a deterministic encoding of name with every field set
// and every repeated field holding two elements (populate).
func populatedDoc(t testing.TB, name protoreflect.FullName) ([]byte, protoreflect.Message) {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(name)
	if err != nil {
		t.Fatalf("%s: %v (issue #68)", name, err)
	}
	m := mt.New()
	populate(m)
	return marshalDet(t, m.Interface()), m
}

func TestTrustDocumentScan(t *testing.T) {
	signed := trustMD(t, "warden.v1.SignedDocument")
	keyset := trustMD(t, "warden.v1.KeysetBody")
	keyEntry := trustMD(t, "warden.v1.KeyEntry")
	catalogEntry := trustMD(t, "warden.v1.CatalogEntry")
	step := trustMD(t, "warden.v1.CatalogStep")
	manifest := trustMD(t, "warden.v1.ManifestBody")

	keysetFull, km := populatedDoc(t, "warden.v1.KeysetBody")
	if km.Get(keyset.Fields().ByNumber(7)).List().Len() != 2 {
		t.Fatal("populated keyset has no audit_checkpoint_keys (field 7)")
	}
	catalogFull, _ := populatedDoc(t, "warden.v1.CatalogBody")
	manifestFull, _ := populatedDoc(t, "warden.v1.ManifestBody")

	fv1 := fVarint(nil, 1, 1)
	keyID := fBytes(nil, 1, make([]byte, 32))
	stepID := fBytes(nil, 1, []byte("restart"))
	pbID := fBytes(nil, 1, []byte("restart-nginx"))
	key := cat(fVarint(nil, 1, 1), fBytes(nil, 2, make([]byte, 32)))

	runScanCases(t, []scanCase{
		// Canonical documents, field 7 of KeysetBody included (§4.4).
		{"keyset_full_with_checkpoint_keys", keyset, keysetFull, nil},
		{"catalog_full", trustMD(t, "warden.v1.CatalogBody"), catalogFull, nil},
		{"manifest_full", manifest, manifestFull, nil},
		{"signed_document_wrapping_keyset", signed,
			cat(keyID, fBytes(nil, 2, keysetFull), fBytes(nil, 3, make([]byte, 64))), nil},

		// R13 (b): unknown fields, at the root and nested.
		{"keyset_unknown_99", keyset, fVarint(append([]byte(nil), keysetFull...), 99, 1), wirescan.ErrUnknownField},
		{"key_entry_unknown_99_nested", keyset, cat(fv1, fBytes(nil, 4, fVarint(append([]byte(nil), key...), 99, 1))), wirescan.ErrUnknownField},

		// R13 (c): a non-repeated field twice.
		{"signed_document_key_id_twice", signed, cat(keyID, keyID), wirescan.ErrDuplicateField},
		// The optional fields are exempt from rule (j) only: twice is
		// still a duplicate.
		{"catalog_entry_max_act_twice", catalogEntry, cat(pbID, fVarint(nil, 7, 1), fVarint(nil, 7, 1)), wirescan.ErrDuplicateField},
		{"enabled_playbook_max_act_twice", manifest, cat(fv1, fBytes(nil, 6, cat(pbID, fVarint(nil, 3, 1), fVarint(nil, 3, 1)))), wirescan.ErrDuplicateField},

		// R13 (d), (a): wire-type mismatch and groups.
		{"keyset_sequence_as_bytes", keyset, cat(fv1, fBytes(nil, 2, []byte{1})), wirescan.ErrWireType},
		{"keyset_keys_as_group", keyset, fGroup(cat(fv1), 4, nil), wirescan.ErrGroup},

		// R13 (e): overlong varint.
		{"keyset_sequence_overlong", keyset, fVarintOverlong(cat(fv1), 2, 5), wirescan.ErrNonCanonical},

		// R13 (j): format_version is implicit presence; an explicit 0 is
		// non-canonical. The two optional max_act_steps_per_hour fields
		// are exempt: a present 0 is canonical for the scanner (its range,
		// 1 … 60, is the verifier's job).
		{"keyset_format_version_explicit_0", keyset, fVarint(nil, 1, 0), wirescan.ErrNonCanonical},
		{"catalog_entry_max_act_present_0", catalogEntry, cat(pbID, fVarint(nil, 7, 0)), nil},
		{"enabled_playbook_max_act_present_0", manifest, cat(fv1, fBytes(nil, 6, cat(pbID, fVarint(nil, 3, 0)))), nil},

		// R13 (i): repeated enums only as one packed record.
		{"allowed_primitives_unpacked", step, cat(stepID, fVarint(nil, 2, 11), fVarint(nil, 2, 13)), wirescan.ErrNonCanonical},
		{"allowed_primitives_two_packed", step, cat(stepID, fBytes(nil, 2, packedVarints(11)), fBytes(nil, 2, packedVarints(13))), wirescan.ErrNonCanonical},
		{"unit_categories_unpacked", catalogEntry, cat(pbID, fVarint(nil, 8, 1), fVarint(nil, 8, 2)), wirescan.ErrNonCanonical},
		{"unit_categories_two_packed", catalogEntry, cat(pbID, fBytes(nil, 8, packedVarints(1)), fBytes(nil, 8, packedVarints(2))), wirescan.ErrNonCanonical},

		// R13 (g): an enum varint of 2^32 or more.
		{"key_role_2^32+1", keyEntry, fVarint(nil, 1, 1<<32+1), wirescan.ErrNonCanonical},

		// R13 (k): fields out of ascending order.
		{"keyset_sequence_before_format", keyset, cat(fVarint(nil, 2, 1), fv1), wirescan.ErrNonCanonical},
		{"catalog_step_rollback_before_primitives", step, cat(stepID, fVarint(nil, 3, 2), fBytes(nil, 2, packedVarints(11))), wirescan.ErrNonCanonical},
		{"signed_document_signature_before_body", signed,
			cat(keyID, fBytes(nil, 3, make([]byte, 64)), fBytes(nil, 2, []byte{1})), wirescan.ErrNonCanonical},
	})
}

// trustDocFuzzSeeds are raw encodings from TestTrustDocumentScan for
// FuzzCheck; they need no descriptor to build.
func trustDocFuzzSeeds() [][]byte {
	fv1 := fVarint(nil, 1, 1)
	keyID := fBytes(nil, 1, make([]byte, 32))
	return [][]byte{
		cat(keyID, fBytes(nil, 2, fv1), fBytes(nil, 3, make([]byte, 64))),
		cat(keyID, keyID),
		fVarint(nil, 1, 0),
		cat(fv1, fBytes(nil, 2, []byte{1})),
		fVarintOverlong(cat(fv1), 2, 5),
		cat(fv1, fBytes(nil, 4, cat(fVarint(nil, 1, 1<<32+1), fVarint(nil, 99, 1)))),
		cat(fv1, fBytes(nil, 4, fBytes(nil, 4, cat(fBytes(nil, 1, []byte("restart")),
			fVarint(nil, 2, 11), fVarint(nil, 2, 13))))),
		cat(fv1, fBytes(nil, 6, cat(fBytes(nil, 1, []byte("restart-nginx")), fVarint(nil, 3, 0)))),
		protowire.AppendTag(cat(fv1), 7, protowire.StartGroupType),
	}
}
