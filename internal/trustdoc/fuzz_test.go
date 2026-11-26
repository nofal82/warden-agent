package trustdoc

// Fuzz tests for both verifiers. Seeds are valid documents signed with keys
// generated in this process plus the attack shapes from the table tests.
// The verifiers must never panic, and anything they accept must still
// satisfy the §4.4 and §4.6 invariants.

import (
	"bytes"
	"crypto/sha256"
	"math"
	"sort"
	"testing"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

func FuzzVerifyKeyset(f *testing.F) {
	fx := newFixture(f)
	body := marshalDet(f, fx.keysetBody())
	sig := sign(fx.root, litDomainKeyset, body)
	kid := spkiID(f, fx.root.pub)
	f.Add(wrap(kid, body, sig))
	f.Add(fx.keysetDoc(f, func(b *wardenv1.KeysetBody) {
		b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(rawID(fx.cp.pub))}
	}))
	f.Add(wrap(kid, body, sig[:63]))
	f.Add(wrap(kid, body, withS(sig, groupOrderL)))
	f.Add(wrap(rawID(fx.root.pub), body, sig))
	f.Add(wrap(kid, body, sign(fx.root, litDomainManifest, body)))
	f.Add(fx.keysetRaw(f, fVarint(body, 99, 1)))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		ks, err := VerifyKeyset(raw, fx.root.pub)
		if err != nil {
			if ks != nil {
				t.Fatal("non-nil keyset with error")
			}
			return
		}
		if len(raw) > MaxKeysetBytes {
			t.Fatalf("accepted %d bytes > MaxKeysetBytes", len(raw))
		}
		if s := ks.Sequence(); s < 1 || s > math.MaxInt64 {
			t.Fatalf("accepted sequence %d", s)
		}
		var doc wardenv1.SignedDocument
		if err := proto.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("accepted bytes that are not a SignedDocument: %v", err)
		}
		if ks.Hash() != sha256.Sum256(message(litDomainKeyset, doc.GetBody())) {
			t.Fatal("Hash is not SHA-256(domain || 0x00 || body)")
		}
		env, man := ks.EnvelopeKeys(), ks.ManifestKeys()
		checkKeys(t, env)
		checkKeys(t, man)
		for _, e := range env {
			for _, m := range man {
				if bytes.Equal(e.PublicKey, m.PublicKey) {
					t.Fatal("accepted the same key in both roles")
				}
			}
		}
	})
}

func checkKeys(t *testing.T, ks []SigningKey) {
	t.Helper()
	if len(ks) < 1 || len(ks) > 2 {
		t.Fatalf("accepted %d keys of one role", len(ks))
	}
	for _, k := range ks {
		if len(k.PublicKey) != 32 {
			t.Fatalf("accepted a %d-byte key", len(k.PublicKey))
		}
		if k.NotBefore < 1 || k.NotBefore >= k.NotAfter || k.NotAfter > 1<<40-1 || k.NotAfter-k.NotBefore > MaxKeyValidity {
			t.Fatalf("accepted validity [%d, %d]", k.NotBefore, k.NotAfter)
		}
	}
}

func FuzzVerifyManifest(f *testing.F) {
	fx := newFixture(f)
	cfg := cfgFor(fx.keyset(f, nil))
	body := marshalDet(f, manifestBody())
	f.Add(manifestRaw(fx.man, litDomainManifest, body))
	f.Add(manifestRaw(fx.env, litDomainManifest, body))
	f.Add(manifestRaw(fx.man, litDomainEnvelope, body))
	f.Add(manifestRaw(fx.man, litDomainKeyset, body))
	f.Add(fx.manifestDoc(f, func(b *wardenv1.ManifestBody) { b.AdminListedUnits = []string{"getty@.service"} }))
	f.Add(fx.manifestDoc(f, func(b *wardenv1.ManifestBody) { b.BackupUnits = []string{"../x.service"} }))
	f.Add(fx.manifestDoc(f, func(b *wardenv1.ManifestBody) { b.IssuedAt = fakeNow + MaxSkew + 1 }))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := VerifyManifest(raw, cfg)
		if err != nil {
			if m != nil {
				t.Fatal("non-nil manifest with error")
			}
			return
		}
		if len(raw) > MaxManifestBytes {
			t.Fatalf("accepted %d bytes > MaxManifestBytes", len(raw))
		}
		if !bytes.Equal(m.KeyID[:], rawID(fx.man.pub)) {
			t.Fatalf("accepted key id %x, not the manifest key", m.KeyID)
		}
		b := m.Body
		if b.GetServerId() != serverA || b.GetIssuedAt() < 1 || b.GetIssuedAt() > fakeNow+MaxSkew {
			t.Fatalf("accepted server %q issued_at %d", b.GetServerId(), b.GetIssuedAt())
		}
		if n := len(b.GetPostRecovery()); n != 0 && n != 24 {
			t.Fatalf("accepted %d-byte post_recovery", n)
		}
		pbs := b.GetPlaybooks()
		if len(pbs) > 64 || !sort.SliceIsSorted(pbs, func(i, j int) bool { return pbs[i].GetPlaybookId() < pbs[j].GetPlaybookId() }) {
			t.Fatal("accepted too many or unsorted playbooks")
		}
		for _, p := range pbs {
			limit, ok := testCatalog().MaxActStepsPerHour(p.GetPlaybookId())
			if !ok || p.MaxActStepsPerHour == nil || p.GetMaxActStepsPerHour() < 1 || p.GetMaxActStepsPerHour() > limit ||
				p.GetAutonomyCeiling() == wardenv1.AutonomyLevel_AUTONOMY_LEVEL_UNSPECIFIED {
				t.Fatalf("accepted playbook %v", p)
			}
		}
		if len(b.GetBackupUnits()) > 8 || len(b.GetAdminListedUnits()) > 32 || len(b.GetUnfreeze()) > 64 {
			t.Fatal("accepted an oversized list")
		}
		for _, u := range append(append([]string(nil), b.GetBackupUnits()...), b.GetAdminListedUnits()...) {
			if !unitOK(u) {
				t.Fatalf("accepted unit name %q", u)
			}
		}
	})
}
