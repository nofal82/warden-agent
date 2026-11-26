package trustdoc

import (
	"crypto/elliptic"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// TestKeysetSizeBound (§4.2): the largest valid keyset, every list at its
// limit and two audit checkpoint entries, verifies and stays under 1 KiB,
// far below MAX_KEYSET_BYTES.
func TestKeysetSizeBound(t *testing.T) {
	fx := newFixture(t)
	env2, man2 := newKey(t), newKey(t)
	raw := fx.keysetDoc(t, func(b *wardenv1.KeysetBody) {
		b.Sequence = 1<<63 - 1
		b.SignedAt = maxTime
		b.Keys = append(b.Keys,
			&wardenv1.KeyEntry{Role: wardenv1.KeyRole_KEY_ROLE_ENVELOPE, PublicKey: env2.pub, NotBefore: validFrom, NotAfter: validUntil},
			&wardenv1.KeyEntry{Role: wardenv1.KeyRole_KEY_ROLE_MANIFEST, PublicKey: man2.pub, NotBefore: validFrom, NotAfter: validUntil})
		b.ControlplaneCas = append(b.ControlplaneCas, &wardenv1.CaEntry{Fingerprint: randBytes(t, 32), NotBefore: validFrom, NotAfter: validUntil})
		b.ReleaseKeys = append(b.ReleaseKeys, ecdsaDER(t, elliptic.P256()))
		b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(randBytes(t, 32)), cpEntry(randBytes(t, 32))}
		sortKeyset(b)
	})
	if _, err := VerifyKeyset(raw, fx.root.pub); err != nil {
		t.Fatalf("largest valid keyset refused: %v", err)
	}
	if len(raw) >= 1024 {
		t.Errorf("largest keyset is %d bytes, want under 1 KiB (§4.2)", len(raw))
	}
}

// TestManifestSizeBound (§4.2): the largest valid manifest, every list at
// its limit with names of the greatest length, verifies and stays under
// 20 KiB, below MAX_MANIFEST_BYTES.
func TestManifestSizeBound(t *testing.T) {
	fx := newFixture(t)
	ks := fx.keyset(t, nil)
	cat := fakeCatalog{}
	// Ids of 63 characters, sorted because the suffix is zero-padded.
	id := func(prefix string, i int) string {
		s := fmt.Sprintf("%s%02d", prefix, i)
		return s + strings.Repeat("a", 63-len(s))
	}
	// Unit names of 249 characters, the longest the pattern allows.
	unit := func(prefix string, i int) string {
		s := fmt.Sprintf("%s%02d", prefix, i)
		return s + strings.Repeat("x", 249-len(".service")-len(s)) + ".service"
	}
	raw := fx.manifestDoc(t, func(b *wardenv1.ManifestBody) {
		b.Sequence = 1<<63 - 1
		b.PostRecovery = randBytes(t, postRecoveryLen)
		b.Playbooks, b.Unfreeze, b.BackupUnits, b.AdminListedUnits = nil, nil, nil, nil
		for i := range maxPlaybooks {
			pid := id("p", i)
			cat[pid] = 60
			b.Playbooks = append(b.Playbooks, &wardenv1.EnabledPlaybook{
				PlaybookId: pid, AutonomyCeiling: wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L3, MaxActStepsPerHour: proto.Uint32(60),
			})
		}
		for i := range maxUnfreeze {
			b.Unfreeze = append(b.Unfreeze, id("u", i))
		}
		for i := range maxBackupUnits {
			b.BackupUnits = append(b.BackupUnits, unit("b", i))
		}
		for i := range maxAdminListedUnits {
			b.AdminListedUnits = append(b.AdminListedUnits, unit("a", i))
		}
	})
	cfg := cfgFor(ks)
	cfg.Catalog = cat
	if _, err := VerifyManifest(raw, cfg); err != nil {
		t.Fatalf("largest valid manifest refused: %v", err)
	}
	if len(raw) >= 20*1024 {
		t.Errorf("largest manifest is %d bytes, want under 20 KiB (§4.2)", len(raw))
	}
}
