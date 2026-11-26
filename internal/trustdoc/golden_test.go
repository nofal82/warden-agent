package trustdoc

// Golden vectors (signing-and-updates §4.3): the exact signed message
// domain || 0x00 || body for a fixed body of each kind. The committed value
// is the SHA-256 of the message, not its hex: gitleaks' generic-api-key rule
// flags the long hex literal, and the hash pins the same bytes. The bodies use
// bytes.Repeat key material and the P-256 base point as release key, so the
// vector is deterministic and contains no real key. A change to the
// encoding, the domain or the field layout changes the vector.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

const (
	goldenFrom  int64 = 1_790_000_000
	goldenUntil int64 = 1_810_000_000
)

func goldenKeysetBody(tb testing.TB) *wardenv1.KeysetBody {
	return &wardenv1.KeysetBody{
		FormatVersion: 1,
		Sequence:      7,
		SignedAt:      fakeNow,
		Keys: []*wardenv1.KeyEntry{
			{Role: wardenv1.KeyRole_KEY_ROLE_ENVELOPE, PublicKey: bytes.Repeat([]byte{0x11}, 32), NotBefore: goldenFrom, NotAfter: goldenUntil},
			{Role: wardenv1.KeyRole_KEY_ROLE_MANIFEST, PublicKey: bytes.Repeat([]byte{0x22}, 32), NotBefore: goldenFrom, NotAfter: goldenUntil},
		},
		ControlplaneCas: []*wardenv1.CaEntry{{Fingerprint: bytes.Repeat([]byte{0x33}, 32), NotBefore: goldenFrom, NotAfter: goldenUntil}},
		ReleaseKeys:     [][]byte{p256GeneratorDER(tb)},
		AuditCheckpointKeys: []*wardenv1.CheckpointKeyEntry{
			{Fingerprint: bytes.Repeat([]byte{0x44}, 32), NotBefore: goldenFrom, NotAfter: goldenUntil},
		},
	}
}

func goldenManifestBody() *wardenv1.ManifestBody {
	return &wardenv1.ManifestBody{
		FormatVersion: 1,
		ServerId:      serverA,
		Sequence:      3,
		IssuedAt:      fakeNow,
		PostRecovery:  bytes.Repeat([]byte{0x55}, 24),
		Playbooks: []*wardenv1.EnabledPlaybook{
			{PlaybookId: "disk-cleanup", AutonomyCeiling: wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L2, MaxActStepsPerHour: proto.Uint32(5)},
		},
		Unfreeze:         []string{"disk-cleanup"},
		BackupUnits:      []string{"backup-nightly.service"},
		AdminListedUnits: []string{"nginx.service", "postgresql@14-main.service"},
	}
}

const goldenKSMessageSHA256 = "776e69be2e8fb1761a590386c6044d51e687abd10da20ecb3881f66b383e5c20"

const goldenManifestMessageSHA256 = "0577e865d155db67bbd7fa2f62f6715fd276a9dc2cf79e29b489828acc97a1bc"

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestGoldenKeyset(t *testing.T) {
	body := marshalDet(t, goldenKeysetBody(t))
	msg := message(litDomainKeyset, body)
	if got := sha256Hex(msg); got != goldenKSMessageSHA256 {
		t.Fatalf("keyset signed message changed: SHA-256 %s, want %s\nmessage %x", got, goldenKSMessageSHA256, msg)
	}
	if DomainKeyset+"\x00" != litDomainKeyset {
		t.Errorf("DomainKeyset = %q, want %q", DomainKeyset, "warden/v1/envelope-keyset")
	}
	root := newKey(t)
	ks, err := VerifyKeyset(wrap(spkiID(t, root.pub), body, sign(root, litDomainKeyset, body)), root.pub)
	if err != nil {
		t.Fatalf("golden keyset refused: %v", err)
	}
	if ks.Hash() != sha256.Sum256(msg) {
		t.Errorf("Hash = %x, want SHA-256 of the golden message", ks.Hash())
	}
	if ks.Sequence() != 7 {
		t.Errorf("Sequence = %d, want 7", ks.Sequence())
	}
}

func TestGoldenManifest(t *testing.T) {
	body := marshalDet(t, goldenManifestBody())
	msg := message(litDomainManifest, body)
	if got := sha256Hex(msg); got != goldenManifestMessageSHA256 {
		t.Fatalf("manifest signed message changed: SHA-256 %s, want %s\nmessage %x", got, goldenManifestMessageSHA256, msg)
	}
	if DomainManifest+"\x00" != litDomainManifest {
		t.Errorf("DomainManifest = %q, want %q", DomainManifest, "warden/v1/server-manifest")
	}
	fx := newFixture(t)
	cfg := cfgFor(fx.keyset(t, nil))
	cfg.Catalog = fakeCatalog{"disk-cleanup": 10}
	m, err := VerifyManifest(manifestRaw(fx.man, litDomainManifest, body), cfg)
	if err != nil {
		t.Fatalf("golden manifest refused: %v", err)
	}
	if !proto.Equal(m.Body, goldenManifestBody()) {
		t.Errorf("Body = %v, want the golden body", m.Body)
	}
}
