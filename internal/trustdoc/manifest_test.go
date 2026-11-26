package trustdoc

// Manifest verifier tests (signing-and-updates §4.6, D5; agent-api AC19).
// No test here uses t.Parallel: rows read the package counters.

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

func TestVerifyManifestAccepts(t *testing.T) {
	fx := newFixture(t)
	m, err := VerifyManifest(fx.manifestDoc(t, nil), cfgFor(fx.keyset(t, nil)))
	if err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
	if !bytes.Equal(m.KeyID[:], rawID(fx.man.pub)) {
		t.Errorf("KeyID = %x, want SHA-256 of the raw manifest key", m.KeyID)
	}
	if !proto.Equal(m.Body, manifestBody()) {
		t.Errorf("Body = %v, want %v", m.Body, manifestBody())
	}
}

// TestVerifyManifestBoundariesAccepted: the inclusive edges of §4.6.
func TestVerifyManifestBoundariesAccepted(t *testing.T) {
	cases := map[string]struct {
		ks  func(*wardenv1.KeysetBody)
		mut func(*wardenv1.ManifestBody)
	}{
		"issued_at_now_plus_max_skew": {mut: func(b *wardenv1.ManifestBody) { b.IssuedAt = fakeNow + MaxSkew }},
		"steps_equal_catalog_value":   {mut: func(b *wardenv1.ManifestBody) { b.Playbooks[1].MaxActStepsPerHour = proto.Uint32(3) }},
		"manifest_key_at_not_after": {ks: func(b *wardenv1.KeysetBody) {
			for _, k := range b.Keys {
				if k.Role == wardenv1.KeyRole_KEY_ROLE_MANIFEST {
					k.NotAfter = fakeNow
				}
			}
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			if _, err := VerifyManifest(fx.manifestDoc(t, c.mut), cfgFor(fx.keyset(t, c.ks))); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// manifestAttack is one row: build returns the raw document and the config
// to verify it with.
type manifestAttack struct {
	name      string
	build     func(t *testing.T, fx *fixture) ([]byte, ManifestConfig)
	preVerify bool
	noDecode  bool
}

func mutManifest(mut func(*wardenv1.ManifestBody)) func(*testing.T, *fixture) ([]byte, ManifestConfig) {
	return func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
		return fx.manifestDoc(t, mut), cfgFor(fx.keyset(t, nil))
	}
}

func TestVerifyManifestAttacks(t *testing.T) {
	rows := []manifestAttack{
		{name: "size_limit_plus_1", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			raw := padBodyTo(t, marshalDet(t, manifestBody()), MaxManifestBytes+1, func(b []byte) []byte {
				return manifestRaw(fx.man, litDomainManifest, b)
			})
			return raw, cfgFor(fx.keyset(t, nil))
		}},
		{name: "signed_under_action_envelope_domain", noDecode: true, build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			return manifestRaw(fx.man, litDomainEnvelope, marshalDet(t, manifestBody())), cfgFor(fx.keyset(t, nil))
		}},
		// Signer (§4.6, AC19).
		{name: "signed_by_envelope_role_key", noDecode: true, build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			return manifestRaw(fx.env, litDomainManifest, marshalDet(t, manifestBody())), cfgFor(fx.keyset(t, nil))
		}},
		{name: "manifest_key_expired", noDecode: true, build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			ks := fx.keyset(t, func(b *wardenv1.KeysetBody) {
				for _, k := range b.Keys {
					if k.Role == wardenv1.KeyRole_KEY_ROLE_MANIFEST {
						k.NotAfter = fakeNow - 1
					}
				}
			})
			return fx.manifestDoc(t, nil), cfgFor(ks)
		}},
		{name: "key_not_in_keyset", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			return manifestRaw(newKey(t), litDomainManifest, marshalDet(t, manifestBody())), cfgFor(fx.keyset(t, nil))
		}},
		{name: "nil_keyset", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			return fx.manifestDoc(t, nil), cfgFor(nil)
		}},
		{name: "R11a_signed_by_checkpoint_key", noDecode: true, build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			ks := fx.keyset(t, func(b *wardenv1.KeysetBody) {
				b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(rawID(fx.cp.pub))}
			})
			return manifestRaw(fx.cp, litDomainManifest, marshalDet(t, manifestBody())), cfgFor(ks)
		}},
		// Body (§4.6, D5).
		{name: "issued_at_now_plus_61", build: mutManifest(func(b *wardenv1.ManifestBody) { b.IssuedAt = fakeNow + MaxSkew + 1 })},
		{name: "server_A_manifest_delivered_to_B", build: func(t *testing.T, fx *fixture) ([]byte, ManifestConfig) {
			cfg := cfgFor(fx.keyset(t, nil))
			cfg.ServerID = serverB
			return fx.manifestDoc(t, nil), cfg
		}},
		{name: "post_recovery_23_bytes", build: mutManifest(func(b *wardenv1.ManifestBody) {
			b.PostRecovery = bytes.Repeat([]byte{0x5a}, 23)
		})},
		{name: "playbook_not_in_catalog", build: mutManifest(func(b *wardenv1.ManifestBody) {
			b.Playbooks = append(b.Playbooks, &wardenv1.EnabledPlaybook{PlaybookId: "zz-not-installed",
				AutonomyCeiling: wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L1, MaxActStepsPerHour: proto.Uint32(1)})
		})},
		{name: "steps_catalog_plus_1", build: mutManifest(func(b *wardenv1.ManifestBody) {
			b.Playbooks[1].MaxActStepsPerHour = proto.Uint32(4)
		})},
		{name: "nine_backup_units", build: mutManifest(func(b *wardenv1.ManifestBody) {
			b.BackupUnits = nil
			for i := range 9 {
				b.BackupUnits = append(b.BackupUnits, "backup-"+string(rune('a'+i))+".service")
			}
		})},
		{name: "template_unit_name", build: mutManifest(func(b *wardenv1.ManifestBody) {
			b.AdminListedUnits = []string{"getty@.service", "nginx.service"}
		})},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			fx := newFixture(t)
			raw, cfg := r.build(t, fx)
			verifies, decodes := signatureVerifies.Load(), bodyDecodes.Load()
			m, err := VerifyManifest(raw, cfg)
			wantRejected(t, m, err, CodeManifestInvalid)
			if r.preVerify && signatureVerifies.Load() != verifies {
				t.Error("ed25519.Verify ran; the rule must refuse before verification")
			}
			if r.noDecode && bodyDecodes.Load() != decodes {
				t.Error("body was decoded before the signature verified")
			}
		})
	}
}

// unitOK documents the unit-name rule the fuzz invariants re-check.
func unitOK(u string) bool {
	if !strings.HasSuffix(u, ".service") || strings.Contains(u, "..") || strings.HasSuffix(u, "@.service") {
		return false
	}
	if len(u) < 9 || len(u) > 249 {
		return false
	}
	for i, c := range u {
		alnum := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if i == 0 && !alnum {
			return false
		}
		if !alnum && !strings.ContainsRune(":_.@-", c) {
			return false
		}
	}
	return true
}
