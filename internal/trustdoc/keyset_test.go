package trustdoc

// Keyset verifier tests (signing-and-updates §4.1–4.4, R1–R13, R11a;
// action-envelope R4a). No test here uses t.Parallel: rows read the
// package's bodyDecodes and signatureVerifies counters.

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

func TestVerifyKeysetAccepts(t *testing.T) {
	fx := newFixture(t)
	body := marshalDet(t, fx.keysetBody())
	ks, err := VerifyKeyset(fx.keysetRaw(t, body), fx.root.pub)
	if err != nil {
		t.Fatalf("valid keyset refused: %v", err)
	}
	if ks.Sequence() != 1 {
		t.Errorf("Sequence = %d, want 1", ks.Sequence())
	}
	if want := sha256.Sum256(message(litDomainKeyset, body)); ks.Hash() != want {
		t.Errorf("Hash = %x, want SHA-256(domain || 0x00 || body) %x", ks.Hash(), want)
	}
	if e := ks.EnvelopeKeys(); len(e) != 1 || !bytes.Equal(e[0].PublicKey, fx.env.pub) ||
		e[0].NotBefore != validFrom || e[0].NotAfter != validUntil {
		t.Errorf("EnvelopeKeys = %+v, want the one envelope key", e)
	}
	if m := ks.ManifestKeys(); len(m) != 1 || !bytes.Equal(m[0].PublicKey, fx.man.pub) {
		t.Errorf("ManifestKeys = %+v, want the one manifest key", m)
	}
}

// TestVerifyKeysetBoundariesAccepted: the inclusive edges of R11a and R13.
func TestVerifyKeysetBoundariesAccepted(t *testing.T) {
	fx := newFixture(t)
	cases := map[string]func(*wardenv1.KeysetBody){
		"checkpoint_0": nil,
		"checkpoint_1": func(b *wardenv1.KeysetBody) {
			b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(rawID(fx.cp.pub))}
		},
		"checkpoint_2": func(b *wardenv1.KeysetBody) {
			b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(randBytes(t, 32)), cpEntry(randBytes(t, 32))}
			sortKeyset(b)
		},
		"key_validity_max": func(b *wardenv1.KeysetBody) {
			b.Keys[0].NotBefore, b.Keys[0].NotAfter = validFrom, validFrom+MaxKeyValidity
		},
		"ca_validity_max": func(b *wardenv1.KeysetBody) {
			b.ControlplaneCas[0].NotBefore, b.ControlplaneCas[0].NotAfter = validFrom, validFrom+MaxCAEntryValidity
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyKeyset(fx.keysetDoc(t, mut), fx.root.pub); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// keysetAttack is one row: build returns the raw document; preVerify means
// the rule must fire before ed25519.Verify, noDecode before the body decode.
type keysetAttack struct {
	name      string
	build     func(t *testing.T, fx *fixture) []byte
	preVerify bool
	noDecode  bool
}

func mutKeyset(mut func(fx *fixture, b *wardenv1.KeysetBody)) func(*testing.T, *fixture) []byte {
	return func(t *testing.T, fx *fixture) []byte {
		return fx.keysetDoc(t, func(b *wardenv1.KeysetBody) { mut(fx, b) })
	}
}

func validKeysetSig(t *testing.T, fx *fixture) (kid, body, sig []byte) {
	body = marshalDet(t, fx.keysetBody())
	return spkiID(t, fx.root.pub), body, sign(fx.root, litDomainKeyset, body)
}

func TestVerifyKeysetAttacks(t *testing.T) {
	rows := []keysetAttack{
		// Common outer checks (§4.1–4.3).
		{name: "size_limit_plus_1", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			return padBodyTo(t, marshalDet(t, fx.keysetBody()), MaxKeysetBytes+1, func(b []byte) []byte { return fx.keysetRaw(t, b) })
		}},
		{name: "key_id_raw_hash_not_spki_hash", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			_, body, sig := validKeysetSig(t, fx)
			return wrap(rawID(fx.root.pub), body, sig)
		}},
		{name: "signature_63_bytes", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			kid, body, sig := validKeysetSig(t, fx)
			return wrap(kid, body, sig[:63])
		}},
		{name: "signature_65_bytes", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			kid, body, sig := validKeysetSig(t, fx)
			return wrap(kid, body, append(sig, 0))
		}},
		{name: "signature_72_bytes_ecdsa_length", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			kid, body, sig := validKeysetSig(t, fx)
			return wrap(kid, body, append(sig, make([]byte, 8)...))
		}},
		{name: "S_equals_L", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			kid, body, sig := validKeysetSig(t, fx)
			return wrap(kid, body, withS(sig, groupOrderL))
		}},
		{name: "S_equals_L_plus_1", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			kid, body, sig := validKeysetSig(t, fx)
			return wrap(kid, body, withS(sig, new(big.Int).Add(groupOrderL, big.NewInt(1))))
		}},
		{name: "bad_signature_modified_body", noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			kid, _, sig := validKeysetSig(t, fx)
			b := fx.keysetBody()
			b.Sequence = 2
			return wrap(kid, marshalDet(t, b), sig)
		}},
		{name: "signed_under_manifest_domain", noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			body := marshalDet(t, fx.keysetBody())
			return wrap(spkiID(t, fx.root.pub), body, sign(fx.root, litDomainManifest, body))
		}},
		{name: "unknown_body_field", build: func(t *testing.T, fx *fixture) []byte {
			return fx.keysetRaw(t, fVarint(marshalDet(t, fx.keysetBody()), 99, 1))
		}},
		// Body rules (§4.4).
		{name: "format_version_2", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) { b.FormatVersion = 2 })},
		{name: "sequence_2_pow_63", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) { b.Sequence = math.MaxInt64 + 1 })},
		{name: "no_manifest_key", build: mutKeyset(func(fx *fixture, b *wardenv1.KeysetBody) {
			b.Keys = []*wardenv1.KeyEntry{
				{Role: wardenv1.KeyRole_KEY_ROLE_ENVELOPE, PublicKey: fx.env.pub, NotBefore: validFrom, NotAfter: validUntil},
				{Role: wardenv1.KeyRole_KEY_ROLE_ENVELOPE, PublicKey: newKey(t).pub, NotBefore: validFrom, NotAfter: validUntil},
			}
			sortKeyset(b)
		})},
		{name: "three_envelope_keys", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			for range 2 {
				b.Keys = append(b.Keys, &wardenv1.KeyEntry{Role: wardenv1.KeyRole_KEY_ROLE_ENVELOPE,
					PublicKey: newKey(t).pub, NotBefore: validFrom, NotAfter: validUntil})
			}
			sortKeyset(b)
		})},
		{name: "keys_unsorted", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			b.Keys[0], b.Keys[1] = b.Keys[1], b.Keys[0]
		})},
		{name: "release_key_p384", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			b.ReleaseKeys = [][]byte{ecdsaDER(t, elliptic.P384())}
		})},
		{name: "key_validity_max_plus_1", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			b.Keys[0].NotBefore, b.Keys[0].NotAfter = validFrom, validFrom+MaxKeyValidity+1
		})},
		{name: "ca_validity_max_plus_1", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			b.ControlplaneCas[0].NotBefore, b.ControlplaneCas[0].NotAfter = validFrom, validFrom+MaxCAEntryValidity+1
		})},
		{name: "R12_envelope_key_is_root", build: mutKeyset(func(fx *fixture, b *wardenv1.KeysetBody) {
			for _, k := range b.Keys {
				if k.Role == wardenv1.KeyRole_KEY_ROLE_ENVELOPE {
					k.PublicKey = fx.root.pub
				}
			}
			sortKeyset(b)
		})},
		{name: "R12_same_key_both_roles", build: mutKeyset(func(fx *fixture, b *wardenv1.KeysetBody) {
			for _, k := range b.Keys {
				k.PublicKey = fx.env.pub
			}
		})},
		// Field 7, audit_checkpoint_keys (R11a, R12, R13).
		{name: "R12_checkpoint_equals_ca_fingerprint", build: mutKeyset(func(fx *fixture, b *wardenv1.KeysetBody) {
			b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(fx.ca)}
		})},
		{name: "checkpoint_3_entries", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			for range 3 {
				b.AuditCheckpointKeys = append(b.AuditCheckpointKeys, cpEntry(randBytes(t, 32)))
			}
			sortKeyset(b)
		})},
		{name: "checkpoint_fingerprint_33_bytes", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(randBytes(t, 33))}
		})},
		{name: "checkpoint_not_before_equals_not_after", build: mutKeyset(func(_ *fixture, b *wardenv1.KeysetBody) {
			e := cpEntry(randBytes(t, 32))
			e.NotAfter = e.NotBefore
			b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{e}
		})},
		// Wrong signer.
		{name: "signed_by_envelope_key", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			body := marshalDet(t, fx.keysetBody())
			return wrap(spkiID(t, fx.env.pub), body, sign(fx.env, litDomainKeyset, body))
		}},
		{name: "R11a_signed_by_checkpoint_key", preVerify: true, noDecode: true, build: func(t *testing.T, fx *fixture) []byte {
			b := fx.keysetBody()
			b.AuditCheckpointKeys = []*wardenv1.CheckpointKeyEntry{cpEntry(rawID(fx.cp.pub))}
			body := marshalDet(t, b)
			return wrap(rawID(fx.cp.pub), body, sign(fx.cp, litDomainKeyset, body))
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			fx := newFixture(t)
			raw := r.build(t, fx)
			verifies, decodes := signatureVerifies.Load(), bodyDecodes.Load()
			ks, err := VerifyKeyset(raw, fx.root.pub)
			wantRejected(t, ks, err, CodeKeysetInvalid)
			if r.preVerify && signatureVerifies.Load() != verifies {
				t.Error("ed25519.Verify ran; the rule must refuse before verification")
			}
			if r.noDecode && bodyDecodes.Load() != decodes {
				t.Error("body was decoded before the signature verified")
			}
		})
	}
}

// TestKeysetHasNoCheckpointAccessor (R11a (c)): the agent never uses an
// audit checkpoint key, so *Keyset must not expose one.
func TestKeysetHasNoCheckpointAccessor(t *testing.T) {
	typ := reflect.TypeOf(&Keyset{})
	for i := range typ.NumMethod() {
		n := strings.ToLower(typ.Method(i).Name)
		if strings.Contains(n, "checkpoint") || strings.Contains(n, "audit") {
			t.Errorf("*Keyset exposes %s (R11a: checkpoint keys are never used by the agent)", typ.Method(i).Name)
		}
	}
	st := typ.Elem()
	for i := range st.NumField() {
		if f := st.Field(i); f.IsExported() {
			t.Errorf("Keyset has exported field %s; access goes through methods only", f.Name)
		}
	}
}
