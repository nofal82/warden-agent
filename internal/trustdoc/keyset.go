package trustdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"math"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// releaseKeyDERLen is the length of a canonical P-256 SubjectPublicKeyInfo
// (§4.3).
const releaseKeyDERLen = 91

// SigningKey is one envelope-role or manifest-role key of a verified
// keyset, with its inclusive validity in Unix seconds.
type SigningKey struct {
	PublicKey ed25519.PublicKey
	NotBefore int64
	NotAfter  int64
}

func (k SigningKey) validAt(t int64) bool { return k.NotBefore <= t && t <= k.NotAfter }

// Keyset is a keyset that passed VerifyKeyset. It is immutable. It holds
// only what servers may use: the audit checkpoint keys are validated and
// then dropped (R11a), so no method can return them. The CA entries and
// release keys are validated but not kept either, until a spec rule that
// uses them is implemented (R14, R15, R40a).
type Keyset struct {
	sequence uint64
	hash     [sha256.Size]byte
	envelope []SigningKey
	manifest []SigningKey
}

// Sequence is the keyset's sequence number. Whether it is acceptable is
// for the executor's store to decide (action-envelope R32, R7a).
func (k *Keyset) Sequence() uint64 { return k.sequence }

// Hash is the R7 document hash, SHA-256(DOMAIN || 0x00 || body).
func (k *Keyset) Hash() [sha256.Size]byte { return k.hash }

// EnvelopeKeys returns a copy of the envelope-role keys.
func (k *Keyset) EnvelopeKeys() []SigningKey { return cloneKeys(k.envelope) }

// ManifestKeys returns a copy of the manifest-role keys.
func (k *Keyset) ManifestKeys() []SigningKey { return cloneKeys(k.manifest) }

func cloneKeys(in []SigningKey) []SigningKey {
	out := make([]SigningKey, len(in))
	for i, k := range in {
		k.PublicKey = bytes.Clone(k.PublicKey)
		out[i] = k
	}
	return out
}

// VerifyKeyset verifies raw as a keyset signed by root, the installation
// root public key from the server's own root-owned file (§4.3). Every
// failure is a *Rejection with CodeKeysetInvalid (action-envelope D1).
func VerifyKeyset(raw []byte, root ed25519.PublicKey) (*Keyset, error) {
	ks, reason := verifyKeyset(raw, root)
	if reason != "" {
		return nil, reject(CodeKeysetInvalid, reason)
	}
	return ks, nil
}

func verifyKeyset(raw []byte, root ed25519.PublicKey) (*Keyset, string) {
	if len(root) != ed25519.PublicKeySize {
		return nil, "root key is not an Ed25519 public key"
	}
	doc, reason := openOuter(raw, MaxKeysetBytes)
	if reason != "" {
		return nil, reason
	}
	// R10: the expected key_id is the root key fingerprint, the SHA-256 of
	// its DER SubjectPublicKeyInfo, computed from the trusted key.
	rootDER, err := x509.MarshalPKIXPublicKey(root)
	if err != nil {
		return nil, "root key does not encode"
	}
	rootID := sha256.Sum256(rootDER)
	if subtle.ConstantTimeCompare(doc.GetKeyId(), rootID[:]) != 1 {
		return nil, "key_id is not the root key fingerprint"
	}
	body := new(wardenv1.KeysetBody)
	hash, reason := verifyAndDecode(root, DomainKeyset, doc, body)
	if reason != "" {
		return nil, reason
	}
	if reason := checkKeysetBody(body, root); reason != "" {
		return nil, reason
	}
	ks := &Keyset{sequence: body.GetSequence(), hash: hash}
	for _, e := range body.GetKeys() {
		k := SigningKey{PublicKey: bytes.Clone(e.GetPublicKey()), NotBefore: e.GetNotBefore(), NotAfter: e.GetNotAfter()}
		if e.GetRole() == wardenv1.KeyRole_KEY_ROLE_ENVELOPE {
			ks.envelope = append(ks.envelope, k)
		} else {
			ks.manifest = append(ks.manifest, k)
		}
	}
	return ks, ""
}

// checkKeysetBody applies the field limits of §4.4 and the cross-field
// rules of R12.
func checkKeysetBody(b *wardenv1.KeysetBody, root ed25519.PublicKey) string {
	switch {
	case b.GetFormatVersion() != 1:
		return "unsupported format_version"
	case b.GetSequence() < 1 || b.GetSequence() > math.MaxInt64:
		return "sequence out of range"
	case b.GetSignedAt() < 1 || b.GetSignedAt() > maxTime:
		return "signed_at out of range"
	}
	if r := checkKeyEntries(b.GetKeys(), root); r != "" {
		return r
	}
	if r := checkCAs(b.GetControlplaneCas()); r != "" {
		return r
	}
	if r := checkReleaseKeys(b.GetReleaseKeys()); r != "" {
		return r
	}
	return checkCheckpointKeys(b, root)
}

func checkKeyEntries(keys []*wardenv1.KeyEntry, root ed25519.PublicKey) string {
	if len(keys) < 2 || len(keys) > 4 {
		return "keys count out of range"
	}
	// One strict order over all keys also refuses a key listed in both
	// roles (R12).
	if !sortedBy(len(keys), func(i int) []byte { return keys[i].GetPublicKey() }) {
		return "keys not sorted or not distinct"
	}
	var env, man int
	for _, e := range keys {
		switch e.GetRole() {
		case wardenv1.KeyRole_KEY_ROLE_ENVELOPE:
			env++
		case wardenv1.KeyRole_KEY_ROLE_MANIFEST:
			man++
		default:
			return "key without a valid role"
		}
		switch {
		case len(e.GetPublicKey()) != ed25519.PublicKeySize:
			return "key is not 32 bytes"
		case bytes.Equal(e.GetPublicKey(), root):
			return "key equal to the root key"
		case !validity(e.GetNotBefore(), e.GetNotAfter(), MaxKeyValidity):
			return "key validity out of range"
		}
	}
	if env < 1 || env > 2 || man < 1 || man > 2 {
		return "wrong number of keys for a role"
	}
	return ""
}

func checkCAs(cas []*wardenv1.CaEntry) string {
	if len(cas) < 1 || len(cas) > 2 {
		return "controlplane_cas count out of range"
	}
	if !sortedBy(len(cas), func(i int) []byte { return cas[i].GetFingerprint() }) {
		return "controlplane_cas not sorted or not distinct"
	}
	for _, c := range cas {
		if len(c.GetFingerprint()) != sha256.Size {
			return "CA fingerprint is not 32 bytes"
		}
		if !validity(c.GetNotBefore(), c.GetNotAfter(), MaxCAEntryValidity) {
			return "CA validity out of range"
		}
	}
	return ""
}

func checkReleaseKeys(keys [][]byte) string {
	if len(keys) < 1 || len(keys) > 2 {
		return "release_keys count out of range"
	}
	if !sortedBy(len(keys), func(i int) []byte { return keys[i] }) {
		return "release_keys not sorted or not distinct"
	}
	for _, der := range keys {
		if !canonicalP256(der) {
			return "release key is not a canonical P-256 key"
		}
	}
	return ""
}

// canonicalP256 is the §4.3 rule: exactly 91 bytes, parses as an ECDSA
// P-256 key, and re-marshals to the identical bytes.
func canonicalP256(der []byte) bool {
	if len(der) != releaseKeyDERLen {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return false
	}
	again, err := x509.MarshalPKIXPublicKey(ec)
	return err == nil && bytes.Equal(again, der)
}

// checkCheckpointKeys validates field 7 (R11, R11a, R12). The entries are
// never returned; they only have to be well formed.
func checkCheckpointKeys(b *wardenv1.KeysetBody, root ed25519.PublicKey) string {
	cps := b.GetAuditCheckpointKeys()
	if len(cps) > 2 {
		return "audit_checkpoint_keys count out of range"
	}
	if !sortedBy(len(cps), func(i int) []byte { return cps[i].GetFingerprint() }) {
		return "audit_checkpoint_keys not sorted or not distinct"
	}
	taken := takenFingerprints(b, root)
	for _, c := range cps {
		fp := c.GetFingerprint()
		if len(fp) != sha256.Size {
			return "checkpoint fingerprint is not 32 bytes"
		}
		if !validity(c.GetNotBefore(), c.GetNotAfter(), MaxKeyValidity) {
			return "checkpoint validity out of range"
		}
		if _, dup := taken[[sha256.Size]byte(fp)]; dup {
			return "checkpoint fingerprint equals another key or CA"
		}
	}
	return ""
}

// takenFingerprints are the values R12 forbids for a checkpoint
// fingerprint: the key_id of every envelope- and manifest-role key, the
// root key's raw-key SHA-256, every CA fingerprint and every release-key
// fingerprint.
func takenFingerprints(b *wardenv1.KeysetBody, root ed25519.PublicKey) map[[sha256.Size]byte]struct{} {
	taken := map[[sha256.Size]byte]struct{}{sha256.Sum256(root): {}}
	for _, e := range b.GetKeys() {
		taken[sha256.Sum256(e.GetPublicKey())] = struct{}{}
	}
	for _, c := range b.GetControlplaneCas() {
		taken[[sha256.Size]byte(c.GetFingerprint())] = struct{}{}
	}
	for _, der := range b.GetReleaseKeys() {
		taken[sha256.Sum256(der)] = struct{}{}
	}
	return taken
}
