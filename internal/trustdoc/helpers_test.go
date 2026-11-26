package trustdoc

// Test helpers for the keyset and manifest verifier tests (issue #69,
// signing-and-updates §4.1–4.6). Nothing here is a real secret: every
// Ed25519 and P-256 key is generated at runtime, and fixed key-shaped bytes
// in golden vectors are built with bytes.Repeat.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"sort"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// fakeNow is the fixed verifier clock (2027-01-15).
const fakeNow int64 = 1_800_000_000

const (
	serverA = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	serverB = "7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d"
)

// Domain literals are written out independently of the package constants so
// a wrong constant cannot make the tests agree with a wrong implementation.
const (
	litDomainKeyset   = "warden/v1/envelope-keyset\x00"
	litDomainManifest = "warden/v1/server-manifest\x00"
	litDomainEnvelope = "warden/v1/action-envelope\x00"
)

func clockAt(sec int64) func() time.Time {
	return func() time.Time { return time.Unix(sec, 0) }
}

type edKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKey(tb testing.TB) edKey {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519 key: %v", err)
	}
	return edKey{pub: pub, priv: priv}
}

// spkiID is the keyset key id: SHA-256 of the DER SubjectPublicKeyInfo.
func spkiID(tb testing.TB, pub ed25519.PublicKey) []byte {
	tb.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		tb.Fatalf("marshal SPKI: %v", err)
	}
	sum := sha256.Sum256(der)
	return sum[:]
}

// rawID is the manifest key id: SHA-256 of the raw 32-byte key.
func rawID(pub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(pub)
	return sum[:]
}

func randBytes(tb testing.TB, n int) []byte {
	tb.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	return b
}

func ecdsaDER(tb testing.TB, c elliptic.Curve) []byte {
	tb.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		tb.Fatalf("marshal SPKI: %v", err)
	}
	return der
}

// p256GeneratorDER is the canonical 91-byte SPKI of the P-256 base point: a
// valid, deterministic release key for golden vectors.
func p256GeneratorDER(tb testing.TB) []byte {
	tb.Helper()
	p := elliptic.P256().Params()
	pt := make([]byte, 65)
	pt[0] = 4
	p.Gx.FillBytes(pt[1:33])
	p.Gy.FillBytes(pt[33:])
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		tb.Fatalf("parse generator: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		tb.Fatalf("marshal SPKI: %v", err)
	}
	return der
}

func fingerprint(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// fixture holds one trust root and the keys a valid keyset names.
type fixture struct {
	root, env, man, cp edKey
	ca                 []byte
	rel                []byte
}

func newFixture(tb testing.TB) *fixture {
	tb.Helper()
	return &fixture{
		root: newKey(tb), env: newKey(tb), man: newKey(tb), cp: newKey(tb),
		ca:  randBytes(tb, 32),
		rel: ecdsaDER(tb, elliptic.P256()),
	}
}

const (
	validFrom  = fakeNow - 1000
	validUntil = fakeNow + 1000
)

// keysetBody returns a valid, canonically sorted body with no checkpoint
// entries.
func (fx *fixture) keysetBody() *wardenv1.KeysetBody {
	b := &wardenv1.KeysetBody{
		FormatVersion: 1,
		Sequence:      1,
		SignedAt:      fakeNow - 10,
		Keys: []*wardenv1.KeyEntry{
			{Role: wardenv1.KeyRole_KEY_ROLE_ENVELOPE, PublicKey: fx.env.pub, NotBefore: validFrom, NotAfter: validUntil},
			{Role: wardenv1.KeyRole_KEY_ROLE_MANIFEST, PublicKey: fx.man.pub, NotBefore: validFrom, NotAfter: validUntil},
		},
		ControlplaneCas: []*wardenv1.CaEntry{{Fingerprint: fx.ca, NotBefore: validFrom, NotAfter: validUntil}},
		ReleaseKeys:     [][]byte{fx.rel},
	}
	sortKeyset(b)
	return b
}

func cpEntry(fp []byte) *wardenv1.CheckpointKeyEntry {
	return &wardenv1.CheckpointKeyEntry{Fingerprint: fp, NotBefore: validFrom, NotAfter: validUntil}
}

// sortKeyset restores the canonical order after a mutation adds entries, so
// a row breaks only the rule under test.
func sortKeyset(b *wardenv1.KeysetBody) {
	sort.SliceStable(b.Keys, func(i, j int) bool { return bytes.Compare(b.Keys[i].PublicKey, b.Keys[j].PublicKey) < 0 })
	sort.SliceStable(b.ControlplaneCas, func(i, j int) bool {
		return bytes.Compare(b.ControlplaneCas[i].Fingerprint, b.ControlplaneCas[j].Fingerprint) < 0
	})
	sort.SliceStable(b.ReleaseKeys, func(i, j int) bool { return bytes.Compare(b.ReleaseKeys[i], b.ReleaseKeys[j]) < 0 })
	sort.SliceStable(b.AuditCheckpointKeys, func(i, j int) bool {
		return bytes.Compare(b.AuditCheckpointKeys[i].Fingerprint, b.AuditCheckpointKeys[j].Fingerprint) < 0
	})
}

func marshalDet(tb testing.TB, m proto.Message) []byte {
	tb.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	return b
}

func message(domain string, body []byte) []byte {
	return append([]byte(domain), body...)
}

func sign(k edKey, domain string, body []byte) []byte {
	return ed25519.Sign(k.priv, message(domain, body))
}

// wrap encodes a SignedDocument by hand so lengths and empty fields are
// exactly what the test says.
func wrap(keyID, body, sig []byte) []byte {
	var b []byte
	if keyID != nil {
		b = fBytes(b, 1, keyID)
	}
	if body != nil {
		b = fBytes(b, 2, body)
	}
	if sig != nil {
		b = fBytes(b, 3, sig)
	}
	return b
}

func fBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func fVarint(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

// keysetRaw signs body with the root under the keyset domain.
func (fx *fixture) keysetRaw(tb testing.TB, body []byte) []byte {
	tb.Helper()
	return wrap(spkiID(tb, fx.root.pub), body, sign(fx.root, litDomainKeyset, body))
}

func (fx *fixture) keysetDoc(tb testing.TB, mut func(*wardenv1.KeysetBody)) []byte {
	tb.Helper()
	b := fx.keysetBody()
	if mut != nil {
		mut(b)
	}
	return fx.keysetRaw(tb, marshalDet(tb, b))
}

func (fx *fixture) keyset(tb testing.TB, mut func(*wardenv1.KeysetBody)) *Keyset {
	tb.Helper()
	ks, err := VerifyKeyset(fx.keysetDoc(tb, mut), fx.root.pub)
	if err != nil {
		tb.Fatalf("fixture keyset refused: %v", err)
	}
	return ks
}

// Manifest fixtures ---------------------------------------------------------

type fakeCatalog map[string]uint32

func (c fakeCatalog) MaxActStepsPerHour(id string) (uint32, bool) {
	v, ok := c[id]
	return v, ok
}

func testCatalog() fakeCatalog {
	return fakeCatalog{"disk-cleanup": 10, "service-recover": 3}
}

func manifestBody() *wardenv1.ManifestBody {
	return &wardenv1.ManifestBody{
		FormatVersion: 1,
		ServerId:      serverA,
		Sequence:      1,
		IssuedAt:      fakeNow - 10,
		Playbooks: []*wardenv1.EnabledPlaybook{
			{PlaybookId: "disk-cleanup", AutonomyCeiling: wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L2, MaxActStepsPerHour: proto.Uint32(5)},
			{PlaybookId: "service-recover", AutonomyCeiling: wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L1, MaxActStepsPerHour: proto.Uint32(3)},
		},
		BackupUnits:      []string{"backup-nightly.service"},
		AdminListedUnits: []string{"nginx.service"},
	}
}

func manifestRaw(k edKey, domain string, body []byte) []byte {
	return wrap(rawID(k.pub), body, sign(k, domain, body))
}

func (fx *fixture) manifestDoc(tb testing.TB, mut func(*wardenv1.ManifestBody)) []byte {
	tb.Helper()
	b := manifestBody()
	if mut != nil {
		mut(b)
	}
	return manifestRaw(fx.man, litDomainManifest, marshalDet(tb, b))
}

func cfgFor(ks *Keyset) ManifestConfig {
	return ManifestConfig{Keyset: ks, Catalog: testCatalog(), ServerID: serverA, Now: clockAt(fakeNow)}
}

// Assertions ----------------------------------------------------------------

func wantRejected(tb testing.TB, got any, err error, code Code) {
	tb.Helper()
	var r *Rejection
	if !errors.As(err, &r) {
		tb.Fatalf("err = %v, want *Rejection %s", err, code)
	}
	if r.Code != code {
		tb.Fatalf("code = %s (%s), want %s", r.Code, r.Reason, code)
	}
	switch v := got.(type) {
	case *Keyset:
		if v != nil {
			tb.Fatal("rejected keyset returned non-nil *Keyset")
		}
	case *Manifest:
		if v != nil {
			tb.Fatal("rejected manifest returned non-nil *Manifest")
		}
	}
}

// Ed25519 group order and S manipulation (R4a) ------------------------------

var groupOrderL = func() *big.Int {
	l, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		panic("bad L constant")
	}
	return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
}()

// withS replaces S (bytes 32..63) of sig with n, little-endian.
func withS(sig []byte, n *big.Int) []byte {
	be := n.Bytes()
	out := append([]byte(nil), sig[:32]...)
	s := make([]byte, 32)
	for i := range be {
		s[i] = be[len(be)-1-i]
	}
	return append(out, s...)
}

// padBodyTo appends one unknown bytes field to body so that the signed
// document built by seal is exactly n bytes. The document is correctly
// signed, so only a size check that runs before verification refuses it
// without moving signatureVerifies.
func padBodyTo(tb testing.TB, body []byte, n int, seal func([]byte) []byte) []byte {
	tb.Helper()
	// Every seal produces a 32-byte key id and a 64-byte signature, so the
	// size is found with placeholders and the document is signed once.
	for k := 0; k <= n; k++ {
		padded := fBytes(append([]byte(nil), body...), 100, make([]byte, k))
		size := len(wrap(make([]byte, 32), padded, make([]byte, 64)))
		if size == n {
			raw := seal(padded)
			if len(raw) != n {
				tb.Fatalf("padded document is %d bytes, want %d", len(raw), n)
			}
			return raw
		}
		if size > n {
			break
		}
	}
	tb.Fatalf("cannot pad document to %d bytes", n)
	return nil
}
