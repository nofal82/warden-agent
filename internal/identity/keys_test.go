package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
)

func TestGenerateKeyIsP256(t *testing.T) {
	t.Parallel()
	k1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	for _, k := range []*ecdsa.PrivateKey{k1, k2} {
		if k == nil || k.Curve != elliptic.P256() {
			t.Fatalf("GenerateKey curve = %v, want P-256", k.Curve)
		}
		if _, err := k.ECDH(); err != nil {
			t.Fatalf("generated key is not a valid P-256 key: %v", err)
		}
	}
	if k1.Equal(k2) || k1.PublicKey.Equal(&k2.PublicKey) {
		t.Fatal("two generated keys are equal")
	}
}

func TestCreateCSR(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	der, err := CreateCSR(key)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if len(der) == 0 || len(der) > MaxCSRBytes {
		t.Fatalf("CSR is %d bytes, want 1..%d", len(der), MaxCSRBytes)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("CSR does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !pub.Equal(&key.PublicKey) {
		t.Fatal("CSR public key is not the agent key's P-256 public key")
	}
	if csr.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("public key algorithm = %v", csr.PublicKeyAlgorithm)
	}
	if len(csr.Subject.Names) != 0 || len(csr.Subject.ExtraNames) != 0 {
		t.Fatalf("CSR carries a subject: %v", csr.Subject)
	}
	if len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 {
		t.Fatalf("CSR carries %d extensions, want none", len(csr.Extensions))
	}
	if len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 {
		t.Fatal("CSR carries SANs")
	}
	if len(csr.Attributes) != 0 { //nolint:staticcheck // checking that no attribute is present
		t.Fatal("CSR carries attributes")
	}
}

func TestCreateCSRRefusesBadKeys(t *testing.T) {
	t.Parallel()
	p384 := newP384(t)
	other := newP256(t)
	cases := []struct {
		name string
		key  *ecdsa.PrivateKey
	}{
		{"nil", nil},
		{"P-384", p384},
		{"P-521", func() *ecdsa.PrivateKey {
			k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return k
		}()},
		{"P-256 curve with P-384 point", rawKey(elliptic.P256(), p384, p384)},
		{"P-384 curve with P-256 point", rawKey(elliptic.P384(), other, other)},
		{"nil curve", rawKey(nil, other, other)},
		{"zero value", &ecdsa.PrivateKey{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			der, err := CreateCSR(tc.key)
			if err == nil {
				t.Fatalf("CreateCSR accepted a bad key (%d bytes)", len(der))
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("CreateCSR error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

// A P-256 key whose public point does not belong to its private scalar must
// not yield a CSR that the control plane would verify against a key the
// agent does not hold.
func TestCreateCSRMismatchedPair(t *testing.T) {
	t.Parallel()
	a, b := newP256(t), newP256(t)
	bad := rawKey(elliptic.P256(), a, b)
	der, err := CreateCSR(bad)
	if err == nil {
		csr, perr := x509.ParseCertificateRequest(der)
		if perr == nil && csr.CheckSignature() == nil {
			t.Fatal("CreateCSR produced a verifying CSR for a mismatched key pair")
		}
		t.Fatal("CreateCSR returned a CSR for a mismatched key pair")
	}
}

// rawKey assembles a private key from the curve, the public point of pubFrom
// and the scalar of dFrom. The raw fields are deprecated because they can
// build inconsistent keys; these tests need exactly that.
//
//nolint:staticcheck // deliberately inconsistent keys
func rawKey(curve elliptic.Curve, pubFrom, dFrom *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: pubFrom.X, Y: pubFrom.Y},
		D:         dFrom.D,
	}
}

// malformedP256 returns caller-built P-256 keys that Go's deprecated raw
// fields allow but that are not valid keys (design §A.4).
//
//nolint:staticcheck // deliberately invalid keys
func malformedP256(t testing.TB) map[string]*ecdsa.PrivateKey {
	t.Helper()
	a, b := newP256(t), newP256(t)
	n := elliptic.P256().Params().N
	withD := func(d *big.Int) *ecdsa.PrivateKey {
		return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: a.X, Y: a.Y}, D: d}
	}
	withPoint := func(x, y *big.Int) *ecdsa.PrivateKey {
		return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: a.D}
	}
	return map[string]*ecdsa.PrivateKey{
		"nil D":                withD(nil),
		"D = 0":                withD(big.NewInt(0)),
		"D = N":                withD(new(big.Int).Set(n)),
		"D = N+1":              withD(new(big.Int).Add(n, big.NewInt(1))),
		"D negative":           withD(new(big.Int).Neg(a.D)),
		"nil X":                withPoint(nil, a.Y),
		"nil Y":                withPoint(a.X, nil),
		"off-curve point":      withPoint(a.X, new(big.Int).Add(a.Y, big.NewInt(1))),
		"point at infinity":    withPoint(big.NewInt(0), big.NewInt(0)),
		"D of another key":     rawKey(elliptic.P256(), a, b),
		"X beyond field prime": withPoint(new(big.Int).Add(a.X, elliptic.P256().Params().P), a.Y),
		"nil D, nil point":     {PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}},
	}
}

// Every entry point that accepts a key refuses the malformed ones with
// ErrInvalidKey and never panics.
func TestMalformedP256KeysRefused(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	good := newP256(t)
	leaf := ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &good.PublicKey)
	for name, key := range malformedP256(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			noPanic(t, "CreateCSR", func() {
				if der, err := CreateCSR(key); !errors.Is(err, ErrInvalidKey) || der != nil {
					t.Errorf("CreateCSR = %d bytes, %v; want ErrInvalidKey", len(der), err)
				}
			})
			noPanic(t, "EncodePendingEnrollKey", func() {
				if out, err := EncodePendingEnrollKey(key, TokenHash(canaryToken())); !errors.Is(err, ErrInvalidKey) || out != nil {
					t.Errorf("EncodePendingEnrollKey = %d bytes, %v; want ErrInvalidKey", len(out), err)
				}
			})
			noPanic(t, "encodeIdentity", func() {
				if out, err := encodeIdentity(key, leaf); !errors.Is(err, ErrInvalidKey) || out != nil {
					t.Errorf("encodeIdentity = %d bytes, %v; want ErrInvalidKey", len(out), err)
				}
			})
			noPanic(t, "VerifyIssued", func() {
				_, err := VerifyIssued(leaf, testServerID, key, ca.cert, testNow)
				if !errors.Is(err, ErrCertificateRejected) || !errors.Is(err, ErrInvalidKey) {
					t.Errorf("VerifyIssued = %v; want ErrCertificateRejected and ErrInvalidKey", err)
				}
			})
		})
	}
}

func noPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked on a malformed key", what)
		}
	}()
	fn()
}
