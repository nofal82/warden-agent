package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
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
