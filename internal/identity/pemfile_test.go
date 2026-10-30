package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"testing"
)

func TestPendingEnrollKeyRoundTrip(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	hash := TokenHash(canaryToken())
	data, err := EncodePendingEnrollKey(key, hash)
	if err != nil {
		t.Fatalf("EncodePendingEnrollKey: %v", err)
	}
	// The encoding is exactly the two blocks, in order, without headers.
	rest := data
	var types []string
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if len(b.Headers) != 0 {
			t.Errorf("block %q carries headers", b.Type)
		}
		types = append(types, b.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		t.Errorf("encoding has trailing data %q", rest)
	}
	if len(types) != 2 || types[0] != privateKeyBlockType() || types[1] != tokenHashBlockType {
		t.Fatalf("block types = %q", types)
	}

	got, gotHash, err := DecodePendingEnrollKey(data)
	if err != nil {
		t.Fatalf("DecodePendingEnrollKey: %v", err)
	}
	if !got.Equal(key) {
		t.Fatal("decoded key differs")
	}
	if gotHash != hash {
		t.Fatal("decoded token hash differs")
	}
	// AC35: the caller can tell a pending key bound to another token.
	if gotHash == TokenHash(otherToken()) {
		t.Fatal("hash equals the hash of another token")
	}
}

func TestPendingEnrollKeyHandBuiltAccepted(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	h := TokenHash(canaryToken())
	got, gotHash, err := DecodePendingEnrollKey(pendingPEM(t, key, h[:]))
	if err != nil {
		t.Fatalf("hand-built canonical file refused: %v", err)
	}
	if !got.Equal(key) || gotHash != h {
		t.Fatal("decoded values differ")
	}
}

func TestEncodePendingEnrollKeyRefusesBadKeys(t *testing.T) {
	t.Parallel()
	h := TokenHash(canaryToken())
	for name, k := range map[string]*ecdsa.PrivateKey{
		"nil":   nil,
		"P-384": newP384(t),
		"zero":  {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := EncodePendingEnrollKey(k, h); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("EncodePendingEnrollKey = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestDecodePendingEnrollKeyStrict(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	h := TokenHash(canaryToken())
	keyBlock := pemBlock(privateKeyBlockType(), pkcs8(t, key), nil)
	hashBlock := pemBlock(tokenHashBlockType, h[:], nil)
	certDER := newCA(t, "x", testNow).cert.Raw

	cases := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"whitespace", []byte("\n\n  \n")},
		{"key only", keyBlock},
		{"hash only", hashBlock},
		{"swapped", cat(hashBlock, keyBlock)},
		{"third block hash", cat(keyBlock, hashBlock, hashBlock)},
		{"third block key", cat(keyBlock, hashBlock, keyBlock)},
		{"third block cert", cat(keyBlock, hashBlock, pemBlock(certBlockType, certDER, nil))},
		{"two key blocks", cat(keyBlock, pemBlock(privateKeyBlockType(), pkcs8(t, newP256(t)), nil), hashBlock)},
		{"data before", cat([]byte("junk\n"), keyBlock, hashBlock)},
		{"data between", cat(keyBlock, []byte("junk\n"), hashBlock)},
		{"data after", cat(keyBlock, hashBlock, []byte("junk"))},
		{"NUL after", cat(keyBlock, hashBlock, []byte{0})},
		{"truncated", cat(keyBlock, hashBlock)[:len(keyBlock)+20]},
		{"key headers", cat(pemBlock(privateKeyBlockType(), pkcs8(t, key), map[string]string{"Proc-Type": "4,ENCRYPTED"}), hashBlock)},
		{"hash headers", cat(keyBlock, pemBlock(tokenHashBlockType, h[:], map[string]string{"X": "y"}))},
		{"SEC1 EC block", cat(pemBlock(ecPrivateKeyBlockType(), sec1(t, key), nil), hashBlock)},
		{"SEC1 bytes in PKCS8 block", cat(pemBlock(privateKeyBlockType(), sec1(t, key), nil), hashBlock)},
		{"PKCS8 bytes in EC block", cat(pemBlock(ecPrivateKeyBlockType(), pkcs8(t, key), nil), hashBlock)},
		{"RSA block type", cat(pemBlock("RSA "+privateKeyBlockType(), pkcs8(t, key), nil), hashBlock)},
		{"encrypted block type", cat(pemBlock("ENCRYPTED "+privateKeyBlockType(), pkcs8(t, key), nil), hashBlock)},
		{"lowercase key type", cat(pemBlock("private key", pkcs8(t, key), nil), hashBlock)},
		{"PKCS8 trailing byte", cat(pemBlock(privateKeyBlockType(), append(pkcs8(t, key), 0), nil), hashBlock)},
		{"PKCS8 garbage", cat(pemBlock(privateKeyBlockType(), []byte("garbage"), nil), hashBlock)},
		{"RSA PKCS8", pendingPEM(t, rsaKey(t), h[:])},
		{"P-384 PKCS8", pendingPEM(t, newP384(t), h[:])},
		{"Ed25519 PKCS8", pendingPEM(t, newEd25519(t), h[:])},
		{"hash 0 bytes", pendingPEM(t, key, nil)},
		{"hash 31 bytes", pendingPEM(t, key, h[:31])},
		{"hash 33 bytes", pendingPEM(t, key, append(h[:], 0))},
		{"hash 64 bytes", pendingPEM(t, key, append(h[:], h[:]...))},
		{"hash type with hyphen", cat(keyBlock, pemBlock("WARDEN ENROLL TOKEN SHA-256", h[:], nil))},
		{"hash type lowercase", cat(keyBlock, pemBlock("warden enroll token sha256", h[:], nil))},
		{"hash type certificate", cat(keyBlock, pemBlock(certBlockType, h[:], nil))},
		{"identity layout", identityPEM(t, key, certDER)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, _, err := DecodePendingEnrollKey(tc.in)
			if !errors.Is(err, ErrMalformedFile) {
				t.Fatalf("DecodePendingEnrollKey = %v, want ErrMalformedFile", err)
			}
			if k != nil {
				t.Error("a key was returned with the error")
			}
			assertNoLeak(t, err.Error(), tc.in, keySecrets(t, key)...)
		})
	}
}

// AC35: a pending key with "no hash" cannot decode as bound to a token, and
// an all-zero hash never equals the hash of a real token.
func TestPendingKeyNoHashNotBound(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	var zero [sha256.Size]byte
	data, err := EncodePendingEnrollKey(key, zero)
	if err != nil {
		t.Fatalf("EncodePendingEnrollKey: %v", err)
	}
	_, h, err := DecodePendingEnrollKey(data)
	if err != nil {
		t.Fatalf("DecodePendingEnrollKey: %v", err)
	}
	if h == TokenHash(canaryToken()) {
		t.Fatal("zero hash matched a token")
	}
}

func issuedIdentity(t testing.TB) (*ecdsa.PrivateKey, []byte, *testCA) {
	t.Helper()
	ca := newCA(t, "agent CA", testNow)
	key := newP256(t)
	der := ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &key.PublicKey)
	return key, der, ca
}

func TestDecodeIdentityHandBuiltAccepted(t *testing.T) {
	t.Parallel()
	key, der, _ := issuedIdentity(t)
	k, c, err := DecodeIdentity(identityPEM(t, key, der))
	if err != nil {
		t.Fatalf("DecodeIdentity: %v", err)
	}
	if !k.Equal(key) || !bytes.Equal(c.Raw, der) {
		t.Fatal("decoded identity differs")
	}
	if k.Curve != elliptic.P256() {
		t.Fatal("decoded key is not P-256")
	}
}

// DecodeIdentity does not judge validity or names (R18a decides): an expired
// certificate for another UUID still decodes when the key matches.
func TestDecodeIdentityIgnoresValidityAndNames(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	key := newP256(t)
	tmpl := agentLeafTemplate(t, otherServerID, testNow.AddDate(-1, 0, 0))
	der := ca.issue(t, tmpl, &key.PublicKey)
	if _, _, err := DecodeIdentity(identityPEM(t, key, der)); err != nil {
		t.Fatalf("DecodeIdentity refused an expired but well-formed pair: %v", err)
	}
}

func TestDecodeIdentityStrict(t *testing.T) {
	t.Parallel()
	key, der, ca := issuedIdentity(t)
	keyBlock := pemBlock(privateKeyBlockType(), pkcs8(t, key), nil)
	certBlock := pemBlock(certBlockType, der, nil)
	otherKey := newP256(t)
	otherCert := ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &otherKey.PublicKey)
	h := TokenHash(canaryToken())

	// Same certificate, other key: key must equal the certificate's.
	p384 := newP384(t)
	p384Cert := ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &p384.PublicKey)
	rsaCert := ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &rsaKey(t).PublicKey)

	cases := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"key only", keyBlock},
		{"cert only", certBlock},
		{"swapped", cat(certBlock, keyBlock)},
		{"third block cert", cat(keyBlock, certBlock, pemBlock(certBlockType, ca.cert.Raw, nil))},
		{"third block key", cat(keyBlock, certBlock, keyBlock)},
		{"two key blocks", cat(keyBlock, keyBlock, certBlock)},
		{"two cert blocks", cat(keyBlock, certBlock, certBlock)},
		{"data before", cat([]byte("junk\n"), keyBlock, certBlock)},
		{"data between", cat(keyBlock, []byte("junk\n"), certBlock)},
		{"data after", cat(keyBlock, certBlock, []byte("junk"))},
		{"key headers", cat(pemBlock(privateKeyBlockType(), pkcs8(t, key), map[string]string{"A": "b"}), certBlock)},
		{"cert headers", cat(keyBlock, pemBlock(certBlockType, der, map[string]string{"A": "b"}))},
		{"SEC1 EC block", cat(pemBlock(ecPrivateKeyBlockType(), sec1(t, key), nil), certBlock)},
		{"SEC1 bytes in PKCS8 block", cat(pemBlock(privateKeyBlockType(), sec1(t, key), nil), certBlock)},
		{"PKCS8 trailing byte", cat(pemBlock(privateKeyBlockType(), append(pkcs8(t, key), 0), nil), certBlock)},
		{"trusted certificate type", cat(keyBlock, pemBlock("TRUSTED CERTIFICATE", der, nil))},
		{"x509 certificate type", cat(keyBlock, pemBlock("X509 CERTIFICATE", der, nil))},
		{"cert DER trailing byte", cat(keyBlock, pemBlock(certBlockType, append(bytes.Clone(der), 0), nil))},
		{"cert garbage", cat(keyBlock, pemBlock(certBlockType, []byte("garbage"), nil))},
		{"key does not match cert", cat(keyBlock, pemBlock(certBlockType, otherCert, nil))},
		{"P-384 pair", identityPEM(t, p384, p384Cert)},
		{"RSA pair", identityPEM(t, rsaKey(t), rsaCert)},
		{"pending layout", pendingPEM(t, key, h[:])},
		{"CA cert with its key mismatch", identityPEM(t, key, ca.cert.Raw)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, c, err := DecodeIdentity(tc.in)
			if !errors.Is(err, ErrMalformedFile) {
				t.Fatalf("DecodeIdentity = %v, want ErrMalformedFile", err)
			}
			if k != nil || c != nil {
				t.Error("values returned with the error")
			}
			assertNoLeak(t, err.Error(), tc.in, keySecrets(t, key)...)
		})
	}
}
