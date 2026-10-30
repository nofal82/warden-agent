package identity

// Native fuzz tests for every parser and validator of the package. Seeds
// are the attack cases of the unit tests; key material is generated at
// runtime, so no seed is a real secret.
//
// Note for whoever runs `make fuzz-short`: a failing input is saved under
// testdata/fuzz/. Inputs of FuzzDecodePendingEnrollKey and
// FuzzDecodeIdentity may contain a PEM private-key header; such a corpus file
// must be reduced (or its block type changed) before it is committed, as the
// rule checker refuses that header.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

var (
	serverIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenRe    = regexp.MustCompile(`^wdn1_[A-Za-z0-9_-]{43}$`)
)

func FuzzValidateServerID(f *testing.F) {
	for _, s := range []string{
		testServerID, otherServerID, strings.ToUpper(testServerID), "", testServerID + "\n",
		"\ufeff" + testServerID, "{" + testServerID + "}", testServerID[:35], testServerID + "0",
		"01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f", "6f1c2d3e-4a5b-4c6d-ce7f-90a1b2c3d4e5",
		"00000000-0000-0000-0000-000000000000", "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e\x00",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateServerID(s)
		// The spec regex is the exact oracle (§4.1).
		if want := serverIDRe.MatchString(s); want != (err == nil) {
			t.Fatalf("ValidateServerID(%q) = %v, regex says valid=%v", s, err, want)
		}
		if err != nil && !errors.Is(err, ErrInvalidServerID) {
			t.Fatalf("wrong error class: %v", err)
		}
		if err == nil && len(s) != 36 {
			t.Fatalf("accepted %d bytes", len(s))
		}
	})
}

func FuzzValidateToken(f *testing.F) {
	body := strings.Repeat("Q", 43)
	for _, s := range []string{
		canaryToken(), otherToken(), "", "wdn1" + "_", "wdn1" + "_" + body[:42],
		"wdn1" + "_" + body + "Q", "wdn1" + "_" + body[:42] + "=", "wdn1" + "_" + body[:42] + "+",
		"wdn1" + "_" + body[:42] + "/", "wdn2" + "_" + body, "WDN1" + "_" + body,
		"wdn1" + "_" + body[:41] + "\u00e9", "wdn1" + "_" + body[:42] + "\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateToken(s)
		if want := tokenRe.MatchString(s); want != (err == nil) {
			t.Fatalf("ValidateToken(len %d) = %v, regex says valid=%v", len(s), err, want)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("wrong error class: %v", err)
			}
			if len(s) >= 8 && strings.Contains(err.Error(), s) {
				t.Fatal("error echoes the input")
			}
		}
	})
}

// ldhName reports whether s is a DNS name under the §4.3 rules.
func ldhName(s string) bool {
	for _, l := range strings.Split(s, ".") {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if !isLDH(l[i]) {
				return false
			}
		}
	}
	return true
}

func isLDH(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

func FuzzValidateServerName(f *testing.F) {
	for _, s := range []string{
		testServerName, "localhost", "192.0.2.10", "2001:db8::10", "::1", "", "*.example.test",
		"cp.example.test.", "-cp.example.test", "cp-.example.test", "cp..example.test",
		"cp_1.example.test", "cp example.test", testServerName + ":443", "[2001:db8::10]",
		"https://" + testServerName, "c\u00e9.example.test", "fe80::1%eth0", strings.Repeat("a", 64),
		strings.Repeat("a.", 127),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateServerName(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidServerName) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if len(s) < 1 || len(s) > 253 {
			t.Fatalf("accepted a name of %d bytes", len(s))
		}
		if strings.ContainsAny(s, "*[]/@% \t\r\n\x00_") {
			t.Fatalf("accepted %q", s)
		}
		addr, ipErr := netip.ParseAddr(s)
		isIP := ipErr == nil && addr.Zone() == ""
		if !isIP && !ldhName(s) {
			t.Fatalf("accepted %q, which is neither an IP literal nor an LDH DNS name", s)
		}
	})
}

func FuzzNewExecutorBinding(f *testing.F) {
	for _, n := range [][2]int{{32, 32}, {0, 0}, {31, 32}, {33, 32}, {32, 31}, {32, 33}, {64, 64}} {
		f.Add(bytesOf(n[0], 0xa5), bytesOf(n[1], 0x5a))
	}
	f.Fuzz(func(t *testing.T, pub, mac []byte) {
		b, err := NewExecutorBinding(pub, mac)
		want := len(pub) == 32 && len(mac) == 32
		if want != (err == nil) {
			t.Fatalf("NewExecutorBinding(%d, %d) = %v", len(pub), len(mac), err)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if !bytes.Equal(b.PublicKey[:], pub) || !bytes.Equal(b.MAC[:], mac) {
			t.Fatal("binding differs from input")
		}
	})
}

func FuzzDecodePendingEnrollKey(f *testing.F) {
	key := newP256(f)
	h := TokenHash(canaryToken())
	keyBlock := pemBlock(privateKeyBlockType(), pkcs8(f, key), nil)
	hashBlock := pemBlock(tokenHashBlockType, h[:], nil)
	for _, s := range [][]byte{
		pendingPEM(f, key, h[:]),
		cat(hashBlock, keyBlock),
		cat(keyBlock, hashBlock, hashBlock),
		cat([]byte("x"), keyBlock, hashBlock),
		cat(keyBlock, hashBlock, []byte("x")),
		pendingPEM(f, key, h[:31]),
		pendingPEM(f, key, append(h[:], 0)),
		pendingPEM(f, newP384(f), h[:]),
		cat(pemBlock(ecPrivateKeyBlockType(), sec1(f, key), nil), hashBlock),
		cat(pemBlock(privateKeyBlockType(), pkcs8(f, key), map[string]string{"A": "b"}), hashBlock),
		{},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, hash, err := DecodePendingEnrollKey(data)
		if err != nil {
			if !errors.Is(err, ErrMalformedFile) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if k == nil || k.Curve != elliptic.P256() {
			t.Fatal("accepted a key that is not P-256")
		}
		again, err := EncodePendingEnrollKey(k, hash)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		k2, h2, err := DecodePendingEnrollKey(again)
		if err != nil || !k2.Equal(k) || h2 != hash {
			t.Fatalf("re-encoded file does not round-trip: %v", err)
		}
	})
}

func FuzzDecodeIdentity(f *testing.F) {
	ca := newCA(f, "agent CA", testNow)
	key := newP256(f)
	der := ca.issue(f, agentLeafTemplate(f, testServerID, testNow), &key.PublicKey)
	keyBlock := pemBlock(privateKeyBlockType(), pkcs8(f, key), nil)
	certBlock := pemBlock(certBlockType, der, nil)
	other := newP256(f)
	for _, s := range [][]byte{
		identityPEM(f, key, der),
		cat(certBlock, keyBlock),
		cat(keyBlock, certBlock, certBlock),
		cat(keyBlock, keyBlock, certBlock),
		cat([]byte("x"), keyBlock, certBlock),
		cat(keyBlock, certBlock, []byte("x")),
		identityPEM(f, other, der),
		cat(keyBlock, pemBlock(certBlockType, append(bytes.Clone(der), 0), nil)),
		cat(pemBlock(ecPrivateKeyBlockType(), sec1(f, key), nil), certBlock),
		{},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, c, err := DecodeIdentity(data)
		if err != nil {
			if !errors.Is(err, ErrMalformedFile) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if k == nil || c == nil || k.Curve != elliptic.P256() {
			t.Fatal("accepted a non-P-256 key or nil values")
		}
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		if !ok || !pub.Equal(&k.PublicKey) {
			t.Fatal("accepted a certificate whose key is not the private key's")
		}
		k2, c2, err := DecodeIdentity(identityPEM(t, k, c.Raw))
		if err != nil || !k2.Equal(k) || !bytes.Equal(c2.Raw, c.Raw) {
			t.Fatalf("re-encoded identity does not round-trip: %v", err)
		}
	})
}

func FuzzVerifyIssued(f *testing.F) {
	fx := newVerifyFixture(f)
	valid := mustParse(f, fx.leaf)
	pub := &fx.key.PublicKey
	other := newCA(f, "warden agent CA", testNow)
	f.Add(fx.leaf)
	f.Add(append(bytes.Clone(fx.leaf), 0))
	f.Add(fx.leaf[:len(fx.leaf)-1])
	f.Add([]byte{})
	f.Add([]byte("garbage"))
	f.Add(fx.ca.cert.Raw)
	f.Add(fx.ca.issue(f, agentLeafTemplate(f, otherServerID, testNow), pub))
	f.Add(other.issue(f, agentLeafTemplate(f, testServerID, testNow), pub))
	srv := agentLeafTemplate(f, testServerID, testNow)
	srv.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	f.Add(fx.ca.issue(f, srv, pub))
	f.Fuzz(func(t *testing.T, der []byte) {
		v, err := VerifyIssued(der, testServerID, fx.key, fx.ca.cert, testNow)
		if err != nil {
			if !errors.Is(err, ErrCertificateRejected) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		// Only the one valid leaf (up to ECDSA signature re-encoding) can be
		// accepted: anything else would need a forged agent-CA signature.
		c := v.Certificate()
		if c == nil || !bytes.Equal(c.RawTBSCertificate, valid.RawTBSCertificate) {
			t.Fatal("accepted a certificate other than the valid leaf")
		}
		if len(der) > MaxCertificateBytes {
			t.Fatalf("accepted %d bytes", len(der))
		}
	})
}
