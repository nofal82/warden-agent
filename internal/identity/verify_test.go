package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// verifyFixture is an agent CA, the agent's pending key and a correct leaf.
type verifyFixture struct {
	ca   *testCA
	key  *ecdsa.PrivateKey
	leaf []byte
}

func newVerifyFixture(t testing.TB) *verifyFixture {
	t.Helper()
	ca := newCA(t, "warden agent CA", testNow)
	key := newP256(t)
	return &verifyFixture{ca: ca, key: key, leaf: ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &key.PublicKey)}
}

func TestVerifyIssuedAccepts(t *testing.T) {
	t.Parallel()
	f := newVerifyFixture(t)
	v, err := VerifyIssued(f.leaf, testServerID, f.key, f.ca.cert, testNow)
	if err != nil {
		t.Fatalf("VerifyIssued refused a correct leaf: %v", err)
	}
	if c := v.Certificate(); c == nil || !bytes.Equal(c.Raw, f.leaf) {
		t.Fatal("Certificate() is not the verified leaf")
	}
	tc := v.TLSCertificate()
	if len(tc.Certificate) != 1 || !bytes.Equal(tc.Certificate[0], f.leaf) {
		t.Fatalf("TLSCertificate chain = %d certs, want exactly the leaf", len(tc.Certificate))
	}
	k, ok := tc.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !k.Equal(f.key) {
		t.Fatal("TLSCertificate private key is not the agent key")
	}
	if tc.Leaf != nil && !bytes.Equal(tc.Leaf.Raw, f.leaf) {
		t.Fatal("TLSCertificate Leaf differs")
	}
}

// Validity edges: one second after not-before and one second before
// not-after are inside the window.
func TestVerifyIssuedValidityEdges(t *testing.T) {
	t.Parallel()
	f := newVerifyFixture(t)
	c := mustParse(t, f.leaf)
	for _, now := range []time.Time{c.NotBefore.Add(time.Second), c.NotAfter.Add(-time.Second)} {
		if _, err := VerifyIssued(f.leaf, testServerID, f.key, f.ca.cert, now); err != nil {
			t.Fatalf("VerifyIssued at %v: %v", now, err)
		}
	}
}

func TestVerifyIssuedRejects(t *testing.T) {
	t.Parallel()
	f := newVerifyFixture(t)
	pub := &f.key.PublicKey
	leaf := func(mut func(*x509.Certificate)) []byte {
		tmpl := agentLeafTemplate(t, testServerID, testNow)
		mut(tmpl)
		return f.ca.issue(t, tmpl, pub)
	}
	otherCA := newCA(t, "warden agent CA", testNow) // same name, other key
	inter := newCAFrom(t, caTemplate(t, "intermediate", testNow), f.ca)
	notCA := func() *testCA {
		tmpl := caTemplate(t, "not a CA", testNow)
		tmpl.IsCA = false
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		return newCAFrom(t, tmpl, nil)
	}()
	upper := strings.ToUpper(testServerID)

	sigFlipped := bytes.Clone(f.leaf)
	sigFlipped[len(sigFlipped)-1] ^= 0x01

	oversized := leaf(func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: bytesOf(4200, 'x')}}
	})
	if len(oversized) <= MaxCertificateBytes {
		t.Fatalf("oversized leaf is only %d bytes", len(oversized))
	}

	cases := []struct {
		name    string
		der     []byte
		agentCA *x509.Certificate
		now     time.Time
	}{
		{"CN other UUID", leaf(func(c *x509.Certificate) { c.Subject.CommonName = otherServerID }), nil, testNow},
		{"SAN other UUID", leaf(func(c *x509.Certificate) { c.URIs = []*url.URL{uuidURN(t, otherServerID)} }), nil, testNow},
		{"both other UUID", f.ca.issue(t, agentLeafTemplate(t, otherServerID, testNow), pub), nil, testNow},
		{"two URI SANs", leaf(func(c *x509.Certificate) { c.URIs = append(c.URIs, uuidURN(t, otherServerID)) }), nil, testNow},
		{"same URI SAN twice", leaf(func(c *x509.Certificate) { c.URIs = append(c.URIs, uuidURN(t, testServerID)) }), nil, testNow},
		{"extra DNS SAN", leaf(func(c *x509.Certificate) { c.DNSNames = []string{testServerName} }), nil, testNow},
		{"extra IP SAN", leaf(func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }), nil, testNow},
		{"extra email SAN", leaf(func(c *x509.Certificate) { c.EmailAddresses = []string{"agent@example.test"} }), nil, testNow},
		{"no SAN", leaf(func(c *x509.Certificate) { c.URIs = nil }), nil, testNow},
		{"SAN uppercase URN scheme", leaf(func(c *x509.Certificate) {
			u, _ := url.Parse("URN:UUID:" + testServerID)
			c.URIs = []*url.URL{u}
		}), nil, testNow},
		{"SAN with query", leaf(func(c *x509.Certificate) {
			u, _ := url.Parse("urn:uuid:" + testServerID + "?x=1")
			c.URIs = []*url.URL{u}
		}), nil, testNow},
		{"SAN https URL", leaf(func(c *x509.Certificate) {
			u, _ := url.Parse("https://" + testServerID + "/")
			c.URIs = []*url.URL{u}
		}), nil, testNow},
		{"no CN", leaf(func(c *x509.Certificate) { c.Subject = pkix.Name{} }), nil, testNow},
		{"CN trailing space", leaf(func(c *x509.Certificate) { c.Subject.CommonName = testServerID + " " }), nil, testNow},
		{"extra O attribute", leaf(func(c *x509.Certificate) { c.Subject.Organization = []string{"Warden"} }), nil, testNow},
		{"second CN", leaf(func(c *x509.Certificate) {
			c.RawSubject = rawSubject(t, pkix.RDNSequence{
				{{Type: oidCommonName, Value: testServerID}},
				{{Type: oidCommonName, Value: otherServerID}},
			})
		}), nil, testNow},
		{"second CN equal", leaf(func(c *x509.Certificate) {
			c.RawSubject = rawSubject(t, pkix.RDNSequence{
				{{Type: oidCommonName, Value: testServerID}},
				{{Type: oidCommonName, Value: testServerID}},
			})
		}), nil, testNow},
		{"multi-valued RDN", leaf(func(c *x509.Certificate) {
			c.RawSubject = rawSubject(t, pkix.RDNSequence{
				{{Type: oidCommonName, Value: testServerID}, {Type: oidOrganization, Value: "x"}},
			})
		}), nil, testNow},
		{"uppercase UUID in cert", leaf(func(c *x509.Certificate) {
			c.Subject.CommonName = upper
			c.URIs = []*url.URL{uuidURN(t, upper)}
		}), nil, testNow},
		{"other public key", f.ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &newP256(t).PublicKey), nil, testNow},
		{"RSA public key", f.ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &rsaKey(t).PublicKey), nil, testNow},
		{"signed by another CA", otherCA.issue(t, agentLeafTemplate(t, testServerID, testNow), pub), nil, testNow},
		{"signed by intermediate under agent CA", inter.issue(t, agentLeafTemplate(t, testServerID, testNow), pub), nil, testNow},
		{"agent CA not a CA", notCA.issue(t, agentLeafTemplate(t, testServerID, testNow), pub), notCA.cert, testNow},
		{"agentCA argument is another CA", leaf(func(*x509.Certificate) {}), inter.cert, testNow},
		{"leaf is a CA", leaf(func(c *x509.Certificate) {
			c.IsCA = true
			c.KeyUsage |= x509.KeyUsageCertSign
		}), nil, testNow},
		{"EKU serverAuth only", leaf(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }), nil, testNow},
		{"EKU clientAuth and serverAuth", leaf(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}), nil, testNow},
		{"EKU any", leaf(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }), nil, testNow},
		{"no EKU", leaf(func(c *x509.Certificate) { c.ExtKeyUsage = nil }), nil, testNow},
		{"expired", f.leaf, nil, testNow.Add(31 * 24 * time.Hour)},
		{"not yet valid", f.leaf, nil, testNow.Add(-2 * time.Minute)},
		{"bad signature", sigFlipped, nil, testNow},
		{"trailing byte", append(bytes.Clone(f.leaf), 0), nil, testNow},
		{"trailing certificate", cat(f.leaf, f.ca.cert.Raw), nil, testNow},
		{"truncated", f.leaf[:len(f.leaf)-1], nil, testNow},
		{"over 4096 bytes", oversized, nil, testNow},
		{"4097 bytes padded", append(bytes.Clone(f.leaf), make([]byte, MaxCertificateBytes+1-len(f.leaf))...), nil, testNow},
		{"empty", []byte{}, nil, testNow},
		{"nil", nil, nil, testNow},
		{"garbage", []byte("not a certificate"), nil, testNow},
		{"PEM instead of DER", pemBlock(certBlockType, f.leaf, nil), nil, testNow},
		{"the agent CA itself", f.ca.cert.Raw, nil, testNow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agentCA := tc.agentCA
			if agentCA == nil {
				agentCA = f.ca.cert
			}
			v, err := VerifyIssued(tc.der, testServerID, f.key, agentCA, tc.now)
			if !errors.Is(err, ErrCertificateRejected) {
				t.Fatalf("VerifyIssued = %v, want ErrCertificateRejected", err)
			}
			if v.Certificate() != nil {
				t.Error("a certificate was returned with the error")
			}
			assertNoLeak(t, err.Error(), nil, keySecrets(t, f.key)...)
		})
	}
}

// The serverID argument itself must be §4.1 canonical, and a mismatch
// between the argument and the certificate is never "fixed" by adopting the
// certificate's UUID.
func TestVerifyIssuedServerIDArgument(t *testing.T) {
	t.Parallel()
	f := newVerifyFixture(t)
	for _, id := range []string{"", strings.ToUpper(testServerID), testServerID + "\n", otherServerID, "urn:uuid:" + testServerID} {
		if _, err := VerifyIssued(f.leaf, id, f.key, f.ca.cert, testNow); err == nil {
			t.Fatalf("VerifyIssued accepted serverID %q", id)
		}
	}
	// A certificate and a serverID that agree with each other but are not
	// §4.1 canonical (uppercase, version 1) are still refused.
	for _, id := range []string{strings.ToUpper(testServerID), "6f1c2d3e-4a5b-1c6d-8e7f-90a1b2c3d4e5"} {
		der := f.ca.issue(t, agentLeafTemplate(t, id, testNow), &f.key.PublicKey)
		if _, err := VerifyIssued(der, id, f.key, f.ca.cert, testNow); !errors.Is(err, ErrCertificateRejected) {
			t.Fatalf("VerifyIssued with matching non-canonical serverID %q: %v, want ErrCertificateRejected", id, err)
		}
	}
}

func TestVerifyIssuedNilInputs(t *testing.T) {
	t.Parallel()
	f := newVerifyFixture(t)
	if _, err := VerifyIssued(f.leaf, testServerID, nil, f.ca.cert, testNow); err == nil {
		t.Fatal("nil key accepted")
	}
	if _, err := VerifyIssued(f.leaf, testServerID, f.key, nil, testNow); err == nil {
		t.Fatal("nil agent CA accepted")
	}
	if _, err := VerifyIssued(f.leaf, testServerID, &ecdsa.PrivateKey{}, f.ca.cert, testNow); err == nil {
		t.Fatal("zero key accepted")
	}
	if _, err := VerifyIssued(f.leaf, testServerID, f.key, &x509.Certificate{}, testNow); err == nil {
		t.Fatal("zero agent CA accepted")
	}
}

// A zero VerifiedIdentity (constructible outside the package) is never a
// usable identity.
func TestZeroVerifiedIdentity(t *testing.T) {
	t.Parallel()
	var v VerifiedIdentity
	if v.Certificate() != nil {
		t.Fatal("zero identity has a certificate")
	}
	if tc := v.TLSCertificate(); len(tc.Certificate) != 0 || tc.PrivateKey != nil {
		t.Fatal("zero identity has a TLS certificate")
	}
}
