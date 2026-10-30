package identity

// Test helpers shared by the identity tests. Nothing here is a real secret:
// every key is generated at runtime, every token is an obvious fake built
// from fragments, and PEM private-key blocks are produced only through
// encoding/pem with the block type assembled at runtime.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// testNow is the fixed clock for tests that take a time (2027-01-15).
var testNow = time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC)

const (
	testServerID   = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	otherServerID  = "7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d"
	testServerName = "cp.example.test"

	certBlockType      = "CERTIFICATE"
	tokenHashBlockType = "WARDEN ENROLL TOKEN SHA256"
)

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
var oidOrganization = asn1.ObjectIdentifier{2, 5, 4, 10}

// privateKeyBlockType is the PKCS #8 PEM type, built at runtime so no file
// carries a private-key PEM header literal.
func privateKeyBlockType() string { return "PRIVATE" + " " + "KEY" }

// ecPrivateKeyBlockType is the SEC 1 PEM type.
func ecPrivateKeyBlockType() string { return "EC " + privateKeyBlockType() }

// canaryToken is an obviously fake enrollment token in the §4.2 text form.
func canaryToken() string { return "wdn1" + "_" + strings.Repeat("Q", 43) }

// otherToken is a second fake token, different from canaryToken.
func otherToken() string { return "wdn1" + "_" + strings.Repeat("R", 43) }

func newP256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return k
}

func newP384(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	return k
}

var (
	rsaOnce sync.Once
	rsaTest *rsa.PrivateKey
	rsaErr  error
)

// rsaKey returns one shared RSA key (generation is slow).
func rsaKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() { rsaTest, rsaErr = rsa.GenerateKey(rand.Reader, 2048) })
	if rsaErr != nil {
		t.Fatalf("generate RSA key: %v", rsaErr)
	}
	return rsaTest
}

func newEd25519(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return k
}

func randSerial(t testing.TB) *big.Int {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("serial: %v", err)
	}
	b[0] &= 0x7f
	return new(big.Int).SetBytes(b)
}

// testCA is a certificate authority built at runtime.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// caTemplate is a CA:true template valid around now.
func caTemplate(t testing.TB, cn string, now time.Time) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
}

// newCAFrom creates a CA from tmpl with a new P-256 key, self-signed when
// parent is nil, otherwise signed by parent (an intermediate).
func newCAFrom(t testing.TB, tmpl *x509.Certificate, parent *testCA) *testCA {
	t.Helper()
	key := newP256(t)
	signerCert, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create CA %q: %v", tmpl.Subject.CommonName, err)
	}
	return &testCA{cert: mustParse(t, der), key: key}
}

func newCA(t testing.TB, cn string, now time.Time) *testCA {
	t.Helper()
	return newCAFrom(t, caTemplate(t, cn, now), nil)
}

// reissueSelf returns a second self-signed certificate for the same CA key
// and subject but a different serial: it verifies the same leaves, yet its
// DER differs from ca.cert byte for byte.
func (ca *testCA) reissueSelf(t testing.TB) *x509.Certificate {
	t.Helper()
	tmpl := caTemplate(t, ca.cert.Subject.CommonName, ca.cert.NotBefore.Add(24*time.Hour))
	tmpl.SubjectKeyId = ca.cert.SubjectKeyId
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, ca.key.Public(), ca.key)
	if err != nil {
		t.Fatalf("reissue CA: %v", err)
	}
	return mustParse(t, der)
}

// issue signs tmpl for pub with the CA and returns the DER.
func (ca *testCA) issue(t testing.TB, tmpl *x509.Certificate, pub any) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	return der
}

func mustParse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return c
}

func uuidURN(t testing.TB, id string) *url.URL {
	t.Helper()
	u, err := url.Parse("urn:uuid:" + id)
	if err != nil {
		t.Fatalf("parse URN: %v", err)
	}
	return u
}

// agentLeafTemplate is the §4.4 agent certificate profile for id, valid at now.
func agentLeafTemplate(t testing.TB, id string, now time.Time) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: id},
		URIs:                  []*url.URL{uuidURN(t, id)},
		NotBefore:             now.Add(-60 * time.Second),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
}

// serverLeafTemplate is the §4.4 control-plane server certificate profile:
// EKU serverAuth only, CA:false, a DNS or IP SAN equal to name.
func serverLeafTemplate(t testing.TB, name string, now time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(80 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	return tmpl
}

// rawSubject marshals an explicit RDN sequence, for subjects Go's pkix.Name
// would not produce (two CNs, multi-valued RDNs).
func rawSubject(t testing.TB, rdns pkix.RDNSequence) []byte {
	t.Helper()
	b, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}
	return b
}

func pkcs8(t testing.TB, key any) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS #8: %v", err)
	}
	return b
}

func sec1(t testing.TB, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal SEC 1: %v", err)
	}
	return b
}

func pemBlock(typ string, body []byte, headers map[string]string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Headers: headers, Bytes: body})
}

func cat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// identityPEM is the §4.7 identity.pem layout built by hand.
func identityPEM(t testing.TB, key any, certDER []byte) []byte {
	t.Helper()
	return cat(pemBlock(privateKeyBlockType(), pkcs8(t, key), nil), pemBlock(certBlockType, certDER, nil))
}

// pendingPEM is the enroll.pending-key.pem layout built by hand.
func pendingPEM(t testing.TB, key any, hash []byte) []byte {
	t.Helper()
	return cat(pemBlock(privateKeyBlockType(), pkcs8(t, key), nil), pemBlock(tokenHashBlockType, hash, nil))
}

func mustCSR(t testing.TB, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

// csrOfSize builds a valid P-256 CSR of exactly target DER bytes, padding
// with one DNS name (the control plane ignores CSR extensions, R14).
func csrOfSize(t testing.TB, key *ecdsa.PrivateKey, target int) []byte {
	t.Helper()
	pad := target - 300
	for i := 0; i < 50; i++ {
		if pad < 1 {
			pad = 1
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			DNSNames: []string{strings.Repeat("a", pad)},
		}, key)
		if err != nil {
			t.Fatalf("create padded CSR: %v", err)
		}
		if len(der) == target {
			return der
		}
		pad += target - len(der)
	}
	t.Fatalf("could not build a CSR of exactly %d bytes", target)
	return nil
}

func bytesOf(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

// Long hex or base64 runs in an error text are key or file bytes (R20).
var (
	hexRun    = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}`)
)

// assertNoLeak fails when msg contains any of the secrets, any base64 body
// line (16+ chars) of a PEM input, or a long hex or base64 run.
func assertNoLeak(t testing.TB, msg string, pemInput []byte, secrets ...string) {
	t.Helper()
	if m := hexRun.FindString(msg); m != "" {
		t.Errorf("error text carries a hex run %q: %q", short(m), msg)
	}
	if m := base64Run.FindString(msg); m != "" {
		t.Errorf("error text carries a base64 run %q: %q", short(m), msg)
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(msg, s) {
			t.Errorf("error text leaks a secret fragment %q: %q", short(s), msg)
		}
	}
	for _, line := range strings.Split(string(pemInput), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(msg, line[:16]) {
			t.Errorf("error text leaks PEM body bytes: %q", msg)
		}
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// keySecrets returns encodings of a private key's material that must never
// appear in an error (R20).
func keySecrets(t testing.TB, key *ecdsa.PrivateKey) []string {
	t.Helper()
	d, err := key.Bytes()
	if err != nil {
		t.Fatalf("key bytes: %v", err)
	}
	der := pkcs8(t, key)
	return []string{
		hex.EncodeToString(d),
		strings.ToUpper(hex.EncodeToString(d)),
		new(big.Int).SetBytes(d).String(),
		base64.StdEncoding.EncodeToString(der)[:32],
		base64.StdEncoding.EncodeToString(d)[:24],
		base64.RawURLEncoding.EncodeToString(d)[:24],
		string(d),
	}
}

// connPair returns the two ends of a connected AF_UNIX socketpair: no
// listening socket, no address, nothing reachable from outside the process.
//
// It is used instead of net.Pipe because net.Pipe is unbuffered: when the
// client refuses the server certificate it stops reading in the middle of
// the server's flight (CertificateVerify, Finished, tickets) and writes an
// alert, while the server is still blocked writing that flight, so both
// sides wait until the deadline. A socketpair has kernel buffers.
func connPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	conns := make([]net.Conn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "tls-test-pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("FileConn: %v", err)
		}
		conns[i] = c
	}
	return conns[0], conns[1]
}

// tlsPair runs one TLS handshake over a socketpair (no listening socket):
// the client side uses clientCfg, the server side serverCfg. After a
// successful handshake the server writes one byte and the client reads it,
// so TLS 1.3 session tickets are processed. It returns the client state and
// both errors.
func tlsPair(t testing.TB, clientCfg, serverCfg *tls.Config) (tls.ConnectionState, error, error) {
	t.Helper()
	c, s := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(10 * time.Second)
	_ = c.SetDeadline(deadline)
	_ = s.SetDeadline(deadline)
	srvErr := make(chan error, 1)
	go func() {
		srv := tls.Server(s, serverCfg)
		err := srv.HandshakeContext(ctx)
		if err == nil {
			_, err = srv.Write([]byte("x"))
		}
		_ = s.Close()
		srvErr <- err
	}()
	cli := tls.Client(c, clientCfg)
	err := cli.HandshakeContext(ctx)
	if err == nil {
		buf := make([]byte, 1)
		_, err = cli.Read(buf)
	}
	state := cli.ConnectionState()
	_ = c.Close()
	return state, err, <-srvErr
}

// serverTLS is the test control-plane peer's configuration (session
// tickets on, the Go default).
func serverTLS(chain [][]byte, key crypto.Signer, maxVersion uint16) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxVersion,
	}
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }
