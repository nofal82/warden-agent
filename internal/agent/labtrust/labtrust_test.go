//go:build linux

package labtrust_test

// Tests for the M1 lab-only control-plane CA trust bootstrap (decision
// 0013, issue #35). What an attacker could try, and what each test pins:
//   - turn lab trust on without the root-owned marker, or with a marker
//     that is unsafe or merely similar: the refusal tests;
//   - use lab trust to override a verified keyset: the keyset tests;
//   - widen trust beyond the file CAs (3 CAs, duplicates, expired or
//     not-yet-valid CAs): the bound tests, which must keep every rule of
//     TrustedControlPlaneCAs;
//   - get a server certificate from another CA accepted: the TLS test.
// No socket is opened: the TLS test uses an AF_UNIX socketpair.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nofal82/warden-agent/internal/agent"
	"github.com/nofal82/warden-agent/internal/agent/labtrust"
	"github.com/nofal82/warden-agent/internal/identity"
)

var testNow = time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC)

const serverName = "cp.example.test"

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// newCA is a self-signed CA valid from notBefore to notAfter.
func newCA(t testing.TB, cn string, notBefore, notAfter time.Time) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

func validCA(t testing.TB, cn string) *testCA {
	t.Helper()
	return newCA(t, cn, testNow.Add(-24*time.Hour), testNow.Add(365*24*time.Hour))
}

// serverTLS is a control-plane peer presenting one leaf issued by ca for
// serverName (the §4.4 server profile).
func serverTLS(t testing.TB, ca *testCA) *tls.Config {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(80 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		Time:         func() time.Time { return testNow },
	}
}

// connPair returns the two ends of an AF_UNIX socketpair: no listening
// socket, nothing reachable from outside the process.
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

// handshake runs one TLS handshake and returns the client's error.
func handshake(t testing.TB, clientCfg, serverCfg *tls.Config) error {
	t.Helper()
	c, s := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(10 * time.Second)
	_ = c.SetDeadline(deadline)
	_ = s.SetDeadline(deadline)
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv := tls.Server(s, serverCfg)
		if srv.HandshakeContext(ctx) == nil {
			_, _ = srv.Write([]byte("x"))
		}
		_ = s.Close()
	}()
	cli := tls.Client(c, clientCfg)
	err := cli.HandshakeContext(ctx)
	if err == nil {
		_, err = cli.Read(make([]byte, 1))
	}
	_ = c.Close()
	<-done
	return err
}

// marker is a fake ReadFunc: it records its calls and returns data, err.
type marker struct {
	data  []byte
	err   error
	calls int
	path  string
	max   int64
}

func (m *marker) read(p string, maxBytes int64) ([]byte, error) {
	m.calls++
	m.path, m.max = p, maxBytes
	return bytes.Clone(m.data), m.err
}

func goodMarker() *marker { return &marker{data: []byte("warden-lab-trust-m1\n")} }

func TestConstants(t *testing.T) {
	t.Parallel()
	if labtrust.MarkerPath != "/etc/warden-agent/lab-trust" {
		t.Errorf("MarkerPath = %q", labtrust.MarkerPath)
	}
	if labtrust.MarkerContent != "warden-lab-trust-m1\n" || len(labtrust.MarkerContent) != 20 {
		t.Errorf("MarkerContent = %q", labtrust.MarkerContent)
	}
	for _, s := range []string{"decision 0013", "without a verified keyset"} {
		if !strings.Contains(labtrust.WarnLine, s) {
			t.Errorf("WarnLine %q lacks %q", labtrust.WarnLine, s)
		}
	}
}

// A missing, unsafe or merely similar marker leaves the lab path off: the
// result is the default refusal (R38).
func TestMarkerRefusals(t *testing.T) {
	t.Parallel()
	good := "warden-lab-trust-m1\n"
	tests := []struct {
		name string
		data []byte
		err  error
	}{
		{"absent", nil, fmt.Errorf("open: %w", fs.ErrNotExist)},
		{"unsafe (symlink, writable, wrong owner)", nil, fmt.Errorf("%w: symlink", identity.ErrUnsafeFile)},
		{"empty", []byte{}, nil},
		{"no trailing newline", []byte("warden-lab-trust-m1"), nil},
		{"CRLF", []byte("warden-lab-trust-m1\r\n"), nil},
		{"trailing space", []byte("warden-lab-trust-m1 \n"), nil},
		{"extra second line", []byte(good + "x\n"), nil},
		{"uppercase", []byte(strings.ToUpper(good)), nil},
		// Matching bytes but an error: the error wins.
		{"too large", []byte(good), fmt.Errorf("%w: lab-trust", identity.ErrFileTooLarge)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &marker{data: tc.data, err: tc.err}
			if labtrust.MarkerOK(m.read) {
				t.Fatalf("MarkerOK accepted %q (err %v)", tc.data, tc.err)
			}
			if m.path != labtrust.MarkerPath || m.max != 20 {
				t.Errorf("read(%q, %d), want (%q, 20)", m.path, m.max, labtrust.MarkerPath)
			}
			ca := validCA(t, "cp CA")
			set, err := labtrust.Trust(agent.KeysetTrust, m.read)([]*x509.Certificate{ca.cert}, testNow)
			if set != nil || !errors.Is(err, agent.ErrTrustCheckImpossible) {
				t.Fatalf("Trust = %v, %v, want ErrTrustCheckImpossible", set, err)
			}
		})
	}
}

// With the marker, the file CAs are filtered by TrustedControlPlaneCAs
// unchanged: the 1–2 bound, duplicates, validity and the empty-set refusal
// all still apply.
func TestLabTrustKeepsBounds(t *testing.T) {
	t.Parallel()
	a, b, c := validCA(t, "cp CA a"), validCA(t, "cp CA b"), validCA(t, "cp CA c")
	expired := newCA(t, "expired", testNow.Add(-48*time.Hour), testNow.Add(-time.Second))
	future := newCA(t, "future", testNow.Add(time.Hour), testNow.Add(48*time.Hour))
	tests := []struct {
		name    string
		cas     []*x509.Certificate
		want    []*x509.Certificate
		wantErr error
	}{
		{"one valid CA", []*x509.Certificate{a.cert}, []*x509.Certificate{a.cert}, nil},
		{"two valid CAs in file order", []*x509.Certificate{b.cert, a.cert}, []*x509.Certificate{b.cert, a.cert}, nil},
		{"three CAs", []*x509.Certificate{a.cert, b.cert, c.cert}, nil, identity.ErrInvalidTrust},
		{"duplicate CA", []*x509.Certificate{a.cert, a.cert}, nil, identity.ErrInvalidTrust},
		{"expired CA", []*x509.Certificate{expired.cert}, nil, identity.ErrNoTrustedControlPlaneCA},
		{"not yet valid CA", []*x509.Certificate{future.cert}, nil, identity.ErrNoTrustedControlPlaneCA},
		{"nil and empty list", nil, nil, identity.ErrInvalidTrust},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inputs := [][]*x509.Certificate{tc.cas}
			if len(tc.cas) == 0 {
				inputs = append(inputs, []*x509.Certificate{}, []*x509.Certificate{nil})
			}
			for _, in := range inputs {
				m := goodMarker()
				set, err := labtrust.Trust(agent.KeysetTrust, m.read)(in, testNow)
				if m.calls != 1 || m.path != labtrust.MarkerPath || m.max != 20 {
					t.Errorf("marker read %d times as (%q, %d)", m.calls, m.path, m.max)
				}
				if tc.wantErr != nil {
					if set != nil || !errors.Is(err, tc.wantErr) {
						t.Fatalf("Trust(%d CAs) = %v, %v, want %v", len(in), set, err, tc.wantErr)
					}
					continue
				}
				if err != nil {
					t.Fatalf("Trust: %v", err)
				}
				if len(set) != len(tc.want) {
					t.Fatalf("Trust returned %d CAs, want %d", len(set), len(tc.want))
				}
				for i := range set {
					if !set[i].Equal(tc.want[i]) {
						t.Errorf("CA %d not in file order", i)
					}
				}
			}
		})
	}
}

// Fallback, not override: whenever the keyset path gives an answer other
// than "impossible", that answer stands and the marker is never read.
func TestKeysetWins(t *testing.T) {
	t.Parallel()
	fileCA, keysetCA := validCA(t, "file CA"), validCA(t, "keyset CA")
	tests := []struct {
		name    string
		set     []*x509.Certificate
		err     error
		wantErr error
	}{
		{"keyset verifies", []*x509.Certificate{keysetCA.cert}, nil, nil},
		{"verified keyset trusts no file CA", nil, identity.ErrNoTrustedControlPlaneCA, identity.ErrNoTrustedControlPlaneCA},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keyset := func([]*x509.Certificate, time.Time) ([]*x509.Certificate, error) { return tc.set, tc.err }
			m := goodMarker()
			set, err := labtrust.Trust(keyset, m.read)([]*x509.Certificate{fileCA.cert}, testNow)
			if m.calls != 0 {
				t.Errorf("marker read although the keyset answered")
			}
			if tc.wantErr != nil {
				if set != nil || !errors.Is(err, tc.wantErr) || errors.Is(err, agent.ErrTrustCheckImpossible) {
					t.Fatalf("Trust = %v, %v, want %v", set, err, tc.wantErr)
				}
				return
			}
			if err != nil || len(set) != 1 || set[0] != keysetCA.cert {
				t.Fatalf("Trust = %v, %v, want the keyset set unchanged", set, err)
			}
		})
	}
}

func TestEntries(t *testing.T) {
	t.Parallel()
	a, b := validCA(t, "a"), newCA(t, "b", testNow.Add(-time.Hour), testNow.Add(time.Hour))
	got := labtrust.Entries([]*x509.Certificate{a.cert, nil, b.cert})
	want := []identity.CAEntry{
		{Fingerprint: sha256.Sum256(a.cert.Raw), NotBefore: a.cert.NotBefore.Unix(), NotAfter: a.cert.NotAfter.Unix()},
		{Fingerprint: sha256.Sum256(b.cert.Raw), NotBefore: b.cert.NotBefore.Unix(), NotAfter: b.cert.NotAfter.Unix()},
	}
	if len(got) != len(want) {
		t.Fatalf("Entries = %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if len(labtrust.Entries(nil)) != 0 {
		t.Errorf("Entries(nil) not empty")
	}
}

// The lab set goes through ClientTLSConfig unchanged: a server certificate
// from another CA is still refused.
func TestLabSetRejectsOtherCA(t *testing.T) {
	t.Parallel()
	lab, other := validCA(t, "lab cp CA"), validCA(t, "attacker CA")
	set, err := labtrust.Trust(agent.KeysetTrust, goodMarker().read)([]*x509.Certificate{lab.cert}, testNow)
	if err != nil {
		t.Fatalf("Trust: %v", err)
	}
	clock := func() time.Time { return testNow }
	cfg, err := identity.ClientTLSConfig(set, serverName, nil, clock)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if err := handshake(t, cfg.Clone(), serverTLS(t, lab)); err != nil {
		t.Fatalf("handshake with the lab CA's server failed: %v", err)
	}
	if err := handshake(t, cfg.Clone(), serverTLS(t, other)); err == nil {
		t.Fatalf("server certificate from another CA accepted")
	}
}

func FuzzMarkerOK(f *testing.F) {
	for _, s := range []string{
		"warden-lab-trust-m1\n", "", "warden-lab-trust-m1", "warden-lab-trust-m1\r\n",
		"warden-lab-trust-m1 \n", "warden-lab-trust-m1\nx\n", "WARDEN-LAB-TRUST-M1\n",
		"\x00warden-lab-trust-m1\n", "warden-lab-trust-m1\n\x00",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		m := &marker{data: content}
		if got, want := labtrust.MarkerOK(m.read), bytes.Equal(content, []byte(labtrust.MarkerContent)); got != want {
			t.Fatalf("MarkerOK(%q) = %v, want %v", content, got, want)
		}
	})
}
