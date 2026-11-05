package controlplane_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

// End-to-end tests of RunEnroll: the real identity.Enroll and state
// directory, the real gRPC client, an in-process control plane that issues
// a certificate from the agent CA, and the fake loop clock.

const e2eServerID = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"

type e2e struct {
	dir    string
	state  *identity.StateDir
	in     identity.EnrollInput
	client *controlplane.EnrollClient
	fs     *fakeServer

	mu        sync.Mutex
	pubs      []any         // public key of every CSR received
	notBefore time.Duration // issued NotBefore, relative to testNow
}

// newE2E starts a control plane whose handler refuses the first `refusals`
// calls with PERMISSION_DENIED, ENROLLMENT_REFUSED and then issues.
func newE2E(t *testing.T, refusals int) *e2e {
	t.Helper()
	e := &e2e{dir: filepath.Join(t.TempDir(), "state"), notBefore: -time.Minute}
	if err := os.Mkdir(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := identity.OpenStateDir(filepath.Clean(e.dir))
	if err != nil {
		t.Fatalf("OpenStateDir: %v", err)
	}
	e.state = st
	e.writeState(t, identity.FileToken, fakeToken())
	agentCA := newCA(t, "agent CA")
	binding, err := identity.NewExecutorBinding(randomBytes(t, 32), randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	e.in = identity.EnrollInput{ServerID: e2eServerID, AgentCA: agentCA.cert, Binding: binding}

	cpCA := newCA(t, "control-plane CA")
	calls := 0
	e.fs = startServer(t, serverTLS(cpCA.leaf(t, goodLeafOpts()), 0), func(_ context.Context, b []byte) ([]byte, error) {
		var req agentapiv1.EnrollRequest
		if err := agentapiv1.StrictUnmarshal(b, &req); err != nil {
			t.Errorf("request fails the strict decoder: %v", err)
			return nil, err
		}
		csr, err := x509.ParseCertificateRequest(req.GetCsr())
		if err != nil {
			t.Errorf("CSR: %v", err)
			return nil, err
		}
		e.mu.Lock()
		e.pubs = append(e.pubs, csr.PublicKey)
		calls++
		n := calls
		notBefore := e.notBefore
		e.mu.Unlock()
		if n <= refusals {
			return nil, statusWith(t, codes.PermissionDenied, "ENROLLMENT_REFUSED", agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED).Err()
		}
		return marshalDet(t, &agentapiv1.EnrollResponse{Certificate: issueAgentLeaf(t, agentCA, csr.PublicKey, testNow.Add(notBefore))}), nil
	})
	e.client = newClient(t, cpCA, e.fs.dialer)
	return e
}

func (e *e2e) writeState(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *e2e) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(e.dir, name))
	return err == nil
}

func issueAgentLeaf(t *testing.T, ca testCA, pub any, notBefore time.Time) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: e2eServerID},
		URIs:         []*url.URL{{Scheme: "urn", Opaque: "uuid:" + e2eServerID}},
		NotBefore:    notBefore,
		NotAfter:     testNow.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestRunEnrollRetriesWithSamePendingKey: two refusals, then success. Every
// request carries the same public key (R12a), the loop waits 1 min then
// 2 min (§4.9), identity.pem holds the issued pair, and the token and the
// pending key are gone (R12a order). The private key never appears in a
// request (AC35).
func TestRunEnrollRetriesWithSamePendingKey(t *testing.T) {
	t.Parallel()
	e := newE2E(t, 2)
	c := newFakeClock()
	id, err := controlplane.RunEnrollWithClock(shortCtx(t, 20*time.Second), e.state, e.in, e.client.Enroll, c)
	if err != nil {
		t.Fatalf("RunEnroll: %v", err)
	}
	if got := id.Certificate().Subject.CommonName; got != e2eServerID {
		t.Fatalf("identity CN %q", got)
	}
	if want := []time.Duration{time.Minute, 2 * time.Minute}; !equalDurations(c.sleeps, want) {
		t.Fatalf("sleeps %v, want %v", c.sleeps, want)
	}
	e.mu.Lock()
	pubs := e.pubs
	e.mu.Unlock()
	if len(pubs) != 3 {
		t.Fatalf("%d requests, want 3", len(pubs))
	}
	for i, p := range pubs {
		if !pubs[0].(*ecdsa.PublicKey).Equal(p) {
			t.Fatalf("request %d used another key", i)
		}
	}
	if !e.exists(identity.FileIdentity) {
		t.Fatal("identity.pem not written")
	}
	for _, name := range []string{identity.FileToken, identity.FileEnrollPendingKey} {
		if e.exists(name) {
			t.Errorf("%s left after enrollment", name)
		}
	}
	key, ok := id.TLSCertificate().PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("identity has no ECDSA key")
	}
	secret, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range e.fs.observed() {
		if bytes.Contains(s.req, secret) {
			t.Fatal("a request carried the private key")
		}
	}
}

// TestRunEnrollTokenExpired: with token-expires in the past no connection
// is made and ErrTokenExpired is returned (R18a case 3, AC42).
func TestRunEnrollTokenExpired(t *testing.T) {
	t.Parallel()
	e := newE2E(t, 0)
	e.writeState(t, identity.FileTokenExpires, strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10))
	c := newFakeClock()
	c.now = time.Now()
	_, err := controlplane.RunEnrollWithClock(shortCtx(t, 10*time.Second), e.state, e.in, e.client.Enroll, c)
	if !errors.Is(err, identity.ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
	if n := e.fs.dials.Load(); n != 0 {
		t.Fatalf("%d dials with an expired token", n)
	}
	if !e.exists(identity.FileToken) {
		t.Fatal("token removed")
	}
}

// TestRunEnrollExpiresDuringRetries: the token expires while the loop
// waits; the next turn sends nothing more and reports the expiry.
func TestRunEnrollExpiresDuringRetries(t *testing.T) {
	t.Parallel()
	e := newE2E(t, 100)
	c := newFakeClock()
	e.writeState(t, identity.FileTokenExpires, strconv.FormatInt(testNow.Add(5*time.Minute).Unix(), 10))
	_, err := controlplane.RunEnrollWithClock(shortCtx(t, 20*time.Second), e.state, e.in, e.client.Enroll, c)
	if !errors.Is(err, identity.ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
	// Attempts at +0, +1 min, +3 min; +7 min is past the expiry.
	if n := e.fs.calls.Load(); n != 3 {
		t.Fatalf("%d calls, want 3", n)
	}
}

// TestRunEnrollCertificateRejected: a certificate that fails R15 (another
// server's UUID) stops the loop, writes no identity and keeps the token
// and pending key.
func TestRunEnrollCertificateRejected(t *testing.T) {
	t.Parallel()
	e := newE2E(t, 0)
	e.in.ServerID = "7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d"
	c := newFakeClock()
	_, err := controlplane.RunEnrollWithClock(shortCtx(t, 10*time.Second), e.state, e.in, e.client.Enroll, c)
	if !errors.Is(err, identity.ErrCertificateRejected) || !errors.Is(err, controlplane.ErrEnrollStopped) {
		t.Fatalf("err = %v, want ErrCertificateRejected and ErrEnrollStopped", err)
	}
	if len(c.sleeps) != 0 {
		t.Fatalf("slept %v after an R15 failure", c.sleeps)
	}
	if e.exists(identity.FileIdentity) || !e.exists(identity.FileToken) || !e.exists(identity.FileEnrollPendingKey) {
		t.Fatal("state changed after an R15 failure")
	}
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRunEnrollClockSkewRetried: the control plane issues a certificate
// valid from testNow+3 min, so R15 reports clock skew at +0 and +1 min
// (beyond MaxSkew) and accepts it at +3 min. The loop retries on the
// normal backoff with the same pending key, and nothing is written until
// R15 passes (Nofal, PR #33).
func TestRunEnrollClockSkewRetried(t *testing.T) {
	t.Parallel()
	e := newE2E(t, 0)
	e.notBefore = 3 * time.Minute
	c := newFakeClock()
	if _, err := controlplane.RunEnrollWithClock(shortCtx(t, 20*time.Second), e.state, e.in, e.client.Enroll, c); err != nil {
		t.Fatalf("RunEnroll: %v", err)
	}
	if want := []time.Duration{time.Minute, 2 * time.Minute}; !equalDurations(c.sleeps, want) {
		t.Fatalf("sleeps %v, want %v", c.sleeps, want)
	}
	e.mu.Lock()
	pubs := e.pubs
	e.mu.Unlock()
	if len(pubs) != 3 {
		t.Fatalf("%d requests, want 3", len(pubs))
	}
	for i, p := range pubs {
		if !pubs[0].(*ecdsa.PublicKey).Equal(p) {
			t.Fatalf("request %d used another key", i)
		}
	}
	if !e.exists(identity.FileIdentity) || e.exists(identity.FileToken) {
		t.Fatal("enrollment did not complete after the clock-skew retries")
	}
}
