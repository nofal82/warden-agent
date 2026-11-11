//go:build linux

package agent_test

// Tests for Serve, the step after start-up (issue #42; agent-api R10,
// R29; agent-identity R31d). The outbox's first watermark may be written
// only right after this run enrolled: otherwise a deleted watermark would
// let message_seq restart at 1 and the control plane would drop real
// messages as duplicates.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
	"github.com/nofal82/warden-agent/internal/identity"
)

var serveInstanceID = strings.Repeat("5e", 16)

// identityPEM is a valid identity.pem for testServerID, generated at
// runtime (key and certificate built by crypto, never a literal).
func identityPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("urn:uuid:" + testServerID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: testServerID},
		URIs:                  []*url.URL{u},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE" + " KEY", Bytes: p8})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

// enrolledIdentity is what a successful enrollment returns: a real
// Identity loaded through identity.Decide from a separate state dir.
func enrolledIdentity(t *testing.T) identity.Identity {
	t.Helper()
	d := stateDir(t, map[string][]byte{identity.FileIdentity: identityPEM(t)})
	st, err := identity.Decide(d, testServerID, testNow)
	if err != nil || st.State != identity.StartUseIdentity {
		t.Fatalf("Decide = %+v, %v", st.State, err)
	}
	return st.Identity
}

type nopOutbox struct{}

func (nopOutbox) Next() (outbox.Message, bool, error) { return outbox.Message{}, false, nil }
func (nopOutbox) Ack(uint64, agentapiv1.AckOutcome, agentapiv1.AckReason) error {
	return nil
}
func (nopOutbox) Rewind()               {}
func (nopOutbox) Recheck() (int, error) { return 0, nil }
func (nopOutbox) Stats() outbox.Stats   { return outbox.Stats{} }

type serveFakes struct {
	cfg     controlplane.StreamConfig
	ob      nopOutbox
	connect int
}

// withServe adds recording fakes for the Serve steps. noWatermark is how
// many OpenOutbox calls answer ErrNoWatermark before succeeding.
func withServe(f *fixture, deps *agent.Deps, cancel context.CancelFunc, noWatermark int) *serveFakes {
	s := &serveFakes{}
	deps.InstanceID = func() (string, error) { f.rec.add("InstanceID"); return serveInstanceID, nil }
	deps.OpenOutbox = func() (controlplane.Outbox, error) {
		f.rec.add("OpenOutbox")
		if noWatermark > 0 {
			noWatermark--
			return nil, fmt.Errorf("open: %w", outbox.ErrNoWatermark)
		}
		return s.ob, nil
	}
	deps.CreateOutbox = func() error { f.rec.add("CreateOutbox"); return nil }
	deps.Connect = func(ctx context.Context, cfg controlplane.StreamConfig) error {
		f.rec.add("Connect")
		s.connect++
		s.cfg = cfg
		cancel()
		return ctx.Err()
	}
	return s
}

func count(calls []string, name string) int {
	n := 0
	for _, c := range calls {
		if c == name {
			n++
		}
	}
	return n
}

// After this run's enrollment a missing watermark is a new outbox: Create
// once, open again, then connect with the right Hello inputs.
func TestServeCreatesOutboxOnlyAfterEnrollment(t *testing.T) {
	t.Parallel()
	f, deps := newFixture(t, withToken())
	want := enrolledIdentity(t)
	deps.Enroll = func(context.Context, *identity.StateDir, identity.EnrollInput, identity.EnrollFunc) (identity.Identity, error) {
		f.rec.add("Enroll")
		return want, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := withServe(f, &deps, cancel, 1)
	if err := agent.Serve(ctx, deps); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v, want a clean stop", err)
	}
	calls := f.rec.got()
	i := slices.Index(calls, "OpenOutbox")
	if i < 0 || !slices.Equal(calls[i:], []string{"OpenOutbox", "CreateOutbox", "OpenOutbox", "Connect"}) &&
		!slices.Equal(calls[i:], []string{"OpenOutbox", "CreateOutbox", "OpenOutbox", "InstanceID", "Connect"}) {
		t.Fatalf("calls = %v, want OpenOutbox, CreateOutbox, OpenOutbox, Connect last", calls)
	}
	if count(calls, "CreateOutbox") != 1 || s.connect != 1 || count(calls, "InstanceID") != 1 {
		t.Fatalf("calls = %v", calls)
	}
	c := s.cfg
	if c.ServerID != testServerID || c.AgentVersion != agent.AgentVersion || c.InstanceID != serveInstanceID {
		t.Errorf("Hello inputs = %q %q %q", c.ServerID, c.AgentVersion, c.InstanceID)
	}
	if c.Endpoint != f.tf.Endpoints.Agent || c.ServerName != f.tf.Endpoints.ServerName {
		t.Errorf("endpoint = %q %q", c.Endpoint, c.ServerName)
	}
	if len(c.Identity.Certificate) != 1 || !slices.Equal(c.Identity.Certificate[0], want.Certificate().Raw) {
		t.Errorf("Identity is not the enrolled certificate")
	}
	if c.Outbox != controlplane.Outbox(s.ob) {
		t.Errorf("Outbox is not the opened outbox")
	}
	if c.Trust == nil {
		t.Fatal("Trust is nil")
	}
	before := count(f.rec.got(), "Trust")
	cas, err := c.Trust(testNow)
	if err != nil || len(cas) != 1 || cas[0] != f.tf.ControlPlaneCAs[0] || count(f.rec.got(), "Trust") != before+1 {
		t.Errorf("Trust did not run deps.Trust over the file CAs: %v, %v", cas, err)
	}
}

// Serve stops before any connection when the start used an existing
// identity and the watermark is gone, or the instance ID cannot be had.
func TestServeRefusesWithoutConnecting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(f *fixture, deps *agent.Deps)
		wantErr error
	}{
		{"existing identity, watermark missing", func(*fixture, *agent.Deps) {}, outbox.ErrNoWatermark},
		{"instance ID unavailable", func(f *fixture, deps *agent.Deps) {
			deps.InstanceID = func() (string, error) { f.rec.add("InstanceID"); return "", agent.ErrInstanceID }
		}, agent.ErrInstanceID},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, deps := newFixture(t, map[string][]byte{identity.FileIdentity: identityPEM(t)})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			missing := 0
			if i == 0 {
				missing = 1
			}
			s := withServe(f, &deps, cancel, missing)
			tc.mutate(f, &deps)
			err := agent.Serve(ctx, deps)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Serve = %v, want %v", err, tc.wantErr)
			}
			calls := f.rec.got()
			if s.connect != 0 || count(calls, "CreateOutbox") != 0 || count(calls, "Enroll") != 0 {
				t.Fatalf("calls = %v: no Create, Enroll or Connect allowed", calls)
			}
			if code := agent.Main(context.Background(), deps, discard()); code != 1 {
				t.Errorf("Main = %d, want 1", code)
			}
		})
	}
}
