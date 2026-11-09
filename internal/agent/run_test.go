//go:build linux

package agent_test

// Tests for the agent start-up sequence (issue #35, decision 0013,
// agent-identity R18a, signing-and-updates R38). Every dependency is a
// recording fake, so each test proves both the result and which later
// steps were NOT reached: a refusal must happen before any connection is
// prepared. Nothing here opens a socket. Tokens are obvious fakes built
// from fragments at runtime.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

var testNow = time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC)

const testServerID = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"

// canaryToken is an obviously fake enrollment token in the §4.2 form.
func canaryToken() string { return "wdn1" + "_" + strings.Repeat("Q", 43) }

func newCACert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
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
	return c
}

// stateDir creates a real agent state directory (mode 0700, owned by the
// effective uid) holding the given files (mode 0600).
func stateDir(t *testing.T, files map[string][]byte) *identity.StateDir {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("StateDir refuses to run as root")
	}
	p := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o700); err != nil { // #nosec G302 -- a directory: 0700 is the state-directory mode (§4.7)
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(p, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := identity.OpenStateDir(p)
	if err != nil {
		t.Fatalf("OpenStateDir: %v", err)
	}
	return d
}

func withToken() map[string][]byte {
	return map[string][]byte{identity.FileToken: []byte(canaryToken())}
}

// recorder records the order of dependency calls.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

type fixture struct {
	tf      identity.TrustFiles
	binding identity.ExecutorBinding
	rec     *recorder
	sent    []*x509.Certificate // trusted set NewSender received
	ep      identity.Endpoints
	in      identity.EnrollInput
}

// newFixture returns Deps whose every step succeeds: Trust stands in for a
// verified keyset that trusts the file CAs, Enroll succeeds.
func newFixture(t *testing.T, files map[string][]byte) (*fixture, agent.Deps) {
	t.Helper()
	f := &fixture{rec: &recorder{}}
	f.tf = identity.TrustFiles{
		ServerID: testServerID,
		Endpoints: identity.Endpoints{
			Enroll:     "enroll.example.test:443",
			Agent:      "agent.example.test:8443",
			ServerName: "cp.example.test",
		},
		AgentCA:         newCACert(t, "agent CA"),
		ControlPlaneCAs: []*x509.Certificate{newCACert(t, "control-plane CA")},
	}
	f.binding.PublicKey[0], f.binding.MAC[0] = 0xa1, 0xb2
	d := stateDir(t, files)
	deps := agent.Deps{
		CheckRules: func() error { f.rec.add("CheckRules"); return nil },
		LoadTrust:  func() (identity.TrustFiles, error) { f.rec.add("LoadTrust"); return f.tf, nil },
		Trust: func(cas []*x509.Certificate, _ time.Time) ([]*x509.Certificate, error) {
			f.rec.add("Trust")
			return cas, nil
		},
		OpenState:   func() (*identity.StateDir, error) { f.rec.add("OpenState"); return d, nil },
		LoadBinding: func() (identity.ExecutorBinding, error) { f.rec.add("LoadBinding"); return f.binding, nil },
		NewSender: func(trusted []*x509.Certificate, ep identity.Endpoints, now func() time.Time) (identity.EnrollFunc, error) {
			f.rec.add("NewSender")
			f.sent, f.ep = trusted, ep
			if now == nil {
				t.Errorf("NewSender got a nil clock")
			}
			return func(context.Context, *agentapiv1.EnrollRequest) ([]byte, error) {
				return nil, errors.New("fake send: not used")
			}, nil
		},
		// One attempt: the send result is ignored, as the fake send fails.
		Enroll: func(ctx context.Context, _ *identity.StateDir, in identity.EnrollInput, send identity.EnrollFunc) (identity.Identity, error) {
			f.rec.add("Enroll")
			f.in = in
			_, _ = send(ctx, &agentapiv1.EnrollRequest{})
			return identity.Identity{}, nil
		},
		Now: func() time.Time { return testNow },
	}
	return f, deps
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)) }

func assertCalls(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("calls = %v, want exactly %v", got, want)
	}
}

// Case 1 (decision 0013 "Guards that fail closed"): the default build, a
// valid CA file and a token, but no executor and no keyset cache: refuse
// before the state directory is opened or anything is dialled.
func TestDefaultBuildFailsClosed(t *testing.T) {
	t.Parallel()
	if !strings.Contains(agent.ErrTrustCheckImpossible.Error(), "trust check impossible: executor unavailable") {
		t.Fatalf("ErrTrustCheckImpossible = %q", agent.ErrTrustCheckImpossible)
	}
	if !strings.Contains(agent.ErrNoIdentity.Error(), identity.HealthNoIdentity) {
		t.Fatalf("ErrNoIdentity = %q", agent.ErrNoIdentity)
	}
	// KeysetTrust refuses whatever it is given.
	for _, in := range [][]*x509.Certificate{nil, {}} {
		set, err := agent.KeysetTrust(in, testNow)
		if set != nil || !errors.Is(err, agent.ErrTrustCheckImpossible) {
			t.Fatalf("KeysetTrust(%d CAs) = %v, %v", len(in), set, err)
		}
	}

	f, deps := newFixture(t, withToken())
	deps.Trust = func(cas []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
		f.rec.add("Trust")
		return agent.KeysetTrust(cas, now)
	}
	_, err := agent.Run(context.Background(), deps)
	if !errors.Is(err, agent.ErrTrustCheckImpossible) {
		t.Fatalf("Run = %v, want ErrTrustCheckImpossible", err)
	}
	assertCalls(t, f.rec.got(), "CheckRules", "LoadTrust", "Trust")

	f2, deps2 := newFixture(t, withToken())
	deps2.Trust = agent.KeysetTrust
	if code := agent.Main(context.Background(), deps2, discard()); code != 1 {
		t.Fatalf("Main = %d, want 1", code)
	}
	assertCalls(t, f2.rec.got(), "CheckRules", "LoadTrust")
}

// Case 2 and 7: each step fails closed and no later step runs.
func TestRunFailsClosedAtEachStep(t *testing.T) {
	t.Parallel()
	errInjected := errors.New("injected failure")
	tests := []struct {
		name    string
		break_  func(f *fixture, d *agent.Deps)
		wantErr error
		calls   []string
	}{
		{
			name: "CheckRules error",
			break_: func(f *fixture, d *agent.Deps) {
				d.CheckRules = func() error { f.rec.add("CheckRules"); return errInjected }
			},
			wantErr: errInjected,
			calls:   []string{"CheckRules"},
		},
		{
			name: "LoadTrust error",
			break_: func(f *fixture, d *agent.Deps) {
				d.LoadTrust = func() (identity.TrustFiles, error) {
					f.rec.add("LoadTrust")
					return identity.TrustFiles{}, fmt.Errorf("%w: injected", identity.ErrUnsafeFile)
				}
			},
			wantErr: identity.ErrUnsafeFile,
			calls:   []string{"CheckRules", "LoadTrust"},
		},
		{
			name: "verified keyset trusts no file CA",
			break_: func(f *fixture, d *agent.Deps) {
				d.Trust = func([]*x509.Certificate, time.Time) ([]*x509.Certificate, error) {
					f.rec.add("Trust")
					return nil, identity.ErrNoTrustedControlPlaneCA
				}
			},
			wantErr: identity.ErrNoTrustedControlPlaneCA,
			calls:   []string{"CheckRules", "LoadTrust", "Trust"},
		},
		{
			name: "LoadBinding error on enroll",
			break_: func(f *fixture, d *agent.Deps) {
				d.LoadBinding = func() (identity.ExecutorBinding, error) {
					f.rec.add("LoadBinding")
					return identity.ExecutorBinding{}, fmt.Errorf("%w: injected", identity.ErrInvalidBinding)
				}
			},
			wantErr: identity.ErrInvalidBinding,
			calls:   []string{"CheckRules", "LoadTrust", "Trust", "OpenState", "LoadBinding"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, deps := newFixture(t, withToken())
			tc.break_(f, &deps)
			if _, err := agent.Run(context.Background(), deps); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run = %v, want %v", err, tc.wantErr)
			}
			assertCalls(t, f.rec.got(), tc.calls...)
			if code := agent.Main(context.Background(), deps, discard()); code != 1 {
				t.Fatalf("Main = %d, want 1", code)
			}
		})
	}
}

// Case 3: NewSender receives exactly the set Trust returned (not the file
// CAs), the endpoints from the trust files, and Enroll the R12b input.
func TestTrustedSetPassedToSender(t *testing.T) {
	t.Parallel()
	f, deps := newFixture(t, withToken())
	other := newCACert(t, "keyset CA")
	f.tf.ControlPlaneCAs = append(f.tf.ControlPlaneCAs, other)
	want := []*x509.Certificate{other}
	deps.Trust = func(cas []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
		f.rec.add("Trust")
		if len(cas) != 2 || !now.Equal(testNow) {
			t.Errorf("Trust got %d CAs at %v", len(cas), now)
		}
		return want, nil
	}
	if _, err := agent.Run(context.Background(), deps); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertCalls(t, f.rec.got(), "CheckRules", "LoadTrust", "Trust", "OpenState", "LoadBinding", "Enroll", "Trust", "NewSender")
	if len(f.sent) != 1 || f.sent[0] != other {
		t.Fatalf("NewSender trusted set = %v, want exactly the Trust result", f.sent)
	}
	if f.ep != f.tf.Endpoints {
		t.Errorf("NewSender endpoints = %+v, want %+v", f.ep, f.tf.Endpoints)
	}
	if f.in.ServerID != testServerID || f.in.AgentCA != f.tf.AgentCA || f.in.Binding != f.binding {
		t.Errorf("EnrollInput = %+v", f.in)
	}
}

// R37 before every new connection: each enroll attempt re-runs the trust
// check, and once it refuses (marker removed, CA expired) no client is
// built and the attempt fails with the trust error.
func TestTrustRecheckedBeforeEveryAttempt(t *testing.T) {
	t.Parallel()
	f, deps := newFixture(t, withToken())
	n := 0
	deps.Trust = func(cas []*x509.Certificate, _ time.Time) ([]*x509.Certificate, error) {
		f.rec.add("Trust")
		if n++; n > 2 {
			return nil, agent.ErrTrustCheckImpossible
		}
		return cas, nil
	}
	var last error
	deps.Enroll = func(ctx context.Context, _ *identity.StateDir, _ identity.EnrollInput, send identity.EnrollFunc) (identity.Identity, error) {
		f.rec.add("Enroll")
		_, _ = send(ctx, &agentapiv1.EnrollRequest{})
		_, last = send(ctx, &agentapiv1.EnrollRequest{})
		return identity.Identity{}, fmt.Errorf("%w: %w", controlplane.ErrEnrollStopped, last)
	}
	if _, err := agent.Run(context.Background(), deps); !errors.Is(err, agent.ErrTrustCheckImpossible) {
		t.Fatalf("Run = %v, want ErrTrustCheckImpossible", err)
	}
	assertCalls(t, f.rec.got(), "CheckRules", "LoadTrust", "Trust", "OpenState", "LoadBinding", "Enroll", "Trust", "NewSender", "Trust")
	if controlplane.ActionOf(last) != controlplane.ActionStop {
		t.Fatalf("ActionOf(trust refusal) = %v, want ActionStop", controlplane.ActionOf(last))
	}
}

// Case 4: a stopped enrollment is an error that keeps its cause.
func TestEnrollStoppedIsFailure(t *testing.T) {
	t.Parallel()
	f, deps := newFixture(t, withToken())
	deps.Enroll = func(context.Context, *identity.StateDir, identity.EnrollInput, identity.EnrollFunc) (identity.Identity, error) {
		f.rec.add("Enroll")
		return identity.Identity{}, fmt.Errorf("%w: x", controlplane.ErrEnrollStopped)
	}
	if _, err := agent.Run(context.Background(), deps); !errors.Is(err, controlplane.ErrEnrollStopped) {
		t.Fatalf("Run = %v, want ErrEnrollStopped", err)
	}
	if code := agent.Main(context.Background(), deps, discard()); code != 1 {
		t.Fatalf("Main = %d, want 1", code)
	}
}

// Case 5: a signal (cancelled context) is a clean stop, not a failure.
func TestCancelledContextIsCleanStop(t *testing.T) {
	t.Parallel()
	_, deps := newFixture(t, withToken())
	deps.Enroll = func(ctx context.Context, _ *identity.StateDir, _ identity.EnrollInput, _ identity.EnrollFunc) (identity.Identity, error) {
		<-ctx.Done()
		return identity.Identity{}, fmt.Errorf("enroll: %w", ctx.Err())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := agent.Run(ctx, deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if code := agent.Main(ctx, deps, discard()); code != 0 {
		t.Fatalf("Main = %d, want 0", code)
	}
}

// Case 6 (R18a cases 3 expired and 4): no binding read, no sender, no enroll.
func TestStartStatesWithoutConnection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		files   map[string][]byte
		wantErr error
	}{
		{
			name: "token expired",
			files: map[string][]byte{
				identity.FileToken:        []byte(canaryToken()),
				identity.FileTokenExpires: []byte(strconv.FormatInt(testNow.Unix()-1, 10)),
			},
			wantErr: identity.ErrTokenExpired,
		},
		{name: "no identity and no token", files: nil, wantErr: agent.ErrNoIdentity},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, deps := newFixture(t, tc.files)
			if _, err := agent.Run(context.Background(), deps); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run = %v, want %v", err, tc.wantErr)
			}
			assertCalls(t, f.rec.got(), "CheckRules", "LoadTrust", "Trust", "OpenState")
			if code := agent.Main(context.Background(), deps, discard()); code != 1 {
				t.Fatalf("Main = %d, want 1", code)
			}
		})
	}
}

// Case 8: Main logs the failure at ERROR and never the token, even when
// the real one-attempt identity.Enroll reads it and the send fails.
func TestMainLogsNoToken(t *testing.T) {
	t.Parallel()
	f, deps := newFixture(t, withToken())
	deps.NewSender = func([]*x509.Certificate, identity.Endpoints, func() time.Time) (identity.EnrollFunc, error) {
		f.rec.add("NewSender")
		return func(_ context.Context, req *agentapiv1.EnrollRequest) ([]byte, error) {
			if req.GetToken() != canaryToken() {
				t.Errorf("send did not receive the token file's token")
			}
			return nil, fmt.Errorf("%w: refused", controlplane.ErrEnrollStopped)
		}, nil
	}
	deps.Enroll = func(ctx context.Context, d *identity.StateDir, in identity.EnrollInput, send identity.EnrollFunc) (identity.Identity, error) {
		f.rec.add("Enroll")
		return identity.Enroll(ctx, d, in, send, testNow)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if code := agent.Main(context.Background(), deps, log); code != 1 {
		t.Fatalf("Main = %d, want 1", code)
	}
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("no ERROR record logged: %q", out)
	}
	tok := canaryToken()
	if strings.Contains(out, tok) || strings.Contains(out, tok[5:20]) {
		t.Errorf("log carries the enrollment token: %q", out)
	}
}
