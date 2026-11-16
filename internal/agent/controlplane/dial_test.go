package controlplane_test

// Dial failure classification (issue #46). When the connection never
// becomes READY, Enroll and RunOnce return a *DialError naming the
// endpoint and a coarse class, so an operator can tell a DNS typo from a
// firewall from a wrong CA. The error text never carries the underlying
// error: a resolver, dialer or TLS message may hold attacker-chosen or
// sensitive text (a certificate subject, a proxy banner), and the agent
// log is shipped to support. Nothing here opens a socket or queries DNS.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/resolver"

	"github.com/nofal82/warden-agent/internal/agent/controlplane"
)

// leakCanary is the text every failing dependency reports; it must never
// reach DialError.Error().
const leakCanary = "FAKE-SECRET-123"

// dnsEndpoint is a name endpoint, so the target uses the dns scheme and
// the test resolver below is consulted.
const dnsEndpoint = "enroll.example.test:8443"

// --- fake resolvers --------------------------------------------------------

type nopResolver struct{}

func (nopResolver) ResolveNow(resolver.ResolveNowOptions) {}
func (nopResolver) Close()                                {}

// failDNS stands in for the "dns" resolver: it reports an error, or a
// successful resolution with no address at all.
type failDNS struct{ noAddress bool }

func (failDNS) Scheme() string { return "dns" }

func (b failDNS) Build(_ resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) (resolver.Resolver, error) {
	if b.noAddress {
		_ = cc.UpdateState(resolver.State{})
	} else {
		cc.ReportError(errors.New("lookup " + leakCanary + ": no such host"))
	}
	return nopResolver{}, nil
}

// --- fake dialers ----------------------------------------------------------

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout " + leakCanary }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func failingDialer(err error) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) { return nil, err }
}

func refusedErr() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
}

func blockingDialer(t *testing.T) func(context.Context, string) (net.Conn, error) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return func(ctx context.Context, _ string) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("released " + leakCanary)
		}
	}
}

// garbageDialer connects to a peer that answers the ClientHello with an
// HTTP banner instead of TLS.
func garbageDialer(t *testing.T) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) {
		c, s := net.Pipe()
		t.Cleanup(func() { _ = s.Close() })
		go func() { _, _ = io.Copy(io.Discard, s) }()
		go func() { _, _ = s.Write([]byte("HTTP/1.1 400 " + leakCanary + "\r\n\r\n")) }()
		return c, nil
	}
}

// --- checks ----------------------------------------------------------------

// checkDial asserts err is a *DialError with the endpoint and class, still
// ErrNotConnected and ActionRetry, and that no forbidden text leaks.
func checkDial(t *testing.T, err error, endpoint string, class controlplane.DialClass, forbidden ...string) {
	t.Helper()
	var de *controlplane.DialError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v (%T), want a *controlplane.DialError", err, err)
	}
	if de.Endpoint != endpoint || de.Class != class {
		t.Errorf("DialError = {%q, %q}, want {%q, %q}", de.Endpoint, de.Class, endpoint, class)
	}
	if !errors.Is(err, controlplane.ErrNotConnected) {
		t.Errorf("errors.Is(err, ErrNotConnected) = false for %v", err)
	}
	if a := controlplane.ActionOf(err); a != controlplane.ActionRetry {
		t.Errorf("ActionOf = %v, want ActionRetry", a)
	}
	want := "controlplane: not connected: " + endpoint + ": " + string(class)
	if got := de.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	for _, f := range append([]string{leakCanary}, forbidden...) {
		if strings.Contains(err.Error(), f) || strings.Contains(de.Error(), f) {
			t.Errorf("error text %q leaks %q", err.Error(), f)
		}
	}
}

// =========================================================================
// DialError itself

func TestDialErrorTextAndUnwrap(t *testing.T) {
	t.Parallel()
	classes := []controlplane.DialClass{controlplane.DialDNS, controlplane.DialRefused,
		controlplane.DialTimeout, controlplane.DialTLS, controlplane.DialOther}
	wantStr := []string{"dns", "refused", "timeout", "tls", "other"}
	for i, c := range classes {
		if string(c) != wantStr[i] {
			t.Errorf("class %d = %q, want %q", i, c, wantStr[i])
		}
		var err error = &controlplane.DialError{Endpoint: dnsEndpoint, Class: c}
		checkDial(t, err, dnsEndpoint, c)
	}
}

// =========================================================================
// EnrollClient

func TestEnrollDialClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		endpoint string
		resolver resolver.Builder
		dialer   func(t *testing.T) func(context.Context, string) (net.Conn, error)
		ctx      time.Duration
		class    controlplane.DialClass
	}{
		{"resolver error", dnsEndpoint, failDNS{}, nil, 2 * time.Second, controlplane.DialDNS},
		{"resolver no address", dnsEndpoint, failDNS{noAddress: true}, nil, 2 * time.Second, controlplane.DialDNS},
		{"connection refused", testEndpoint, nil,
			func(*testing.T) func(context.Context, string) (net.Conn, error) { return failingDialer(refusedErr()) },
			2 * time.Second, controlplane.DialRefused},
		{"dial blocks past deadline", testEndpoint, nil, blockingDialer, 300 * time.Millisecond, controlplane.DialTimeout},
		{"net.Error timeout", testEndpoint, nil,
			func(*testing.T) func(context.Context, string) (net.Conn, error) { return failingDialer(timeoutErr{}) },
			2 * time.Second, controlplane.DialTimeout},
		{"peer is not TLS", testEndpoint, nil, garbageDialer, 2 * time.Second, controlplane.DialTLS},
		{"other dial error", testEndpoint, nil,
			func(*testing.T) func(context.Context, string) (net.Conn, error) {
				return failingDialer(errors.New("proxy said " + leakCanary))
			},
			2 * time.Second, controlplane.DialOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t, "CA")
			var dials atomic.Int32
			inner := failingDialer(errors.New("unexpected dial " + leakCanary))
			if tc.dialer != nil {
				inner = tc.dialer(t)
			}
			c, err := controlplane.NewEnrollClient(tc.endpoint, []*x509.Certificate{ca.cert}, testServerName, fixedNow)
			if err != nil {
				t.Fatalf("NewEnrollClient: %v", err)
			}
			controlplane.SetDialer(c, func(ctx context.Context, a string) (net.Conn, error) {
				dials.Add(1)
				return inner(ctx, a)
			})
			if tc.resolver != nil {
				controlplane.SetResolver(c, tc.resolver)
			}
			_, err = c.Enroll(shortCtx(t, tc.ctx), testRequest())
			checkDial(t, err, tc.endpoint, tc.class, fakeToken())
			if tc.class == controlplane.DialDNS && dials.Load() != 0 {
				t.Errorf("dialer called %d times after a failed resolution", dials.Load())
			}
		})
	}
}

// TestEnrollDialUntrustedCA: a server whose certificate chains to a CA the
// agent does not trust is a tls failure, and the CA's subject (chosen by
// whoever runs that server) never appears in the error.
func TestEnrollDialUntrustedCA(t *testing.T) {
	t.Parallel()
	trusted := newCA(t, "CA")
	const rogueCN = "FAKE-ROGUE-CA-SUBJECT"
	rogue := newCA(t, rogueCN)
	fs := startServer(t, serverTLS(rogue.leaf(t, goodLeafOpts()), tls.VersionTLS13),
		func(context.Context, []byte) ([]byte, error) { return nil, nil })
	c := newClient(t, trusted, fs.dialer)
	_, err := c.Enroll(shortCtx(t, 2*time.Second), testRequest())
	checkDial(t, err, testEndpoint, controlplane.DialTLS, rogueCN, "control plane", "x509")
	if n := fs.calls.Load(); n != 0 {
		t.Errorf("server saw %d calls over an untrusted connection", n)
	}
}

// =========================================================================
// ConnectClient

const connectDNSEndpoint = "agent.example.test:8443"

func TestConnectDialClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		endpoint string
		resolver resolver.Builder
		dialer   func(t *testing.T) func(context.Context, string) (net.Conn, error)
		class    controlplane.DialClass
	}{
		{"resolver error", connectDNSEndpoint, failDNS{}, nil, controlplane.DialDNS},
		{"connection refused", testEndpoint, nil,
			func(*testing.T) func(context.Context, string) (net.Conn, error) { return failingDialer(refusedErr()) },
			controlplane.DialRefused},
		{"dial deadline (R47)", testEndpoint, nil, blockingDialer, controlplane.DialTimeout},
		{"peer is not TLS", testEndpoint, nil, garbageDialer, controlplane.DialTLS},
		{"other dial error", testEndpoint, nil,
			func(*testing.T) func(context.Context, string) (net.Conn, error) {
				return failingDialer(errors.New("proxy said " + leakCanary))
			},
			controlplane.DialOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newStreamPKI(t)
			cfg := streamCfg(p, newFakeOutbox(t, 0))
			cfg.Endpoint = tc.endpoint
			c, err := controlplane.NewConnectClient(cfg)
			if err != nil {
				t.Fatalf("NewConnectClient: %v", err)
			}
			var dials atomic.Int32
			inner := failingDialer(errors.New("unexpected dial " + leakCanary))
			if tc.dialer != nil {
				inner = tc.dialer(t)
			}
			controlplane.SetConnectDialer(c, func(ctx context.Context, a string) (net.Conn, error) {
				dials.Add(1)
				return inner(ctx, a)
			})
			if tc.resolver != nil {
				controlplane.SetConnectResolver(c, tc.resolver)
			}
			tm := controlplane.DefaultTimings
			tm.Dial = 300 * time.Millisecond
			controlplane.SetStreamTimings(c, tm)
			_, err = c.RunOnce(shortCtx(t, 5*time.Second))
			checkDial(t, err, tc.endpoint, tc.class)
			if tc.class == controlplane.DialDNS && dials.Load() != 0 {
				t.Errorf("dialer called %d times after a failed resolution", dials.Load())
			}
		})
	}
}

// TestConnectRunOnEndSeesDialError: Run hands OnEnd the *DialError, so the
// agent can log the endpoint and class.
func TestConnectRunOnEndSeesDialError(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	cfg := streamCfg(p, newFakeOutbox(t, 0))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan error, 8)
	cfg.OnEnd = func(err error, _ time.Duration) {
		select {
		case got <- err:
		default:
		}
		cancel()
	}
	c, err := controlplane.NewConnectClient(cfg)
	if err != nil {
		t.Fatalf("NewConnectClient: %v", err)
	}
	controlplane.SetConnectDialer(c, failingDialer(refusedErr()))
	_ = c.Run(ctx)
	select {
	case err := <-got:
		checkDial(t, err, testEndpoint, controlplane.DialRefused)
	default:
		t.Fatal("OnEnd never called")
	}
}
