//go:build linux

package agent_test

// Logging of unreachable control-plane endpoints (issue #46). Every failed
// attempt whose error is a *controlplane.DialError gives exactly one WARN
// record "agent: control-plane endpoint unreachable" with call, endpoint
// and class, and nothing else from the attempt: never the token, a key or
// certificate bytes. Records are read with a JSON handler so attributes
// are compared exactly.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

const (
	unreachableMsg = "agent: control-plane endpoint unreachable"
	streamEndedMsg = "agent: control-plane stream ended"
)

// fakeKeyPEM is a PEM header that must never reach a log, built from
// fragments so no scanner sees a key literal.
func fakeKeyPEM() string {
	return "-----BEGIN " + "PRIVATE KEY-----\n" + strings.Repeat("Q", 64) + "\n-----END " + "PRIVATE KEY-----"
}

// fakeCertBytes stands in for certificate DER bytes.
func fakeCertBytes() []byte { return []byte("FAKE-CERT-DER-" + strings.Repeat("Z", 32)) }

func jsonLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

func withMsg(rs []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, r := range rs {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

func checkUnreachable(t *testing.T, r map[string]any, call, endpoint string, class controlplane.DialClass) {
	t.Helper()
	if r["level"] != "WARN" || r["call"] != call || r["endpoint"] != endpoint || r["class"] != string(class) {
		t.Errorf("record = %v, want level=WARN call=%s endpoint=%s class=%s", r, call, endpoint, class)
	}
}

// enrollDeps returns fixture Deps whose send fails with sendErr on every
// attempt, and whose Enroll makes three attempts carrying the token and
// certificate bytes in the request.
func enrollDeps(t *testing.T, sendErr error) agent.Deps {
	t.Helper()
	_, deps := newFixture(t, withToken())
	deps.NewSender = func([]*x509.Certificate, identity.Endpoints, func() time.Time) (identity.EnrollFunc, error) {
		return func(context.Context, *agentapiv1.EnrollRequest) ([]byte, error) { return nil, sendErr }, nil
	}
	deps.Enroll = func(ctx context.Context, _ *identity.StateDir, _ identity.EnrollInput, send identity.EnrollFunc) (identity.Identity, error) {
		req := &agentapiv1.EnrollRequest{Token: canaryToken(), Csr: fakeCertBytes()}
		var last error
		for range 3 {
			_, last = send(ctx, req)
		}
		return identity.Identity{}, fmt.Errorf("fake enroll gave up: %w", last)
	}
	return deps
}

// TestEnrollDialErrorLoggedOncePerAttempt: three failed attempts, three
// WARN records with call=enroll, the endpoint and the class.
func TestEnrollDialErrorLoggedOncePerAttempt(t *testing.T) {
	t.Parallel()
	const ep = "enroll.example.test:8443"
	de := &controlplane.DialError{Endpoint: ep, Class: controlplane.DialDNS}
	deps := enrollDeps(t, de)
	log, buf := jsonLogger()
	deps.Log = log
	if _, err := agent.Run(context.Background(), deps); err == nil {
		t.Fatal("Run succeeded with a failing enrollment")
	}
	got := withMsg(records(t, buf), unreachableMsg)
	if len(got) != 3 {
		t.Fatalf("%d %q records, want 3 (one per attempt); log:\n%s", len(got), unreachableMsg, buf.String())
	}
	for _, r := range got {
		checkUnreachable(t, r, "enroll", ep, controlplane.DialDNS)
	}
	out := buf.String()
	tok := canaryToken()
	for name, secret := range map[string]string{
		"token": tok, "token fragment": tok[5:20], "private key": "PRIVATE KEY",
		"key body": strings.Repeat("Q", 64)[:40], "certificate bytes": string(fakeCertBytes()),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("log carries the %s:\n%s", name, out)
		}
	}
}

// TestEnrollNonDialErrorNotReportedUnreachable: a send error that is not a
// DialError keeps its existing logging; no "unreachable" record.
func TestEnrollNonDialErrorNotReportedUnreachable(t *testing.T) {
	t.Parallel()
	deps := enrollDeps(t, errors.New("fake send: refused"))
	log, buf := jsonLogger()
	deps.Log = log
	_, _ = agent.Run(context.Background(), deps)
	if got := withMsg(records(t, buf), unreachableMsg); len(got) != 0 {
		t.Errorf("non-dial error logged as unreachable: %v", got)
	}
}

// TestReportEndDialError: a stream end caused by a (wrapped) DialError is
// one "unreachable" record with call=connect instead of "stream ended";
// any other end keeps the "stream ended" record.
func TestReportEndDialError(t *testing.T) {
	t.Parallel()
	const ep = "agent.example.test:8443"
	cases := []struct {
		name        string
		err         error
		unreachable int
		ended       int
	}{
		{"wrapped DialError",
			fmt.Errorf("controlplane: connect: %w", &controlplane.DialError{Endpoint: ep, Class: controlplane.DialRefused}),
			1, 0},
		{"other error", errors.New("controlplane: stream: rpc error: code = Unavailable"), 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			log, buf := jsonLogger()
			agent.ReportEnd(log)(tc.err, 0)
			rs := records(t, buf)
			un, ended := withMsg(rs, unreachableMsg), withMsg(rs, streamEndedMsg)
			if len(un) != tc.unreachable || len(ended) != tc.ended {
				t.Fatalf("unreachable=%d ended=%d, want %d and %d; log:\n%s",
					len(un), len(ended), tc.unreachable, tc.ended, buf.String())
			}
			for _, r := range un {
				checkUnreachable(t, r, "connect", ep, controlplane.DialRefused)
			}
		})
	}
}
