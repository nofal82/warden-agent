package controlplane_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// respond returns a handler that answers every call with b.
func respond(b []byte) handler {
	return func(context.Context, []byte) ([]byte, error) { return b, nil }
}

func goodServer(t *testing.T, h handler) (testCA, *fakeServer) {
	t.Helper()
	ca := newCA(t, "control-plane CA")
	fs := startServer(t, serverTLS(ca.leaf(t, goodLeafOpts()), tls.VersionTLS13), h)
	return ca, fs
}

func TestEnrollHappyPath(t *testing.T) {
	t.Parallel()
	cert := randomBytes(t, 700)
	ca, fs := goodServer(t, respond(marshalDet(t, &agentapiv1.EnrollResponse{Certificate: cert})))
	c := newClient(t, ca, fs.dialer)
	req := testRequest()

	got, err := c.Enroll(shortCtx(t, 10*time.Second), req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !bytes.Equal(got, cert) {
		t.Fatal("returned certificate differs from the server's")
	}
	obs := fs.observed()
	if len(obs) != 1 {
		t.Fatalf("server saw %d calls, want 1", len(obs))
	}
	s := obs[0]
	if s.method != agentapiv1.AgentEnrollment_Enroll_FullMethodName {
		t.Errorf("method %q", s.method)
	}
	// Exactly the deterministic encoding, and it passes the strict decoder.
	if want := marshalDet(t, req); !bytes.Equal(s.req, want) {
		t.Error("request bytes are not the deterministic encoding of req")
	}
	var dec agentapiv1.EnrollRequest
	if err := agentapiv1.StrictUnmarshal(s.req, &dec); err != nil {
		t.Fatalf("request fails the strict decoder: %v", err)
	}
	if !proto.Equal(&dec, req) {
		t.Error("decoded request differs from req")
	}
	if !s.hasTLS {
		t.Fatal("no TLS on the server side")
	}
	if s.tls.Version != tls.VersionTLS13 {
		t.Errorf("TLS version %#x, want TLS 1.3", s.tls.Version)
	}
	if len(s.tls.PeerCertificates) != 0 {
		t.Error("the enrollment client presented a certificate")
	}
	if v := s.md.Get("grpc-encoding"); len(v) != 0 && v[0] != "identity" {
		t.Errorf("request compressed: grpc-encoding %q", v)
	}
	ct := s.md.Get("content-type")
	if len(ct) != 1 || (ct[0] != "application/grpc" && ct[0] != "application/grpc+proto") {
		t.Errorf("content-type %q, want application/grpc[+proto]", ct)
	}
}

// TestEnrollReturnsCopy: mutating the returned certificate must not change
// what a later call returns, nor any buffer the client keeps.
func TestEnrollReturnsCopy(t *testing.T) {
	t.Parallel()
	cert := randomBytes(t, 300)
	ca, fs := goodServer(t, respond(marshalDet(t, &agentapiv1.EnrollResponse{Certificate: cert})))
	c := newClient(t, ca, fs.dialer)
	first, err := c.Enroll(shortCtx(t, 10*time.Second), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		first[i] ^= 0xff
	}
	second, err := c.Enroll(shortCtx(t, 10*time.Second), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, cert) {
		t.Fatal("second result changed after mutating the first")
	}
}

func TestEnrollTLSAttacks(t *testing.T) {
	t.Parallel()
	trusted := newCA(t, "trusted CA")
	other := newCA(t, "attacker CA")
	expired := goodLeafOpts()
	expired.notBefore, expired.notAfter = testNow.Add(-48*time.Hour), testNow.Add(-time.Hour)
	notYet := goodLeafOpts()
	notYet.notBefore, notYet.notAfter = testNow.Add(time.Hour), testNow.Add(48*time.Hour)
	wrongSAN := goodLeafOpts()
	wrongSAN.dns = []string{"other.warden.test"}
	wildcard := goodLeafOpts()
	wildcard.dns = []string{"*.warden.test"}
	clientEKU := goodLeafOpts()
	clientEKU.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	bothEKU := goodLeafOpts()
	bothEKU.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	caLeaf := goodLeafOpts()
	caLeaf.isCA = true

	cases := []struct {
		name string
		cfg  *tls.Config
	}{
		{"untrusted CA", serverTLS(other.leaf(t, goodLeafOpts()), tls.VersionTLS13)},
		{"wrong SAN", serverTLS(trusted.leaf(t, wrongSAN), tls.VersionTLS13)},
		{"wildcard SAN", serverTLS(trusted.leaf(t, wildcard), tls.VersionTLS13)},
		{"expired", serverTLS(trusted.leaf(t, expired), tls.VersionTLS13)},
		{"not yet valid", serverTLS(trusted.leaf(t, notYet), tls.VersionTLS13)},
		{"clientAuth EKU", serverTLS(trusted.leaf(t, clientEKU), tls.VersionTLS13)},
		{"serverAuth+clientAuth EKU", serverTLS(trusted.leaf(t, bothEKU), tls.VersionTLS13)},
		{"CA as leaf", serverTLS(trusted.leaf(t, caLeaf), tls.VersionTLS13)},
		{"TLS 1.2 only", serverTLS(trusted.leaf(t, goodLeafOpts()), tls.VersionTLS12)},
	}
	resp := marshalDet(t, &agentapiv1.EnrollResponse{Certificate: []byte{1}})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fs := startServer(t, tc.cfg, respond(resp))
			c := newClient(t, trusted, fs.dialer)
			start := time.Now()
			_, err := c.Enroll(shortCtx(t, 15*time.Second), testRequest())
			if !errors.Is(err, controlplane.ErrNotConnected) {
				t.Fatalf("err = %v, want ErrNotConnected", err)
			}
			if a := controlplane.ActionOf(err); a != controlplane.ActionRetry {
				t.Errorf("ActionOf = %v, want ActionRetry", a)
			}
			if n := fs.calls.Load(); n != 0 {
				t.Errorf("handler called %d times", n)
			}
			if el := time.Since(start); el > controlplane.DialDeadline+2*time.Second {
				t.Errorf("took %v", el)
			}
		})
	}
}

// responseAttacks are response bodies the client must refuse. maxOK
// reports whether the case is within the 4608-byte limit, so it must fail
// with ErrResponseRefused rather than a gRPC receive-limit error.
func responseAttacks(t testing.TB) []struct {
	name string
	b    []byte
} {
	t.Helper()
	valid := marshalDet(t, &agentapiv1.EnrollResponse{Certificate: []byte("FAKE-CERT")})
	field1 := func(n int) []byte {
		b := protowire.AppendTag(nil, 1, protowire.BytesType)
		return protowire.AppendBytes(b, bytes.Repeat([]byte{0x30}, n))
	}
	unknown := protowire.AppendVarint(protowire.AppendTag(append([]byte(nil), valid...), 2, protowire.VarintType), 1)
	unknownHigh := protowire.AppendBytes(protowire.AppendTag(append([]byte(nil), valid...), 1000, protowire.BytesType), []byte("x"))
	unknownBefore := append(protowire.AppendVarint(protowire.AppendTag(nil, 0x1fffffff, protowire.VarintType), 1), valid...)
	dup := append(append([]byte(nil), valid...), valid...)
	wrongWT := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 5)
	fixed := protowire.AppendFixed32(protowire.AppendTag(nil, 1, protowire.Fixed32Type), 5)
	group := protowire.AppendTag(nil, 1, protowire.StartGroupType)
	group = protowire.AppendTag(group, 1, protowire.EndGroupType)
	return []struct {
		name string
		b    []byte
	}{
		{"empty response", nil},
		{"explicit empty certificate", []byte{0x0a, 0x00}},
		{"unknown field after", unknown},
		{"unknown high field", unknownHigh},
		{"unknown field before", unknownBefore},
		{"duplicate certificate", dup},
		{"wrong wire type varint", wrongWT},
		{"wrong wire type fixed32", fixed},
		{"group wire type", group},
		{"field number 0", []byte{0x02, 0x01, 0x41}},
		{"certificate 4097 bytes", field1(4097)},
		{"message 4608 bytes, certificate 4605", field1(4605)},
		{"trailing garbage", append(append([]byte(nil), valid...), 0xff)},
		{"trailing zero", append(append([]byte(nil), valid...), 0x00)},
		{"truncated length", []byte{0x0a, 0x0a, 0x41, 0x41}},
		{"truncated tag", []byte{0x8a}},
		{"non-minimal length varint", []byte{0x0a, 0x81, 0x00, 0x41}},
		{"non-minimal tag varint", []byte{0x8a, 0x00, 0x01, 0x41}},
		{"length overflow", []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},
		{"length 2^32", append([]byte{0x0a, 0x80, 0x80, 0x80, 0x80, 0x10}, 0x41)},
	}
}

func TestDecodeEnrollResponseAttacks(t *testing.T) {
	t.Parallel()
	for _, tc := range append(responseAttacks(t), struct {
		name string
		b    []byte
	}{"message 4609 bytes", func() []byte {
		b := protowire.AppendTag(nil, 1, protowire.BytesType)
		return protowire.AppendBytes(b, make([]byte, 4606))
	}()}) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := controlplane.DecodeEnrollResponse(tc.b)
			if !errors.Is(err, controlplane.ErrResponseRefused) {
				t.Fatalf("err = %v (cert %d bytes), want ErrResponseRefused", err, len(got))
			}
			if got != nil {
				t.Error("returned bytes with an error")
			}
		})
	}
}

func TestDecodeEnrollResponseValid(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 2, 127, 128, 4095, 4096} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			cert := randomBytes(t, n)
			in := marshalDet(t, &agentapiv1.EnrollResponse{Certificate: cert})
			got, err := controlplane.DecodeEnrollResponse(in)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !bytes.Equal(got, cert) {
				t.Fatal("certificate differs")
			}
			// No aliasing of the input buffer.
			for i := range in {
				in[i] = 0
			}
			if !bytes.Equal(got, cert) {
				t.Fatal("result aliases the input buffer")
			}
		})
	}
}

// TestEnrollResponseAttacks sends each bad body through a real gRPC call.
func TestEnrollResponseAttacks(t *testing.T) {
	t.Parallel()
	cases := append(responseAttacks(t), struct {
		name string
		b    []byte
	}{"message 4609 bytes (gRPC receive limit)", func() []byte {
		b := protowire.AppendTag(nil, 1, protowire.BytesType)
		return protowire.AppendBytes(b, make([]byte, 4606))
	}()}, struct {
		name string
		b    []byte
	}{"message 64 KiB", bytes.Repeat([]byte{0x41}, 64<<10)})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca, fs := goodServer(t, respond(tc.b))
			c := newClient(t, ca, fs.dialer)
			got, err := c.Enroll(shortCtx(t, 10*time.Second), testRequest())
			if err == nil {
				t.Fatalf("accepted a bad response (%d-byte certificate)", len(got))
			}
			// R16: a refused response is retried; the gRPC library's own
			// receive-limit error must not be read as the server's
			// RESOURCE_EXHAUSTED "do not retry" row.
			if a := controlplane.ActionOf(err); a != controlplane.ActionRetry {
				t.Errorf("ActionOf(%v) = %v, want ActionRetry", err, a)
			}
			if len(tc.b) <= 4608 && !errors.Is(err, controlplane.ErrResponseRefused) {
				t.Errorf("err = %v, want ErrResponseRefused", err)
			}
		})
	}
}

// statusWith builds a status with one EndDetail of reason r.
func statusWith(t testing.TB, code codes.Code, msg string, r agentapiv1.EndReason) *status.Status {
	t.Helper()
	a := &anypb.Any{
		TypeUrl: "type.googleapis.com/warden.agentapi.v1.EndDetail",
		Value:   marshalDet(t, &agentapiv1.EndDetail{Reason: r}),
	}
	p := status.New(code, msg).Proto()
	p.Details = []*anypb.Any{a}
	return status.FromProto(p)
}

func TestEnrollStatusMapping(t *testing.T) {
	t.Parallel()
	statusUnknownField := func() *status.Status {
		p := statusWith(t, codes.PermissionDenied, "", agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED).Proto()
		p.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
		return status.FromProto(p)
	}
	cases := []struct {
		name      string
		st        *status.Status
		reason    agentapiv1.EndReason
		hasDetail bool
		action    controlplane.Action
	}{
		{"PERMISSION_DENIED ENROLLMENT_REFUSED", statusWith(t, codes.PermissionDenied, "ENROLLMENT_REFUSED", agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED),
			agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED, true, controlplane.ActionRetry},
		{"UNAVAILABLE DATABASE_UNAVAILABLE", statusWith(t, codes.Unavailable, "DATABASE_UNAVAILABLE", agentapiv1.EndReason_END_REASON_DATABASE_UNAVAILABLE),
			agentapiv1.EndReason_END_REASON_DATABASE_UNAVAILABLE, true, controlplane.ActionRetry},
		{"RESOURCE_EXHAUSTED RATE_LIMITED", statusWith(t, codes.ResourceExhausted, "", agentapiv1.EndReason_END_REASON_RATE_LIMITED),
			agentapiv1.EndReason_END_REASON_RATE_LIMITED, true, controlplane.ActionRetry},
		{"RESOURCE_EXHAUSTED no detail", status.New(codes.ResourceExhausted, "grpc: received message larger than max"),
			agentapiv1.EndReason_END_REASON_UNSPECIFIED, false, controlplane.ActionStop},
		{"RESOURCE_EXHAUSTED reason 19", statusWith(t, codes.ResourceExhausted, "", 19),
			agentapiv1.EndReason_END_REASON_UNSPECIFIED, true, controlplane.ActionRetryLongest},
		{"UNIMPLEMENTED", status.New(codes.Unimplemented, "unknown method"),
			agentapiv1.EndReason_END_REASON_UNSPECIFIED, false, controlplane.ActionStop},
		{"INTERNAL", status.New(codes.Internal, "boom"),
			agentapiv1.EndReason_END_REASON_UNSPECIFIED, false, controlplane.ActionRetryLongest},
		{"UNKNOWN", status.New(codes.Unknown, "boom"),
			agentapiv1.EndReason_END_REASON_UNSPECIFIED, false, controlplane.ActionRetryLongest},
		{"PERMISSION_DENIED mismatched DATABASE_UNAVAILABLE", statusWith(t, codes.PermissionDenied, "", agentapiv1.EndReason_END_REASON_DATABASE_UNAVAILABLE),
			agentapiv1.EndReason_END_REASON_UNSPECIFIED, true, controlplane.ActionRetry},
		{"unknown field on Status", statusUnknownField(),
			agentapiv1.EndReason_END_REASON_UNSPECIFIED, true, controlplane.ActionRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := tc.st
			ca, fs := goodServer(t, func(context.Context, []byte) ([]byte, error) { return nil, st.Err() })
			c := newClient(t, ca, fs.dialer)
			_, err := c.Enroll(shortCtx(t, 10*time.Second), testRequest())
			var se *controlplane.StatusError
			if !errors.As(err, &se) {
				t.Fatalf("err = %v, want *StatusError", err)
			}
			if se.Code != st.Code() || se.Reason != tc.reason || se.HasDetail != tc.hasDetail {
				t.Errorf("StatusError = %+v, want code %v reason %v hasDetail %v", *se, st.Code(), tc.reason, tc.hasDetail)
			}
			if a := controlplane.ActionOf(err); a != tc.action {
				t.Errorf("ActionOf = %v, want %v", a, tc.action)
			}
		})
	}
}

// TestEnrollStatusMessageNotInError: the peer's status message is data for
// a bounded local log only; it never reaches the error string (R20, R45).
func TestEnrollStatusMessageNotInError(t *testing.T) {
	t.Parallel()
	tok := fakeToken()
	marker := "PEER-TEXT-MARKER"
	msgs := map[string]string{
		"short with escapes": marker + " " + tok + "\n\x1b[31mred\x1b[0m\r\x00",
		"1 KiB":              strings.Repeat("A", 1000) + tok + marker,
		"8 KiB":              strings.Repeat("B", 8<<10) + tok + marker,
	}
	for name, msg := range msgs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := statusWith(t, codes.PermissionDenied, msg, agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED)
			ca, fs := goodServer(t, func(context.Context, []byte) ([]byte, error) { return nil, st.Err() })
			c := newClient(t, ca, fs.dialer)
			_, err := c.Enroll(shortCtx(t, 10*time.Second), testRequest())
			if err == nil {
				t.Fatal("no error")
			}
			for _, s := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
				for _, bad := range []string{tok, marker, "\n", "\x1b", "\r", "\x00", "QQQQQQQQ"} {
					if strings.Contains(s, bad) {
						t.Errorf("error text contains %q: %q", bad, s)
					}
				}
			}
			// Wrapped by identity.Enroll, the same must hold.
			if s := fmt.Errorf("identity: enroll: %w", err).Error(); strings.Contains(s, tok) || strings.Contains(s, marker) {
				t.Errorf("wrapped error leaks the status message: %q", s)
			}
		})
	}
}

// TestEnrollBlockingHandler: a server that never answers is cut off by the
// caller's deadline, and the timeout is retried (R16).
func TestEnrollBlockingHandler(t *testing.T) {
	t.Parallel()
	ca, fs := goodServer(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c := newClient(t, ca, fs.dialer)
	start := time.Now()
	_, err := c.Enroll(shortCtx(t, 300*time.Millisecond), testRequest())
	if err == nil {
		t.Fatal("no error")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("returned after %v", el)
	}
	if a := controlplane.ActionOf(err); a != controlplane.ActionRetry {
		t.Errorf("ActionOf(%v) = %v, want ActionRetry", err, a)
	}
}

// TestEnrollBlockingDialer: a dial that never completes ends with
// ErrNotConnected once the caller's deadline passes.
func TestEnrollBlockingDialer(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "CA")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := newClient(t, ca, func(ctx context.Context, _ string) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("released")
		}
	})
	start := time.Now()
	_, err := c.Enroll(shortCtx(t, 300*time.Millisecond), testRequest())
	if !errors.Is(err, controlplane.ErrNotConnected) {
		t.Fatalf("err = %v, want ErrNotConnected", err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("returned after %v", el)
	}
	if a := controlplane.ActionOf(err); a != controlplane.ActionRetry {
		t.Errorf("ActionOf = %v, want ActionRetry", a)
	}
}

// TestEnrollCancelledContext: no dial at all with a context already done.
func TestEnrollCancelledContext(t *testing.T) {
	t.Parallel()
	ca, fs := goodServer(t, respond(marshalDet(t, &agentapiv1.EnrollResponse{Certificate: []byte{1}})))
	c := newClient(t, ca, fs.dialer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Enroll(ctx, testRequest()); err == nil {
		t.Fatal("no error with a cancelled context")
	}
	// Give a background dial, if one was wrongly started, time to show up.
	time.Sleep(50 * time.Millisecond)
	if n := fs.dials.Load(); n != 0 {
		t.Errorf("%d dials with a cancelled context", n)
	}
}

// TestEnrollOneConnectionPerAttempt: each call dials once and closes its
// connection before returning (R47, agent-identity §7).
func TestEnrollOneConnectionPerAttempt(t *testing.T) {
	t.Parallel()
	ca, fs := goodServer(t, respond(marshalDet(t, &agentapiv1.EnrollResponse{Certificate: []byte{1}})))
	c := newClient(t, ca, fs.dialer)
	for i := int32(1); i <= 2; i++ {
		if _, err := c.Enroll(shortCtx(t, 10*time.Second), testRequest()); err != nil {
			t.Fatal(err)
		}
		if n := fs.dials.Load(); n != i {
			t.Fatalf("after call %d: %d dials", i, n)
		}
		waitFor(t, "connection close", func() bool { return fs.closes.Load() == i })
	}
	// Also after a failed call.
	failing, fs2 := goodServer(t, func(context.Context, []byte) ([]byte, error) {
		return nil, status.Error(codes.Unavailable, "x")
	})
	c2 := newClient(t, failing, fs2.dialer)
	if _, err := c2.Enroll(shortCtx(t, 10*time.Second), testRequest()); err == nil {
		t.Fatal("no error")
	}
	waitFor(t, "connection close after failure", func() bool {
		return fs2.dials.Load() >= 1 && fs2.closes.Load() == fs2.dials.Load()
	})
}

// TestEnrollRequestOverSendLimit: a request over 8 KiB is refused by the
// client before anything reaches a handler, and is not retried (§4.8
// RESOURCE_EXHAUSTED library row).
func TestEnrollRequestOverSendLimit(t *testing.T) {
	t.Parallel()
	ca, fs := goodServer(t, respond(marshalDet(t, &agentapiv1.EnrollResponse{Certificate: []byte{1}})))
	c := newClient(t, ca, fs.dialer)
	req := testRequest()
	req.Csr = make([]byte, 9000)
	_, err := c.Enroll(shortCtx(t, 10*time.Second), req)
	if err == nil {
		t.Fatal("oversized request sent")
	}
	if n := fs.calls.Load(); n != 0 {
		t.Errorf("handler called %d times", n)
	}
	if a := controlplane.ActionOf(err); a != controlplane.ActionStop {
		t.Errorf("ActionOf(%v) = %v, want ActionStop", err, a)
	}
}

func TestEnrollNilRequest(t *testing.T) {
	t.Parallel()
	ca, fs := goodServer(t, respond(marshalDet(t, &agentapiv1.EnrollResponse{Certificate: []byte{1}})))
	c := newClient(t, ca, fs.dialer)
	if _, err := c.Enroll(shortCtx(t, 10*time.Second), nil); err == nil {
		t.Fatal("nil request accepted")
	}
	if n := fs.calls.Load(); n != 0 {
		t.Errorf("handler called %d times", n)
	}
}

func TestNewEnrollClient(t *testing.T) {
	t.Parallel()
	ca1, ca2, ca3 := newCA(t, "a"), newCA(t, "b"), newCA(t, "c")
	leaf := ca1.leaf(t, goodLeafOpts()).Leaf
	cas := func(c ...*x509.Certificate) []*x509.Certificate { return c }
	cases := []struct {
		name     string
		endpoint string
		cas      []*x509.Certificate
		sn       string
		want     error
	}{
		{"one CA", testEndpoint, cas(ca1.cert), testServerName, nil},
		{"two CAs", testEndpoint, cas(ca1.cert, ca2.cert), testServerName, nil},
		{"DNS endpoint, no lookup at construction", "enroll.invalid:443", cas(ca1.cert), testServerName, nil},
		{"zero CAs", testEndpoint, nil, testServerName, identity.ErrInvalidTrust},
		{"empty slice", testEndpoint, cas(), testServerName, identity.ErrInvalidTrust},
		{"three CAs", testEndpoint, cas(ca1.cert, ca2.cert, ca3.cert), testServerName, identity.ErrInvalidTrust},
		{"non-CA cert", testEndpoint, cas(leaf), testServerName, identity.ErrInvalidTrust},
		{"nil CA", testEndpoint, cas(nil), testServerName, identity.ErrInvalidTrust},
		{"empty server name", testEndpoint, cas(ca1.cert), "", identity.ErrInvalidServerName},
		{"server name with space", testEndpoint, cas(ca1.cert), "a b", identity.ErrInvalidServerName},
		{"server name with zone", testEndpoint, cas(ca1.cert), "fe80::1%eth0", identity.ErrInvalidServerName},
		{"server name wildcard", testEndpoint, cas(ca1.cert), "*.warden.test", identity.ErrInvalidServerName},
		{"bad endpoint", "unix:///tmp/x", cas(ca1.cert), testServerName, controlplane.ErrInvalidEndpoint},
		{"empty endpoint", "", cas(ca1.cert), testServerName, controlplane.ErrInvalidEndpoint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			c, err := controlplane.NewEnrollClient(tc.endpoint, tc.cas, tc.sn, nil)
			if time.Since(start) > time.Second {
				t.Error("construction is slow: network activity?")
			}
			if tc.want == nil {
				if err != nil || c == nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if c != nil {
				t.Error("client returned with an error")
			}
		})
	}
	// ErrCompressorRegistered is not tested here: grpc has no way to
	// unregister a compressor, so registering one would leak into every
	// other test in this binary, and re-running the test binary as a child
	// process would need os/exec, which CLAUDE.md forbids outside the
	// executor primitives. The source scan below checks no gzip import.
}
