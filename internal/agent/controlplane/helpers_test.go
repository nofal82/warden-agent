package controlplane_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
)

// testServerName is the control plane's server_name in every test; the
// endpoint is an IP literal so no name is ever resolved.
const (
	testServerName = "enroll.warden.test"
	testEndpoint   = "127.0.0.1:443"
)

// testNow is the fixed clock of the client's certificate checks.
var testNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return testNow }

// --- PKI, generated at runtime -------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial atomic.Int64

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t testing.TB, cn string) testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

type leafOpts struct {
	dns       []string
	eku       []x509.ExtKeyUsage
	isCA      bool
	notBefore time.Time
	notAfter  time.Time
}

func goodLeafOpts() leafOpts {
	return leafOpts{
		dns:       []string{testServerName},
		eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		notBefore: testNow.Add(-time.Hour),
		notAfter:  testNow.Add(30 * 24 * time.Hour),
	}
}

func (ca testCA) leaf(t testing.TB, o leafOpts) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: "control plane"},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		DNSNames:              o.dns,
		ExtKeyUsage:           o.eku,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  o.isCA,
		BasicConstraintsValid: true,
	}
	if o.isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// --- raw-bytes codec -------------------------------------------------------

// frame carries one message's bytes unchanged, so a test controls every
// byte of the response and sees every byte of the request.
type frame struct{ b []byte }

type rawCodec struct{}

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	f, ok := v.(*frame)
	if !ok {
		return nil, errors.New("rawCodec: not a frame")
	}
	return mem.BufferSlice{mem.SliceBuffer(append([]byte(nil), f.b...))}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	f, ok := v.(*frame)
	if !ok {
		return errors.New("rawCodec: not a frame")
	}
	f.b = data.Materialize()
	return nil
}

func (rawCodec) Name() string { return "proto" }

// --- fake control plane over bufconn -------------------------------------

// seen is what the server observed for one call.
type seen struct {
	method string
	req    []byte
	md     metadata.MD
	tls    tls.ConnectionState
	hasTLS bool
}

// handler answers one call with response bytes or an error (a status).
type handler func(ctx context.Context, req []byte) ([]byte, error)

type fakeServer struct {
	lis    *bufconn.Listener
	calls  atomic.Int32
	dials  atomic.Int32
	closes atomic.Int32

	mu   sync.Mutex
	seen []seen
}

func serverTLS(cert tls.Certificate, maxVersion uint16) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxVersion,
		// Ask for a client certificate so a client that had one would send
		// it; the enrollment client must send none.
		ClientAuth: tls.RequestClientCert,
	}
}

// startServer runs a gRPC server on an in-memory listener. h answers every
// method; no service is registered, so the raw codec sees every byte.
func startServer(t *testing.T, cfg *tls.Config, h handler) *fakeServer {
	t.Helper()
	fs := &fakeServer{lis: bufconn.Listen(1 << 20)}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(cfg)),
		grpc.ForceServerCodecV2(rawCodec{}),
		grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
			var in frame
			if err := ss.RecvMsg(&in); err != nil {
				return err
			}
			// Counted only once a whole request arrived: a stream the
			// client opens and then abandons is not a call.
			fs.calls.Add(1)
			s := seen{req: in.b}
			s.method, _ = grpc.MethodFromServerStream(ss)
			s.md, _ = metadata.FromIncomingContext(ss.Context())
			if p, ok := peer.FromContext(ss.Context()); ok {
				if info, ok := p.AuthInfo.(credentials.TLSInfo); ok {
					s.tls, s.hasTLS = info.State, true
				}
			}
			fs.mu.Lock()
			fs.seen = append(fs.seen, s)
			fs.mu.Unlock()
			out, err := h(ss.Context(), in.b)
			if err != nil {
				return err
			}
			return ss.SendMsg(&frame{b: out})
		}),
	)
	go func() { _ = srv.Serve(fs.lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = fs.lis.Close()
	})
	return fs
}

func (fs *fakeServer) observed() []seen {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]seen(nil), fs.seen...)
}

// dialer counts dials and wraps each conn to count closes.
func (fs *fakeServer) dialer(ctx context.Context, _ string) (net.Conn, error) {
	fs.dials.Add(1)
	c, err := fs.lis.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	return &trackedConn{Conn: c, closes: &fs.closes}, nil
}

type trackedConn struct {
	net.Conn
	once   sync.Once
	closes *atomic.Int32
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.closes.Add(1) })
	return c.Conn.Close()
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- client --------------------------------------------------------------

func newClient(t *testing.T, ca testCA, dial func(context.Context, string) (net.Conn, error)) *controlplane.EnrollClient {
	t.Helper()
	c, err := controlplane.NewEnrollClient(testEndpoint, []*x509.Certificate{ca.cert}, testServerName, fixedNow)
	if err != nil {
		t.Fatalf("NewEnrollClient: %v", err)
	}
	controlplane.SetDialer(c, dial)
	return c
}

// fakeToken is an obviously fake token in the §4.2 shape, built at runtime.
func fakeToken() string { return "wdn1" + "_" + strings.Repeat("Q", 43) }

func testRequest() *agentapiv1.EnrollRequest {
	return &agentapiv1.EnrollRequest{
		FormatVersion:      1,
		Token:              fakeToken(),
		ServerId:           "00000000-0000-4000-8000-000000000001",
		Csr:                []byte("FAKE-CSR-DER"),
		ExecutorPublicKey:  make32(0x11),
		ExecutorBindingMac: make32(0x22),
	}
}

func make32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func marshalDet(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func shortCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
