package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/identity"
)

// Limits of R2 and R47.
const (
	// EnrollDeadline bounds one whole attempt, dial included (R47,
	// agent-identity §7).
	EnrollDeadline = 30 * time.Second
	// DialDeadline bounds name resolution, TCP connect and the TLS
	// handshake together (R47).
	DialDeadline = 10 * time.Second
	// MaxHeaderListSize is the R2 header-list limit.
	MaxHeaderListSize = 8 << 10
	// StreamWindow and ConnWindow are the R2 flow-control windows; setting
	// them also turns off gRPC's dynamic window growth.
	StreamWindow = 64 << 10
	ConnWindow   = 256 << 10
)

var (
	// ErrNotConnected: no ready connection within DialDeadline, or the
	// connection failed (name resolution, TCP, TLS). Retried (R16).
	ErrNotConnected = errors.New("controlplane: not connected")
	// ErrResponseRefused: the EnrollResponse is over its size limit, fails
	// the strict decoder or breaks a field limit. Retried (R16).
	ErrResponseRefused = errors.New("controlplane: enroll response refused")
	// ErrCompressorRegistered: a gRPC compressor is registered in the
	// process (R2); no connection is made.
	ErrCompressorRegistered = errors.New("controlplane: a gRPC compressor is registered")
	// ErrEnrollStopped: RunEnroll ended for good on an error that a retry
	// cannot fix (ActionStop). It wraps the cause. The agent exits
	// non-zero; restarting it is systemd's job (Nofal, PR #33).
	ErrEnrollStopped = errors.New("controlplane: enrollment stopped")
	// ErrInvalidEndpoint: the endpoint is not host:port.
	ErrInvalidEndpoint = errors.New("controlplane: invalid endpoint")
	// errNilRequest: a caller defect; nothing is sent.
	errNilRequest = errors.New("controlplane: nil enroll request")
)

// knownCompressors are the names a Go program can register by importing a
// compression package. gRPC has no list of what is registered, so R2's
// start-up assertion checks these names.
var knownCompressors = []string{"gzip", "deflate", "zstd", "snappy", "s2", "lz4", "br"}

// EnrollClient sends one EnrollRequest per call to the enrollment endpoint.
type EnrollClient struct {
	target string
	tls    *tls.Config
	limits enrollLimits
	// dialer replaces gRPC's TCP dialer in tests only (export_test.go).
	dialer func(context.Context, string) (net.Conn, error)
}

// NewEnrollClient returns a client for the enrollment endpoint (endpoint
// is enroll_endpoint of endpoints.json). trustedCAs is the R10d set and
// serverName is server_name; both go to identity.ClientTLSConfig with no
// client certificate. now is the clock for certificate checks; nil means
// time.Now. An empty trustedCAs is refused: no connection is made (R3).
// Nothing is dialled here.
func NewEnrollClient(endpoint string, trustedCAs []*x509.Certificate, serverName string, now func() time.Time) (*EnrollClient, error) {
	for _, name := range knownCompressors {
		if encoding.GetCompressor(name) != nil {
			return nil, fmt.Errorf("%w: %s", ErrCompressorRegistered, name)
		}
	}
	target, err := Target(endpoint)
	if err != nil {
		return nil, err
	}
	cfg, err := identity.ClientTLSConfig(trustedCAs, serverName, nil, now)
	if err != nil {
		return nil, err
	}
	l, err := limits()
	if err != nil {
		return nil, err
	}
	return &EnrollClient{target: target, tls: cfg, limits: l}, nil
}

// Enroll sends req once, on a new connection that is closed before it
// returns, and returns the certificate DER of a response that passed the
// size, strict-decoding and field checks. It has the signature of
// identity.EnrollFunc. A gRPC error is returned as *StatusError; a failed
// connection as ErrNotConnected; a refused response as ErrResponseRefused.
func (c *EnrollClient) Enroll(ctx context.Context, req *agentapiv1.EnrollRequest) ([]byte, error) {
	if req == nil {
		return nil, errNilRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("controlplane: enroll: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, EnrollDeadline)
	defer cancel()
	conn, err := grpc.NewClient(c.target, c.dialOptions()...)
	if err != nil {
		return nil, fmt.Errorf("controlplane: enroll client: %w", err)
	}
	defer func() { _ = conn.Close() }() // nothing to do on a close error; the attempt's outcome stands
	if err := waitReady(ctx, conn); err != nil {
		return nil, err
	}
	var (
		frame  rawFrame
		header metadata.MD
	)
	if err := conn.Invoke(ctx, agentapiv1.AgentEnrollment_Enroll_FullMethodName, req, &frame, grpc.Header(&header)); err != nil {
		return nil, callError(err, header)
	}
	return c.decode(frame.b)
}

func (c *EnrollClient) dialOptions() []grpc.DialOption {
	return commonDialOptions(c.tls, c.limits.response, c.limits.request, c.dialer)
}

// commonDialOptions are the R2 and R3 options of every connection: TLS
// from cfg (never insecure), no proxy, no service config, no gRPC retry,
// the header-list limit, fixed windows, the size limits and the raw codec.
func commonDialOptions(cfg *tls.Config, recv, send int, dialer func(context.Context, string) (net.Conn, error)) []grpc.DialOption {
	opts := []grpc.DialOption{
		// credentials.NewTLS clones the config; never insecure (R3).
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithNoProxy(),
		grpc.WithDisableServiceConfig(),
		grpc.WithDisableRetry(),
		grpc.WithMaxHeaderListSize(MaxHeaderListSize),
		grpc.WithInitialWindowSize(StreamWindow),
		grpc.WithInitialConnWindowSize(ConnWindow),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(recv),
			grpc.MaxCallSendMsgSize(send),
			grpc.ForceCodecV2(rawCodec{}),
		),
	}
	if dialer != nil {
		opts = append(opts, grpc.WithContextDialer(dialer))
	}
	return opts
}

// waitReady starts the connection and waits for READY within DialDeadline
// (R47). A first failure ends the attempt: gRPC would otherwise reconnect
// on its own backoff inside the deadline, and every reconnect counts
// against the enrollment endpoint's per-source limits.
func waitReady(ctx context.Context, conn *grpc.ClientConn) error {
	return waitReadyWithin(ctx, conn, DialDeadline)
}

func waitReadyWithin(ctx context.Context, conn *grpc.ClientConn, deadline time.Duration) error {
	dctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	conn.Connect()
	for {
		s := conn.GetState()
		switch s {
		case connectivity.Ready:
			return nil
		case connectivity.TransientFailure, connectivity.Shutdown:
			return fmt.Errorf("%w: connection failed", ErrNotConnected)
		}
		if !conn.WaitForStateChange(dctx, s) {
			return fmt.Errorf("%w: dial deadline", ErrNotConnected)
		}
	}
}

// callError reduces a gRPC error to a StatusError (R45). A
// RESOURCE_EXHAUSTED after response headers arrived is our own receive
// limit tripping on an oversized response (§4.2: refuse and retry), not
// the library answer of the control plane, which is a trailers-only
// response with no headers.
func callError(err error, header metadata.MD) error {
	st := status.Convert(err)
	if st.Code() == codes.ResourceExhausted && len(header) > 0 {
		return fmt.Errorf("%w: over the size limit", ErrResponseRefused)
	}
	reason, _ := ParseEndDetail(st)
	return &StatusError{Code: st.Code(), Reason: reason, HasDetail: len(st.Proto().GetDetails()) > 0}
}

// decodeEnrollResponse is the response path after gRPC delivered the
// bytes: size limit, strict decode, field limits, copy (§4.2, §4.3, R16).
func decodeEnrollResponse(b []byte) ([]byte, error) {
	l, err := limits()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponseRefused, err)
	}
	return (&EnrollClient{limits: l}).decode(b)
}

func (c *EnrollClient) decode(b []byte) ([]byte, error) {
	if len(b) > c.limits.response {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrResponseRefused, len(b), c.limits.response)
	}
	var resp agentapiv1.EnrollResponse
	if err := agentapiv1.StrictUnmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("%w: strict decoding failed", ErrResponseRefused)
	}
	cert := resp.GetCertificate()
	if len(cert) < c.limits.certMin || len(cert) > c.limits.certMax {
		return nil, fmt.Errorf("%w: certificate is %d bytes, want %d to %d", ErrResponseRefused, len(cert), c.limits.certMin, c.limits.certMax)
	}
	return bytes.Clone(cert), nil
}
