package controlplane

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
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
	// StreamWindow and ConnWindow are the R2 flow-control windows.
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
	// ErrInvalidEndpoint: the endpoint is not host:port.
	ErrInvalidEndpoint = errors.New("controlplane: invalid endpoint")
)

// Target returns the explicit gRPC target of R2 for an endpoint host:port
// from endpoints.json: passthrough:///<ip>:<port> for an IP literal,
// dns:///<host>:<port> otherwise.
func Target(endpoint string) (string, error) {
	return "", errors.ErrUnsupported
}

// EnrollClient sends one EnrollRequest per call to the enrollment endpoint.
type EnrollClient struct {
	target string
	cfgErr error
	// dialer replaces gRPC's TCP dialer in tests only (export_test.go).
	dialer func(context.Context, string) (net.Conn, error)
}

// NewEnrollClient returns a client for the enrollment endpoint (endpoint
// is enroll_endpoint of endpoints.json). trustedCAs is the R10d set and
// serverName is server_name; both go to identity.ClientTLSConfig with no
// client certificate. now is the clock for certificate checks; nil means
// time.Now. An empty trustedCAs is refused: no connection is made (R3).
func NewEnrollClient(endpoint string, trustedCAs []*x509.Certificate, serverName string, now func() time.Time) (*EnrollClient, error) {
	return nil, errors.ErrUnsupported
}

// Enroll sends req once and returns the certificate DER of a response that
// passed the size, strict-decoding and field checks. It has the signature
// of identity.EnrollFunc. A gRPC error is returned as *StatusError.
func (c *EnrollClient) Enroll(ctx context.Context, req *agentapiv1.EnrollRequest) ([]byte, error) {
	return nil, errors.ErrUnsupported
}

// StatusError is a gRPC error from the control plane, reduced to what R45
// lets the agent use: the code and the EndDetail reason. Reason is
// END_REASON_UNSPECIFIED when the status had no valid detail (none, more
// than one, or one that fails the R45 checks). HasDetail reports whether
// the status carried any detail at all.
type StatusError struct {
	Code      codes.Code
	Reason    agentapiv1.EndReason
	HasDetail bool
}

func (e *StatusError) Error() string { return "controlplane: " + e.Code.String() }

// ParseEndDetail applies R45 to st: exactly one detail, no unknown fields
// on the Status or the Any, type URL
// type.googleapis.com/warden.agentapi.v1.EndDetail, an Any of at most 128
// bytes, a value that passes the strict decoder, and a known EndReason that
// §4.8 pairs with st's code. It returns the reason and true only then.
// It reads Status.Proto().GetDetails(), never Status.Details().
func ParseEndDetail(st *status.Status) (agentapiv1.EndReason, bool) {
	return agentapiv1.EndReason_END_REASON_UNSPECIFIED, false
}

// Action is what the enrollment loop does after a failed attempt.
type Action int

// Actions.
const (
	// ActionStop: do not retry; return the error to the caller.
	ActionStop Action = iota + 1
	// ActionRetry: retry under the enrollment backoff (§4.9).
	ActionRetry
	// ActionRetryLongest: retry after the longest enrollment backoff
	// (R45: unknown code or unknown reason).
	ActionRetryLongest
)

// ActionOf maps an error of one enrollment attempt to an Action, per R16,
// R45 and §4.8. Errors that did not come from the call (local file, key or
// R15 failures) are ActionStop.
func ActionOf(err error) Action {
	return ActionStop
}
