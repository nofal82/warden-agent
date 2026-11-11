package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

// Constants of R6, R32, R39, R49 and §4.9.
const (
	// ContractVersion is the only contract version V1 supports (R49).
	ContractVersion = 1
	// KeepaliveTime and KeepaliveTimeout are R6.
	KeepaliveTime    = 60 * time.Second
	KeepaliveTimeout = 20 * time.Second
	// MessageAckTimeout is MESSAGE_ACK_TIMEOUT (R32).
	MessageAckTimeout = 60 * time.Second
	// HealthInterval is HEALTH_INTERVAL and HealthMinGap the coalescing
	// window of R39.
	HealthInterval = 60 * time.Second
	HealthMinGap   = 10 * time.Second
	// Outbox RETRY_LATER backoff (§4.9).
	RetryLaterFirst = time.Second
	RetryLaterCap   = 60 * time.Second
	// Connect reconnect backoff (§4.9).
	ReconnectFirstMax = 10 * time.Second
	ReconnectBase     = 2 * time.Second
	ReconnectCap      = 300 * time.Second
	ReconnectReset    = 60 * time.Second
	// CertRefusedWait is the §4.9 "certificate refused" row.
	CertRefusedWait = 300 * time.Second
)

var (
	// ErrStreamConfig: a StreamConfig field is missing or invalid.
	ErrStreamConfig = errors.New("controlplane: invalid stream configuration")
	// ErrControlRefused: a ControlMessage failed the size limit, the
	// strict decoder or a field check (§4.5, R12). The agent ends the
	// stream.
	ErrControlRefused = errors.New("controlplane: control message refused")
	// ErrProtocol: a valid ControlMessage out of place (no Welcome first, a
	// second Welcome, a MessageAck for a message not in flight, a
	// delivery_id not strictly increasing). The agent ends the stream.
	ErrProtocol = errors.New("controlplane: stream protocol violation")
	// ErrAckTimeout: no MessageAck within MESSAGE_ACK_TIMEOUT (R32).
	ErrAckTimeout = errors.New("controlplane: message acknowledgement timeout")
)

// Outbox is what the stream needs from package outbox.
type Outbox interface {
	Next() (outbox.Message, bool, error)
	Ack(seq uint64, outcome agentapiv1.AckOutcome, reason agentapiv1.AckReason) error
	Rewind()
	Recheck() (int, error)
	Stats() outbox.Stats
}

// StreamConfig is what one agent needs to hold its Connect stream.
type StreamConfig struct {
	// Endpoint is agent_endpoint and ServerName server_name of
	// endpoints.json.
	Endpoint   string
	ServerName string
	// Trust returns the R10d CA set at now. It runs before every new
	// connection (signing-and-updates R37); an error or an empty set means
	// no connection.
	Trust func(now time.Time) ([]*x509.Certificate, error)
	// Identity is the client certificate (identity.pem, or
	// identity.prev.pem under agent-identity R18a case 2).
	Identity tls.Certificate
	// ServerID, InstanceID and AgentVersion go into Hello (R10).
	ServerID     string
	InstanceID   string
	AgentVersion string
	// ExecutorAvailable reports whether the last status request was
	// answered (R10, R39); nil means false.
	ExecutorAvailable func() bool
	// CAFileSHA256 is the SHA-256 of each certificate in the agent's
	// reading of controlplane-ca.pem (R40), at most 2.
	CAFileSHA256 [][]byte
	// Outbox is the open outbox.
	Outbox Outbox
	// OnWelcome runs after the first valid Welcome of each stream, for
	// agent-identity R18a (StateDir.AfterHandshake). Nil skips it.
	OnWelcome func()
	// Now is the clock for certificate checks and agent_time_ms; nil
	// means time.Now.
	Now func() time.Time
	// Log receives local reports (never payloads, R15); nil discards.
	Log *slog.Logger
}

// timings are the stream's durations; production uses defaultTimings,
// tests shorten them (export_test.go).
type timings struct {
	AckTimeout        time.Duration
	HealthInterval    time.Duration
	HealthMinGap      time.Duration
	RetryLaterFirst   time.Duration
	RetryLaterCap     time.Duration
	ReconnectFirstMax time.Duration
	ReconnectBase     time.Duration
	ReconnectCap      time.Duration
	ReconnectReset    time.Duration
	CertRefusedWait   time.Duration
	Dial              time.Duration
}

var defaultTimings = timings{
	AckTimeout: MessageAckTimeout, HealthInterval: HealthInterval, HealthMinGap: HealthMinGap,
	RetryLaterFirst: RetryLaterFirst, RetryLaterCap: RetryLaterCap,
	ReconnectFirstMax: ReconnectFirstMax, ReconnectBase: ReconnectBase, ReconnectCap: ReconnectCap,
	ReconnectReset: ReconnectReset, CertRefusedWait: CertRefusedWait, Dial: DialDeadline,
}

// ConnectClient holds the agent's one Connect stream (R5) and reconnects
// it under §4.9.
type ConnectClient struct {
	cfg    StreamConfig
	target string
	t      timings
	clock  clock
	// uniform returns a uniform random duration in [0, max] for the first
	// reconnect (§4.9); crypto/rand in production.
	uniform func(max time.Duration) time.Duration
	// dialer replaces gRPC's TCP dialer in tests only (export_test.go).
	dialer func(context.Context, string) (net.Conn, error)
}

// NewConnectClient checks cfg and returns a client. Nothing is dialled.
func NewConnectClient(cfg StreamConfig) (*ConnectClient, error) {
	return nil, errors.New("not implemented")
}

// Run holds the stream until ctx is done, reconnecting under §4.9 after
// every end, and returns ctx's error.
func (c *ConnectClient) Run(ctx context.Context) error {
	return errors.New("not implemented")
}

// RunOnce dials, runs one stream until it ends, and closes the
// connection. It returns how long the stream was up after Welcome (zero
// when no Welcome arrived) and why it ended.
func (c *ConnectClient) RunOnce(ctx context.Context) (time.Duration, error) {
	return 0, errors.New("not implemented")
}

// EndAction is what the reconnect loop does after a stream ended.
type EndAction int

// End actions (§4.8, R45).
const (
	// EndReconnect: reconnect under the normal backoff.
	EndReconnect EndAction = iota + 1
	// EndReconnectLongest: unknown code or reason; wait ReconnectCap.
	EndReconnectLongest
	// EndCertRefused: CERTIFICATE_REVOKED; wait CertRefusedWait, keep
	// every buffered message.
	EndCertRefused
	// EndRecheckOutbox: MESSAGE_SEQ_UNREADABLE; re-check the outbox with
	// the strict scanner, then reconnect under the normal backoff (R32a).
	EndRecheckOutbox
)

// EndActionOf maps the error that ended a stream to an EndAction.
func EndActionOf(err error) EndAction {
	return EndReconnectLongest
}

// ReconnectDelay is the un-jittered delay before reconnect number n
// (n ≥ 2): ReconnectBase doubled n-2 times, at most ReconnectCap. The first
// reconnect (n ≤ 1) waits a uniform random delay in [0, ReconnectFirstMax]
// instead and is not covered here.
func ReconnectDelay(n int) time.Duration {
	return 0
}

// RetryLaterDelay is the un-jittered delay before the n-th consecutive
// retry of a RETRY_LATER message (n ≥ 1): RetryLaterFirst doubled n-1
// times, at most RetryLaterCap.
func RetryLaterDelay(n int) time.Duration {
	return 0
}

// DecodeControl applies §4.5 and R12 to one ControlMessage from the
// control plane: the size limit, the strict decoder, exactly one member,
// and the field limits of §4.5 (Welcome, Delivery and its content,
// MessageAck with its outcome and reason pairing).
func DecodeControl(b []byte) (*agentapiv1.ControlMessage, error) {
	return nil, errors.New("not implemented")
}

// HealthInput is what a HealthReport is built from.
type HealthInput struct {
	Now               time.Time
	ExecutorAvailable bool
	Outbox            outbox.Stats
	CAFileSHA256      [][]byte
}

// BuildHealth returns the HealthReport of R39–R41 for in. It never
// carries the instance ID.
func BuildHealth(in HealthInput) *agentapiv1.HealthReport {
	return nil
}
