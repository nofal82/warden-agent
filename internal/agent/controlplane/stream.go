package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	// OnEnd runs after every stream end, before the reconnect wait, with
	// the error that ended it and how long it was up after Welcome, so the
	// caller can report it locally. The package itself never logs. Nil
	// skips it.
	OnEnd func(err error, up time.Duration)
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

// HealthInput is what a HealthReport is built from.
type HealthInput struct {
	Now               time.Time
	ExecutorAvailable bool
	Outbox            outbox.Stats
	CAFileSHA256      [][]byte
}
