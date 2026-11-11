package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
	"github.com/nofal82/warden-agent/internal/identity"
	"github.com/nofal82/warden-agent/redact"
)

// ErrNoTrust: the R37 trust check refused, so no connection was made.
var ErrNoTrust = errors.New("controlplane: no trusted control-plane CA")

// §4.4 HealthReport bounds.
const (
	maxOutboxMessages = 1_000_000
	maxCounter        = 1 << 40
	maxCAFileHashes   = 2
)

// streamLimits are the §4.2 limits of the Connect stream, from the
// contract options (R52c).
type streamLimits struct {
	recv int // ControlMessage max_message_bytes
	send int // the largest AgentMessage: one carrying the largest OutboxMessage
}

var connectLimits = sync.OnceValues(func() (l streamLimits, err error) {
	defer func() {
		if recover() != nil {
			l, err = streamLimits{}, errors.New("controlplane: reading the Connect limits panicked")
		}
	}()
	if l.recv, err = uint32Option((&agentapiv1.ControlMessage{}).ProtoReflect().Descriptor().Options(), wardenv1.E_MaxMessageBytes); err != nil {
		return streamLimits{}, err
	}
	if l.send, err = uint32Option((&agentapiv1.OutboxMessage{}).ProtoReflect().Descriptor().Options(), wardenv1.E_MaxMessageBytes); err != nil {
		return streamLimits{}, err
	}
	return l, nil
})

// NewConnectClient checks cfg and returns a client. Nothing is dialled.
func NewConnectClient(cfg StreamConfig) (*ConnectClient, error) {
	for _, name := range knownCompressors {
		if encodingRegistered(name) {
			return nil, fmt.Errorf("%w: %s", ErrCompressorRegistered, name)
		}
	}
	target, err := Target(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStreamConfig, err)
	}
	if err := checkStreamConfig(cfg); err != nil {
		return nil, err
	}
	if _, err := connectLimits(); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &ConnectClient{cfg: cfg, target: target, t: defaultTimings, clock: realClock{}, uniform: uniform}, nil
}

func checkStreamConfig(cfg StreamConfig) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrStreamConfig, what) }
	switch {
	case cfg.Trust == nil:
		return bad("no trust function")
	case cfg.Outbox == nil:
		return bad("no outbox")
	case len(cfg.Identity.Certificate) == 0 || cfg.Identity.PrivateKey == nil:
		return bad("no client certificate")
	case identity.ValidateServerName(cfg.ServerName) != nil:
		return bad("server_name")
	case identity.ValidateServerID(cfg.ServerID) != nil:
		return bad("server_id")
	case !instanceIDRE.MatchString(cfg.InstanceID):
		return bad("instance_id")
	case len(cfg.AgentVersion) > 32 || !semverRE.MatchString(cfg.AgentVersion):
		return bad("agent_version")
	case len(cfg.CAFileSHA256) > maxCAFileHashes:
		return bad("more than 2 CA file hashes")
	}
	for _, h := range cfg.CAFileSHA256 {
		if len(h) != 32 {
			return bad("CA file hash is not 32 bytes")
		}
	}
	return nil
}

// Run holds the stream until ctx is done, reconnecting under §4.9 after
// every end, and returns ctx's error. The first connection is made at
// once; the first reconnect waits a uniform random delay so a fleet does
// not reconnect together (R46).
func (c *ConnectClient) Run(ctx context.Context) error {
	for n := 1; ; n++ {
		up, err := c.RunOnce(ctx)
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if up >= c.t.ReconnectReset {
			n = 1
		}
		act := EndActionOf(err)
		if c.cfg.OnEnd != nil {
			c.cfg.OnEnd(err, up)
		}
		if act == EndRecheckOutbox {
			// R32a. The outbox logs and counts every file it removes; a
			// failed re-check is retried after the next end.
			_, _ = c.cfg.Outbox.Recheck()
		}
		if err := c.clock.Sleep(ctx, c.reconnectWait(act, n)); err != nil {
			return err
		}
	}
}

// reconnectWait is the wait before the next connection: n is the number
// of consecutive ends since the last reset.
func (c *ConnectClient) reconnectWait(act EndAction, n int) time.Duration {
	switch act {
	case EndCertRefused:
		return min(c.clock.Jitter(c.t.CertRefusedWait), c.t.CertRefusedWait)
	case EndReconnectLongest:
		return c.t.ReconnectCap
	}
	if n <= 1 {
		return c.uniform(c.t.ReconnectFirstMax)
	}
	return min(c.clock.Jitter(doubling(c.t.ReconnectBase, c.t.ReconnectCap, n-1)), c.t.ReconnectCap)
}

// doubling is first doubled k-1 times, at most limit (k below 1 is 1).
func doubling(first, limit time.Duration, k int) time.Duration {
	d := first
	for i := 1; i < k && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

// ReconnectDelay is the un-jittered delay before reconnect number n
// (n ≥ 2): ReconnectBase doubled n-2 times, at most ReconnectCap. The first
// reconnect (n ≤ 1) waits a uniform random delay in [0, ReconnectFirstMax]
// instead and is not covered here.
func ReconnectDelay(n int) time.Duration {
	return doubling(ReconnectBase, ReconnectCap, n-1)
}

// RetryLaterDelay is the un-jittered delay before the n-th consecutive
// retry of a RETRY_LATER message (n ≥ 1): RetryLaterFirst doubled n-1
// times, at most RetryLaterCap.
func RetryLaterDelay(n int) time.Duration {
	return doubling(RetryLaterFirst, RetryLaterCap, n)
}

// uniform is a crypto/rand delay in [0, limit].
func uniform(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])                                                       // crypto/rand.Read never fails (Go 1.24+)
	return time.Duration(binary.LittleEndian.Uint64(b[:]) % (uint64(limit) + 1)) // #nosec G115 -- the remainder is at most limit, an int64
}

// RunOnce dials, runs one stream until it ends, and closes the
// connection. It returns how long the stream was up after Welcome (zero
// when no Welcome arrived) and why it ended.
func (c *ConnectClient) RunOnce(ctx context.Context) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	trusted, err := c.cfg.Trust(c.cfg.Now())
	if err != nil || len(trusted) == 0 {
		return 0, ErrNoTrust // R3, R37: an empty set means no connection
	}
	cert := c.cfg.Identity
	tlsCfg, err := identity.ClientTLSConfig(trusted, c.cfg.ServerName, &cert, c.cfg.Now)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNoTrust, err)
	}
	l, err := connectLimits()
	if err != nil {
		return 0, err
	}
	conn, err := grpc.NewClient(c.target, c.dialOptions(tlsCfg, l)...)
	if err != nil {
		return 0, fmt.Errorf("controlplane: connect client: %w", err)
	}
	defer func() { _ = conn.Close() }() // R5: closed before the next one opens
	if err := waitReadyWithin(ctx, conn, c.t.Dial); err != nil {
		return 0, err
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	desc := &grpc.StreamDesc{StreamName: "Connect", ServerStreams: true, ClientStreams: true}
	cs, err := conn.NewStream(sctx, desc, agentapiv1.AgentControl_Connect_FullMethodName)
	if err != nil {
		return 0, streamError(err, cs)
	}
	s := newSession(c, cs, l)
	return s.run(sctx)
}

func (c *ConnectClient) dialOptions(cfg *tls.Config, l streamLimits) []grpc.DialOption {
	opts := commonDialOptions(cfg, l.recv, l.send, c.dialer)
	return append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time: KeepaliveTime, Timeout: KeepaliveTimeout, PermitWithoutStream: true, // R6
	}))
}

// EndActionOf maps the error that ended a stream to an EndAction (§4.8,
// R45). Errors the agent raised itself (a refused or out-of-place control
// message, an acknowledgement timeout, a failed dial, no trust) reconnect
// under the normal backoff. A status from the control plane is decided by
// its code and its strictly decoded reason only: an unknown reason under a
// known code follows that code's row; an unknown code waits the longest
// backoff.
func EndActionOf(err error) EndAction {
	var se *StatusError
	if !errors.As(err, &se) {
		st, ok := status.FromError(err)
		if !ok {
			return EndReconnect
		}
		reason, _ := ParseEndDetail(st)
		se = &StatusError{Code: st.Code(), Reason: reason, HasDetail: len(st.Proto().GetDetails()) > 0}
	}
	switch se.Code {
	case codes.Unauthenticated:
		return EndCertRefused
	case codes.InvalidArgument:
		if se.Reason == agentapiv1.EndReason_END_REASON_MESSAGE_SEQ_UNREADABLE {
			return EndRecheckOutbox
		}
		return EndReconnect
	case codes.ResourceExhausted:
		if se.Reason == agentapiv1.EndReason_END_REASON_RATE_LIMITED {
			return EndReconnect
		}
		// The library row (no detail) names no message the agent could
		// drop, so the stream waits the longest backoff instead of
		// stopping for good; an unknown reason does the same (R45).
		return EndReconnectLongest
	case codes.Unavailable, codes.PermissionDenied, codes.FailedPrecondition,
		codes.DeadlineExceeded, codes.Aborted, codes.AlreadyExists:
		return EndReconnect
	}
	// UNIMPLEMENTED (library row, logged), INTERNAL and every code §4.8
	// does not list.
	return EndReconnectLongest
}

// DecodeControl applies §4.5 and R12 to one ControlMessage from the
// control plane: the size limit, the strict decoder, exactly one member,
// and the field limits of §4.5 (Welcome, Delivery and its content,
// MessageAck with its outcome and reason pairing).
func DecodeControl(b []byte) (*agentapiv1.ControlMessage, error) {
	l, err := connectLimits()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrControlRefused, err)
	}
	if len(b) > l.recv {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrControlRefused, len(b), l.recv)
	}
	var m agentapiv1.ControlMessage
	if err := agentapiv1.StrictUnmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: strict decoding failed", ErrControlRefused)
	}
	if err := checkControl(&m); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrControlRefused, err.Error())
	}
	return &m, nil
}

func checkControl(m *agentapiv1.ControlMessage) error {
	switch {
	case m.GetWelcome() != nil:
		w := m.GetWelcome()
		if w.GetContractVersion() != ContractVersion {
			return errors.New("welcome: contract_version outside the Hello range")
		}
		if w.GetControlPlaneTimeMs() <= 0 {
			return errors.New("welcome: control_plane_time_ms")
		}
		return nil
	case m.GetDelivery() != nil:
		return checkDelivery(m.GetDelivery())
	case m.GetMessageAck() != nil:
		return checkMessageAck(m.GetMessageAck())
	}
	return errors.New("no member")
}

func checkDelivery(d *agentapiv1.Delivery) error {
	if d.GetDeliveryId() == 0 {
		return errors.New("delivery: delivery_id zero")
	}
	c := d.GetContent()
	switch {
	case c.GetEnvelope() != nil:
		if len(c.GetEnvelope().GetSignedEnvelope()) == 0 {
			return errors.New("delivery: empty envelope")
		}
	case c.GetTrustDocument() != nil:
		td := c.GetTrustDocument()
		if td.GetKind() < wardenv1.TrustKind_TRUST_KIND_KEYSET || td.GetKind() > wardenv1.TrustKind_TRUST_KIND_CONTROLPLANE_CA {
			return errors.New("delivery: trust document kind")
		}
		if len(td.GetDocument()) == 0 {
			return errors.New("delivery: empty trust document")
		}
	case c.GetStatusRequest() != nil:
		if len(c.GetStatusRequest().GetChallenge()) != 32 {
			return errors.New("delivery: challenge is not 32 bytes")
		}
	default:
		return errors.New("delivery: no content")
	}
	return nil
}

func checkMessageAck(a *agentapiv1.MessageAck) error {
	if a.GetMessageSeq() == 0 {
		return errors.New("message_ack: message_seq zero")
	}
	r := a.GetReason()
	retry := r >= agentapiv1.AckReason_ACK_REASON_REVOCATION_STATE_STALE && r <= agentapiv1.AckReason_ACK_REASON_ORDER
	reject := r == agentapiv1.AckReason_ACK_REASON_TOO_LARGE || r == agentapiv1.AckReason_ACK_REASON_MALFORMED
	ok := false
	switch a.GetOutcome() {
	case agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED, agentapiv1.AckOutcome_ACK_OUTCOME_DUPLICATE:
		ok = r == agentapiv1.AckReason_ACK_REASON_UNSPECIFIED
	case agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER:
		ok = retry
	case agentapiv1.AckOutcome_ACK_OUTCOME_REJECTED:
		ok = reject
	default:
		return errors.New("message_ack: outcome")
	}
	if !ok {
		return errors.New("message_ack: reason does not match the outcome")
	}
	return nil
}

// BuildHealth returns the HealthReport of R39–R41 for in. It never
// carries the instance ID.
func BuildHealth(in HealthInput) *agentapiv1.HealthReport {
	var conds []agentapiv1.AgentCondition
	if !in.ExecutorAvailable {
		conds = append(conds, agentapiv1.AgentCondition_AGENT_CONDITION_EXECUTOR_UNAVAILABLE)
	}
	// OUTBOX_FULL replaces OUTBOX_HIGH_WATER: full can also come from the
	// free-space floor below 80 % of the caps (R33 storage).
	switch in.Outbox.Condition {
	case outbox.ConditionFull:
		conds = append(conds, agentapiv1.AgentCondition_AGENT_CONDITION_OUTBOX_FULL)
	case outbox.ConditionHighWater:
		conds = append(conds, agentapiv1.AgentCondition_AGENT_CONDITION_OUTBOX_HIGH_WATER)
	}
	hashes := make([][]byte, 0, len(in.CAFileSHA256))
	for _, h := range in.CAFileSHA256 {
		hashes = append(hashes, bytes.Clone(h))
	}
	slices.SortFunc(hashes, bytes.Compare)
	hashes = slices.CompactFunc(hashes, bytes.Equal)
	return &agentapiv1.HealthReport{
		AgentTimeMs:          max(in.Now.UnixMilli(), 1),
		Conditions:           conds,
		ControlplaneCaSha256: hashes,
		OutboxMessages:       uint32(min(in.Outbox.Messages, maxOutboxMessages)), // #nosec G115 -- capped at 1,000,000
		OutboxBytes:          min(in.Outbox.Bytes, maxCounter),
		RejectedMessages:     min(in.Outbox.Rejected, maxCounter),
		RedactRulesVersion:   redact.RulesVersion,
	}
}

// outboxFrame is the AgentMessage carrying one stored OutboxMessage: field
// 3, the stored bytes unchanged (R29: the same bytes every time).
func outboxFrame(b []byte) []byte {
	f := protowire.AppendTag(make([]byte, 0, len(b)+8), 3, protowire.BytesType)
	return protowire.AppendBytes(f, b)
}

func marshalAgent(m *agentapiv1.AgentMessage) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}
