package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

// §4.4 Hello patterns.
var (
	instanceIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	semverRE     = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$`)
)

func encodingRegistered(name string) bool { return encoding.GetCompressor(name) != nil }

// recvd is one control message, or the error that ended the receive side.
type recvd struct {
	m   *agentapiv1.ControlMessage
	err error
}

// session is one Connect stream. Every send happens on the goroutine that
// runs run; a second goroutine only receives, so gRPC's rule of one
// sender and one receiver at a time holds.
type session struct {
	c  *ConnectClient
	cs grpc.ClientStream
	l  streamLimits

	inflight map[uint64]time.Time // message_seq → when it was sent
	retryN   int                  // consecutive RETRY_LATER (§4.9 reset on ACCEPTED)
	paused   bool                 // waiting out a RETRY_LATER backoff
	resume   *time.Timer

	lastDelivery uint64
	deliveries   uint64 // validated deliveries not acted on (M1)

	lastHealth time.Time
	lastConds  []agentapiv1.AgentCondition
}

func newSession(c *ConnectClient, cs grpc.ClientStream, l streamLimits) *session {
	return &session{c: c, cs: cs, l: l, inflight: map[uint64]time.Time{}}
}

func (s *session) run(ctx context.Context) (time.Duration, error) {
	defer func() {
		if s.resume != nil {
			s.resume.Stop()
		}
	}()
	in := make(chan recvd, 1)
	go s.receive(ctx, in)

	if err := s.sendHello(); err != nil {
		return 0, err
	}
	if err := s.awaitWelcome(ctx, in); err != nil {
		return 0, err
	}
	welcomed := time.Now()
	up := func() time.Duration { return time.Since(welcomed) }
	if s.c.cfg.OnWelcome != nil {
		s.c.cfg.OnWelcome()
	}
	// R32: every stream starts again from the oldest unacknowledged message.
	s.c.cfg.Outbox.Rewind()
	if err := s.sendHealth(true); err != nil {
		return up(), err
	}
	tick := time.NewTicker(s.c.t.HealthMinGap)
	defer tick.Stop()
	for {
		if err := s.fill(); err != nil {
			return up(), err
		}
		ackWait, stopAck := s.ackDeadline()
		var resume <-chan time.Time
		if s.paused {
			resume = s.resume.C
		}
		select {
		case <-ctx.Done():
			stopAck()
			return up(), ctx.Err()
		case r := <-in:
			stopAck()
			if r.err != nil {
				return up(), r.err
			}
			if err := s.handle(r.m); err != nil {
				return up(), err
			}
			if err := s.sendHealth(false); err != nil {
				return up(), err
			}
		case <-ackWait:
			return up(), ErrAckTimeout
		case <-resume:
			stopAck()
			s.paused = false
		case <-tick.C:
			stopAck()
			if err := s.sendHealth(false); err != nil {
				return up(), err
			}
		}
	}
}

// receive decodes every control message strictly before it is handed
// over; the first failure ends the receive side.
func (s *session) receive(ctx context.Context, out chan<- recvd) {
	for {
		var f rawFrame
		if err := s.cs.RecvMsg(&f); err != nil {
			s.deliver(ctx, out, recvd{err: streamError(err, s.cs)})
			return
		}
		m, err := DecodeControl(f.b)
		if err != nil {
			// Reported with the length only (§4.5, R15), never the bytes.
			s.deliver(ctx, out, recvd{err: fmt.Errorf("%w (%d bytes)", err, len(f.b))})
			return
		}
		if !s.deliver(ctx, out, recvd{m: m}) {
			return
		}
	}
}

func (s *session) deliver(ctx context.Context, out chan<- recvd, r recvd) bool {
	select {
	case out <- r:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *session) awaitWelcome(ctx context.Context, in <-chan recvd) error {
	// The control plane answers Hello at once (R9); a peer that never does
	// must not hold the agent forever, so the wait is bounded like an
	// acknowledgement.
	t := time.NewTimer(s.c.t.AckTimeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return fmt.Errorf("%w: no Welcome", ErrAckTimeout)
	case r := <-in:
		if r.err != nil {
			return r.err
		}
		if r.m.GetWelcome() == nil {
			return fmt.Errorf("%w: first control message is not Welcome", ErrProtocol)
		}
		return nil
	}
}

func (s *session) sendHello() error {
	cfg := s.c.cfg
	avail := cfg.ExecutorAvailable != nil && cfg.ExecutorAvailable()
	return s.send(&agentapiv1.AgentMessage{Body: &agentapiv1.AgentMessage_Hello{Hello: &agentapiv1.Hello{
		ContractVersionMin: ContractVersion,
		ContractVersionMax: ContractVersion,
		ServerId:           cfg.ServerID,
		InstanceId:         cfg.InstanceID,
		AgentVersion:       cfg.AgentVersion,
		ExecutorAvailable:  avail,
	}}})
}

// sendHealth sends a HealthReport when forced (after Welcome), when its
// conditions changed, or when HEALTH_INTERVAL passed; never twice within
// HealthMinGap (R39). Changes inside the gap go out on a later tick.
func (s *session) sendHealth(force bool) error {
	cfg := s.c.cfg
	h := BuildHealth(HealthInput{
		Now:               cfg.Now(),
		ExecutorAvailable: cfg.ExecutorAvailable != nil && cfg.ExecutorAvailable(),
		Outbox:            cfg.Outbox.Stats(),
		CAFileSHA256:      cfg.CAFileSHA256,
	})
	since := time.Since(s.lastHealth)
	changed := !slices.Equal(h.GetConditions(), s.lastConds)
	if !force && (since < s.c.t.HealthMinGap || (!changed && since < s.c.t.HealthInterval)) {
		return nil
	}
	if err := s.send(&agentapiv1.AgentMessage{Body: &agentapiv1.AgentMessage_Health{Health: h}}); err != nil {
		return err
	}
	s.lastHealth, s.lastConds = time.Now(), h.GetConditions()
	return nil
}

// fill sends outbox messages in message_seq order while fewer than
// OUTBOX_WINDOW are in flight (R31) and no RETRY_LATER backoff runs.
func (s *session) fill() error {
	for !s.paused && len(s.inflight) < outbox.Window {
		m, ok, err := s.c.cfg.Outbox.Next()
		if err != nil {
			return fmt.Errorf("controlplane: outbox: %w", err)
		}
		if !ok {
			return nil
		}
		if err := s.sendRaw(outboxFrame(m.Bytes)); err != nil {
			return err
		}
		s.inflight[m.Seq] = time.Now()
	}
	return nil
}

// ackDeadline returns a channel that fires MESSAGE_ACK_TIMEOUT after the
// oldest message in flight was sent (nil when none is), and its stop.
func (s *session) ackDeadline() (<-chan time.Time, func()) {
	if len(s.inflight) == 0 {
		return nil, func() {}
	}
	var oldest time.Time
	for _, t := range s.inflight {
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	t := time.NewTimer(max(time.Until(oldest.Add(s.c.t.AckTimeout)), 0))
	return t.C, func() { t.Stop() }
}

func (s *session) handle(m *agentapiv1.ControlMessage) error {
	switch {
	case m.GetWelcome() != nil:
		return fmt.Errorf("%w: second Welcome", ErrProtocol)
	case m.GetDelivery() != nil:
		id := m.GetDelivery().GetDeliveryId()
		if id <= s.lastDelivery {
			return fmt.Errorf("%w: delivery_id not increasing", ErrProtocol)
		}
		s.lastDelivery = id
		// M1 forwards nothing to the executor yet, so nothing is
		// acknowledged (R21: only after forwarding); the control plane
		// sends the delivery again.
		s.deliveries++
		return nil
	}
	return s.ack(m.GetMessageAck())
}

func (s *session) ack(a *agentapiv1.MessageAck) error {
	seq := a.GetMessageSeq()
	if _, ok := s.inflight[seq]; !ok {
		return fmt.Errorf("%w: acknowledgement for message_seq %d not in flight", ErrProtocol, seq)
	}
	if err := s.c.cfg.Outbox.Ack(seq, a.GetOutcome(), a.GetReason()); err != nil {
		return fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	delete(s.inflight, seq)
	switch a.GetOutcome() {
	case agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED:
		s.retryN = 0
	case agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER:
		// ORDER means "an earlier message is waiting": it is re-sent at once
		// after that message's retry, so it starts no backoff of its own
		// while one runs. An ORDER with no earlier retry pending is
		// treated as a plain RETRY_LATER, so no answer can make the agent
		// re-send without waiting.
		if a.GetReason() == agentapiv1.AckReason_ACK_REASON_ORDER && s.paused {
			return nil
		}
		s.retryN++
		wait := min(s.c.clock.Jitter(doubling(s.c.t.RetryLaterFirst, s.c.t.RetryLaterCap, s.retryN)), s.c.t.RetryLaterCap)
		if s.resume == nil {
			s.resume = time.NewTimer(wait)
		} else {
			s.resume.Reset(wait)
		}
		s.paused = true
	}
	return nil
}

func (s *session) send(m *agentapiv1.AgentMessage) error {
	b, err := marshalAgent(m)
	if err != nil {
		return fmt.Errorf("controlplane: encode: %w", err)
	}
	return s.sendRaw(b)
}

func (s *session) sendRaw(b []byte) error {
	if len(b) > s.l.send {
		return fmt.Errorf("controlplane: message of %d bytes over the send limit", len(b))
	}
	if err := s.cs.SendMsg(&rawFrame{b: b}); err != nil {
		if errors.Is(err, io.EOF) {
			// The stream ended; the real status comes from RecvMsg.
			var f rawFrame
			return streamError(s.cs.RecvMsg(&f), s.cs)
		}
		return streamError(err, s.cs)
	}
	return nil
}

// streamError reduces the error that ended a stream to a StatusError
// (R45). A RESOURCE_EXHAUSTED after response headers is the agent's own
// receive limit on an oversized control message (§4.2), so it is a
// refused control message, not the control plane's library answer.
func streamError(err error, cs grpc.ClientStream) error {
	if err == nil || errors.Is(err, io.EOF) {
		// A stream closed with OK carries no §4.8 code: the unknown-code row.
		return &StatusError{Code: codes.OK}
	}
	st := status.Convert(err)
	if st.Code() == codes.ResourceExhausted && cs != nil {
		if h, herr := cs.Header(); herr == nil && len(h) > 0 {
			return fmt.Errorf("%w: over the size limit", ErrControlRefused)
		}
	}
	reason, _ := ParseEndDetail(st)
	return &StatusError{Code: st.Code(), Reason: reason, HasDetail: len(st.Proto().GetDetails()) > 0}
}
