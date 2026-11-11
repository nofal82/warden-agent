package controlplane_test

// Attack and failure tests for the agent's Connect stream (issue #42;
// agent-api R2, R3, R5, R9, R10, R12, §4.5, R31–R33, R39, R45, R46, §4.4,
// §4.8, §4.9). The fake control plane is an in-process gRPC server over
// bufconn with mutual TLS and a raw codec, so it can send any bytes and
// sees every byte the agent sends. No socket is opened.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

const (
	streamServerID   = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	streamInstanceID = "0123456789abcdef0123456789abcdef"
	streamVersion    = "0.1.0-m1"
)

// --- PKI -------------------------------------------------------------------

type streamPKI struct {
	cp, agentCA testCA
	server      tls.Certificate
	client      tls.Certificate
}

func newStreamPKI(t *testing.T) streamPKI {
	t.Helper()
	p := streamPKI{cp: newCA(t, "control-plane CA"), agentCA: newCA(t, "agent CA")}
	p.server = p.cp.leaf(t, goodLeafOpts())
	key := newKey(t)
	u, err := url.Parse("urn:uuid:" + streamServerID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: streamServerID},
		URIs:                  []*url.URL{u},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.agentCA.cert, &key.PublicKey, p.agentCA.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p.client = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return p
}

// --- fake control plane ---------------------------------------------------

// session is one Connect stream as the server sees it.
type session struct {
	ss     grpc.ServerStream
	method string
	in     chan []byte // every frame the agent sent; closed when the stream ends

	mu     sync.Mutex
	frames [][]byte
}

var errNoFrame = errors.New("no frame")

// next returns the next frame, or errNoFrame after d or when closed.
func (s *session) next(d time.Duration) ([]byte, error) {
	select {
	case b, ok := <-s.in:
		if !ok {
			return nil, errNoFrame
		}
		return b, nil
	case <-time.After(d):
		return nil, errNoFrame
	}
}

// nextOutbox skips HealthReports and returns the next outbox frame.
func (s *session) nextOutbox(d time.Duration) (*agentapiv1.OutboxMessage, []byte, error) {
	deadline := time.Now().Add(d)
	for {
		b, err := s.next(time.Until(deadline))
		if err != nil {
			return nil, nil, err
		}
		m := decodeAgent(b)
		if m == nil {
			return nil, b, errors.New("agent sent undecodable bytes")
		}
		if o := m.GetOutbox(); o != nil {
			return o, b, nil
		}
		if m.GetHealth() == nil {
			return nil, b, fmt.Errorf("unexpected agent message %T", m.GetBody())
		}
	}
}

// waitEnd waits for the agent to end the stream.
func (s *session) waitEnd(d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case _, ok := <-s.in:
			if !ok {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func (s *session) send(b []byte) error { return s.ss.SendMsg(&frame{b: b}) }

func (s *session) all() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.frames...)
}

type streamServer struct {
	lis   *bufconn.Listener
	dials atomic.Int32

	mu       sync.Mutex
	sessions []*session
}

// startStream runs a mutual-TLS gRPC server whose every stream is handled
// by script. A script error ends the stream with that status.
func startStream(t *testing.T, p streamPKI, script func(s *session) error) *streamServer {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(p.agentCA.cert)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{p.server},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	srv := &streamServer{lis: bufconn.Listen(1 << 20)}
	g := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(cfg)),
		grpc.ForceServerCodecV2(rawCodec{}),
		grpc.MaxRecvMsgSize(1<<20),
		grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
			s := &session{ss: ss, in: make(chan []byte, 4096)}
			s.method, _ = grpc.MethodFromServerStream(ss)
			srv.mu.Lock()
			srv.sessions = append(srv.sessions, s)
			srv.mu.Unlock()
			go func() {
				defer close(s.in)
				for {
					var f frame
					if err := ss.RecvMsg(&f); err != nil {
						return
					}
					s.mu.Lock()
					s.frames = append(s.frames, f.b)
					s.mu.Unlock()
					s.in <- f.b
				}
			}()
			return script(s)
		}),
	)
	go func() { _ = g.Serve(srv.lis) }()
	t.Cleanup(func() {
		g.Stop()
		_ = srv.lis.Close()
	})
	return srv
}

func (srv *streamServer) dialer(ctx context.Context, _ string) (net.Conn, error) {
	srv.dials.Add(1)
	return srv.lis.DialContext(ctx)
}

func (srv *streamServer) list() []*session {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return append([]*session(nil), srv.sessions...)
}

// --- messages --------------------------------------------------------------

func decodeAgent(b []byte) *agentapiv1.AgentMessage {
	m := &agentapiv1.AgentMessage{}
	if proto.Unmarshal(b, m) != nil {
		return nil
	}
	return m
}

func ctl(t testing.TB, m *agentapiv1.ControlMessage) []byte { return marshalDet(t, m) }

func welcome(t testing.TB, version uint32, ms int64) []byte {
	return ctl(t, &agentapiv1.ControlMessage{Body: &agentapiv1.ControlMessage_Welcome{
		Welcome: &agentapiv1.Welcome{ContractVersion: version, ControlPlaneTimeMs: ms}}})
}

func goodWelcome(t testing.TB) []byte { return welcome(t, 1, testNow.UnixMilli()) }

func ack(t testing.TB, seq uint64, o agentapiv1.AckOutcome, r agentapiv1.AckReason) []byte {
	return ctl(t, &agentapiv1.ControlMessage{Body: &agentapiv1.ControlMessage_MessageAck{
		MessageAck: &agentapiv1.MessageAck{MessageSeq: seq, Outcome: o, Reason: r}}})
}

func statusDelivery(t testing.TB, id uint64, challenge []byte) []byte {
	return ctl(t, &agentapiv1.ControlMessage{Body: &agentapiv1.ControlMessage_Delivery{Delivery: &agentapiv1.Delivery{
		DeliveryId: id,
		Content: &agentapiv1.DeliveryContent{Content: &agentapiv1.DeliveryContent_StatusRequest{
			StatusRequest: &agentapiv1.StatusRequest{Challenge: challenge}}},
	}}})
}

// endStatus ends a stream with code and the given details.
func endStatus(code codes.Code, details ...*anypb.Any) error {
	return status.FromProto(&spb.Status{Code: int32(code), Message: "test end", Details: details}).Err()
}

func endDetail(t testing.TB, r agentapiv1.EndReason) *anypb.Any {
	t.Helper()
	a, err := anypb.New(&agentapiv1.EndDetail{Reason: r})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// --- fake outbox -----------------------------------------------------------

type ackCall struct {
	seq     uint64
	outcome agentapiv1.AckOutcome
	reason  agentapiv1.AckReason
}

// fakeOutbox follows outbox.Outbox's documented semantics: Next stops at
// Window in flight, RETRY_LATER makes the message the next one, Rewind
// forgets what is in flight.
type fakeOutbox struct {
	mu       sync.Mutex
	queue    []outbox.Message
	inflight map[uint64]bool
	cursor   int
	acks     []ackCall
	rewinds  int
	rechecks int
	nexts    int
	stats    outbox.Stats
}

var _ controlplane.Outbox = (*fakeOutbox)(nil)

func newFakeOutbox(t testing.TB, n int) *fakeOutbox {
	o := &fakeOutbox{inflight: map[uint64]bool{}}
	for i := 1; i <= n; i++ {
		b := marshalDet(t, &agentapiv1.OutboxMessage{
			MessageSeq: uint64(i), // #nosec G115 -- small positive test counter
			Payload: &agentapiv1.OutboxPayload{Payload: &agentapiv1.OutboxPayload_RecoveryReport{
				RecoveryReport: &agentapiv1.RecoveryReport{RecoveryId: bytes.Repeat([]byte{byte(i)}, 24)}}},
		})
		o.queue = append(o.queue, outbox.Message{Seq: uint64(i), Bytes: b}) // #nosec G115 -- small positive test counter
	}
	return o
}

func (o *fakeOutbox) Next() (outbox.Message, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.nexts++
	if len(o.inflight) >= outbox.Window || o.cursor >= len(o.queue) {
		return outbox.Message{}, false, nil
	}
	m := o.queue[o.cursor]
	o.cursor++
	o.inflight[m.Seq] = true
	return outbox.Message{Seq: m.Seq, Bytes: append([]byte(nil), m.Bytes...)}, true, nil
}

func (o *fakeOutbox) Ack(seq uint64, outcome agentapiv1.AckOutcome, reason agentapiv1.AckReason) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.acks = append(o.acks, ackCall{seq, outcome, reason})
	idx := -1
	for i, m := range o.queue {
		if m.Seq == seq {
			idx = i
		}
	}
	if idx < 0 {
		return errors.New("fake outbox: unknown seq")
	}
	delete(o.inflight, seq)
	if outcome == agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER {
		for _, m := range o.queue[idx:] {
			delete(o.inflight, m.Seq)
		}
		o.cursor = idx
		return nil
	}
	o.queue = append(o.queue[:idx], o.queue[idx+1:]...)
	if idx < o.cursor {
		o.cursor--
	}
	return nil
}

func (o *fakeOutbox) Rewind() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rewinds++
	o.inflight = map[uint64]bool{}
	o.cursor = 0
}

func (o *fakeOutbox) Recheck() (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rechecks++
	return 0, nil
}

func (o *fakeOutbox) Stats() outbox.Stats {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.stats
}

func (o *fakeOutbox) snapshot() (acks []ackCall, rewinds, rechecks int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]ackCall(nil), o.acks...), o.rewinds, o.rechecks
}

// --- client ----------------------------------------------------------------

func streamCfg(p streamPKI, ob controlplane.Outbox) controlplane.StreamConfig {
	sum := sha256.Sum256(p.cp.cert.Raw)
	return controlplane.StreamConfig{
		Endpoint:          testEndpoint,
		ServerName:        testServerName,
		Trust:             func(time.Time) ([]*x509.Certificate, error) { return []*x509.Certificate{p.cp.cert}, nil },
		Identity:          p.client,
		ServerID:          streamServerID,
		InstanceID:        streamInstanceID,
		AgentVersion:      streamVersion,
		ExecutorAvailable: func() bool { return true },
		CAFileSHA256:      [][]byte{sum[:]},
		Outbox:            ob,
		Now:               fixedNow,
	}
}

func newConnect(t *testing.T, cfg controlplane.StreamConfig, srv *streamServer, tune func(*controlplane.Timings)) *controlplane.ConnectClient {
	t.Helper()
	c, err := controlplane.NewConnectClient(cfg)
	if err != nil {
		t.Fatalf("NewConnectClient: %v", err)
	}
	controlplane.SetConnectDialer(c, srv.dialer)
	tm := controlplane.DefaultTimings
	if tune != nil {
		tune(&tm)
	}
	controlplane.SetStreamTimings(c, tm)
	return c
}

// =========================================================================

func TestNewConnectClientRefuses(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	cases := []struct {
		name   string
		mutate func(c *controlplane.StreamConfig)
		ok     bool
	}{
		{"valid", func(*controlplane.StreamConfig) {}, true},
		{"unix endpoint", func(c *controlplane.StreamConfig) { c.Endpoint = "unix:///run/warden-agent/x.sock" }, false},
		{"nil Trust", func(c *controlplane.StreamConfig) { c.Trust = nil }, false},
		{"instance ID 31 chars", func(c *controlplane.StreamConfig) { c.InstanceID = streamInstanceID[:31] }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := streamCfg(p, newFakeOutbox(t, 0))
			tc.mutate(&cfg)
			c, err := controlplane.NewConnectClient(cfg)
			if tc.ok {
				if err != nil || c == nil {
					t.Fatalf("NewConnectClient = %v, %v; want a client", c, err)
				}
				return
			}
			if !errors.Is(err, controlplane.ErrStreamConfig) || c != nil {
				t.Fatalf("NewConnectClient = %v, %v; want ErrStreamConfig", c, err)
			}
		})
	}
}

// R37: no connection without a trusted CA set, and the reconnect loop
// still waits between refusals instead of spinning.
func TestConnectTrustRefusedNeverDials(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	srv := startStream(t, p, func(*session) error { return nil })
	cfg := streamCfg(p, newFakeOutbox(t, 1))
	cfg.Trust = func(time.Time) ([]*x509.Certificate, error) { return nil, errors.New("FAKE trust refusal") }
	c := newConnect(t, cfg, srv, nil)
	if _, err := c.RunOnce(shortCtx(t, 5*time.Second)); err == nil {
		t.Fatal("RunOnce = nil with a refused trust check")
	}

	cfg.Trust = func(time.Time) ([]*x509.Certificate, error) { return nil, nil } // empty set
	c = newConnect(t, cfg, srv, nil)
	clk := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clk.onSleep = func(context.Context) error {
		if len(clk.sleeps) >= 3 {
			cancel()
		}
		return nil
	}
	controlplane.SetConnectClock(c, clk)
	controlplane.SetConnectUniform(c, func(time.Duration) time.Duration { return time.Second })
	if err := c.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if srv.dials.Load() != 0 {
		t.Fatalf("dialled %d times without a trusted CA set", srv.dials.Load())
	}
	for _, d := range clk.sleeps {
		if d <= 0 {
			t.Fatalf("sleeps = %v: a zero wait is a spin", clk.sleeps)
		}
	}
}

// R9, R10, R31: Hello first and alone until Welcome; then outbox messages
// in order, byte for byte, at most OUTBOX_WINDOW unacknowledged.
func TestConnectHelloThenWindowOfEight(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	ob := newFakeOutbox(t, 10)
	stored := make(map[uint64][]byte)
	for _, m := range ob.queue {
		stored[m.Seq] = m.Bytes
	}
	var welcomes atomic.Int32
	var mu sync.Mutex
	var beforeWelcome []byte
	welcomedEarly := int32(-1)
	srv := startStream(t, p, func(s *session) error {
		if _, err := s.next(5 * time.Second); err != nil {
			return err
		}
		// Nothing but Hello may arrive before Welcome.
		b, err := s.next(300 * time.Millisecond)
		mu.Lock()
		if err == nil {
			beforeWelcome = b
		}
		welcomedEarly = welcomes.Load()
		mu.Unlock()
		if err := s.send(goodWelcome(t)); err != nil {
			return err
		}
		for i := 0; i < outbox.Window; i++ {
			if _, _, err := s.nextOutbox(5 * time.Second); err != nil {
				return err
			}
		}
		// Acks withheld: a ninth message is a window violation.
		if _, b, err := s.nextOutbox(500 * time.Millisecond); err == nil {
			return fmt.Errorf("ninth unacknowledged message sent: %x", b)
		}
		return nil
	})
	cfg := streamCfg(p, ob)
	cfg.OnWelcome = func() { welcomes.Add(1) }
	c := newConnect(t, cfg, srv, nil)
	_, _ = c.RunOnce(shortCtx(t, 10*time.Second))

	ss := srv.list()
	if len(ss) != 1 || ss[0].method != agentapiv1.AgentControl_Connect_FullMethodName {
		t.Fatalf("streams = %d", len(ss))
	}
	mu.Lock()
	if beforeWelcome != nil {
		t.Errorf("agent sent %x before Welcome", beforeWelcome)
	}
	if welcomedEarly != 0 || welcomes.Load() != 1 {
		t.Errorf("OnWelcome before Welcome = %d, total = %d; want 0, 1", welcomedEarly, welcomes.Load())
	}
	mu.Unlock()
	frames := ss[0].all()
	if len(frames) == 0 {
		t.Fatal("no frames")
	}
	h := decodeAgent(frames[0]).GetHello()
	if h == nil || h.GetContractVersionMin() != 1 || h.GetContractVersionMax() != 1 ||
		h.GetServerId() != streamServerID || h.GetInstanceId() != streamInstanceID ||
		h.GetAgentVersion() != streamVersion || !h.GetExecutorAvailable() {
		t.Fatalf("first message = %v, want the Hello", h)
	}
	var seqs []uint64
	for _, b := range frames[1:] {
		m := decodeAgent(b)
		if m.GetHealth() != nil {
			if bytes.Contains(b, []byte(streamInstanceID)) {
				t.Errorf("HealthReport carries the instance ID")
			}
			continue
		}
		o := m.GetOutbox()
		if o == nil {
			t.Fatalf("unexpected message %v", m)
		}
		seq := o.GetMessageSeq()
		want := protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), stored[seq])
		if !bytes.Equal(b, want) {
			t.Errorf("seq %d: wire bytes are not field 3 with the stored bytes unchanged", seq)
		}
		seqs = append(seqs, seq)
	}
	if fmt.Sprint(seqs) != "[1 2 3 4 5 6 7 8]" {
		t.Fatalf("outbox seqs on the wire = %v, want 1..8", seqs)
	}
}

// §4.5, R9: a Welcome that fails a check, or anything but a Welcome
// first, ends the stream before any outbox message is sent.
func TestConnectRefusesBadWelcome(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	cases := []struct {
		name string
		send func(t testing.TB) []byte
	}{
		{"contract_version 2", func(t testing.TB) []byte { return welcome(t, 2, testNow.UnixMilli()) }},
		{"MessageAck first", func(t testing.TB) []byte {
			return ack(t, 1, agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED, 0)
		}},
		{"oversize ControlMessage", func(t testing.TB) []byte {
			return ctl(t, &agentapiv1.ControlMessage{Body: &agentapiv1.ControlMessage_Delivery{Delivery: &agentapiv1.Delivery{
				DeliveryId: 1,
				Content: &agentapiv1.DeliveryContent{Content: &agentapiv1.DeliveryContent_Envelope{
					Envelope: &agentapiv1.EnvelopeDelivery{SignedEnvelope: make([]byte, 266241)}}},
			}}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ob := newFakeOutbox(t, 1)
			var welcomes atomic.Int32
			srv := startStream(t, p, func(s *session) error {
				if _, err := s.next(5 * time.Second); err != nil {
					return err
				}
				if err := s.send(tc.send(t)); err != nil {
					return err
				}
				s.waitEnd(5 * time.Second)
				return nil
			})
			cfg := streamCfg(p, ob)
			cfg.OnWelcome = func() { welcomes.Add(1) }
			c := newConnect(t, cfg, srv, nil)
			up, err := c.RunOnce(shortCtx(t, 10*time.Second))
			if !errors.Is(err, controlplane.ErrControlRefused) && !errors.Is(err, controlplane.ErrProtocol) {
				t.Fatalf("RunOnce = %v, want ErrControlRefused or ErrProtocol", err)
			}
			if up != 0 || welcomes.Load() != 0 {
				t.Errorf("up = %v, OnWelcome = %d after a refused Welcome", up, welcomes.Load())
			}
			acks, _, _ := ob.snapshot()
			if len(acks) != 0 {
				t.Errorf("Outbox.Ack called: %v", acks)
			}
			for _, ss := range srv.list() {
				if n := len(ss.all()); n != 1 {
					t.Errorf("agent sent %d messages, want only the Hello", n)
				}
			}
		})
	}
}

func TestDecodeControl(t *testing.T) {
	t.Parallel()
	const (
		accepted  = agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED
		inboxFull = agentapiv1.AckReason_ACK_REASON_INBOX_FULL
	)
	cases := []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"valid MessageAck", ack(t, 1, accepted, 0), true},
		{"MessageAck seq 0", ack(t, 0, accepted, 0), false},
		{"outcome 99", ack(t, 1, 99, 0), false},
		{"ACCEPTED with a reason", ack(t, 1, accepted, inboxFull), false},
		{"StatusRequest challenge 31 bytes", statusDelivery(t, 1, make([]byte, 31)), false},
		{"empty ControlMessage", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := controlplane.DecodeControl(tc.b)
			if tc.ok {
				if err != nil || m == nil || m.GetBody() == nil {
					t.Fatalf("DecodeControl = %v, %v; want accepted", m, err)
				}
				return
			}
			if !errors.Is(err, controlplane.ErrControlRefused) || m != nil {
				t.Fatalf("DecodeControl = %v, %v; want ErrControlRefused", m, err)
			}
		})
	}
}

func FuzzDecodeControl(f *testing.F) {
	f.Add(goodWelcome(f))
	f.Add(welcome(f, 2, 1))
	f.Add(welcome(f, 1, 0))
	f.Add(ack(f, 1, agentapiv1.AckOutcome_ACK_OUTCOME_REJECTED, agentapiv1.AckReason_ACK_REASON_INBOX_FULL))
	f.Add(ack(f, 1, agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED, 99))
	f.Add(statusDelivery(f, 1, make([]byte, 32)))
	f.Add(statusDelivery(f, 0, make([]byte, 33)))
	f.Add(append(goodWelcome(f), goodWelcome(f)...)) // duplicated member
	f.Add([]byte{0x0a, 0x00, 0xf8, 0x01, 0x01})      // empty Welcome and unknown field 31
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		orig := append([]byte(nil), in...)
		m, err := controlplane.DecodeControl(in)
		if !bytes.Equal(in, orig) {
			t.Fatal("DecodeControl modified its input")
		}
		if err != nil {
			if m != nil || !errors.Is(err, controlplane.ErrControlRefused) {
				t.Fatalf("refusal = %v, %v", m, err)
			}
			return
		}
		if len(in) > 266240 || m == nil || m.GetBody() == nil {
			t.Fatalf("accepted %d bytes without exactly one member", len(in))
		}
		if a := m.GetMessageAck(); a != nil && a.GetMessageSeq() == 0 {
			t.Fatal("accepted message_seq 0")
		}
		if w := m.GetWelcome(); w != nil && (w.GetContractVersion() != 1 || w.GetControlPlaneTimeMs() <= 0) {
			t.Fatalf("accepted Welcome %v", w)
		}
	})
}

// R32: the outcome is passed to the outbox; an ack for a message not in
// flight ends the stream and touches nothing.
func TestConnectAckNotInFlight(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	ob := newFakeOutbox(t, 1)
	srv := startStream(t, p, func(s *session) error {
		if _, err := s.next(5 * time.Second); err != nil {
			return err
		}
		if err := s.send(goodWelcome(t)); err != nil {
			return err
		}
		if _, _, err := s.nextOutbox(5 * time.Second); err != nil {
			return err
		}
		if err := s.send(ack(t, 1, agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED, 0)); err != nil {
			return err
		}
		if err := s.send(ack(t, 999, agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED, 0)); err != nil {
			return err
		}
		s.waitEnd(5 * time.Second)
		return nil
	})
	c := newConnect(t, streamCfg(p, ob), srv, nil)
	if _, err := c.RunOnce(shortCtx(t, 10*time.Second)); !errors.Is(err, controlplane.ErrProtocol) {
		t.Fatalf("RunOnce = %v, want ErrProtocol", err)
	}
	acks, _, _ := ob.snapshot()
	if len(acks) != 1 || acks[0] != (ackCall{1, agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED, 0}) {
		t.Fatalf("Outbox.Ack calls = %v, want only seq 1 ACCEPTED", acks)
	}
}

// §4.9 backoff tables.
func TestBackoffDelays(t *testing.T) {
	t.Parallel()
	for n, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 7: 60 * time.Second, 1 << 20: 60 * time.Second} {
		if got := controlplane.RetryLaterDelay(n); got != want {
			t.Errorf("RetryLaterDelay(%d) = %v, want %v", n, got, want)
		}
	}
	for n, want := range map[int]time.Duration{2: 2 * time.Second, 3: 4 * time.Second, 9: 256 * time.Second, 10: 300 * time.Second, 1 << 20: 300 * time.Second} {
		if got := controlplane.ReconnectDelay(n); got != want {
			t.Errorf("ReconnectDelay(%d) = %v, want %v", n, got, want)
		}
	}
}

// R32, §4.9: a control plane that answers every message RETRY_LATER at
// once must not make the agent spin.
func TestConnectRetryLaterDoesNotSpin(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	ob := newFakeOutbox(t, 1)
	var sent atomic.Int32
	srv := startStream(t, p, func(s *session) error {
		if _, err := s.next(5 * time.Second); err != nil {
			return err
		}
		if err := s.send(goodWelcome(t)); err != nil {
			return err
		}
		end := time.Now().Add(time.Second)
		for time.Now().Before(end) {
			o, _, err := s.nextOutbox(time.Until(end))
			if err != nil {
				break
			}
			sent.Add(1)
			if err := s.send(ack(t, o.GetMessageSeq(), agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER,
				agentapiv1.AckReason_ACK_REASON_RATE_LIMITED)); err != nil {
				return err
			}
		}
		return nil
	})
	c := newConnect(t, streamCfg(p, ob), srv, func(tm *controlplane.Timings) {
		tm.RetryLaterFirst, tm.RetryLaterCap = 100*time.Millisecond, 400*time.Millisecond
	})
	_, _ = c.RunOnce(shortCtx(t, 10*time.Second))
	if n := sent.Load(); n < 2 || n > 6 {
		t.Fatalf("server received %d copies in 1 s, want 2..6 (re-sent, after backoff)", n)
	}
	acks, _, _ := ob.snapshot()
	if len(acks) == 0 || acks[0].outcome != agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER {
		t.Fatalf("Outbox.Ack calls = %v, want RETRY_LATER passed on", acks)
	}
}

// R32: no ack within MESSAGE_ACK_TIMEOUT ends the stream; the next stream
// re-sends from the oldest unacknowledged message.
func TestConnectAckTimeoutRewinds(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	ob := newFakeOutbox(t, 2)
	srv := startStream(t, p, func(s *session) error {
		if _, err := s.next(5 * time.Second); err != nil {
			return err
		}
		if err := s.send(goodWelcome(t)); err != nil {
			return err
		}
		s.waitEnd(5 * time.Second)
		return nil
	})
	c := newConnect(t, streamCfg(p, ob), srv, func(tm *controlplane.Timings) { tm.AckTimeout = 200 * time.Millisecond })
	for i := 0; i < 2; i++ {
		start := time.Now()
		if _, err := c.RunOnce(shortCtx(t, 10*time.Second)); !errors.Is(err, controlplane.ErrAckTimeout) {
			t.Fatalf("RunOnce %d = %v, want ErrAckTimeout", i, err)
		}
		if time.Since(start) > 4*time.Second {
			t.Fatalf("ack timeout took %v", time.Since(start))
		}
	}
	if _, rewinds, _ := ob.snapshot(); rewinds < 2 {
		t.Fatalf("Rewind called %d times, want once per stream", rewinds)
	}
	ss := srv.list()
	if len(ss) != 2 {
		t.Fatalf("streams = %d", len(ss))
	}
	for i, s := range ss {
		var first uint64
		for _, b := range s.all() {
			if o := decodeAgent(b).GetOutbox(); o != nil {
				first = o.GetMessageSeq()
				break
			}
		}
		if first != 1 {
			t.Errorf("stream %d first outbox seq = %d, want 1", i, first)
		}
	}
}

// R39–R41, §4.4.
func TestBuildHealth(t *testing.T) {
	t.Parallel()
	a, b := bytes.Repeat([]byte{0xbb}, 32), bytes.Repeat([]byte{0xaa}, 32)
	h := controlplane.BuildHealth(controlplane.HealthInput{
		Now:               testNow,
		ExecutorAvailable: false,
		Outbox:            outbox.Stats{Messages: 3, Bytes: 4096, Rejected: 2, Condition: outbox.ConditionFull},
		CAFileSHA256:      [][]byte{a, b},
	})
	if h == nil {
		t.Fatal("BuildHealth = nil")
	}
	want := []agentapiv1.AgentCondition{
		agentapiv1.AgentCondition_AGENT_CONDITION_EXECUTOR_UNAVAILABLE,
		agentapiv1.AgentCondition_AGENT_CONDITION_OUTBOX_FULL,
	}
	if fmt.Sprint(h.GetConditions()) != fmt.Sprint(want) {
		t.Errorf("conditions = %v, want %v", h.GetConditions(), want)
	}
	if h.GetOutboxMessages() != 3 || h.GetOutboxBytes() != 4096 || h.GetRejectedMessages() != 2 {
		t.Errorf("outbox figures = %d %d %d", h.GetOutboxMessages(), h.GetOutboxBytes(), h.GetRejectedMessages())
	}
	if h.GetAgentTimeMs() != testNow.UnixMilli() || h.GetRedactRulesVersion() < 1 {
		t.Errorf("agent_time_ms = %d, redact_rules_version = %d", h.GetAgentTimeMs(), h.GetRedactRulesVersion())
	}
	cas := h.GetControlplaneCaSha256()
	if len(cas) != 2 || !bytes.Equal(cas[0], b) || !bytes.Equal(cas[1], a) {
		t.Errorf("controlplane_ca_sha256 not the two hashes sorted")
	}
	if n := len(marshalDet(t, h)); n > 1024 {
		t.Errorf("HealthReport is %d bytes, over 1024", n)
	}

	h = controlplane.BuildHealth(controlplane.HealthInput{
		Now: testNow, ExecutorAvailable: true, Outbox: outbox.Stats{Condition: outbox.ConditionHighWater},
	})
	if fmt.Sprint(h.GetConditions()) != fmt.Sprint([]agentapiv1.AgentCondition{agentapiv1.AgentCondition_AGENT_CONDITION_OUTBOX_HIGH_WATER}) {
		t.Errorf("conditions = %v, want only OUTBOX_HIGH_WATER", h.GetConditions())
	}
}

// R45, §4.8: only a well-formed EndDetail under its paired code is
// trusted; anything else falls back to the code's own row.
func TestEndActionOf(t *testing.T) {
	t.Parallel()
	revoked := endDetail(t, agentapiv1.EndReason_END_REASON_CERTIFICATE_REVOKED)
	unreadable := endDetail(t, agentapiv1.EndReason_END_REASON_MESSAGE_SEQ_UNREADABLE)
	cases := []struct {
		name string
		err  error
		want controlplane.EndAction
	}{
		{"UNAUTHENTICATED + CERTIFICATE_REVOKED", endStatus(codes.Unauthenticated, revoked), controlplane.EndCertRefused},
		{"INVALID_ARGUMENT + MESSAGE_SEQ_UNREADABLE", endStatus(codes.InvalidArgument, unreadable), controlplane.EndRecheckOutbox},
		{"unknown code DataLoss", endStatus(codes.DataLoss), controlplane.EndReconnectLongest},
		{"CERTIFICATE_REVOKED under UNAVAILABLE", endStatus(codes.Unavailable, revoked), controlplane.EndReconnect},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := controlplane.EndActionOf(tc.err); got != tc.want {
				t.Fatalf("EndActionOf = %v, want %v", got, tc.want)
			}
		})
	}
}

// R32a: a stream ended with MESSAGE_SEQ_UNREADABLE makes Run re-check the
// outbox before it reconnects.
func TestRunRechecksOutboxOnSeqUnreadable(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	ob := newFakeOutbox(t, 0)
	srv := startStream(t, p, func(s *session) error {
		if _, err := s.next(5 * time.Second); err != nil {
			return err
		}
		return endStatus(codes.InvalidArgument, endDetail(t, agentapiv1.EndReason_END_REASON_MESSAGE_SEQ_UNREADABLE))
	})
	c := newConnect(t, streamCfg(p, ob), srv, nil)
	clk := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var atSleep = -1
	clk.onSleep = func(context.Context) error {
		_, _, atSleep = ob.snapshot()
		cancel()
		return nil
	}
	controlplane.SetConnectClock(c, clk)
	controlplane.SetConnectUniform(c, func(time.Duration) time.Duration { return time.Second })
	if err := c.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if atSleep != 1 {
		t.Fatalf("Recheck calls before the reconnect wait = %d, want 1", atSleep)
	}
}

// §4.9 reconnect schedule: uniform first wait, then doubling from 2 s with
// jitter; certificate refused waits 300 s every time.
func TestRunReconnectSchedule(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	cases := []struct {
		name   string
		reason agentapiv1.EndReason
		code   codes.Code
		want   []time.Duration
	}{
		{"SHUTTING_DOWN", agentapiv1.EndReason_END_REASON_SHUTTING_DOWN, codes.Unavailable,
			[]time.Duration{7 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}},
		{"CERTIFICATE_REVOKED", agentapiv1.EndReason_END_REASON_CERTIFICATE_REVOKED, codes.Unauthenticated,
			[]time.Duration{300 * time.Second, 300 * time.Second, 300 * time.Second, 300 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := startStream(t, p, func(s *session) error {
				if _, err := s.next(5 * time.Second); err != nil {
					return err
				}
				return endStatus(tc.code, endDetail(t, tc.reason))
			})
			c := newConnect(t, streamCfg(p, newFakeOutbox(t, 0)), srv, nil)
			clk := newFakeClock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clk.onSleep = func(context.Context) error {
				if len(clk.sleeps) >= len(tc.want) {
					cancel()
				}
				return nil
			}
			var uniformMax time.Duration
			controlplane.SetConnectClock(c, clk)
			controlplane.SetConnectUniform(c, func(m time.Duration) time.Duration { uniformMax = m; return 7 * time.Second })
			done := make(chan error, 1)
			go func() { done <- c.Run(ctx) }()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Run = %v, want context.Canceled", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return after cancel")
			}
			if fmt.Sprint(clk.sleeps) != fmt.Sprint(tc.want) {
				t.Fatalf("waits = %v, want %v", clk.sleeps, tc.want)
			}
			if tc.code == codes.Unavailable && (uniformMax != controlplane.ReconnectFirstMax || len(clk.jitters) < 3) {
				t.Errorf("uniform max = %v, jitter calls = %v", uniformMax, clk.jitters)
			}
			if n := srv.dials.Load(); n < int32(len(tc.want)) || n > int32(len(tc.want))+1 {
				t.Errorf("dials = %d for %d waits", n, len(tc.want))
			}
		})
	}
}
