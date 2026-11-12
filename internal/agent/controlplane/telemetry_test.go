package controlplane_test

// Telemetry upload and health fields (issue #44; agent-api R5, R43, R44,
// R46, R47, §4.4, §4.7; redaction §4.6a). The fake control plane is the
// bufconn server of stream_test.go; UploadTelemetry calls arrive as their
// own sessions, so the server sees every batch byte and answers any bytes.

import (
	"bytes"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/agent/telemetry"
	pubredact "github.com/nofal82/warden-agent/redact"
)

// fakeTelemetry follows telemetry.Buffer's documented semantics: Next
// returns the oldest batch until Accepted or Rejected removes it.
type fakeTelemetry struct {
	mu       sync.Mutex
	queue    []uint64
	bodies   map[uint64][]byte
	accepted []uint64
	rejected []uint64
	nexts    int
}

var _ controlplane.TelemetrySource = (*fakeTelemetry)(nil)

func newFakeTelemetry(t testing.TB, n int) *fakeTelemetry {
	f := &fakeTelemetry{bodies: map[uint64][]byte{}}
	for i := 1; i <= n; i++ {
		seq := uint64(i) // #nosec G115 -- small positive test counter
		f.queue = append(f.queue, seq)
		f.bodies[seq] = marshalDet(t, &agentapiv1.TelemetryBatch{
			FormatVersion: 1, ServerId: streamServerID, InstanceId: streamInstanceID, BatchSeq: seq,
			CollectedFromMs: testNow.UnixMilli(), CollectedToMs: testNow.UnixMilli(),
			LogEvents: []*agentapiv1.LogEvent{{RuleId: "nginx-error", UnitId: "nginx.service",
				ObservedAtMs: testNow.UnixMilli(), Count: 1, Extract: "[error] FAKE-SECRET-123 redacted elsewhere"}},
		})
	}
	return f
}

func (f *fakeTelemetry) Next() (uint64, []byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nexts++
	if len(f.queue) == 0 {
		return 0, nil, false
	}
	s := f.queue[0]
	return s, bytes.Clone(f.bodies[s]), true
}

func (f *fakeTelemetry) remove(seq uint64) {
	f.queue = slices.DeleteFunc(f.queue, func(s uint64) bool { return s == seq })
}

func (f *fakeTelemetry) Accepted(seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepted = append(f.accepted, seq)
	f.remove(seq)
}

func (f *fakeTelemetry) Rejected(seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected = append(f.rejected, seq)
	f.remove(seq)
}

func (f *fakeTelemetry) snapshot() (acc, rej []uint64, left int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.accepted), slices.Clone(f.rejected), len(f.queue)
}

func ackBytes(t testing.TB, seq uint64) []byte {
	return marshalDet(t, &agentapiv1.TelemetryAck{BatchSeq: seq})
}

// upload is one UploadTelemetry call as the server saw it.
type upload struct {
	at          time.Time
	body        []byte
	hasDeadline bool
	deadline    time.Duration
}

// answer decides the server's reply to the n-th upload (from 0): bytes to
// send, or an error status.
type answer func(n int, seq uint64) ([]byte, error)

type telemetryServer struct {
	srv       *streamServer
	mu        sync.Mutex
	uploads   []upload
	welcomeAt time.Time
	done      func() bool
}

// startTelemetry serves Connect (Hello, then Welcome after welcomeDelay,
// then hold the stream until done) and UploadTelemetry (reply by ans).
func startTelemetry(t *testing.T, p streamPKI, welcomeDelay time.Duration, ans answer, done func() bool) *telemetryServer {
	t.Helper()
	ts := &telemetryServer{done: done}
	var n atomic.Int32
	ts.srv = startStream(t, p, func(s *session) error {
		switch s.method {
		case agentapiv1.AgentControl_Connect_FullMethodName:
			if _, err := s.next(5 * time.Second); err != nil {
				return err
			}
			time.Sleep(welcomeDelay)
			ts.mu.Lock()
			ts.welcomeAt = time.Now()
			ts.mu.Unlock()
			if err := s.send(goodWelcome(t)); err != nil {
				return err
			}
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) && !ts.done() {
				time.Sleep(20 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond) // let a stray extra upload show
			return nil
		case agentapiv1.AgentControl_UploadTelemetry_FullMethodName:
			b, err := s.next(5 * time.Second)
			if err != nil {
				return err
			}
			u := upload{at: time.Now(), body: b}
			if dl, ok := s.ss.Context().Deadline(); ok {
				u.hasDeadline, u.deadline = true, time.Until(dl)
			}
			ts.mu.Lock()
			ts.uploads = append(ts.uploads, u)
			ts.mu.Unlock()
			var batch agentapiv1.TelemetryBatch
			if err := agentapiv1.StrictUnmarshal(b, &batch); err != nil {
				return endStatus(codes.InvalidArgument)
			}
			reply, err := ans(int(n.Add(1)-1), batch.GetBatchSeq())
			if err != nil {
				return err
			}
			return s.send(reply)
		default:
			return fmt.Errorf("unexpected method %s", s.method)
		}
	})
	return ts
}

func (ts *telemetryServer) snapshot() ([]upload, time.Time) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return slices.Clone(ts.uploads), ts.welcomeAt
}

func runTelemetry(t *testing.T, p streamPKI, ts *telemetryServer, src controlplane.TelemetrySource) {
	t.Helper()
	cfg := streamCfg(p, newFakeOutbox(t, 0))
	if src != nil {
		cfg.Telemetry = src
	}
	c := newConnect(t, cfg, ts.srv, nil)
	controlplane.SetConnectClock(c, newFakeClock())
	_, _ = c.RunOnce(shortCtx(t, 40*time.Second)) // above TelemetryDeadline, so the call deadline is its own
}

// R5, R44, R47: uploads start only after Welcome, on the stream's own
// connection, one batch at a time with a 30 s deadline, bytes unchanged.
func TestUploadTelemetryAfterWelcome(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	src := newFakeTelemetry(t, 3)
	ok := func(_ int, seq uint64) ([]byte, error) { return ackBytes(t, seq), nil }
	ts := startTelemetry(t, p, 400*time.Millisecond, ok, func() bool { _, _, left := src.snapshot(); return left == 0 })
	runTelemetry(t, p, ts, src)

	ups, welcomeAt := ts.snapshot()
	acc, rej, left := src.snapshot()
	if left != 0 || fmt.Sprint(acc) != "[1 2 3]" || len(rej) != 0 {
		t.Fatalf("accepted %v rejected %v left %d; want 1 2 3 accepted", acc, rej, left)
	}
	if len(ups) != 3 {
		t.Errorf("uploads = %d, want 3 (one per batch, none repeated)", len(ups))
	}
	for i, u := range ups {
		if u.at.Before(welcomeAt) {
			t.Errorf("upload %d before Welcome", i)
		}
		if !u.hasDeadline || u.deadline > 30*time.Second || u.deadline < 20*time.Second {
			t.Errorf("upload %d deadline = %v (set %v), want about 30 s", i, u.deadline, u.hasDeadline)
		}
		if seq := uint64(i + 1); !bytes.Equal(u.body, src.bodies[seq]) { // #nosec G115 -- small index
			t.Errorf("upload %d bytes differ from the buffered batch", i)
		}
	}
	if d := ts.srv.dials.Load(); d != 1 {
		t.Errorf("dials = %d; telemetry must share the stream's connection", d)
	}

	// No source: no UploadTelemetry call at all.
	ts2 := startTelemetry(t, p, 0, ok, func() bool { return true })
	runTelemetry(t, p, ts2, nil)
	if ups, _ := ts2.snapshot(); len(ups) != 0 {
		t.Errorf("%d uploads with no telemetry source", len(ups))
	}
}

// R43, R46, §4.8: only a well-formed ack naming the sent batch_seq counts
// as accepted; INVALID_ARGUMENT drops the batch; any other failure retries
// the same batch and never drops it.
func TestUploadTelemetryAckOutcomes(t *testing.T) {
	t.Parallel()
	p := newStreamPKI(t)
	oversized := protowire.AppendBytes(protowire.AppendTag(ackBytes(t, 1), 15, protowire.BytesType), make([]byte, 64<<10))
	firstThenOK := func(first func(seq uint64) ([]byte, error)) answer {
		return func(n int, seq uint64) ([]byte, error) {
			if n == 0 {
				return first(seq)
			}
			return ackBytes(t, seq), nil
		}
	}
	cases := []struct {
		name         string
		ans          answer
		wantAccepted string
		wantRejected string
		minUploads   int
	}{
		{"matching ack", firstThenOK(func(seq uint64) ([]byte, error) { return ackBytes(t, seq), nil }), "[1]", "[]", 1},
		{"ack names another batch_seq", firstThenOK(func(seq uint64) ([]byte, error) { return ackBytes(t, seq+1), nil }), "[1]", "[]", 2},
		{"ack batch_seq 0", firstThenOK(func(uint64) ([]byte, error) { return []byte{}, nil }), "[1]", "[]", 2},
		{"malformed ack: duplicate field", firstThenOK(func(seq uint64) ([]byte, error) {
			return append(ackBytes(t, seq), ackBytes(t, seq)...), nil
		}), "[1]", "[]", 2},
		{"malformed ack: truncated varint", firstThenOK(func(uint64) ([]byte, error) { return []byte{0x08, 0x81}, nil }), "[1]", "[]", 2},
		{"oversized ack", firstThenOK(func(uint64) ([]byte, error) { return oversized, nil }), "[1]", "[]", 2},
		{"UNAVAILABLE", firstThenOK(func(uint64) ([]byte, error) { return nil, endStatus(codes.Unavailable) }), "[1]", "[]", 2},
		{"RESOURCE_EXHAUSTED", firstThenOK(func(uint64) ([]byte, error) { return nil, endStatus(codes.ResourceExhausted) }), "[1]", "[]", 2},
		{"INVALID_ARGUMENT", firstThenOK(func(uint64) ([]byte, error) { return nil, endStatus(codes.InvalidArgument) }), "[]", "[1]", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := newFakeTelemetry(t, 1)
			ts := startTelemetry(t, p, 0, tc.ans, func() bool { _, _, left := src.snapshot(); return left == 0 })
			runTelemetry(t, p, ts, src)
			acc, rej, left := src.snapshot()
			ups, _ := ts.snapshot()
			if fmt.Sprint(acc) != tc.wantAccepted || fmt.Sprint(rej) != tc.wantRejected || left != 0 {
				t.Errorf("accepted %v rejected %v left %d; want %s %s", acc, rej, left, tc.wantAccepted, tc.wantRejected)
			}
			if len(ups) < tc.minUploads {
				t.Errorf("uploads = %d, want at least %d (the same batch retried)", len(ups), tc.minUploads)
			}
			for i, u := range ups {
				if !bytes.Equal(u.body, src.bodies[1]) {
					t.Errorf("upload %d is not batch 1 unchanged", i)
				}
			}
		})
	}
}

func TestDecodeTelemetryAck(t *testing.T) {
	t.Parallel()
	for _, seq := range []uint64{1, 1 << 40, ^uint64(0)} {
		a, err := controlplane.DecodeTelemetryAck(ackBytes(t, seq))
		if err != nil || a.GetBatchSeq() != seq {
			t.Errorf("DecodeTelemetryAck(%d) = %v, %v", seq, a, err)
		}
	}
	for name, b := range ackAttacks(t) {
		if a, err := controlplane.DecodeTelemetryAck(b); err == nil || a != nil {
			t.Errorf("DecodeTelemetryAck(%s) accepted", name)
		}
	}
}

func ackAttacks(t testing.TB) map[string][]byte {
	good := ackBytes(t, 7)
	return map[string][]byte{
		"empty (batch_seq 0)":    {},
		"explicit zero":          {0x08, 0x00},
		"duplicate field":        append(bytes.Clone(good), good...),
		"unknown field":          append(bytes.Clone(good), 0x10, 0x01),
		"wrong wire type":        {0x0a, 0x01, 0x07},
		"truncated varint":       {0x08, 0xff},
		"non-minimal varint":     {0x08, 0x87, 0x00},
		"varint over 64 bits":    {0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"field 0":                {0x00, 0x01},
		"oversized padding":      protowire.AppendBytes(protowire.AppendTag(bytes.Clone(good), 15, protowire.BytesType), make([]byte, 1<<20)),
		"trailing garbage":       append(bytes.Clone(good), 0xff),
		"group start":            {0x0b},
		"length-delimited field": protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte{1}),
	}
}

func FuzzDecodeTelemetryAck(f *testing.F) {
	for _, b := range ackAttacks(f) {
		f.Add(b)
	}
	f.Add(ackBytes(f, 1))
	f.Add(ackBytes(f, ^uint64(0)))
	f.Fuzz(func(t *testing.T, in []byte) {
		orig := bytes.Clone(in)
		a, err := controlplane.DecodeTelemetryAck(in)
		if !bytes.Equal(in, orig) {
			t.Fatal("decoder modified its input")
		}
		if err != nil {
			if a != nil {
				t.Fatal("ack returned with an error")
			}
			return
		}
		if a.GetBatchSeq() < 1 {
			t.Fatal("accepted batch_seq 0")
		}
		if len(in) > 11 {
			t.Fatalf("accepted a %d-byte ack", len(in))
		}
		if !bytes.Equal(marshalDet(t, a), in) {
			t.Fatalf("accepted a non-canonical encoding %x", in)
		}
	})
}

// §4.4, §4.6a, R44: BuildHealth carries the redaction rule version, the
// redact drop counts (copied, sorted, capped, zero classes left out), the
// telemetry drop total and TELEMETRY_DROPPING while dropping.
func TestBuildHealthTelemetryAndRedact(t *testing.T) {
	t.Parallel()
	drops := []*agentapiv1.RedactDropCount{
		{Class: agentapiv1.RedactClass_REDACT_CLASS_E_TEXT, Dropped: 3},
		{Class: agentapiv1.RedactClass_REDACT_CLASS_L_VALUE, Dropped: 0},
		{Class: agentapiv1.RedactClass_REDACT_CLASS_T_NAME, Dropped: 1 << 50},
	}
	h := controlplane.BuildHealth(controlplane.HealthInput{
		Now: testNow, ExecutorAvailable: true,
		Telemetry:   telemetry.Stats{DroppedTotal: 1 << 50, Dropping: true},
		RedactDrops: drops,
	})
	if h.GetRedactRulesVersion() != pubredact.RulesVersion {
		t.Errorf("redact_rules_version = %d, want %d", h.GetRedactRulesVersion(), pubredact.RulesVersion)
	}
	if !slices.Contains(h.GetConditions(), agentapiv1.AgentCondition_AGENT_CONDITION_TELEMETRY_DROPPING) {
		t.Errorf("conditions %v lack TELEMETRY_DROPPING", h.GetConditions())
	}
	if !slices.IsSorted(h.GetConditions()) {
		t.Errorf("conditions %v not sorted", h.GetConditions())
	}
	if h.GetTelemetryDroppedBatches() != 1<<40 {
		t.Errorf("telemetry_dropped_batches = %d, want capped at 2^40", h.GetTelemetryDroppedBatches())
	}
	got := h.GetRedactDrops()
	if len(got) != 2 || got[0].GetClass() != agentapiv1.RedactClass_REDACT_CLASS_T_NAME || got[0].GetDropped() != 1<<40 ||
		got[1].GetClass() != agentapiv1.RedactClass_REDACT_CLASS_E_TEXT || got[1].GetDropped() != 3 {
		t.Errorf("redact_drops = %v; want T_NAME capped, E_TEXT 3, L_VALUE left out", got)
	}
	drops[0].Dropped = 999
	if h.GetRedactDrops()[1].GetDropped() != 3 {
		t.Error("redact_drops aliases the input")
	}
	b := marshalDet(t, h)
	if len(b) > 1024 {
		t.Errorf("HealthReport is %d bytes, over 1024", len(b))
	}
	var back agentapiv1.HealthReport
	if err := agentapiv1.StrictUnmarshal(b, &back); err != nil {
		t.Errorf("HealthReport fails the strict decoder: %v", err)
	}

	h = controlplane.BuildHealth(controlplane.HealthInput{Now: testNow, ExecutorAvailable: true,
		Telemetry: telemetry.Stats{DroppedTotal: 5}})
	if slices.Contains(h.GetConditions(), agentapiv1.AgentCondition_AGENT_CONDITION_TELEMETRY_DROPPING) {
		t.Error("TELEMETRY_DROPPING set while not dropping")
	}
	if h.GetTelemetryDroppedBatches() != 5 || len(h.GetRedactDrops()) != 0 {
		t.Errorf("dropped %d, redact_drops %v", h.GetTelemetryDroppedBatches(), h.GetRedactDrops())
	}
}
