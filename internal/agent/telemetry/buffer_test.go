package telemetry_test

// Telemetry buffer tests (issue #44; agent-api R43, R44, §4.7):
// batch_seq persisted before use and strictly increasing across restarts,
// bounded memory dropping oldest whole batches, MaxAge, the 200-event and
// 256 KiB batch limits, and every encoded batch passing the strict decoder
// and the contract checks.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/telemetry"
)

const (
	testServerID   = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	testInstanceID = "0123456789abcdef0123456789abcdef"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newBuffer(t *testing.T, dir string, c *clock) *telemetry.Buffer {
	t.Helper()
	b, err := telemetry.New(telemetry.Config{ServerID: testServerID, InstanceID: testInstanceID, RuntimeDir: dir, Now: c.now})
	if err != nil {
		t.Fatalf("telemetry.New: %v", err)
	}
	return b
}

func event(at time.Time, extractLen int) *agentapiv1.LogEvent {
	return &agentapiv1.LogEvent{
		RuleId: "nginx-error", UnitId: "nginx.service", ObservedAtMs: at.UnixMilli(), Count: 1,
		Extract: strings.Repeat("e", extractLen),
	}
}

// checkBatch decodes body with the strict decoder and applies the
// agent-api §4.7 container rules.
func checkBatch(t *testing.T, body []byte, seq uint64) *agentapiv1.TelemetryBatch {
	t.Helper()
	if len(body) > telemetry.MaxBatchBytes {
		t.Errorf("batch %d is %d bytes, over MaxBatchBytes", seq, len(body))
	}
	var b agentapiv1.TelemetryBatch
	if err := agentapiv1.StrictUnmarshal(body, &b); err != nil {
		t.Fatalf("batch %d fails the strict decoder: %v", seq, err)
	}
	if b.GetFormatVersion() != 1 || b.GetServerId() != testServerID || b.GetInstanceId() != testInstanceID {
		t.Errorf("batch %d header = %d %q %q", seq, b.GetFormatVersion(), b.GetServerId(), b.GetInstanceId())
	}
	if b.GetBatchSeq() != seq || seq < 1 {
		t.Errorf("batch_seq = %d, Next said %d", b.GetBatchSeq(), seq)
	}
	from, to := b.GetCollectedFromMs(), b.GetCollectedToMs()
	if from <= 0 || to < from || to-from > 3_600_000 {
		t.Errorf("batch %d window [%d, %d] breaks §4.7", seq, from, to)
	}
	if len(b.GetLogEvents()) > telemetry.MaxLogEvents || b.GetDroppedBatches() > 1<<40 {
		t.Errorf("batch %d: %d events, dropped %d", seq, len(b.GetLogEvents()), b.GetDroppedBatches())
	}
	for _, ev := range b.GetLogEvents() {
		x := ev.GetExtract()
		if ev.GetObservedAtMs() < from || ev.GetObservedAtMs() > to {
			t.Errorf("event observed at %d outside [%d, %d]", ev.GetObservedAtMs(), from, to)
		}
		if len(x) > 4096 || strings.ContainsRune(x, 0) || !utf8.ValidString(x) {
			t.Errorf("extract of %d bytes breaks §4.7", len(x))
		}
		if ev.GetCount() < 1 || !agentapiv1.ValidUnitID(ev.GetUnitId()) {
			t.Errorf("event count %d unit %q", ev.GetCount(), ev.GetUnitId())
		}
	}
	return &b
}

func drain(t *testing.T, b *telemetry.Buffer) (seqs []uint64, batches []*agentapiv1.TelemetryBatch) {
	t.Helper()
	for i := 0; i < 10_000; i++ {
		seq, body, ok := b.Next()
		if !ok {
			return seqs, batches
		}
		batches = append(batches, checkBatch(t, body, seq))
		seqs = append(seqs, seq)
		b.Accepted(seq)
	}
	t.Fatal("Next never ran dry")
	return nil, nil
}

func TestBatchLimitsAndContract(t *testing.T) {
	t.Parallel()
	c := &clock{t: t0}
	b := newBuffer(t, t.TempDir(), c)

	if err := b.Flush(); err != nil {
		t.Fatalf("Flush with no events: %v", err)
	}
	if _, _, ok := b.Next(); ok {
		t.Fatal("Flush with no events produced a batch")
	}
	for i := 0; i < 450; i++ {
		b.Add(event(c.now(), 40))
		c.advance(time.Millisecond)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// 200 extracts of 4,096 bytes cannot fit one 256 KiB batch.
	for i := 0; i < 200; i++ {
		b.Add(event(c.now(), 4096))
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	seqs, batches := drain(t, b)
	total := 0
	for i, bt := range batches {
		total += len(bt.GetLogEvents())
		if i > 0 && seqs[i] <= seqs[i-1] {
			t.Errorf("batch_seq not strictly increasing: %v", seqs)
		}
	}
	if seqs[0] != 1 {
		t.Errorf("first batch_seq = %d, want 1 (the empty Flush must not use a number)", seqs[0])
	}
	if total != 650 {
		t.Errorf("events delivered = %d, want 650", total)
	}
}

// R43: batch_seq is persisted when the batch is sealed, so a restart
// never reuses a number, even for a batch that was never sent.
func TestBatchSeqPersistedAcrossRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := &clock{t: t0}
	var last uint64
	for run := 0; run < 4; run++ {
		b := newBuffer(t, dir, c)
		b.Add(event(c.now(), 10))
		if err := b.Flush(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(dir, telemetry.SeqFile)); err != nil {
			t.Fatalf("run %d: seq file not written by Flush: %v", run, err)
		}
		if run%2 == 1 {
			continue // crash before Next: the number is still burnt
		}
		seq, body, ok := b.Next()
		if !ok {
			t.Fatalf("run %d: no batch", run)
		}
		checkBatch(t, body, seq)
		if seq <= last {
			t.Fatalf("run %d: batch_seq %d not above %d", run, seq, last)
		}
		last = seq
	}
	if last < 3 {
		t.Errorf("last batch_seq = %d; numbers of unsent batches were reused", last)
	}
	fi, err := os.Lstat(filepath.Join(dir, telemetry.SeqFile))
	if err != nil || fi.Mode().Perm()&0o077 != 0 || !fi.Mode().IsRegular() {
		t.Errorf("seq file mode = %v, %v; want a regular owner-only file", fi.Mode(), err)
	}
}

func TestNewRefusesBadSeqFile(t *testing.T) {
	t.Parallel()
	if _, err := telemetry.New(telemetry.Config{ServerID: testServerID, InstanceID: testInstanceID, RuntimeDir: t.TempDir(), Now: time.Now}); err != nil {
		t.Fatalf("missing seq file refused: %v", err)
	}
	cases := map[string]func(p string) error{
		"garbage":   func(p string) error { return os.WriteFile(p, []byte("\xff\xfe junk"), 0o600) },
		"negative":  func(p string) error { return os.WriteFile(p, []byte("-5"), 0o600) },
		"oversized": func(p string) error { return os.WriteFile(p, bytes.Repeat([]byte{'9'}, 1<<20), 0o600) },
		"directory": func(p string) error { return os.Mkdir(p, 0o700) },
		"symlink": func(p string) error {
			tgt := filepath.Join(filepath.Dir(p), "elsewhere")
			if err := os.WriteFile(tgt, []byte("FAKE-SECRET-123"), 0o600); err != nil {
				return err
			}
			return os.Symlink(tgt, p)
		},
	}
	for name, mk := range cases {
		dir := t.TempDir()
		if err := mk(filepath.Join(dir, telemetry.SeqFile)); err != nil {
			t.Fatal(err)
		}
		if b, err := telemetry.New(telemetry.Config{ServerID: testServerID, InstanceID: testInstanceID, RuntimeDir: dir, Now: time.Now}); err == nil || b != nil {
			t.Errorf("New(%s seq file) accepted", name)
		}
	}
	bad := map[string]telemetry.Config{
		"bad server id":   {ServerID: "not-a-uuid", InstanceID: testInstanceID, RuntimeDir: t.TempDir()},
		"bad instance id": {ServerID: testServerID, InstanceID: "../x", RuntimeDir: t.TempDir()},
		"no runtime dir":  {ServerID: testServerID, InstanceID: testInstanceID},
	}
	for name, cfg := range bad {
		if b, err := telemetry.New(cfg); err == nil || b != nil {
			t.Errorf("New(%s) accepted", name)
		}
	}
}

// R44: over TELEMETRY_BUFFER_BYTES the oldest whole batches go, counted,
// Dropping set, the count reported in the next batch and cleared after it
// is accepted, kept after a rejection.
func TestBufferOverflowDropsOldest(t *testing.T) {
	t.Parallel()
	c := &clock{t: t0}
	b := newBuffer(t, t.TempDir(), c)
	for i := 0; i < 60; i++ { // about 60 x 200 KiB = 12 MiB
		for j := 0; j < 50; j++ {
			b.Add(event(c.now(), 4000))
		}
		if err := b.Flush(); err != nil {
			t.Fatal(err)
		}
		c.advance(time.Second)
	}
	st := b.Stats()
	if !st.Dropping || st.DroppedTotal == 0 {
		t.Fatalf("Stats = %+v, want Dropping and drops counted", st)
	}
	if st.Bytes > telemetry.BufferBytes || st.Bytes <= 0 || st.Batches <= 0 {
		t.Errorf("Stats bytes %d batches %d; want within (0, BufferBytes]", st.Bytes, st.Batches)
	}
	seq, body, ok := b.Next()
	if !ok {
		t.Fatal("no batch left")
	}
	first := checkBatch(t, body, seq)
	if seq == 1 {
		t.Error("oldest batch (seq 1) survived the overflow")
	}
	if first.GetDroppedBatches() != st.DroppedTotal {
		t.Errorf("dropped_batches = %d, want %d", first.GetDroppedBatches(), st.DroppedTotal)
	}

	// A rejected batch does not clear the count.
	b.Rejected(seq)
	seq2, body2, ok := b.Next()
	if !ok || seq2 == seq {
		t.Fatalf("Rejected batch still next (%d)", seq2)
	}
	if got := checkBatch(t, body2, seq2).GetDroppedBatches(); got != st.DroppedTotal {
		t.Errorf("after Rejected dropped_batches = %d, want %d still", got, st.DroppedTotal)
	}
	// Next again without an ack returns the same batch (retry).
	if s, _, _ := b.Next(); s != seq2 {
		t.Errorf("Next without an ack moved from %d to %d", seq2, s)
	}
	b.Accepted(seq2)
	seq3, body3, ok := b.Next()
	if !ok {
		t.Fatal("no third batch")
	}
	if got := checkBatch(t, body3, seq3).GetDroppedBatches(); got != 0 {
		t.Errorf("after Accepted dropped_batches = %d, want 0", got)
	}
	b.Accepted(seq3 + 1000) // unknown seq: ignored, nothing removed
	if s, _, _ := b.Next(); s != seq3 {
		t.Errorf("Accepted(unknown) removed batch %d", seq3)
	}
	if b.Stats().DroppedTotal != st.DroppedTotal {
		t.Error("DroppedTotal is not a monotonic total since start")
	}
}

// R43, TELEMETRY_MAX_AGE: a batch older than 24 h is dropped and counted.
func TestBufferMaxAge(t *testing.T) {
	t.Parallel()
	c := &clock{t: t0}
	b := newBuffer(t, t.TempDir(), c)
	b.Add(event(c.now(), 10))
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	c.advance(telemetry.MaxAge + time.Minute)
	b.Add(event(c.now(), 10))
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	seq, body, ok := b.Next()
	if !ok {
		t.Fatal("no batch")
	}
	bt := checkBatch(t, body, seq)
	if seq != 2 || bt.GetDroppedBatches() != 1 {
		t.Errorf("Next = seq %d dropped %d; want seq 2 with 1 dropped", seq, bt.GetDroppedBatches())
	}
	if b.Stats().DroppedTotal != 1 {
		t.Errorf("DroppedTotal = %d, want 1", b.Stats().DroppedTotal)
	}
	if bt.GetCollectedFromMs() < c.now().Add(-telemetry.MaxAge).UnixMilli() {
		t.Error("sent batch older than MaxAge")
	}
}
