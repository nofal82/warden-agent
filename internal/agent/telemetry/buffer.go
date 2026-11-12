package telemetry

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

// Limits of agent-api §4.7 and §7.
const (
	BufferBytes   = 8 << 20          // TELEMETRY_BUFFER_BYTES
	MaxBatchBytes = 256 << 10        // MAX_TELEMETRY_BATCH
	MaxLogEvents  = 200              // TelemetryBatch.log_events
	BatchInterval = 15 * time.Second // TELEMETRY_BATCHES_PER_MIN = 4
	MaxAge        = 24 * time.Hour   // TELEMETRY_MAX_AGE
	SeqFile       = "telemetry-seq"
	// maxWindowMs is collected_to_ms - collected_from_ms at most (§4.7).
	maxWindowMs = 3_600_000
	// ageMargin keeps a batch from reaching the control plane just past
	// TELEMETRY_MAX_AGE after the upload's own delay.
	ageMargin = 5 * time.Minute
	// headroom leaves room for the header and dropped_batches.
	headroom    = 512
	maxCounter  = 1 << 40
	maxSeqBytes = 20
)

var (
	serverIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	instanceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	ruleIDPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

	// ErrConfig: a Config field is invalid.
	ErrConfig = errors.New("telemetry: invalid configuration")
	// ErrSeqFile: the persisted batch_seq cannot be read or written.
	ErrSeqFile = errors.New("telemetry: batch sequence file unusable")
)

// Config configures a Buffer.
type Config struct {
	ServerID   string
	InstanceID string
	// RuntimeDir holds SeqFile next to the instance ID (agent-api R43).
	RuntimeDir string
	Now        func() time.Time
}

type batch struct {
	msg  *agentapiv1.TelemetryBatch
	size int
	// sentDropped is the dropped_batches value of the last Next.
	sentDropped uint64
}

// Stats is the buffer's state for the HealthReport.
type Stats struct {
	DroppedTotal uint64
	Dropping     bool
	Batches      int
	Bytes        int
}

// Buffer is safe for concurrent use: the collector adds, the uploader
// sends.
type Buffer struct {
	cfg Config

	mu       sync.Mutex
	seq      uint64
	pending  []*agentapiv1.LogEvent
	pendSize int
	pendFrom int64
	pendTo   int64
	batches  []*batch
	bytes    int
	dropped  uint64 // since start
	unsent   uint64 // dropped since the last accepted batch
	dropping bool
	invalid  uint64
	sealErr  error
}

// New reads the persisted batch_seq (missing means 0) and returns an
// empty buffer.
func New(cfg Config) (*Buffer, error) {
	if !serverIDPattern.MatchString(cfg.ServerID) || !instanceIDPattern.MatchString(cfg.InstanceID) ||
		!filepath.IsAbs(cfg.RuntimeDir) {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	seq, err := readSeq(filepath.Join(cfg.RuntimeDir, SeqFile))
	if err != nil {
		return nil, err
	}
	return &Buffer{cfg: cfg, seq: seq}, nil
}

func validEvent(ev *agentapiv1.LogEvent) bool {
	x := ev.GetExtract()
	return ruleIDPattern.MatchString(ev.GetRuleId()) && agentapiv1.ValidUnitID(ev.GetUnitId()) &&
		ev.GetCount() >= 1 && ev.GetCount() <= 1_000_000 && ev.GetObservedAtMs() > 0 &&
		len(x) <= 4096 && utf8.ValidString(x) && !strings.ContainsRune(x, 0)
}

// Add queues one redacted event. A pending set that is full, too large or
// spans the batch window limit is sealed first.
func (b *Buffer) Add(ev *agentapiv1.LogEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ev == nil || !validEvent(ev) {
		b.invalid++
		return
	}
	at := ev.GetObservedAtMs()
	size := proto.Size(ev) + 4
	if len(b.pending) > 0 && (len(b.pending) >= MaxLogEvents || b.pendSize+size > MaxBatchBytes-headroom ||
		max(b.pendTo, at)-min(b.pendFrom, at) > maxWindowMs/2) {
		if err := b.seal(); err != nil {
			b.sealErr = err
		}
	}
	if len(b.pending) == 0 {
		b.pendFrom, b.pendTo = at, at
	}
	b.pending = append(b.pending, proto.CloneOf(ev))
	b.pendSize += size
	b.pendFrom, b.pendTo = min(b.pendFrom, at), max(b.pendTo, at)
}

// Flush seals the pending events into a batch; no events, no batch.
func (b *Buffer) Flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := b.sealErr
	b.sealErr = nil
	if len(b.pending) > 0 {
		err = errors.Join(err, b.seal())
	}
	return err
}

// seal persists the next batch_seq, then turns the pending events into a
// batch. If the number cannot be persisted, the events are dropped: a
// batch whose number could be reused after a restart is never sent.
func (b *Buffer) seal() error {
	evs := b.pending
	from, to := b.pendFrom, b.pendTo
	b.pending, b.pendSize = nil, 0
	next := b.seq + 1
	if err := writeSeq(b.cfg.RuntimeDir, next); err != nil {
		b.invalid += uint64(len(evs))
		return err
	}
	b.seq = next
	now := b.cfg.Now().UnixMilli()
	if now > to && now-from <= maxWindowMs {
		to = now
	}
	msg := &agentapiv1.TelemetryBatch{
		FormatVersion: 1, ServerId: b.cfg.ServerID, InstanceId: b.cfg.InstanceID, BatchSeq: next,
		CollectedFromMs: max(from, 1), CollectedToMs: max(to, 1), LogEvents: evs,
	}
	bt := &batch{msg: msg, size: proto.Size(msg) + 8}
	b.batches = append(b.batches, bt)
	b.bytes += bt.size
	for b.bytes > BufferBytes && len(b.batches) > 1 {
		b.dropOldest()
	}
	return nil
}

func (b *Buffer) dropOldest() {
	b.bytes -= b.batches[0].size
	b.batches[0] = nil
	b.batches = b.batches[1:]
	b.dropped = min(b.dropped+1, maxCounter)
	b.unsent = min(b.unsent+1, maxCounter)
	b.dropping = true
}

// Next returns the oldest batch encoded for sending, with dropped_batches
// set; batches past TELEMETRY_MAX_AGE are dropped and counted first.
func (b *Buffer) Next() (uint64, []byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.cfg.Now().Add(-MaxAge + ageMargin).UnixMilli()
	for len(b.batches) > 0 && b.batches[0].msg.GetCollectedFromMs() < limit {
		b.dropOldest()
	}
	if len(b.batches) == 0 {
		return 0, nil, false
	}
	bt := b.batches[0]
	bt.msg.DroppedBatches = b.unsent
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(bt.msg)
	if err != nil || len(body) > MaxBatchBytes {
		b.dropOldest() // cannot happen with the sealing limits; never send it
		return 0, nil, false
	}
	bt.sentDropped = b.unsent
	return bt.msg.GetBatchSeq(), body, true
}

// Accepted removes batch seq after a matching TelemetryAck. The drops it
// reported are no longer owed.
func (b *Buffer) Accepted(seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if i := b.find(seq); i >= 0 {
		b.unsent -= min(b.unsent, b.batches[i].sentDropped)
		b.remove(i)
		b.dropping = b.unsent > 0
	}
}

// Rejected removes batch seq after INVALID_ARGUMENT: it is not retried,
// and its drop count is still owed.
func (b *Buffer) Rejected(seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if i := b.find(seq); i >= 0 {
		b.remove(i)
	}
}

func (b *Buffer) find(seq uint64) int {
	for i, bt := range b.batches {
		if bt.msg.GetBatchSeq() == seq {
			return i
		}
	}
	return -1
}

func (b *Buffer) remove(i int) {
	b.bytes -= b.batches[i].size
	b.batches = append(b.batches[:i], b.batches[i+1:]...)
}

// Stats returns the buffer's counters.
func (b *Buffer) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{DroppedTotal: b.dropped, Dropping: b.dropping, Batches: len(b.batches), Bytes: b.bytes}
}

func readSeq(path string) (uint64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: open: %w", ErrSeqFile, err)
	}
	f := os.NewFile(uintptr(fd), path) // #nosec G115 -- descriptor from unix.Open
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, fmt.Errorf("%w: not a regular file", ErrSeqFile)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSeqBytes+2))
	if err != nil {
		return 0, fmt.Errorf("%w: read: %w", ErrSeqFile, err)
	}
	s, ok := bytes.CutSuffix(raw, []byte("\n"))
	if !ok || len(s) == 0 || len(s) > maxSeqBytes {
		return 0, ErrSeqFile
	}
	v, err := strconv.ParseUint(string(s), 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != string(s) || v == ^uint64(0) {
		return 0, ErrSeqFile
	}
	return v, nil
}

// writeSeq replaces SeqFile atomically and durably (temp file, fsync,
// rename, directory fsync); a symlink at the path is replaced, never
// followed.
func writeSeq(dir string, v uint64) error {
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: directory: %w", ErrSeqFile, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	tmp := SeqFile + ".tmp"
	_ = unix.Unlinkat(dfd, tmp, 0) // a crash leftover
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create: %w", ErrSeqFile, err)
	}
	f := os.NewFile(uintptr(fd), tmp) // #nosec G115 -- descriptor from unix.Openat
	_, werr := f.WriteString(strconv.FormatUint(v, 10) + "\n")
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("%w: write: %w", ErrSeqFile, err)
	}
	if err := unix.Renameat(dfd, tmp, dfd, SeqFile); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("%w: rename: %w", ErrSeqFile, err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("%w: sync directory: %w", ErrSeqFile, err)
	}
	return nil
}
