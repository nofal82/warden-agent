package outbox_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

const blockSize = 4096

// fakeFS is an injectable statfs: tests never depend on the real
// filesystem's free space.
type fakeFS struct {
	mu    sync.Mutex
	st    outbox.FSStat
	err   error
	calls int
}

func newFakeFS() *fakeFS {
	return &fakeFS{st: outbox.FSStat{
		TotalBytes: outbox.StorageBudget,
		AvailBytes: 1 << 40,
		BlockSize:  blockSize,
	}}
}

func (f *fakeFS) statfs(int) (outbox.FSStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return outbox.FSStat{}, f.err
	}
	return f.st, nil
}

func (f *fakeFS) setAvail(v uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.AvailBytes = v
}

func (f *fakeFS) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func acceptStorage(outbox.FSStat) error { return nil }

// newDir returns an empty 0700 directory owned by the test user.
func newDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "outbox")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil { // #nosec G302 -- a directory needs its x bit; 0700 is owner only
		t.Fatal(err)
	}
	return d
}

func opts(fs *fakeFS) outbox.Options {
	return outbox.Options{Statfs: fs.statfs, ConfirmStorage: acceptStorage}
}

// openOrFail opens dir with a time limit, so an implementation that blocks
// on a FIFO fails the test instead of hanging it.
func openOrFail(t *testing.T, dir string, fs *fakeFS) *outbox.Outbox {
	t.Helper()
	o, err := openTimed(t, dir, opts(fs))
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	if o == nil {
		t.Fatal("Open returned nil outbox and nil error")
	}
	return o
}

func openTimed(t *testing.T, dir string, opt outbox.Options) (*outbox.Outbox, error) {
	t.Helper()
	type res struct {
		o   *outbox.Outbox
		err error
	}
	ch := make(chan res, 1)
	go func() {
		o, err := outbox.Open(dir, opt)
		ch <- res{o, err}
	}()
	select {
	case r := <-ch:
		return r.o, r.err
	case <-time.After(20 * time.Second):
		t.Fatal("Open blocked for 20 s (followed or opened a FIFO?)")
		return nil, nil
	}
}

func fresh(t *testing.T) (*outbox.Outbox, string, *fakeFS) {
	t.Helper()
	dir := newDir(t)
	fs := newFakeFS()
	return openOrFail(t, dir, fs), dir, fs
}

// fill returns n deterministic bytes; seed makes payloads distinct.
func fill(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31) ^ seed // #nosec G115 -- test seed, wraps by design
	}
	return b
}

func signedReply(kind agentapiv1.ReplyKind, signedLen int, seed byte) *agentapiv1.OutboxPayload {
	return &agentapiv1.OutboxPayload{Payload: &agentapiv1.OutboxPayload_SignedReply{
		SignedReply: &agentapiv1.SignedReplyReport{Kind: kind, Signed: fill(signedLen, seed)},
	}}
}

func envResult(seed byte) *agentapiv1.OutboxPayload {
	return signedReply(agentapiv1.ReplyKind_REPLY_KIND_ENVELOPE_RESULT, 300, seed)
}

func trustResult(seed byte) *agentapiv1.OutboxPayload {
	return signedReply(agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT, 200, seed)
}

func statusReply(seed byte) *agentapiv1.OutboxPayload {
	return signedReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 2000, seed)
}

// bigReply is the largest reply that respects the field options (signed
// and unsigned_body at 28,672 bytes each).
func bigReply(kind agentapiv1.ReplyKind, seed byte) *agentapiv1.OutboxPayload {
	return &agentapiv1.OutboxPayload{Payload: &agentapiv1.OutboxPayload_SignedReply{
		SignedReply: &agentapiv1.SignedReplyReport{
			Kind:         kind,
			Signed:       fill(28672, seed),
			UnsignedBody: fill(28672, seed+1),
		},
	}}
}

func advisory(seed byte) *agentapiv1.OutboxPayload {
	return &agentapiv1.OutboxPayload{Payload: &agentapiv1.OutboxPayload_EnvelopeAdvisory{
		EnvelopeAdvisory: &agentapiv1.EnvelopeAdvisory{
			EnvelopeSha256: fill(32, seed),
			Reason:         agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_EXPIRED,
		},
	}}
}

func oversize() *agentapiv1.OutboxPayload {
	return &agentapiv1.OutboxPayload{Payload: &agentapiv1.OutboxPayload_TrustDocumentOversize{
		TrustDocumentOversize: &agentapiv1.TrustDocumentOversize{
			Kind:         wardenv1.TrustKind_TRUST_KIND_KEYSET,
			ReceivedSize: 70000,
		},
	}}
}

func recovery(seed byte) *agentapiv1.OutboxPayload {
	return &agentapiv1.OutboxPayload{Payload: &agentapiv1.OutboxPayload_RecoveryReport{
		RecoveryReport: &agentapiv1.RecoveryReport{RecoveryId: fill(24, seed)},
	}}
}

// encode is the deterministic marshal of the stored OutboxMessage.
func encode(t testing.TB, seq uint64, p *agentapiv1.OutboxPayload) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(
		&agentapiv1.OutboxMessage{MessageSeq: seq, Payload: p})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sized returns an ENVELOPE_RESULT payload whose OutboxMessage at seq
// encodes to exactly total bytes.
func sized(t *testing.T, seq uint64, total int) *agentapiv1.OutboxPayload {
	t.Helper()
	for n := total - 24; n <= total; n++ {
		if n < 0 {
			continue
		}
		p := signedReply(agentapiv1.ReplyKind_REPLY_KIND_ENVELOPE_RESULT, n, 7)
		if len(encode(t, seq, p)) == total {
			return p
		}
	}
	t.Fatalf("cannot build a message of %d bytes", total)
	return nil
}

func enqueue(t *testing.T, o *outbox.Outbox, p *agentapiv1.OutboxPayload) uint64 {
	t.Helper()
	seq, err := o.Enqueue(p)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	return seq
}

func enqueueN(t *testing.T, o *outbox.Outbox, n int) []uint64 {
	t.Helper()
	var seqs []uint64
	for i := 0; i < n; i++ {
		seqs = append(seqs, enqueue(t, o, envResult(byte(i))))
	}
	return seqs
}

func next(t *testing.T, o *outbox.Outbox) (outbox.Message, bool) {
	t.Helper()
	m, ok, err := o.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return m, ok
}

func mustNext(t *testing.T, o *outbox.Outbox, want uint64) outbox.Message {
	t.Helper()
	m, ok := next(t, o)
	if !ok {
		t.Fatalf("Next: nothing, want seq %d", want)
	}
	if m.Seq != want {
		t.Fatalf("Next seq = %d, want %d", m.Seq, want)
	}
	return m
}

func ack(t *testing.T, o *outbox.Outbox, seq uint64, out agentapiv1.AckOutcome) {
	t.Helper()
	reason := agentapiv1.AckReason_ACK_REASON_UNSPECIFIED
	switch out {
	case agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER:
		reason = agentapiv1.AckReason_ACK_REASON_INBOX_FULL
	case agentapiv1.AckOutcome_ACK_OUTCOME_REJECTED:
		reason = agentapiv1.AckReason_ACK_REASON_MALFORMED
	}
	if err := o.Ack(seq, out, reason); err != nil {
		t.Fatalf("Ack(%d, %v): %v", seq, out, err)
	}
}

const (
	accepted   = agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED
	duplicate  = agentapiv1.AckOutcome_ACK_OUTCOME_DUPLICATE
	retryLater = agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER
	rejected   = agentapiv1.AckOutcome_ACK_OUTCOME_REJECTED
)

func fileName(seq uint64, suffix string) string { return fmt.Sprintf("%020d.%s", seq, suffix) }

// msgPath finds the message file of seq in any part; "" when none.
func msgPath(dir string, seq uint64) string {
	for _, s := range []string{"g", "r", "t"} {
		p := filepath.Join(dir, fileName(seq, s))
		if _, err := os.Lstat(p); err == nil {
			return p
		}
	}
	return ""
}

func mustMsgPath(t *testing.T, dir string, seq uint64) string {
	t.Helper()
	p := msgPath(dir, seq)
	if p == "" {
		t.Fatalf("no message file for seq %d in %s", seq, dir)
	}
	return p
}

func suffixOf(t *testing.T, dir string, seq uint64) string {
	t.Helper()
	return strings.TrimPrefix(filepath.Ext(mustMsgPath(t, dir, seq)), ".")
}

func readWatermark(t *testing.T, dir string) uint64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, outbox.WatermarkFile)) // #nosec G304 -- test file under t.TempDir()
	if err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	if len(b) != 8 {
		t.Fatalf("watermark is %d bytes, want 8", len(b))
	}
	return binary.BigEndian.Uint64(b)
}

func writeWatermark(t *testing.T, dir string, v uint64) {
	t.Helper()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	if err := os.WriteFile(filepath.Join(dir, outbox.WatermarkFile), b[:], 0o600); err != nil {
		t.Fatal(err)
	}
}

// snapshot is every directory entry with its mode and contents, to prove a
// refused call changed nothing on disk.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p) // #nosec G304 -- test file under t.TempDir()
		m[e.Name()] = fmt.Sprintf("%v|%x", fi.Mode(), b)
	}
	return m
}

func sameSnapshot(t *testing.T, what string, a, b map[string]string) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("%s: directory has %d entries, was %d", what, len(b), len(a))
	}
	for k, v := range a {
		if b[k] != v {
			t.Fatalf("%s: entry %s changed or removed", what, k)
		}
	}
}

func messageFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if e.Name() != outbox.WatermarkFile {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func equalSeqs(t *testing.T, what string, got, want []uint64) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// decodeStrict decodes b with the shared strict decoder.
func decodeStrict(t *testing.T, b []byte) *agentapiv1.OutboxMessage {
	t.Helper()
	var m agentapiv1.OutboxMessage
	if err := agentapiv1.StrictUnmarshal(b, &m); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	return &m
}

func mustBytesEqual(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: bytes differ (len %d vs %d)", what, len(got), len(want))
	}
}

// mixed is one payload of every kind the outbox carries (R30).
func mixed() []*agentapiv1.OutboxPayload {
	return []*agentapiv1.OutboxPayload{
		envResult(1), trustResult(2), statusReply(3), advisory(4), oversize(), recovery(6),
	}
}

// seedGeneral writes n general-part message files (seq 1 … n) straight to
// dir, without the outbox and without fsync, and the watermark n+1, so the
// cap tests start near a limit without 20,000 durable writes. Open then
// loads and checks them like any other files.
func seedGeneral(t *testing.T, dir string, n uint64, payload func(i uint64) *agentapiv1.OutboxPayload) {
	t.Helper()
	for i := uint64(1); i <= n; i++ {
		b := encode(t, i, payload(i))
		if err := os.WriteFile(filepath.Join(dir, fileName(i, "g")), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeWatermark(t, dir, n+1)
}
