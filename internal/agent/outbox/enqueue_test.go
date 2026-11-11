package outbox_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

func TestEnqueueRejectsInvalidPayload(t *testing.T) {
	cases := []struct {
		name string
		p    *agentapiv1.OutboxPayload
	}{
		{"nil", nil},
		{"no member", &agentapiv1.OutboxPayload{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, dir, _ := fresh(t)
			before := snapshot(t, dir)
			if _, err := o.Enqueue(c.p); !errors.Is(err, outbox.ErrInvalidMessage) {
				t.Fatalf("err = %v, want ErrInvalidMessage", err)
			}
			sameSnapshot(t, "dir", before, snapshot(t, dir))
			if s := enqueue(t, o, recovery(1)); s != 1 {
				t.Fatalf("seq after a refused Enqueue = %d, want 1", s)
			}
		})
	}
}

// TestEnqueueSizeBoundary: R11 (MAX_INBOX_MESSAGE of the AgentMessage
// carrying it); a refused message consumes no seq.
func TestEnqueueSizeBoundary(t *testing.T) {
	o, dir, _ := fresh(t)
	mx := maxBytes(t)
	before := snapshot(t, dir)
	for _, p := range []*agentapiv1.OutboxPayload{
		sized(t, 1, mx+1),
		sized(t, 1, mx+2),
		signedReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 1<<20, 1),
		signedReply(agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT, 70000, 1),
	} {
		if _, err := o.Enqueue(p); !errors.Is(err, outbox.ErrTooLarge) {
			t.Fatalf("Enqueue of %d bytes: err = %v, want ErrTooLarge", len(encode(t, 1, p)), err)
		}
	}
	sameSnapshot(t, "dir after ErrTooLarge", before, snapshot(t, dir))

	p := sized(t, 1, mx)
	if s := enqueue(t, o, p); s != 1 {
		t.Fatalf("seq = %d, want 1 (a refused message must not advance the watermark)", s)
	}
	fi, err := os.Stat(filepath.Join(dir, fileName(1, "g")))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(mx) {
		t.Fatalf("file size = %d, want %d", fi.Size(), mx)
	}
	m := mustNext(t, o, 1)
	if len(m.Bytes) != mx {
		t.Fatalf("Next bytes = %d, want %d", len(m.Bytes), mx)
	}
}

// TestEnqueueStoresExactBytes: R28 (signed bytes carried exactly), R29 (the
// file holds the exact bytes sent).
func TestEnqueueStoresExactBytes(t *testing.T) {
	o, dir, _ := fresh(t)
	ps := append(mixed(),
		bigReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 4),
		bigReply(agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT, 5),
		signedReply(agentapiv1.ReplyKind_REPLY_KIND_ENVELOPE_RESULT, 1, 0),
		// Signed bytes that look like protobuf must not be re-encoded.
		&agentapiv1.OutboxPayload{Payload: &agentapiv1.OutboxPayload_SignedReply{
			SignedReply: &agentapiv1.SignedReplyReport{
				Kind:   agentapiv1.ReplyKind_REPLY_KIND_ENVELOPE_RESULT,
				Signed: []byte{0x08, 0x81, 0x80, 0x00, 0x08, 0x01, 0x0a, 0x00},
			}}},
	)
	var want [][]byte
	for _, p := range ps {
		seq := enqueue(t, o, p)
		raw := encode(t, seq, p)
		want = append(want, raw)
		path := filepath.Join(dir, fileName(seq, "g"))
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("seq %d: general part has room, want file %s: %v", seq, fileName(seq, "g"), err)
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("seq %d: mode %v, want regular 0600", seq, fi.Mode())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && (st.Nlink != 1 || int(st.Uid) != os.Geteuid()) {
			t.Fatalf("seq %d: nlink %d uid %d", seq, st.Nlink, st.Uid)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		mustBytesEqual(t, "file bytes", got, raw)
		m := decodeStrict(t, got)
		if m.GetMessageSeq() != seq {
			t.Fatalf("stored message_seq = %d, want %d", m.GetMessageSeq(), seq)
		}
		if sr := p.GetSignedReply(); sr != nil {
			mustBytesEqual(t, "signed", m.GetPayload().GetSignedReply().GetSigned(), sr.GetSigned())
		}
	}
	for i := range ps {
		m := mustNext(t, o, uint64(i+1))
		mustBytesEqual(t, "Next bytes", m.Bytes, want[i])
		ack(t, o, m.Seq, accepted) // stay inside the window
	}
}

// TestEnqueueDoesNotAliasPayloadOrResult: neither the caller's payload nor
// a returned Message can change what is stored or re-sent.
func TestEnqueueDoesNotAliasPayloadOrResult(t *testing.T) {
	o, dir, _ := fresh(t)
	p := envResult(1)
	want := encode(t, 1, p)
	enqueue(t, o, p)
	p.GetSignedReply().Signed[0] ^= 0xff
	p.GetSignedReply().Kind = agentapiv1.ReplyKind_REPLY_KIND_STATUS

	got, err := os.ReadFile(filepath.Join(dir, fileName(1, "g")))
	if err != nil {
		t.Fatal(err)
	}
	mustBytesEqual(t, "file after payload mutation", got, want)
	m := mustNext(t, o, 1)
	mustBytesEqual(t, "Next after payload mutation", m.Bytes, want)
	for i := range m.Bytes {
		m.Bytes[i] = 0
	}
	o.Rewind()
	m2 := mustNext(t, o, 1)
	mustBytesEqual(t, "Next after caller mutated Bytes", m2.Bytes, want)
}

// TestConcurrentEnqueue: seqs are unique and strictly increasing (run with
// -race).
func TestConcurrentEnqueue(t *testing.T) {
	o, dir, _ := fresh(t)
	const workers, each = 8, 25
	var wg sync.WaitGroup
	got := make([][]uint64, workers)
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				s, err := o.Enqueue(recovery(byte(w*each + i)))
				if err != nil {
					errs <- err
					return
				}
				got[w] = append(got[w], s)
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Enqueue: %v", err)
	}
	var all []uint64
	for w, seqs := range got {
		for i := 1; i < len(seqs); i++ {
			if seqs[i] <= seqs[i-1] {
				t.Fatalf("worker %d: seqs not increasing: %v", w, seqs)
			}
		}
		all = append(all, seqs...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	want := make([]uint64, workers*each)
	for i := range want {
		want[i] = uint64(i + 1)
	}
	equalSeqs(t, "all seqs", all, want)
	equalSeqs(t, "Seqs()", o.Seqs(), want)
	if wm := readWatermark(t, dir); wm != workers*each+1 {
		t.Fatalf("watermark = %d, want %d", wm, workers*each+1)
	}
	for _, s := range want {
		b, err := os.ReadFile(mustMsgPath(t, dir, s))
		if err != nil {
			t.Fatal(err)
		}
		if decodeStrict(t, b).GetMessageSeq() != s {
			t.Fatalf("file %d holds another seq", s)
		}
	}
}

// TestCheckFile: the strict check of one stored message (R29, R32a).
func TestCheckFile(t *testing.T) {
	mx := maxBytes(t)
	valid := encode(t, 2, envResult(1))
	seq2 := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2)
	cases := []struct {
		name string
		seq  uint64
		b    []byte
		ok   bool
	}{
		{"valid", 2, valid, true},
		{"valid advisory", 5, encode(t, 5, advisory(1)), true},
		{"valid at max size", 1, encode(t, 1, sized(t, 1, mx)), true},
		{"over max size", 1, encode(t, 1, sized(t, 1, mx+1)), false},
		{"seq mismatch", 3, valid, false},
		{"seq zero", 0, encode(t, 0, envResult(1)), false},
		{"nil", 2, nil, false},
		{"empty", 2, []byte{}, false},
		{"garbage", 2, fill(64, 5), false},
		{"truncated", 2, valid[:len(valid)-1], false},
		{"duplicate field 1", 2, append(append([]byte{}, seq2...), valid...), false},
		{"field 1 as bytes", 2, append(protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte{2}), valid[len(seq2):]...), false},
		{"overlong seq varint", 2, append([]byte{0x08, 0x82, 0x00}, valid[len(seq2):]...), false},
		{"no payload", 2, seq2, false},
		{"empty payload", 2, protowire.AppendBytes(protowire.AppendTag(append([]byte{}, seq2...), 2, protowire.BytesType), nil), false},
		{"unknown field", 2, protowire.AppendVarint(protowire.AppendTag(append([]byte{}, valid...), 3, protowire.VarintType), 1), false},
		{"trailing zero", 2, append(append([]byte{}, valid...), 0), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := outbox.CheckFile(c.seq, c.b)
			if c.ok != (err == nil) {
				t.Fatalf("CheckFile = %v, want ok=%v", err, c.ok)
			}
		})
	}
	if !bytes.Equal(valid, encode(t, 2, envResult(1))) {
		t.Fatal("CheckFile modified its input")
	}
}
