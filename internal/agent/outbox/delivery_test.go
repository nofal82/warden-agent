package outbox_test

import (
	"errors"
	"os"
	"testing"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

// TestNextOrderAndWindow: R31 (message_seq order, at most OUTBOX_WINDOW
// unacknowledged).
func TestNextOrderAndWindow(t *testing.T) {
	o, dir, _ := fresh(t)
	enqueueN(t, o, outbox.Window+2)
	for s := uint64(1); s <= outbox.Window; s++ {
		mustNext(t, o, s)
	}
	if m, ok := next(t, o); ok {
		t.Fatalf("Next returned seq %d with %d in flight", m.Seq, outbox.Window)
	}
	ack(t, o, 1, accepted)
	if msgPath(dir, 1) != "" {
		t.Fatal("ACCEPTED message still on disk")
	}
	mustNext(t, o, outbox.Window+1)
	if _, ok := next(t, o); ok {
		t.Fatal("window exceeded")
	}
	ack(t, o, 2, duplicate)
	mustNext(t, o, outbox.Window+2)
	if _, ok := next(t, o); ok {
		t.Fatal("Next returned a message when none is left")
	}
	for s := uint64(3); s <= outbox.Window+2; s++ {
		ack(t, o, s, accepted)
	}
	if len(o.Seqs()) != 0 || len(messageFiles(t, dir)) != 0 {
		t.Fatalf("after acking everything: Seqs %v, files %v", o.Seqs(), messageFiles(t, dir))
	}
	if _, ok := next(t, o); ok {
		t.Fatal("Next on a drained outbox returned a message")
	}
}

// TestAckOutcomes: R32 (removed only on ACCEPTED, DUPLICATE, REJECTED;
// REJECTED counted).
func TestAckOutcomes(t *testing.T) {
	cases := []struct {
		out      agentapiv1.AckOutcome
		reason   agentapiv1.AckReason
		removed  bool
		rejected uint64
	}{
		{accepted, agentapiv1.AckReason_ACK_REASON_UNSPECIFIED, true, 0},
		{duplicate, agentapiv1.AckReason_ACK_REASON_UNSPECIFIED, true, 0},
		{rejected, agentapiv1.AckReason_ACK_REASON_TOO_LARGE, true, 1},
		{rejected, agentapiv1.AckReason_ACK_REASON_MALFORMED, true, 1},
		{retryLater, agentapiv1.AckReason_ACK_REASON_INBOX_FULL, false, 0},
		{retryLater, agentapiv1.AckReason_ACK_REASON_REVOCATION_STATE_STALE, false, 0},
		{retryLater, agentapiv1.AckReason_ACK_REASON_DATABASE_UNAVAILABLE, false, 0},
		{retryLater, agentapiv1.AckReason_ACK_REASON_ORDER, false, 0},
	}
	for _, c := range cases {
		t.Run(c.out.String()+"/"+c.reason.String(), func(t *testing.T) {
			o, dir, _ := fresh(t)
			enqueueN(t, o, 2)
			first := mustNext(t, o, 1)
			if err := o.Ack(1, c.out, c.reason); err != nil {
				t.Fatalf("Ack: %v", err)
			}
			_, err := os.Lstat(mustMsgPathOrEmpty(dir, 1))
			if c.removed == (err == nil) {
				t.Fatalf("file present = %v, want removed = %v", err == nil, c.removed)
			}
			if r := o.Stats().Rejected; r != c.rejected {
				t.Fatalf("Rejected = %d, want %d", r, c.rejected)
			}
			if c.removed {
				equalSeqs(t, "Seqs", o.Seqs(), []uint64{2})
				mustNext(t, o, 2)
				return
			}
			equalSeqs(t, "Seqs", o.Seqs(), []uint64{1, 2})
			again := mustNext(t, o, 1)
			mustBytesEqual(t, "re-sent bytes", again.Bytes, first.Bytes)
		})
	}
}

func mustMsgPathOrEmpty(dir string, seq uint64) string {
	if p := msgPath(dir, seq); p != "" {
		return p
	}
	return dir + "/" + fileName(seq, "g")
}

// TestRetryLaterResendsInOrder: R32 head of line (RETRY_LATER, then ORDER
// for every later message; all re-sent in order with the same bytes).
func TestRetryLaterResendsInOrder(t *testing.T) {
	o, dir, _ := fresh(t)
	enqueueN(t, o, 5)
	sent := map[uint64][]byte{}
	for s := uint64(1); s <= 5; s++ {
		sent[s] = append([]byte{}, mustNext(t, o, s).Bytes...)
	}
	ack(t, o, 1, accepted)
	ack(t, o, 2, retryLater)
	mustBytesEqual(t, "seq 2 re-sent", mustNext(t, o, 2).Bytes, sent[2])
	for s := uint64(3); s <= 5; s++ {
		if err := o.Ack(s, retryLater, agentapiv1.AckReason_ACK_REASON_ORDER); err != nil {
			t.Fatalf("Ack(%d, ORDER): %v", s, err)
		}
	}
	for s := uint64(3); s <= 5; s++ {
		mustBytesEqual(t, "re-sent", mustNext(t, o, s).Bytes, sent[s])
	}
	if m, ok := next(t, o); ok {
		t.Fatalf("Next returned %d, nothing is left", m.Seq)
	}
	equalSeqs(t, "Seqs", o.Seqs(), []uint64{2, 3, 4, 5})
	for s := uint64(2); s <= 5; s++ {
		ack(t, o, s, accepted)
	}
	if f := messageFiles(t, dir); len(f) != 0 {
		t.Fatalf("files left: %v", f)
	}
}

// TestUnexpectedAck: an acknowledgement for a seq not in flight or with an
// unknown outcome removes nothing.
func TestUnexpectedAck(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, o *outbox.Outbox)
		seq     uint64
		out     agentapiv1.AckOutcome
	}{
		{"queued but not sent", nil, 2, accepted},
		{"unknown seq", nil, 99, accepted},
		{"seq zero", nil, 0, accepted},
		{"max seq", nil, ^uint64(0), rejected},
		{"UNSPECIFIED outcome", nil, 1, agentapiv1.AckOutcome_ACK_OUTCOME_UNSPECIFIED},
		{"outcome out of range", nil, 1, agentapiv1.AckOutcome(99)},
		{"negative outcome", nil, 1, agentapiv1.AckOutcome(-1)},
		{"already acknowledged", func(t *testing.T, o *outbox.Outbox) { ack(t, o, 1, accepted) }, 1, accepted},
		{"already rejected", func(t *testing.T, o *outbox.Outbox) { ack(t, o, 1, rejected) }, 1, rejected},
		{"after Rewind", func(t *testing.T, o *outbox.Outbox) { o.Rewind() }, 1, accepted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, dir, _ := fresh(t)
			enqueueN(t, o, 3)
			mustNext(t, o, 1)
			if c.prepare != nil {
				c.prepare(t, o)
			}
			seqs := o.Seqs()
			rej := o.Stats().Rejected
			before := snapshot(t, dir)
			err := o.Ack(c.seq, c.out, agentapiv1.AckReason_ACK_REASON_UNSPECIFIED)
			if !errors.Is(err, outbox.ErrUnexpectedAck) {
				t.Fatalf("err = %v, want ErrUnexpectedAck", err)
			}
			sameSnapshot(t, "dir", before, snapshot(t, dir))
			equalSeqs(t, "Seqs", o.Seqs(), seqs)
			if r := o.Stats().Rejected; r != rej {
				t.Fatalf("Rejected changed from %d to %d", rej, r)
			}
		})
	}
}

// TestRewindRestartsAtOldestUnacked: R32 (a new stream re-sends from the
// oldest unacknowledged message).
func TestRewindRestartsAtOldestUnacked(t *testing.T) {
	o, _, _ := fresh(t)
	enqueueN(t, o, 4)
	sent := map[uint64][]byte{}
	for s := uint64(1); s <= 3; s++ {
		sent[s] = append([]byte{}, mustNext(t, o, s).Bytes...)
	}
	ack(t, o, 1, accepted)
	o.Rewind()
	for s := uint64(2); s <= 4; s++ {
		m := mustNext(t, o, s)
		if b, ok := sent[s]; ok {
			mustBytesEqual(t, "re-sent after Rewind", m.Bytes, b)
		}
	}
	o.Rewind()
	o.Rewind() // idempotent
	mustNext(t, o, 2)
}

// TestNextSkipsFileRemovedOrCorruptedBehindBack: R32a (the agent removes a
// file that fails the strict check and continues with the next message).
func TestNextSkipsFileRemovedOrCorruptedBehindBack(t *testing.T) {
	cases := []struct {
		name    string
		do      func(t *testing.T, p, outside string)
		counted bool
	}{
		{"deleted", func(t *testing.T, p, _ string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"garbage", func(t *testing.T, p, _ string) { writeOver(fill(80, 1))(t, p, "", nil) }, true},
		{"truncated", func(t *testing.T, p, _ string) {
			b, _ := os.ReadFile(p) // #nosec G304 G703 -- test file under t.TempDir()
			writeOver(b[:len(b)/2])(t, p, "", nil)
		}, true},
		{"seq of another message", func(t *testing.T, p, _ string) {
			writeOver(encode(t, 3, envResult(1)))(t, p, "", nil)
		}, true},
		{"symlink to a valid copy", func(t *testing.T, p, out string) {
			b, _ := os.ReadFile(p) // #nosec G304 G703 -- test file under t.TempDir()
			target := out + "/copy"
			if err := os.WriteFile(target, b, 0o600); err != nil { // #nosec G304 G703 -- test file under t.TempDir()
				t.Fatal(err)
			}
			replaceWithSymlink(t, p, target)
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, dir, _ := fresh(t)
			enqueueN(t, o, 3)
			p := mustMsgPath(t, dir, 2)
			outside := t.TempDir()
			c.do(t, p, outside)
			before := snapshot(t, outside)
			mustBytesEqual(t, "seq 1", mustNext(t, o, 1).Bytes, encode(t, 1, envResult(0)))
			mustBytesEqual(t, "seq 3", mustNext(t, o, 3).Bytes, encode(t, 3, envResult(2)))
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("failing file still present (%v)", err)
			}
			equalSeqs(t, "Seqs", o.Seqs(), []uint64{1, 3})
			if c.counted && o.Stats().Rejected != 1 {
				t.Fatalf("Rejected = %d, want 1", o.Stats().Rejected)
			}
			sameSnapshot(t, "outside", before, snapshot(t, outside))
		})
	}
}

// TestRecheck: R32a (on MESSAGE_SEQ_UNREADABLE the agent re-checks every
// file and removes the ones that fail).
func TestRecheck(t *testing.T) {
	o, dir, _ := fresh(t)
	enqueueN(t, o, 5)
	mustNext(t, o, 1)
	writeOver(fill(40, 2))(t, mustMsgPath(t, dir, 2), "", nil)
	b, _ := os.ReadFile(mustMsgPath(t, dir, 4))
	writeOver(b[:len(b)-3])(t, mustMsgPath(t, dir, 4), "", nil)

	n, err := o.Recheck()
	if err != nil || n != 2 {
		t.Fatalf("Recheck = %d, %v; want 2, nil", n, err)
	}
	equalSeqs(t, "Seqs", o.Seqs(), []uint64{1, 3, 5})
	if msgPath(dir, 2) != "" || msgPath(dir, 4) != "" {
		t.Fatal("failing files still on disk")
	}
	if r := o.Stats().Rejected; r != 2 {
		t.Fatalf("Rejected = %d, want 2", r)
	}
	if n, err := o.Recheck(); err != nil || n != 0 {
		t.Fatalf("second Recheck = %d, %v; want 0, nil", n, err)
	}
	o.Rewind()
	mustNext(t, o, 1)
	mustNext(t, o, 3)
	mustNext(t, o, 5)
}
