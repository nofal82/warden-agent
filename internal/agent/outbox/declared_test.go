package outbox_test

// Issue #59 (PR #61 LOW finding): a stored message carrying an undeclared
// enum value or a missing required field fails the strict check (R12, R29,
// V4 of PR #60) and is removed and counted at Open (AC23).

import (
	"os"
	"testing"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

func undeclaredPayloads() []struct {
	name string
	p    *agentapiv1.OutboxPayload
} {
	badReason := advisory(1)
	badReason.GetEnvelopeAdvisory().Reason = agentapiv1.AdvisoryReason(99)
	return []struct {
		name string
		p    *agentapiv1.OutboxPayload
	}{
		{"SignedReplyReport kind UNSPECIFIED", signedReply(agentapiv1.ReplyKind_REPLY_KIND_UNSPECIFIED, 300, 1)},
		{"SignedReplyReport kind 99", signedReply(agentapiv1.ReplyKind(99), 300, 1)},
		{"EnvelopeAdvisory reason 99", badReason},
	}
}

// TestCheckFileRefusesUndeclared: R12 and V4 applied to stored files (R29).
func TestCheckFileRefusesUndeclared(t *testing.T) {
	t.Parallel()
	for _, c := range undeclaredPayloads() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if err := outbox.CheckFile(2, encode(t, 2, c.p)); err == nil {
				t.Fatal("CheckFile accepted an undeclared value")
			}
		})
	}
}

// TestOpenRemovesUndeclared: AC23, R29: a file that fails the check at
// start is removed and counted in rejected_messages; the others survive.
func TestOpenRemovesUndeclared(t *testing.T) {
	o, dir, fs := fresh(t)
	enqueue(t, o, envResult(0))
	enqueue(t, o, envResult(1))
	enqueue(t, o, envResult(2))
	p := mustMsgPath(t, dir, 2)
	bad := undeclaredPayloads()[0].p
	if err := os.WriteFile(p, encode(t, 2, bad), 0o600); err != nil { // #nosec G304 G703 -- test file under t.TempDir()
		t.Fatal(err)
	}
	o2 := openOrFail(t, dir, fs)
	equalSeqs(t, "Seqs after Open", o2.Seqs(), []uint64{1, 3})
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("bad file still present (err %v)", err)
	}
	if r := o2.Stats().Rejected; r != 1 {
		t.Fatalf("Rejected = %d, want 1", r)
	}
}
