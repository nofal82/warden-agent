package outbox_test

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

// TestTransientReadErrorKeepsFiles: a transient read error (EMFILE, EIO)
// is never a verdict on the file. Open, Next and Recheck return an error
// and remove nothing, so a valid signed reply is never lost (R28, security
// review HIGH).
func TestTransientReadErrorKeepsFiles(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.EIO, syscall.ENOMEM} {
		t.Run(errno.Error(), func(t *testing.T) {
			for _, step := range []string{"open", "next", "recheck"} {
				t.Run(step, func(t *testing.T) {
					o, dir, fs := fresh(t)
					seqs := enqueueN(t, o, 3)
					before := snapshot(t, dir)
					restore := outbox.SetOpenat(func(dirfd int, path string, flags int, mode uint32) (int, error) {
						if path != outbox.WatermarkFile && !strings.HasPrefix(path, ".") {
							return -1, errno
						}
						return syscall.Openat(dirfd, path, flags, mode)
					})
					var err error
					switch step {
					case "open":
						_, err = openTimed(t, dir, opts(fs))
					case "next":
						_, _, err = o.Next()
					case "recheck":
						_, err = o.Recheck()
					}
					restore()
					if err == nil || !errors.Is(err, errno) {
						t.Fatalf("err = %v, want %v", err, errno)
					}
					sameSnapshot(t, "outbox dir", before, snapshot(t, dir))
					if r := o.Stats().Rejected; r != 0 {
						t.Fatalf("Rejected = %d, want 0", r)
					}
					o2 := openOrFail(t, dir, fs)
					equalSeqs(t, "Seqs after recovery", o2.Seqs(), seqs)
					if m := mustNext(t, o2, seqs[0]); len(m.Bytes) == 0 {
						t.Fatal("empty message after recovery")
					}
				})
			}
		})
	}
}

// TestDefiniteVerdictStillRemoves: the fix keeps removing files that are
// definitely bad, here a file gone behind the outbox's back (ENOENT) and
// a symlink (ELOOP), both seen by Next.
func TestDefiniteVerdictStillRemoves(t *testing.T) {
	o, dir, _ := fresh(t)
	seqs := enqueueN(t, o, 3)
	p0, p, p2 := mustMsgPath(t, dir, seqs[0]), mustMsgPath(t, dir, seqs[1]), mustMsgPath(t, dir, seqs[2])
	if err := os.Remove(p0); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p2, p); err != nil {
		t.Fatal(err)
	}
	mustNext(t, o, seqs[2])
	if r := o.Stats().Rejected; r != 2 {
		t.Fatalf("Rejected = %d, want 2", r)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink not removed: %v", err)
	}
}
