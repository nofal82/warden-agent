package logs_test

// Tailer attacks and rotation (issue #44): OpenFile refuses every unsafe
// source; Poll survives rename rotation, copytruncate, partial and
// oversized lines and a symlink swapped in after the open.

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nofal82/warden-agent/internal/agent/logs"
)

const pollMax = 1 << 20

func TestOpenFileRefuses(t *testing.T) {
	dir := t.TempDir()
	realDir := mkdir(t, dir, "real")
	good := filepath.Join(realDir, "error.log")
	writeFile(t, good, nginxErr("ok"))
	secret := filepath.Join(dir, "shadow")
	writeFile(t, secret, "FAKE-SECRET-123\n")

	f, err := logs.OpenFile(good)
	if err != nil {
		t.Fatalf("OpenFile(regular file of another uid) = %v", err)
	}
	_ = f.Close()

	linkFinal := filepath.Join(realDir, "link.log")
	must(t, os.Symlink(secret, linkFinal))
	linkDir := filepath.Join(dir, "linkdir")
	must(t, os.Symlink(realDir, linkDir))
	hard := filepath.Join(realDir, "hard.log")
	writeFile(t, hard, "x\n")
	must(t, os.Link(hard, filepath.Join(dir, "hard-second")))
	fifo := filepath.Join(realDir, "fifo.log")
	must(t, syscall.Mkfifo(fifo, 0o600))
	locked := filepath.Join(realDir, "locked.log")
	writeFile(t, locked, "x\n")
	must(t, os.Chmod(locked, 0o000))

	cases := []struct {
		name, path string
		want       error
	}{
		{"symlink final component", linkFinal, logs.ErrUnsafeFile},
		{"symlink in a parent directory", filepath.Join(linkDir, "error.log"), logs.ErrUnsafeFile},
		{"directory", realDir, logs.ErrUnsafeFile},
		{"FIFO", fifo, logs.ErrUnsafeFile},
		{"character device", "/dev/null", logs.ErrUnsafeFile},
		{"hard link nlink 2", hard, logs.ErrUnsafeFile},
		{"missing", filepath.Join(realDir, "missing.log"), os.ErrNotExist},
		{"unreadable", locked, logs.ErrUnreadable},
		{"NUL in path", good + "\x00/etc/shadow", nil},
		{"relative path", "error.log", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "unreadable" && os.Geteuid() == 0 {
				t.Skip("root reads a 000 file")
			}
			var f *os.File
			err := openWithin(t, 3*time.Second, func() error {
				var e error
				f, e = logs.OpenFile(tc.path)
				return e
			}, unblockFIFO(fifo))
			if f != nil {
				_ = f.Close()
			}
			if err == nil || f != nil {
				t.Fatalf("OpenFile(%s) succeeded", tc.name)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("OpenFile(%s) = %v, want %v", tc.name, err, tc.want)
			}
			if strings.Contains(err.Error(), "FAKE-SECRET-123") {
				t.Error("error carries file content")
			}
		})
	}

	t.Run("owned by the agent's own uid", func(t *testing.T) {
		restore := logs.SetOwnUIDForTest(os.Geteuid())
		defer restore()
		f, err := logs.OpenFile(good)
		if f != nil {
			_ = f.Close()
		}
		if !errors.Is(err, logs.ErrUnsafeFile) {
			t.Fatalf("OpenFile(own-uid file) = %v, want ErrUnsafeFile", err)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// pollAll polls until two polls in a row return nothing.
func pollAll(t *testing.T, tl *logs.Tailer, max int) []string {
	t.Helper()
	var all []string
	empty := 0
	for i := 0; i < 1000 && empty < 2; i++ {
		lines, _, err := tl.Poll(max)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Poll: %v", err)
		}
		if len(lines) == 0 {
			empty++
			continue
		}
		empty = 0
		all = append(all, lines...)
	}
	return all
}

func TestTailerStartPositions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "error.log")
	writeFile(t, p, "l1\nl2\n")

	cases := []struct {
		name  string
		saved func() *logs.Position
		want  []string
	}{
		{"first start: end of file, no history", func() *logs.Position { return nil }, []string{"new"}},
		{"saved position same inode", func() *logs.Position { s := posOf(t, p, 3); return &s }, []string{"l2", "new"}},
		{"saved position at end", func() *logs.Position { s := posOf(t, p, 6); return &s }, []string{"new"}},
		{"saved position other inode: rotated while down", func() *logs.Position {
			s := posOf(t, p, 3)
			s.Ino++
			return &s
		}, []string{"l1", "l2", "new"}},
		{"saved offset beyond size: truncated while down", func() *logs.Position { s := posOf(t, p, 1<<40); return &s }, []string{"l1", "l2", "new"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, p, "l1\nl2\n")
			tl := logs.NewTailer(p, tc.saved())
			defer func() { _ = tl.Close() }()
			appendFile(t, p, "new\n")
			got := pollAll(t, tl, pollMax)
			if !slices.Equal(got, tc.want) {
				t.Errorf("lines = %q, want %q", got, tc.want)
			}
			_, pos, _ := tl.Poll(pollMax)
			if pos.Offset != 10 {
				t.Errorf("position offset = %d, want 10", pos.Offset)
			}
		})
	}
}

func TestTailerPartialAndLongLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "error.log")
	writeFile(t, p, "")
	tl := logs.NewTailer(p, nil)
	defer func() { _ = tl.Close() }()

	appendFile(t, p, "part")
	if got := pollAll(t, tl, pollMax); len(got) != 0 {
		t.Fatalf("partial line returned: %q", got)
	}
	appendFile(t, p, "ial\r\nnext\n")
	if got := pollAll(t, tl, pollMax); !slices.Equal(got, []string{"partial\r", "next"}) {
		t.Fatalf("lines = %q, want partial\\r and next", got)
	}

	// A line over MaxLineRead: exactly its first MaxLineRead bytes, the
	// rest skipped up to its newline, the next line intact.
	long := strings.Repeat("A", logs.MaxLineRead) + strings.Repeat("B", 5000)
	appendFile(t, p, long+"\nafter\n")
	got := pollAll(t, tl, pollMax)
	if len(got) != 2 || got[0] != long[:logs.MaxLineRead] || got[1] != "after" {
		t.Fatalf("long line: %d lines, first %d bytes", len(got), len(got[0]))
	}

	// The same, written in two chunks with a poll between them.
	appendFile(t, p, strings.Repeat("C", logs.MaxLineRead+10))
	got = pollAll(t, tl, pollMax)
	appendFile(t, p, strings.Repeat("D", 3000)+"\nlast\n")
	got = append(got, pollAll(t, tl, pollMax)...)
	if len(got) != 2 || got[0] != strings.Repeat("C", logs.MaxLineRead) || got[1] != "last" {
		t.Fatalf("split long line: %d lines", len(got))
	}
	for _, l := range got {
		if strings.Contains(l, "D") {
			t.Error("skipped tail of a long line was returned")
		}
	}

	// maxBytes bounds the input per poll; nothing lost or duplicated.
	var want []string
	for i := 0; i < 50; i++ {
		l := "line-" + strings.Repeat("x", i)
		want = append(want, l)
		appendFile(t, p, l+"\n")
	}
	var all []string
	for i := 0; i < 500 && len(all) < len(want); i++ {
		lines, _, err := tl.Poll(64)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, l := range lines {
			n += len(l) + 1
		}
		if n > 64 && len(lines) > 1 {
			t.Fatalf("Poll(64) consumed %d bytes of input", n)
		}
		all = append(all, lines...)
	}
	if !slices.Equal(all, want) {
		t.Fatalf("maxBytes polling returned %d lines, want %d in order", len(all), len(want))
	}
}

func TestTailerRotation(t *testing.T) {
	t.Run("rename rotation mid-stream", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "error.log")
		writeFile(t, p, "old-history\n")
		tl := logs.NewTailer(p, nil)
		defer func() { _ = tl.Close() }()
		appendFile(t, p, "a\n")
		if got := pollAll(t, tl, pollMax); !slices.Equal(got, []string{"a"}) {
			t.Fatalf("before rotation = %q", got)
		}
		appendFile(t, p, "b\n")
		must(t, os.Rename(p, p+".1"))
		appendFile(t, p+".1", "c\n") // the writer still holds the old file
		writeFile(t, p, "d\n")
		got := pollAll(t, tl, pollMax)
		if !slices.Equal(got, []string{"b", "c", "d"}) {
			t.Fatalf("after rotation = %q, want b c d exactly once", got)
		}
		_, pos, _ := tl.Poll(pollMax)
		if want := posOf(t, p, 2); pos != want {
			t.Errorf("position = %+v, want the new file at 2 %+v", pos, want)
		}
	})
	t.Run("copytruncate", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "error.log")
		writeFile(t, p, strings.Repeat("history\n", 10))
		tl := logs.NewTailer(p, nil)
		defer func() { _ = tl.Close() }()
		must(t, os.Truncate(p, 0))
		appendFile(t, p, "fresh\n")
		if got := pollAll(t, tl, pollMax); !slices.Equal(got, []string{"fresh"}) {
			t.Fatalf("after truncation = %q, want fresh", got)
		}
	})
	t.Run("file removed", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "error.log")
		writeFile(t, p, "")
		tl := logs.NewTailer(p, nil)
		defer func() { _ = tl.Close() }()
		must(t, os.Remove(p))
		lines, _, err := tl.Poll(pollMax)
		if len(lines) != 0 || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Poll(missing) = %q, %v", lines, err)
		}
	})
}

// TOCTOU: after a safe open, the path is swapped for a symlink to a
// secret file, a FIFO or a hard link. Poll never reads through the new
// object and never blocks.
func TestTailerSwapAfterOpen(t *testing.T) {
	for _, kind := range []string{"symlink", "FIFO", "hard link", "own uid"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "error.log")
			writeFile(t, p, "")
			secret := filepath.Join(dir, "shadow")
			writeFile(t, secret, "FAKE-SECRET-123 root:x:0:0\n")
			tl := logs.NewTailer(p, nil)
			defer func() { _ = tl.Close() }()
			appendFile(t, p, "safe\n")
			if got := pollAll(t, tl, pollMax); !slices.Equal(got, []string{"safe"}) {
				t.Fatalf("before swap = %q", got)
			}
			must(t, os.Rename(p, p+".1"))
			switch kind {
			case "symlink":
				must(t, os.Symlink(secret, p))
			case "FIFO":
				must(t, syscall.Mkfifo(p, 0o600))
			case "hard link":
				must(t, os.Link(secret, p))
			case "own uid":
				writeFile(t, p, "FAKE-SECRET-123 own\n")
				restore := logs.SetOwnUIDForTest(os.Geteuid())
				defer restore()
			}
			appendFile(t, secret, "FAKE-SECRET-123 more\n")
			var got []string
			_ = openWithin(t, 3*time.Second, func() error {
				got = pollAll(t, tl, pollMax)
				return nil
			}, unblockFIFO(p))
			for _, l := range got {
				if strings.Contains(l, "FAKE-SECRET-123") {
					t.Fatalf("Poll read through a swapped %s: %d lines", kind, len(got))
				}
			}
		})
	}
}
