//go:build linux

package identity

// File tests for R10e and §4.7. They run as an unprivileged user: the
// unexported readOwnedFile seam takes the start directory and the required
// owner, so the root-owned rules are exercised with owner = our uid (accept)
// and owner = another uid (refuse).

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// tree builds start/a/b/file with dirs 0755 and the file 0644, chmod'ed
// explicitly so the umask does not matter.
func tree(t *testing.T, content []byte) (start, rel string) {
	t.Helper()
	start = t.TempDir()
	mustChmod(t, start, 0o755)
	dir := filepath.Join(start, "a", "b")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, filepath.Join(start, "a"), 0o755)
	mustChmod(t, dir, 0o755)
	writeMode(t, filepath.Join(dir, "file"), content, 0o644)
	return start, "a/b/file"
}

// rootFileMode is the R10e mode of a root-owned trust file. It is a
// variable so the mode passes through helpers rather than literal calls.
var rootFileMode os.FileMode = 0o644

// readTestFile reads a fixture the test itself created.
func readTestFile(p string) ([]byte, error) { return os.ReadFile(filepath.Clean(p)) }

func mustChmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

func writeMode(t *testing.T, p string, data []byte, m os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, p, m)
}

func mkfifo(t *testing.T, p string) {
	t.Helper()
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
}

// noBlock runs fn and fails if it does not return within 5 s (a FIFO opened
// for reading without O_NONBLOCK blocks forever). On timeout it opens the
// FIFO for writing to release the stuck reader.
func noBlock(t *testing.T, fifo string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		if f, err := os.OpenFile(filepath.Clean(fifo), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("call blocked on a FIFO")
		return nil
	}
}

func TestReadOwnedFileAccepts(t *testing.T) {
	t.Parallel()
	content := []byte("trusted content\n")
	start, rel := tree(t, content)
	got, err := readOwnedFile(start, rel, os.Getuid(), 1024)
	if err != nil {
		t.Fatalf("readOwnedFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content = %q", got)
	}
	// A file directly in start, and a 0600 file, are accepted too.
	writeMode(t, filepath.Join(start, "top"), content, 0o600)
	if _, err := readOwnedFile(start, "top", os.Getuid(), 1024); err != nil {
		t.Fatalf("file in start: %v", err)
	}
	// An empty file is accepted.
	writeMode(t, filepath.Join(start, "empty"), nil, 0o644)
	if got, err := readOwnedFile(start, "empty", os.Getuid(), 1024); err != nil || len(got) != 0 {
		t.Fatalf("empty file: %q, %v", got, err)
	}
}

func TestReadOwnedFileSizeBound(t *testing.T) {
	t.Parallel()
	content := bytes.Repeat([]byte("x"), 100)
	start, rel := tree(t, content)
	if _, err := readOwnedFile(start, rel, os.Getuid(), 100); err != nil {
		t.Fatalf("exact size refused: %v", err)
	}
	if _, err := readOwnedFile(start, rel, os.Getuid(), 99); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("one byte over: %v, want ErrFileTooLarge", err)
	}
	if _, err := readOwnedFile(start, rel, os.Getuid(), 0); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("limit 0: %v, want ErrFileTooLarge", err)
	}
}

func TestReadOwnedFileRefusesUnsafe(t *testing.T) {
	t.Parallel()
	uid := os.Getuid()
	cases := []struct {
		name  string
		setup func(t *testing.T) (start, rel string, owner int)
	}{
		{"file is a symlink", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			real := filepath.Join(start, "a", "b", "real")
			writeMode(t, real, []byte("x"), 0o644)
			link := filepath.Join(start, "a", "b", "link")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			_ = rel
			return start, "a/b/link", uid
		}},
		{"file is a relative symlink", func(t *testing.T) (string, string, int) {
			start, _ := tree(t, []byte("x"))
			if err := os.Symlink("file", filepath.Join(start, "a", "b", "link")); err != nil {
				t.Fatal(err)
			}
			return start, "a/b/link", uid
		}},
		{"file symlink to /etc/shadow", func(t *testing.T) (string, string, int) {
			start, _ := tree(t, []byte("x"))
			if err := os.Symlink("/etc/shadow", filepath.Join(start, "a", "b", "link")); err != nil {
				t.Fatal(err)
			}
			return start, "a/b/link", uid
		}},
		{"intermediate dir is a symlink", func(t *testing.T) (string, string, int) {
			start, _ := tree(t, []byte("x"))
			if err := os.Symlink(filepath.Join(start, "a", "b"), filepath.Join(start, "a", "c")); err != nil {
				t.Fatal(err)
			}
			return start, "a/c/file", uid
		}},
		{"start dir is a symlink", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			link := filepath.Join(t.TempDir(), "start-link")
			if err := os.Symlink(start, link); err != nil {
				t.Fatal(err)
			}
			return link, rel, uid
		}},
		{"file group-writable", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			mustChmod(t, filepath.Join(start, rel), 0o664)
			return start, rel, uid
		}},
		{"file other-writable", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			mustChmod(t, filepath.Join(start, rel), 0o646)
			return start, rel, uid
		}},
		{"file 0666", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			mustChmod(t, filepath.Join(start, rel), 0o666)
			return start, rel, uid
		}},
		{"leaf dir group-writable", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			mustChmod(t, filepath.Join(start, "a", "b"), 0o775)
			return start, rel, uid
		}},
		{"middle dir other-writable", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			mustChmod(t, filepath.Join(start, "a"), 0o757)
			return start, rel, uid
		}},
		{"start dir group-writable", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			mustChmod(t, start, 0o775)
			return start, rel, uid
		}},
		{"start dir sticky other-writable like /tmp", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			mustChmod(t, start, 0o777|os.ModeSticky)
			return start, rel, uid
		}},
		{"not owned by the required owner", func(t *testing.T) (string, string, int) {
			start, rel := tree(t, []byte("x"))
			return start, rel, uid + 1
		}},
		{"required owner root, files ours", func(t *testing.T) (string, string, int) {
			if os.Geteuid() == 0 {
				t.Skip("running as root: our files are root's")
			}
			start, rel := tree(t, []byte("x"))
			return start, rel, 0
		}},
		{"file is a directory", func(t *testing.T) (string, string, int) {
			start, _ := tree(t, []byte("x"))
			return start, "a/b", uid
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start, rel, owner := tc.setup(t)
			got, err := readOwnedFile(start, rel, owner, 1024)
			if !errors.Is(err, ErrUnsafeFile) {
				t.Fatalf("readOwnedFile = %v, want ErrUnsafeFile", err)
			}
			if got != nil {
				t.Error("content returned with the error")
			}
		})
	}
}

// With root, the owner checks of each element are tested by chown.
func TestReadOwnedFileChownAsRoot(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown; covered by the owner+1 case")
	}
	for _, target := range []string{"a/b/file", "a/b", "a", "."} {
		start, rel := tree(t, []byte("x"))
		if err := os.Lchown(filepath.Join(start, target), 12345, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := readOwnedFile(start, rel, 0, 1024); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("%s owned by another uid: %v, want ErrUnsafeFile", target, err)
		}
	}
}

func TestReadOwnedFileFIFODoesNotBlock(t *testing.T) {
	t.Parallel()
	start, _ := tree(t, []byte("x"))
	fifo := filepath.Join(start, "a", "b", "fifo")
	mkfifo(t, fifo)
	mustChmod(t, fifo, 0o644)
	err := noBlock(t, fifo, func() error {
		_, err := readOwnedFile(start, "a/b/fifo", os.Getuid(), 1024)
		return err
	})
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("FIFO: %v, want ErrUnsafeFile", err)
	}
}

func TestReadOwnedFileBadRel(t *testing.T) {
	t.Parallel()
	start, _ := tree(t, []byte("x"))
	// A file outside start that ".." would reach.
	outside := filepath.Join(filepath.Dir(start), "outside-"+filepath.Base(start))
	writeMode(t, outside, []byte("outside"), 0o644)
	t.Cleanup(func() { _ = os.Remove(outside) })
	for _, rel := range []string{
		"", ".", "..", "./a/b/file", "a/./b/file", "a/../a/b/file", "a/b/../b/file",
		"a//b/file", "/a/b/file", "a/b/file/", "a/b/", "../" + filepath.Base(outside),
		"a/b/file\x00", "a/b/fi\x00le", "a\\b\\file", strings.Repeat("a/", 3000) + "file",
		filepath.Join(start, "a/b/file"),
	} {
		got, err := readOwnedFile(start, rel, os.Getuid(), 1024)
		if err == nil {
			t.Errorf("rel %q accepted (read %q)", short(rel), got)
		}
	}
}

func TestReadOwnedFileMissing(t *testing.T) {
	t.Parallel()
	start, _ := tree(t, []byte("x"))
	if _, err := readOwnedFile(start, "a/b/missing", os.Getuid(), 1024); err == nil {
		t.Fatal("missing file read")
	}
	if _, err := readOwnedFile(filepath.Join(start, "nope"), "file", os.Getuid(), 1024); err == nil {
		t.Fatal("missing start read")
	}
}

// TOCTOU: the file and an intermediate directory are swapped with symlinks
// to a different file while readOwnedFile runs. The symlinked content must
// never be returned.
func TestReadOwnedFileSwapRace(t *testing.T) {
	t.Parallel()
	good := []byte("GOOD")
	target := []byte("TARGET-NEVER-READ")
	t.Run("file swap", func(t *testing.T) {
		t.Parallel()
		start, _ := tree(t, good)
		dir := filepath.Join(start, "a", "b")
		secret := filepath.Join(start, "secret")
		writeMode(t, secret, target, 0o644)
		final := filepath.Join(dir, "file")
		race(t, func(i int) {
			tmp := filepath.Join(dir, "tmp")
			_ = os.Remove(tmp)
			if i%2 == 0 {
				_ = os.Symlink(secret, tmp)
			} else {
				_ = os.WriteFile(tmp, good, 0o600)
				_ = os.Chmod(tmp, rootFileMode)
			}
			_ = os.Rename(tmp, final)
		}, func() {
			got, err := readOwnedFile(start, "a/b/file", os.Getuid(), 1024)
			if err == nil && !bytes.Equal(got, good) {
				t.Errorf("read through a swapped-in symlink: %q", got)
			}
		})
	})
	t.Run("dir swap", func(t *testing.T) {
		t.Parallel()
		start, _ := tree(t, good)
		other := filepath.Join(start, "other")
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		mustChmod(t, other, 0o755)
		writeMode(t, filepath.Join(other, "file"), target, 0o644)
		b := filepath.Join(start, "a", "b")
		parked := filepath.Join(start, "a", "parked")
		race(t, func(i int) {
			if i%2 == 0 {
				_ = os.Rename(b, parked)
				_ = os.Symlink(other, b)
			} else {
				_ = os.Remove(b)
				_ = os.Rename(parked, b)
			}
		}, func() {
			got, err := readOwnedFile(start, "a/b/file", os.Getuid(), 1024)
			if err == nil && !bytes.Equal(got, good) {
				t.Errorf("read through a swapped-in directory symlink: %q", got)
			}
		})
	})
}

// race runs swap in a loop while read runs 2000 times.
func race(t *testing.T, swap func(i int), read func()) {
	t.Helper()
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			swap(i)
		}
	}()
	for i := 0; i < 2000 && !t.Failed(); i++ {
		read()
	}
	stop.Store(true)
	wg.Wait()
}

func TestReadRootFilePathRules(t *testing.T) {
	t.Parallel()
	for _, p := range []string{
		"", "etc/passwd", "./etc/passwd", "/etc/../etc/passwd", "/etc//passwd",
		"/etc/./passwd", "/etc/passwd/", "/", "/etc/passwd\x00",
	} {
		if _, err := ReadRootFile(p, 1<<20); err == nil {
			t.Errorf("ReadRootFile(%q) accepted", p)
		}
	}
}

// rootSafe reports whether every element of p is a root-owned, not group-
// or other-writable non-symlink, as R10e requires.
func rootSafe(p string) bool {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := "/"
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, parts[i])
		}
		fi, err := os.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0o022 != 0 {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if i == len(parts)-1 && !fi.Mode().IsRegular() {
			return false
		}
	}
	return true
}

func TestReadRootFileRealRootFile(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/etc/passwd", "/etc/hostname", "/etc/os-release"} {
		if !rootSafe(p) {
			continue
		}
		want, err := readTestFile(p)
		if err != nil {
			continue
		}
		got, err := ReadRootFile(p, int64(len(want))+1)
		if err != nil {
			t.Fatalf("ReadRootFile(%s): %v", p, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ReadRootFile(%s) content differs", p)
		}
		if len(want) > 0 {
			if _, err := ReadRootFile(p, int64(len(want))-1); !errors.Is(err, ErrFileTooLarge) {
				t.Fatalf("ReadRootFile(%s) one byte over: %v, want ErrFileTooLarge", p, err)
			}
		}
		return
	}
	t.Skip("no root-owned, safely permissioned file found on this machine")
}

func TestReadRootFileRefusesUnsafe(t *testing.T) {
	t.Parallel()
	// A file we own in a temp dir: not root-owned, and /tmp is 1777.
	p := filepath.Join(t.TempDir(), "agent-ca.pem")
	writeMode(t, p, []byte("x"), 0o644)
	if os.Geteuid() != 0 {
		if _, err := ReadRootFile(p, 1024); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("ReadRootFile of an agent-owned file: %v, want ErrUnsafeFile", err)
		}
	}
	// A directory.
	if rootSafe("/etc") {
		if _, err := ReadRootFile("/etc", 1<<20); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("ReadRootFile(/etc): %v, want ErrUnsafeFile", err)
		}
	}
	// A root-owned symlink in a safe directory.
	for _, l := range []string{"/etc/mtab", "/etc/localtime", "/etc/resolv.conf"} {
		fi, err := os.Lstat(l)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 || !rootSafe("/etc") {
			continue
		}
		if _, err := ReadRootFile(l, 1<<20); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("ReadRootFile(%s) symlink: %v, want ErrUnsafeFile", l, err)
		}
	}
}

// stateDir returns an opened StateDir over a fresh 0700 directory.
func stateDir(t *testing.T) (*StateDir, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("StateDir refuses to run as root")
	}
	p := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, p, 0o700)
	d, err := OpenStateDir(p)
	if err != nil {
		t.Fatalf("OpenStateDir: %v", err)
	}
	return d, p
}

var stateNames = []string{FileIdentity, FileIdentityPrev, FileIdentityPendingKey, FileEnrollPendingKey, FileToken, FileTokenExpires}

func TestOpenStateDir(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		d := t.TempDir()
		mustChmod(t, d, 0o700)
		if _, err := OpenStateDir(d); err == nil {
			t.Fatal("OpenStateDir accepted running as root")
		}
		return
	}
	stateDir(t) // 0700 owned by us: accepted

	mk := func(t *testing.T, mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), "identity")
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		mustChmod(t, p, mode)
		return p
	}
	cases := []struct {
		name string
		path func(t *testing.T) string
		want error
	}{
		{"0750", func(t *testing.T) string { return mk(t, 0o750) }, ErrUnsafeFile},
		{"0705", func(t *testing.T) string { return mk(t, 0o705) }, ErrUnsafeFile},
		{"0770", func(t *testing.T) string { return mk(t, 0o770) }, ErrUnsafeFile},
		{"0710", func(t *testing.T) string { return mk(t, 0o710) }, ErrUnsafeFile},
		{"0701", func(t *testing.T) string { return mk(t, 0o701) }, ErrUnsafeFile},
		{"0755", func(t *testing.T) string { return mk(t, 0o755) }, ErrUnsafeFile},
		{"0777", func(t *testing.T) string { return mk(t, 0o777) }, ErrUnsafeFile},
		{"symlink to a 0700 dir", func(t *testing.T) string {
			real := mk(t, 0o700)
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, ErrUnsafeFile},
		{"regular file", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "f")
			writeMode(t, p, nil, 0o600)
			return p
		}, ErrUnsafeFile},
		{"FIFO", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "fifo")
			mkfifo(t, p)
			return p
		}, ErrUnsafeFile},
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }, nil},
		{"empty path", func(*testing.T) string { return "" }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := tc.path(t)
			d, err := OpenStateDir(p)
			if err == nil || d != nil {
				t.Fatalf("OpenStateDir(%s) accepted", tc.name)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("OpenStateDir = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStateDirRoundTripAllNames(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	for _, name := range stateNames {
		data := []byte("content of " + name)
		if err := d.WriteFile(name, data); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
		got, err := d.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("ReadFile(%s) = %q", name, got)
		}
		fi, err := os.Lstat(filepath.Join(p, name))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, %v; want regular 0600", name, fi.Mode(), err)
		}
	}
}

func TestStateDirRefusesNames(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	parent := filepath.Dir(p)
	for _, name := range []string{
		"", ".", "..", "../x", "x/y", "identity.pem/", "/identity.pem", "./identity.pem",
		"foo", "IDENTITY.PEM", "identity.pem\x00", "identity.pem ", "token\n",
		"../identity/token", filepath.Join(p, FileToken), "identity.pem.tmp",
	} {
		if _, err := d.ReadFile(name); err == nil {
			t.Errorf("ReadFile(%q) accepted", name)
		}
		if err := d.WriteFile(name, []byte("x")); err == nil {
			t.Errorf("WriteFile(%q) accepted", name)
		}
		if err := d.Remove(name); err == nil {
			t.Errorf("Remove(%q) accepted", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, "x")); err == nil {
		t.Fatal("WriteFile(../x) created a file outside the state directory")
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("refused writes left %d entries in the state directory", len(entries))
	}
}

func TestStateDirReadRefusesUnsafe(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	target := filepath.Join(t.TempDir(), "outside")
	writeMode(t, target, []byte("OUTSIDE"), 0o600)

	cases := []struct {
		name  string
		file  string
		setup func(t *testing.T, path string)
		want  error
	}{
		{"symlink to a file we own", FileIdentity, func(t *testing.T, path string) {
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}, ErrUnsafeFile},
		{"dangling symlink", FileIdentityPrev, func(t *testing.T, path string) {
			if err := os.Symlink(target+".missing", path); err != nil {
				t.Fatal(err)
			}
		}, ErrUnsafeFile},
		{"mode 0640", FileToken, func(t *testing.T, path string) { writeMode(t, path, []byte("x"), 0o640) }, ErrUnsafeFile},
		{"mode 0604", FileTokenExpires, func(t *testing.T, path string) { writeMode(t, path, []byte("x"), 0o604) }, ErrUnsafeFile},
		{"mode 0620", FileEnrollPendingKey, func(t *testing.T, path string) { writeMode(t, path, []byte("x"), 0o620) }, ErrUnsafeFile},
		{"mode 0601", FileIdentityPendingKey, func(t *testing.T, path string) { writeMode(t, path, []byte("x"), 0o601) }, ErrUnsafeFile},
	}
	for _, tc := range cases {
		path := filepath.Join(p, tc.file)
		_ = os.Remove(path)
		tc.setup(t, path)
		got, err := d.ReadFile(tc.file)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: ReadFile = %v, want %v", tc.name, err, tc.want)
		}
		if bytes.Contains(got, []byte("OUTSIDE")) {
			t.Errorf("%s: followed the symlink", tc.name)
		}
		_ = os.Remove(path)
	}

	t.Run("directory", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(p, FileToken), 0o700); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Remove(filepath.Join(p, FileToken)) }()
		if _, err := d.ReadFile(FileToken); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("directory at a state name: %v, want ErrUnsafeFile", err)
		}
	})
	t.Run("FIFO", func(t *testing.T) {
		fifo := filepath.Join(p, FileToken)
		mkfifo(t, fifo)
		defer func() { _ = os.Remove(fifo) }()
		err := noBlock(t, fifo, func() error { _, err := d.ReadFile(FileToken); return err })
		if !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("FIFO: %v, want ErrUnsafeFile", err)
		}
	})
	t.Run("size", func(t *testing.T) {
		path := filepath.Join(p, FileIdentity)
		writeMode(t, path, bytes.Repeat([]byte("x"), MaxStateFileBytes), 0o600)
		if _, err := d.ReadFile(FileIdentity); err != nil {
			t.Fatalf("file of exactly MaxStateFileBytes: %v", err)
		}
		writeMode(t, path, bytes.Repeat([]byte("x"), MaxStateFileBytes+1), 0o600)
		if _, err := d.ReadFile(FileIdentity); !errors.Is(err, ErrFileTooLarge) {
			t.Fatalf("file over MaxStateFileBytes: %v, want ErrFileTooLarge", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := d.ReadFile(FileIdentityPrev); err == nil {
			t.Fatal("missing file read")
		}
	})
}

func TestStateDirWriteReplacesAndLeavesNoTemp(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	if err := d.WriteFile(FileToken, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile(FileToken, []byte("second")); err != nil {
		t.Fatal(err)
	}
	got, err := readTestFile(filepath.Join(p, FileToken))
	if err != nil || string(got) != "second" {
		t.Fatalf("content after replace = %q, %v", got, err)
	}
	if err := d.WriteFile(FileTokenExpires, nil); err != nil {
		t.Fatalf("empty write: %v", err)
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 {
		t.Fatalf("state directory holds %q, want only the two written files", names)
	}
}

func TestStateDirWriteDoesNotFollowSymlinks(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	outsideDir := t.TempDir()
	target := filepath.Join(outsideDir, "victim")
	writeMode(t, target, []byte("VICTIM"), 0o600)

	// A symlink at the final name.
	final := filepath.Join(p, FileIdentity)
	if err := os.Symlink(target, final); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile(FileIdentity, []byte("NEW")); err != nil {
		t.Fatalf("WriteFile over a planted symlink: %v", err)
	}
	if got, _ := readTestFile(target); string(got) != "VICTIM" {
		t.Fatalf("symlink target changed to %q", got)
	}
	fi, err := os.Lstat(final)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("final name is %v, %v; want a regular 0600 file", fi.Mode(), err)
	}
	if got, _ := readTestFile(final); string(got) != "NEW" {
		t.Fatalf("final content %q", got)
	}

	// A hard link at the final name to a file outside.
	hard := filepath.Join(p, FileToken)
	if err := os.Link(target, hard); err == nil {
		if err := d.WriteFile(FileToken, []byte("NEW")); err != nil {
			t.Fatalf("WriteFile over a hard link: %v", err)
		}
		if got, _ := readTestFile(target); string(got) != "VICTIM" {
			t.Fatalf("hard-linked file changed to %q", got)
		}
	}

	// Remove of a symlink never touches its target.
	link := filepath.Join(p, FileIdentityPrev)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_ = d.Remove(FileIdentityPrev)
	if got, err := readTestFile(target); err != nil || string(got) != "VICTIM" {
		t.Fatalf("Remove followed a symlink: %q, %v", got, err)
	}
}

// The mode is exactly 0600 whatever the umask. Not parallel: the umask is
// process-wide.
func TestStateDirWriteModeIgnoresUmask(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("StateDir refuses to run as root")
	}
	for _, mask := range []int{0, 0o022, 0o077, 0o277} {
		p := filepath.Join(t.TempDir(), "identity")
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		mustChmod(t, p, 0o700)
		d, err := OpenStateDir(p)
		if err != nil {
			t.Fatal(err)
		}
		var werr error
		func() {
			old := syscall.Umask(mask)
			defer syscall.Umask(old)
			werr = d.WriteFile(FileToken, []byte("x"))
		}()
		if werr != nil {
			t.Fatalf("umask %#o: WriteFile: %v", mask, werr)
		}
		fi, err := os.Lstat(filepath.Join(p, FileToken))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("umask %#o: mode %v, want 0600", mask, fi.Mode().Perm())
		}
	}
}

// Every operation re-checks the directory: a change after OpenStateDir is
// caught.
func TestStateDirRechecksEveryOperation(t *testing.T) {
	t.Parallel()
	t.Run("mode becomes 0755", func(t *testing.T) {
		t.Parallel()
		d, p := stateDir(t)
		if err := d.WriteFile(FileToken, []byte("x")); err != nil {
			t.Fatal(err)
		}
		mustChmod(t, p, 0o755)
		if _, err := d.ReadFile(FileToken); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("ReadFile: %v, want ErrUnsafeFile", err)
		}
		if err := d.WriteFile(FileToken, []byte("y")); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("WriteFile: %v, want ErrUnsafeFile", err)
		}
		if err := d.Remove(FileToken); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("Remove: %v, want ErrUnsafeFile", err)
		}
		mustChmod(t, p, 0o700)
		if got, _ := readTestFile(filepath.Join(p, FileToken)); string(got) != "x" {
			t.Errorf("refused operations changed the file: %q", got)
		}
	})
	t.Run("dir replaced by symlink", func(t *testing.T) {
		t.Parallel()
		d, p := stateDir(t)
		elsewhere := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.Mkdir(elsewhere, 0o700); err != nil {
			t.Fatal(err)
		}
		mustChmod(t, elsewhere, 0o700)
		writeMode(t, filepath.Join(elsewhere, FileToken), []byte("ELSEWHERE"), 0o600)
		if err := os.Rename(p, p+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, p); err != nil {
			t.Fatal(err)
		}
		if got, err := d.ReadFile(FileToken); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("ReadFile through symlinked dir: %q, %v; want ErrUnsafeFile", got, err)
		}
		if err := d.WriteFile(FileToken, []byte("y")); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("WriteFile through symlinked dir: %v, want ErrUnsafeFile", err)
		}
		if err := d.Remove(FileToken); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("Remove through symlinked dir: %v, want ErrUnsafeFile", err)
		}
		if got, _ := readTestFile(filepath.Join(elsewhere, FileToken)); string(got) != "ELSEWHERE" {
			t.Errorf("file behind the symlink changed: %q", got)
		}
	})
	t.Run("dir removed", func(t *testing.T) {
		t.Parallel()
		d, p := stateDir(t)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := d.WriteFile(FileToken, []byte("y")); err == nil {
			t.Error("WriteFile into a removed directory succeeded")
		}
	})
}

func TestStateDirRemove(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	if err := d.Remove(FileToken); err != nil {
		t.Fatalf("Remove of a missing file: %v", err)
	}
	if err := d.WriteFile(FileToken, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(FileToken); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(p, FileToken)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still there: %v", err)
	}
}

func TestWriteIdentityRoundTrip(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	f := newVerifyFixture(t)
	v, err := VerifyIssued(f.leaf, testServerID, f.key, f.ca.cert, testNow)
	if err != nil {
		t.Fatalf("VerifyIssued: %v", err)
	}
	if err := d.WriteIdentity(v); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	data, err := d.ReadFile(FileIdentity)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	key, cert, err := DecodeIdentity(data)
	if err != nil {
		t.Fatalf("DecodeIdentity of what WriteIdentity wrote: %v", err)
	}
	if !key.Equal(f.key) || !bytes.Equal(cert.Raw, f.leaf) {
		t.Fatal("round trip changed the identity")
	}
	fi, err := os.Lstat(filepath.Join(p, FileIdentity))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity.pem mode %v, %v", fi.Mode(), err)
	}
}

func TestWriteIdentityRefusesZeroValue(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	if err := d.WriteIdentity(VerifiedIdentity{}); err == nil {
		t.Fatal("WriteIdentity stored an unverified zero identity")
	}
	if _, err := os.Lstat(filepath.Join(p, FileIdentity)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a file was written for the zero identity")
	}
}
