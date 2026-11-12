package logs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var (
	// ErrUnsafeFile: a symlink in the path, not a regular file, more than
	// one hard link, or owned by the agent's own user.
	ErrUnsafeFile = errors.New("logs: unsafe log file")
	// ErrUnreadable: the agent's user may not read the file (EACCES,
	// EPERM). Reported locally, never escalated.
	ErrUnreadable = errors.New("logs: log file not readable by the agent user")
	// ErrBadPath: not an absolute clean path, or holds NUL.
	ErrBadPath = errors.New("logs: invalid log path")
)

// ownUID is the agent's effective uid. A log owned by it is refused: a
// process running as the agent's user, or a planted link, must not turn
// the agent's own files (its key) into log input.
var ownUID atomic.Int64

func init() { ownUID.Store(int64(os.Geteuid())) }

// setOwnUID replaces ownUID for tests (export_test.go) and returns a
// restore function.
func setOwnUID(uid int) func() {
	old := ownUID.Swap(int64(uid))
	return func() { ownUID.Store(old) }
}

const (
	pathFlags = unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	dirFlags  = pathFlags | unix.O_DIRECTORY
	readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK
)

// openDirNoFollow opens dir as an O_PATH descriptor, walking from "/" one
// component at a time with O_NOFOLLOW|O_DIRECTORY, so a symlink anywhere
// in the path fails (ENOTDIR or ELOOP).
func openDirNoFollow(dir string) (int, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || strings.IndexByte(dir, 0) >= 0 {
		return -1, ErrBadPath
	}
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return -1, classify(err)
	}
	for _, c := range strings.Split(dir, "/") {
		if c == "" {
			continue
		}
		next, err := unix.Openat(fd, c, dirFlags, 0)
		_ = unix.Close(fd) // O_PATH descriptor: nothing to flush
		if err != nil {
			return -1, classify(err)
		}
		fd = next
	}
	return fd, nil
}

// OpenFile opens a log file for reading under the rules of the package
// doc. The file is checked through an O_PATH descriptor before it is
// opened for reading (so a FIFO or a device is never opened), and the
// opened file is checked again to close the swap gap.
func OpenFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrBadPath
	}
	dfd, err := openDirNoFollow(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("logs: open %s: %w", path, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	base := filepath.Base(path)
	pfd, err := unix.Openat(dfd, base, pathFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("logs: open %s: %w", path, classify(err))
	}
	var first unix.Stat_t
	err = unix.Fstat(pfd, &first)
	_ = unix.Close(pfd)
	if err != nil {
		return nil, fmt.Errorf("logs: stat %s: %w", path, classify(err))
	}
	if err := checkStat(&first); err != nil {
		return nil, fmt.Errorf("logs: %s: %w", path, err)
	}
	fd, err := unix.Openat(dfd, base, readFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("logs: open %s: %w", path, classify(err))
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("logs: stat %s: %w", path, classify(err))
	}
	if err := checkStat(&st); err != nil || st.Dev != first.Dev || st.Ino != first.Ino {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("logs: %s: %w", path, ErrUnsafeFile)
	}
	return os.NewFile(uintptr(fd), path), nil // #nosec G115 -- descriptor from unix.Openat
}

func checkStat(st *unix.Stat_t) error {
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG, st.Nlink != 1, int64(st.Uid) == ownUID.Load():
		return ErrUnsafeFile
	}
	return nil
}

// classify maps an errno to the package's errors. ENOENT stays itself
// (errors.Is(err, os.ErrNotExist)).
func classify(err error) error {
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return ErrUnsafeFile
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return ErrUnreadable
	}
	return err
}

// fileID returns the device and inode of an open file.
func fileID(f *os.File) (dev, ino uint64, size int64, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil { // #nosec G115 -- descriptor of an open file
		return 0, 0, 0, err
	}
	return uint64(st.Dev), st.Ino, st.Size, nil // #nosec G115 -- device number
}

// pathID returns the device and inode now at path, without following a
// symlink in any component.
func pathID(path string) (dev, ino uint64, err error) {
	dfd, err := openDirNoFollow(filepath.Dir(path))
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, 0, classify(err)
	}
	return uint64(st.Dev), st.Ino, nil // #nosec G115 -- device number
}

// listDir returns up to max entry names of dir, opened without following
// symlinks.
func listDir(dir string, max int) ([]string, error) {
	pfd, err := openDirNoFollow(dir)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(pfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	_ = unix.Close(pfd)
	if err != nil {
		return nil, classify(err)
	}
	f := os.NewFile(uintptr(fd), dir) // #nosec G115 -- descriptor from unix.Openat
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(max)
	if err != nil && len(names) == 0 {
		return nil, nil // empty directory (io.EOF) or a read error: nothing to tail
	}
	return names, nil
}
