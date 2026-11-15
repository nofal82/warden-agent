package logs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Position is a persisted read position: the file's identity and the
// offset just past the last line handed on.
type Position struct {
	Dev, Ino uint64
	Offset   int64
}

const (
	// MaxOffsetsFile bounds the state file.
	MaxOffsetsFile = 64 << 10
	maxEntries     = 256
	maxPathBytes   = 4096
	offsetsHeader  = "warden-log-offsets 1\n"
)

// ErrBadOffsets: the state file or map is not valid. The caller starts
// every source at its end (no history replay).
var ErrBadOffsets = errors.New("logs: invalid offsets state")

func validKey(p string) bool {
	if len(p) == 0 || len(p) > maxPathBytes || !filepath.IsAbs(p) || filepath.Clean(p) != p || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// EncodeOffsets is the state file's encoding: a header, then one line per
// entry, sorted by path: "<dev> <ino> <offset> <path>". The encoding is
// canonical, so ParseOffsets can refuse any other spelling.
func EncodeOffsets(m map[string]Position) ([]byte, error) {
	if len(m) > maxEntries {
		return nil, ErrBadOffsets
	}
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if !validKey(k) || v.Offset < 0 {
			return nil, ErrBadOffsets
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	b := []byte(offsetsHeader)
	for _, k := range keys {
		v := m[k]
		b = strconv.AppendUint(b, v.Dev, 10)
		b = append(b, ' ')
		b = strconv.AppendUint(b, v.Ino, 10)
		b = append(b, ' ')
		b = strconv.AppendInt(b, v.Offset, 10)
		b = append(b, ' ')
		b = append(b, k...)
		b = append(b, '\n')
	}
	if len(b) > MaxOffsetsFile {
		return nil, ErrBadOffsets
	}
	return b, nil
}

// ParseOffsets decodes EncodeOffsets' output and refuses anything else,
// including a non-canonical spelling of a valid map.
func ParseOffsets(b []byte) (map[string]Position, error) {
	if len(b) > MaxOffsetsFile || !bytes.HasPrefix(b, []byte(offsetsHeader)) {
		return map[string]Position{}, ErrBadOffsets
	}
	m := map[string]Position{}
	rest := string(b[len(offsetsHeader):])
	for rest != "" {
		line, tail, ok := strings.Cut(rest, "\n")
		if !ok {
			return map[string]Position{}, ErrBadOffsets
		}
		rest = tail
		f := strings.SplitN(line, " ", 4)
		if len(f) != 4 {
			return map[string]Position{}, ErrBadOffsets
		}
		dev, e1 := strconv.ParseUint(f[0], 10, 64)
		ino, e2 := strconv.ParseUint(f[1], 10, 64)
		off, e3 := strconv.ParseInt(f[2], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			return map[string]Position{}, ErrBadOffsets
		}
		if _, dup := m[f[3]]; dup {
			return map[string]Position{}, ErrBadOffsets
		}
		m[f[3]] = Position{Dev: dev, Ino: ino, Offset: off}
	}
	again, err := EncodeOffsets(m)
	if err != nil || !bytes.Equal(again, b) {
		return map[string]Position{}, ErrBadOffsets
	}
	return m, nil
}

// LoadOffsets reads the state file at path. A missing file is an empty
// map and no error. A symlink, a non-regular file, an oversized or a bad
// file is an empty map and an error.
func LoadOffsets(path string) (map[string]Position, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if errors.Is(err, unix.ENOENT) {
		return map[string]Position{}, nil
	}
	if err != nil {
		return map[string]Position{}, fmt.Errorf("%w: open: %w", ErrBadOffsets, err)
	}
	f := os.NewFile(uintptr(fd), path) // #nosec G115 -- descriptor from unix.Open
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return map[string]Position{}, fmt.Errorf("%w: not a regular file", ErrBadOffsets)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxOffsetsFile+1))
	if err != nil {
		return map[string]Position{}, fmt.Errorf("%w: read: %w", ErrBadOffsets, err)
	}
	return ParseOffsets(b)
}

// SaveOffsets writes m to path atomically: a new temporary file (0600,
// O_EXCL, no symlink followed), fsync, rename over path, fsync of the
// directory. Rename replaces a symlink at path, never writes through it.
func SaveOffsets(path string, m map[string]Position) error {
	b, err := EncodeOffsets(m)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("logs: offsets directory: %w", err)
	}
	defer func() { _ = unix.Close(dfd) }()
	tmp := filepath.Base(path) + ".tmp"
	_ = unix.Unlinkat(dfd, tmp, 0) // a leftover of a crash; never a directory
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("logs: offsets temp file: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp) // #nosec G115 -- descriptor from unix.Openat
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("logs: write offsets: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("logs: sync offsets: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("logs: close offsets: %w", err)
	}
	if err := unix.Renameat(dfd, tmp, dfd, filepath.Base(path)); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("logs: rename offsets: %w", err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("logs: sync offsets directory: %w", err)
	}
	return nil
}
