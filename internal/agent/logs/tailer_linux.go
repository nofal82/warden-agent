package logs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	pubredact "github.com/nofal82/warden-agent/redact"
)

// MaxLineRead is the longest line Poll returns: one byte over the
// redactor's line limit, so a longer line is replaced whole by the
// redactor's fixed text and never scanned cut (redaction R39).
const MaxLineRead = pubredact.MaxLine + 1

// maxChunk bounds one read.
const maxChunk = 1 << 20

// Tailer follows one log path across rotation and truncation. It is not
// safe for concurrent use.
type Tailer struct {
	path string
	f    *os.File
	dev  uint64
	ino  uint64
	// off is the committed position: just past the last whole line
	// returned, or the start of a long line whose tail is being skipped
	// (a restart then returns its prefix again, which the redactor
	// replaces whole; its tail is never returned as a line).
	off int64
	// readOff is where the next read starts; it differs from off only
	// while skipping.
	readOff  int64
	skipping bool
	// buf is reused across reads, so an idle or busy source allocates
	// nothing per poll.
	buf []byte
	// saved is the position to resume at the first open; nil means
	// "start at the end" (first start: no history).
	saved  *Position
	opened bool
	// problem is why the path cannot be opened now (ErrUnsafeFile,
	// ErrUnreadable), nil otherwise.
	problem error
}

// NewTailer returns a Tailer for path and tries the first open. saved is
// the persisted position, or nil on a first start (read from the end).
func NewTailer(path string, saved *Position) *Tailer {
	t := &Tailer{path: path}
	if saved != nil {
		s := *saved
		t.saved = &s
	}
	_ = t.open() // a failure is retried by Poll and shown by Problem
	return t
}

// Problem reports why the path cannot be opened safely now, or nil. It is
// kept apart from Poll's error so a refused source is reported locally
// while the tailer keeps waiting for a safe file.
func (t *Tailer) Problem() error { return t.problem }

func (t *Tailer) open() error {
	f, err := OpenFile(t.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.problem = err
		} else {
			t.problem = nil
		}
		return err
	}
	dev, ino, size, err := fileID(f)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("logs: stat %s: %w", t.path, err)
	}
	t.problem = nil
	var off int64
	switch {
	case t.opened: // a rotated-in file: all of it is new
	case t.saved == nil:
		off = size // first start: no history
	case t.saved.Dev == dev && t.saved.Ino == ino && t.saved.Offset <= size:
		off = t.saved.Offset
	default: // rotated or truncated while the agent was down
	}
	t.f, t.dev, t.ino, t.off, t.readOff, t.skipping, t.opened = f, dev, ino, off, off, false, true
	return nil
}

func (t *Tailer) pos() Position {
	if t.f == nil {
		return Position{}
	}
	return Position{Dev: t.dev, Ino: t.ino, Offset: t.off}
}

// Poll returns the complete lines appended since the last call, without
// their "\n", consuming at most maxBytes of input (always at least one
// line when one is complete), and the position just past them. A missing
// path returns an error wrapping os.ErrNotExist; a path that cannot be
// opened safely returns no lines and no error (see Problem).
func (t *Tailer) Poll(maxBytes int) ([]string, Position, error) {
	if t.f == nil {
		if err := t.open(); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, t.pos(), err
			}
			return nil, t.pos(), nil
		}
	}
	_, _, size, err := fileID(t.f)
	if err != nil {
		return nil, t.pos(), fmt.Errorf("logs: stat %s: %w", t.path, err)
	}
	if size < t.readOff { // copytruncate or truncation
		t.off, t.readOff, t.skipping = 0, 0, false
	}
	if size > t.readOff {
		lines, err := t.read(maxBytes, size)
		if err != nil || len(lines) > 0 {
			return lines, t.pos(), err
		}
	}
	// Nothing new in the open file: has the path been rotated?
	dev, ino, err := pathID(t.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, t.pos(), fmt.Errorf("logs: %s: %w", t.path, err)
		}
		t.problem = err
		return nil, t.pos(), nil
	}
	if dev == t.dev && ino == t.ino {
		return nil, t.pos(), nil
	}
	_ = t.f.Close() // read-only file: nothing to lose
	t.f = nil
	if err := t.open(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, t.pos(), err
		}
		return nil, t.pos(), nil
	}
	_, _, size, err = fileID(t.f)
	if err != nil || size == 0 {
		return nil, t.pos(), err
	}
	lines, err := t.read(maxBytes, size)
	return lines, t.pos(), err
}

// read reads at most what is new (size - readOff), bounded by maxBytes
// (at least one whole line) and maxChunk, into the reused buffer.
func (t *Tailer) read(maxBytes int, size int64) ([]string, error) {
	maxBytes = max(maxBytes, 1)
	want := int(min(size-t.readOff, int64(min(max(maxBytes, MaxLineRead+1), maxChunk))))
	if want <= 0 {
		return nil, nil
	}
	if cap(t.buf) < want {
		t.buf = make([]byte, want)
	}
	buf := t.buf[:want]
	n, err := t.f.ReadAt(buf, t.readOff)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("logs: read %s: %w", t.path, err)
	}
	data := buf[:n]
	var lines []string
	used, taken := 0, 0
	for used < len(data) {
		rest := data[used:]
		i := bytes.IndexByte(rest, '\n')
		if t.skipping {
			if i < 0 {
				used = len(data)
				break
			}
			used += i + 1
			t.skipping = false
			t.off = t.readOff + int64(used)
			continue
		}
		switch {
		case i < 0 && len(rest) < MaxLineRead: // partial line: wait for its newline
			t.readOff += int64(used)
			return lines, nil
		case len(lines) > 0 && taken+min(i+1, MaxLineRead) > maxBytes && i >= 0:
			t.readOff += int64(used)
			return lines, nil
		case i < 0 || i >= MaxLineRead: // long line: return its prefix, skip the rest
			lines = append(lines, string(rest[:MaxLineRead]))
			taken += MaxLineRead
			if i < 0 {
				used += MaxLineRead
				t.skipping = true
				continue
			}
			used += i + 1
		default:
			lines = append(lines, string(rest[:i]))
			taken += i + 1
			used += i + 1
		}
		t.off = t.readOff + int64(used)
		if taken >= maxBytes {
			break
		}
	}
	t.readOff += int64(used)
	return lines, nil
}

// Close closes the open file, if any.
func (t *Tailer) Close() error {
	if t.f == nil {
		return nil
	}
	err := t.f.Close()
	t.f, t.buf = nil, nil
	return err
}
