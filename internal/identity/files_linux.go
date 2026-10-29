package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

// File locations of §4.7.
const (
	ConfigDir    = "/etc/warden-agent"
	StateDirPath = "/var/lib/warden-agent/identity"
)

// State file names of §4.7. StateDir accepts no other name.
const (
	FileIdentity           = "identity.pem"
	FileIdentityPrev       = "identity.prev.pem"
	FileIdentityPendingKey = "identity.pending-key.pem"
	FileEnrollPendingKey   = "enroll.pending-key.pem"
	FileToken              = "token"
	FileTokenExpires       = "token-expires"
)

// MaxStateFileBytes bounds every state-file read.
const MaxStateFileBytes = 16 << 10

var stateFileNames = map[string]bool{
	FileIdentity:           true,
	FileIdentityPrev:       true,
	FileIdentityPendingKey: true,
	FileEnrollPendingKey:   true,
	FileToken:              true,
	FileTokenExpires:       true,
}

const (
	dirFlags  = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	readFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NOCTTY |
		syscall.O_NONBLOCK // a planted FIFO must not block the open
	tmpFlags = syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
)

// ReadRootFile reads a file the agent relies on but must never change
// (R10e), such as /etc/warden-agent/agent-ca.pem. path must be absolute and
// clean. Every directory from "/" down is opened without following
// symlinks and must be owned by root and not group- or other-writable; the
// file itself must be a regular file, not a symlink, owned by root and not
// group- or other-writable, and at most maxBytes long. The checks run on
// the opened descriptors, so the file read is the file checked.
func ReadRootFile(p string, maxBytes int64) ([]byte, error) {
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return nil, fmt.Errorf("%w: %q is not an absolute clean file path", ErrUnsafeFile, p)
	}
	return readOwnedFile("/", p[1:], 0, maxBytes)
}

// readOwnedFile is ReadRootFile with the start directory and the required
// owner as parameters, so tests can run it without root: ReadRootFile is
// readOwnedFile("/", path without its leading "/", 0, maxBytes). start is
// opened without following a symlink and checked like every directory
// below it; rel is a clean relative path ("a/b/file", no "." or ".."
// element, no empty element).
func readOwnedFile(start, rel string, owner int, maxBytes int64) ([]byte, error) {
	elems := strings.Split(rel, "/")
	for _, e := range elems {
		if e == "" || e == "." || e == ".." {
			return nil, fmt.Errorf("%w: %q is not a clean relative path", ErrUnsafeFile, rel)
		}
	}
	dfd, err := openCheckedDir(start, owner, 0o022)
	if err != nil {
		return nil, err
	}
	at := start
	for _, e := range elems[:len(elems)-1] {
		at = path.Join(at, e)
		next, err := openatCheckedDir(dfd, e, at, owner, 0o022)
		closeFD(dfd)
		if err != nil {
			return nil, err
		}
		dfd = next
	}
	defer closeFD(dfd)
	return readAt(dfd, elems[len(elems)-1], path.Join(start, rel), owner, 0o022, maxBytes)
}

// StateDir is the agent state directory (§4.7). Every operation reopens the
// directory without following a symlink and checks that it is a directory
// owned by the agent user (the process's effective uid) with no group or
// other permission bits.
type StateDir struct {
	path string
	uid  int
}

// OpenStateDir checks the directory at path and returns a handle to it. It
// refuses to run as root: the agent is never root (CLAUDE.md, R12).
func OpenStateDir(p string) (*StateDir, error) {
	uid := os.Geteuid()
	if uid == 0 {
		return nil, errors.New("identity: refusing to use the agent state directory as root")
	}
	if !path.IsAbs(p) || path.Clean(p) != p {
		return nil, fmt.Errorf("%w: %q is not an absolute clean path", ErrUnsafeFile, p)
	}
	d := &StateDir{path: p, uid: uid}
	fd, err := d.open()
	if err != nil {
		return nil, err
	}
	closeFD(fd)
	return d, nil
}

func (d *StateDir) open() (int, error) {
	return openCheckedDir(d.path, d.uid, 0o077)
}

func (d *StateDir) checkName(name string) error {
	if !stateFileNames[name] {
		return fmt.Errorf("%w: %q is not an agent state file", ErrUnsafeFile, name)
	}
	return nil
}

// ReadFile reads one §4.7 state file. It refuses a name not listed above, a
// symlink, a file that is not regular, not owned by the agent user, or has
// any group or other permission bit, and a file over MaxStateFileBytes.
func (d *StateDir) ReadFile(name string) ([]byte, error) {
	if err := d.checkName(name); err != nil {
		return nil, err
	}
	dfd, err := d.open()
	if err != nil {
		return nil, err
	}
	defer closeFD(dfd)
	return readAt(dfd, name, path.Join(d.path, name), d.uid, 0o077, MaxStateFileBytes)
}

// WriteFile replaces one §4.7 state file atomically with mode 0600: a new
// file under a random temporary name created with O_EXCL and O_NOFOLLOW,
// written, fsync'ed, renamed into place, then the directory fsync'ed. A
// crash leaves either the old file or the new one, never a partial file.
func (d *StateDir) WriteFile(name string, data []byte) error {
	if err := d.checkName(name); err != nil {
		return err
	}
	if len(data) > MaxStateFileBytes {
		return fmt.Errorf("%w: %s would be %d bytes", ErrFileTooLarge, name, len(data))
	}
	dfd, err := d.open()
	if err != nil {
		return err
	}
	defer closeFD(dfd)
	tmp, err := tempName()
	if err != nil {
		return err
	}
	if err := writeNew(dfd, tmp, data); err != nil {
		_ = syscall.Unlinkat(dfd, tmp) // best effort; the name is random and unused
		return fmt.Errorf("identity: write %s: %w", path.Join(d.path, name), err)
	}
	// rename replaces whatever is at name, a planted symlink included,
	// without following it.
	if err := syscall.Renameat(dfd, tmp, dfd, name); err != nil {
		_ = syscall.Unlinkat(dfd, tmp)
		return fmt.Errorf("identity: rename into %s: %w", path.Join(d.path, name), err)
	}
	if err := syscall.Fsync(dfd); err != nil {
		return fmt.Errorf("identity: fsync %s: %w", d.path, err)
	}
	return nil
}

// Remove removes one §4.7 state file and fsyncs the directory. A missing
// file is not an error.
func (d *StateDir) Remove(name string) error {
	if err := d.checkName(name); err != nil {
		return err
	}
	dfd, err := d.open()
	if err != nil {
		return err
	}
	defer closeFD(dfd)
	if err := syscall.Unlinkat(dfd, name); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("identity: remove %s: %w", path.Join(d.path, name), err)
	}
	if err := syscall.Fsync(dfd); err != nil {
		return fmt.Errorf("identity: fsync %s: %w", d.path, err)
	}
	return nil
}

// WriteIdentity writes identity.pem (§4.7): v's private key (PKCS #8) then
// its certificate, both PEM, through WriteFile.
func (d *StateDir) WriteIdentity(v VerifiedIdentity) error {
	if v.key == nil || v.cert == nil {
		return fmt.Errorf("%w: identity was not verified", ErrCertificateRejected)
	}
	data, err := encodeIdentity(v.key, v.cert.Raw)
	if err != nil {
		return err
	}
	defer clear(data)
	return d.WriteFile(FileIdentity, data)
}

func writeNew(dfd int, name string, data []byte) error {
	fd, err := syscall.Openat(dfd, name, tmpFlags, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	// The umask can only remove bits; set the mode exactly anyway.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func tempName() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("identity: temporary name: %w", err)
	}
	return ".tmp-" + hex.EncodeToString(b[:]), nil
}

// openCheckedDir opens p as a directory without following a final symlink
// and checks owner and forbidden mode bits on the descriptor.
func openCheckedDir(p string, owner int, forbidden uint32) (int, error) {
	fd, err := syscall.Open(p, dirFlags, 0)
	if err != nil {
		return -1, openErr(p, err)
	}
	if err := checkFD(fd, p, syscall.S_IFDIR, owner, forbidden); err != nil {
		closeFD(fd)
		return -1, err
	}
	return fd, nil
}

func openatCheckedDir(dfd int, name, display string, owner int, forbidden uint32) (int, error) {
	fd, err := syscall.Openat(dfd, name, dirFlags, 0)
	if err != nil {
		return -1, openErr(display, err)
	}
	if err := checkFD(fd, display, syscall.S_IFDIR, owner, forbidden); err != nil {
		closeFD(fd)
		return -1, err
	}
	return fd, nil
}

// readAt opens name in dfd without following a symlink, checks it on the
// descriptor and reads at most maxBytes.
func readAt(dfd int, name, display string, owner int, forbidden uint32, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Openat(dfd, name, readFlags, 0)
	if err != nil {
		return nil, openErr(display, err)
	}
	f := os.NewFile(uintptr(fd), display)
	defer func() { _ = f.Close() }()
	if err := checkFD(fd, display, syscall.S_IFREG, owner, forbidden); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", display, err)
	}
	if int64(len(data)) > maxBytes {
		clear(data)
		return nil, fmt.Errorf("%w: %s is over %d bytes", ErrFileTooLarge, display, maxBytes)
	}
	return data, nil
}

func checkFD(fd int, display string, kind uint32, owner int, forbidden uint32) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("identity: stat %s: %w", display, err)
	}
	switch {
	case st.Mode&syscall.S_IFMT != kind:
		return fmt.Errorf("%w: %s has the wrong file type", ErrUnsafeFile, display)
	case int64(st.Uid) != int64(owner):
		return fmt.Errorf("%w: %s is owned by uid %d, want %d", ErrUnsafeFile, display, st.Uid, owner)
	case st.Mode&forbidden != 0:
		return fmt.Errorf("%w: %s has mode %04o", ErrUnsafeFile, display, st.Mode&0o7777)
	}
	return nil
}

// openErr keeps "does not exist" testable with errors.Is(err,
// fs.ErrNotExist) and reports a symlink (ELOOP, or ENOTDIR for a symlink
// opened as a directory) as ErrUnsafeFile.
func openErr(display string, err error) error {
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return fmt.Errorf("%w: %s is a symlink or not a directory", ErrUnsafeFile, display)
	}
	return &os.PathError{Op: "open", Path: display, Err: err}
}

func closeFD(fd int) { _ = syscall.Close(fd) }
