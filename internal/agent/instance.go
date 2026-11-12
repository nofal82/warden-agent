//go:build linux

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"

	"golang.org/x/sys/unix"
)

// Instance ID (agent-identity R31d, §4.8). The file lives in the agent's
// runtime directory, which systemd creates on a tmpfs that is cleared at
// boot (RuntimeDirectory= with RuntimeDirectoryPreserve=yes, so a restart
// keeps it): one ID per boot, never per process start.
const (
	RuntimeDir     = "/run/warden-agent"
	InstanceIDFile = "instance-id"
)

// ErrInstanceID: the runtime directory or the instance-id file is unsafe
// or holds something other than one ID.
var ErrInstanceID = errors.New("agent: instance ID")

var instanceIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

const instanceIDLen = 32

// LoadInstanceID returns this boot's instance ID from dir/instance-id,
// creating it from 16 crypto/rand bytes when it does not exist yet. dir
// must be an absolute clean path to a directory owned by the process's
// user with no group or other permissions. The file holds exactly 32
// lowercase hex characters, mode 0600; anything else is refused (never
// replaced, so a tampered file cannot be turned into a fresh ID that
// alternates with the old one).
func LoadInstanceID(dir string) (string, error) {
	if !path.IsAbs(dir) || path.Clean(dir) != dir {
		return "", fmt.Errorf("%w: %q is not an absolute clean path", ErrInstanceID, dir)
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("%w: open %s: %w", ErrInstanceID, dir, err)
	}
	defer func() { _ = unix.Close(dfd) }() // read-only descriptor
	if err := checkOwned(dfd, unix.S_IFDIR, 0o700); err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrInstanceID, dir, err)
	}
	id, err := readInstanceID(dfd)
	if !errors.Is(err, unix.ENOENT) {
		return id, err
	}
	return createInstanceID(dfd)
}

// checkOwned checks that fd is of kind, owned by this user, with no
// permission bits outside allowed.
func checkOwned(fd int, kind, allowed uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case st.Mode&unix.S_IFMT != kind:
		return errors.New("wrong file type")
	case int(st.Uid) != os.Geteuid():
		return errors.New("not owned by the agent user")
	case st.Mode&0o7777&^allowed != 0:
		return fmt.Errorf("mode %#o allows more than %#o", st.Mode&0o7777, allowed)
	}
	return nil
}

func readInstanceID(dfd int) (string, error) {
	fd, err := unix.Openat(dfd, InstanceIDFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return "", err
	}
	if err != nil {
		return "", fmt.Errorf("%w: open %s: %w", ErrInstanceID, InstanceIDFile, err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only descriptor
	if err := checkOwned(fd, unix.S_IFREG, 0o600); err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrInstanceID, InstanceIDFile, err)
	}
	var buf [instanceIDLen + 1]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %w", ErrInstanceID, InstanceIDFile, err)
	}
	id := string(buf[:n])
	if n != instanceIDLen || !instanceIDRE.MatchString(id) {
		return "", fmt.Errorf("%w: %s does not hold one instance ID", ErrInstanceID, InstanceIDFile)
	}
	return id, nil
}

// createInstanceID writes a new ID to a temporary name and renames it into
// place without replacing anything, so a crash never leaves a partial
// instance-id that would be refused until the next boot.
func createInstanceID(dfd int) (string, error) {
	var raw [16]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read never fails (Go 1.24+)
	id := hex.EncodeToString(raw[:])
	var tr [8]byte
	_, _ = rand.Read(tr[:])
	tmp := "." + InstanceIDFile + "." + hex.EncodeToString(tr[:])
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return "", fmt.Errorf("%w: create: %w", ErrInstanceID, err)
	}
	_, werr := unix.Write(fd, []byte(id))
	if werr == nil {
		werr = unix.Fsync(fd)
	}
	if cerr := unix.Close(fd); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = unix.Renameat2(dfd, tmp, dfd, InstanceIDFile, unix.RENAME_NOREPLACE)
	}
	if werr != nil {
		_ = unix.Unlinkat(dfd, tmp, 0) // best effort; the error below stands
		if errors.Is(werr, unix.EEXIST) {
			return readInstanceID(dfd)
		}
		return "", fmt.Errorf("%w: write: %w", ErrInstanceID, werr)
	}
	return id, nil
}
