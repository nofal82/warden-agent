package logs

import (
	"errors"

	"golang.org/x/sys/unix"
)

// busySuffix names the marker that exists while lines are being redacted.
// It is created and removed without fsync: it only has to survive a
// process crash (R9a), which leaves the page cache intact; after a power
// loss the restart is simply not counted.
const busySuffix = ".busy"

// setBusy creates the marker; false when it could not be created (the
// restart then goes uncounted, the lines are still handled).
func setBusy(path string) bool {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return false
	}
	_ = unix.Close(fd) // empty file: nothing to flush
	return true
}

func clearBusy(path string) { _ = unix.Unlink(path) } // a leftover only over-counts one restart

// busyLeft reports and removes a marker left by a previous process. Only
// a regular file counts; anything else at the path is left alone.
func busyLeft(path string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != unix.Geteuid() {
		return false
	}
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return true // counted; the next start may count it again
	}
	return true
}
