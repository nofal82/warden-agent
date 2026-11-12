package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nofal82/warden-agent/internal/agent/labtrust"
	"github.com/nofal82/warden-agent/internal/identity"
)

// env is everything install depends on outside the bundle. Production uses
// root "/", uid 0 and the warden-agent user; tests use a temporary
// directory and their own uid, which is why owners are parameters.
type env struct {
	root               string
	rootUID, rootGID   int
	agentUID, agentGID int
	now                func() time.Time
	rand               io.Reader
	// outboxFS reports the filesystem of the outbox mount point (fd) and
	// whether it is a separate mount from its parent (parentFD). Nil
	// refuses: the installer never writes without a confirmed outbox
	// filesystem (agent-api R33 "Storage").
	outboxFS func(parentFD, fd int) (outboxFS, error)
}

// outboxFS is what the installer checks about the outbox's filesystem.
type outboxFS struct {
	totalBytes uint64 // statfs size of the filesystem
	separate   bool   // a different device from the parent directory
}

// The outbox's dedicated filesystem (agent-api R29, R33 "Storage"; lab
// layout, agent-packaging.md not written). The admin creates and mounts
// the image before the installer runs (cmd/warden-agent-lab/README.md);
// the installer checks it, creates the queue directory for the agent user
// and writes a mount unit so it is mounted again after a reboot. The agent
// writes the first watermark on its first enrollment.
const (
	dirOutbox     = "outbox" // inside dirAgentVar: the mount point
	dirQueue      = "queue"  // inside dirOutbox: the outbox directory
	outboxImage   = "/var/lib/warden-agent-outbox.img"
	fileMountUnit = `var-lib-warden\x2dagent-outbox.mount`
	outboxBudget  = 96 << 20 // OUTBOX_STORAGE_BUDGET
)

// Paths relative to env.root. File names not fixed by a spec
// (result-key.seed, the unit) are lab decisions recorded in the PR, since
// agent-packaging.md is not written yet.
const (
	dirExecutor  = "etc/warden-executor"  // R10 root-only 0700 (agent-identity §4.1)
	dirAgentConf = "etc/warden-agent"     // R10e, root 0755
	dirSystemd   = "etc/systemd/system"   // must exist
	dirAgentVar  = "var/lib/warden-agent" // agent user 0700
	dirState     = "identity"             // inside dirAgentVar; agent user 0700 (§4.7)
	fileSeed     = "result-key.seed"      // executor-ipc R28
	fileUnit     = "warden-agent-lab.service"
	seedSize     = ed25519.SeedSize
)

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK
	tmpFlags  = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
)

// labUnit is the lab systemd unit. The installer only writes it: starting
// it needs systemctl, and this command never runs another program.
const labUnit = `# M1 lab only (decision 0013). Written by warden-agent-lab-install; removed in M2.
[Unit]
Description=Warden agent, M1 lab build (control-plane CA trusted without a keyset)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=warden-agent
Group=warden-agent
ExecStart=/usr/local/bin/warden-agent-lab
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
LimitCORE=0
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/warden-agent
RequiresMountsFor=/var/lib/warden-agent/outbox
RuntimeDirectory=warden-agent
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
MemoryMax=128M
CPUQuota=20%
TasksMax=64

[Install]
WantedBy=multi-user.target
`

// mountUnit mounts the outbox image again after a reboot (agent-api R29:
// the outbox survives reboots). The admin creates the image and mounts it
// the first time (cmd/warden-agent-lab/README.md).
const mountUnit = `# M1 lab only (decision 0013). Written by warden-agent-lab-install; removed in M2.
[Unit]
Description=Warden agent outbox filesystem, M1 lab (agent-api R33 storage)

[Mount]
What=` + outboxImage + `
Where=/var/lib/warden-agent/outbox
Type=ext4
Options=loop,nodev,nosuid,noexec

[Install]
WantedBy=multi-user.target
`

// output is one file to write: directory, name, owner, mode, content.
type output struct {
	dir      *int
	dirName  string
	name     string
	uid, gid int
	mode     uint32
	data     []byte
}

// install reads the bundle at bundleRel (relative to e.root), validates it
// fully, checks that no target exists, then writes every file and finally
// removes the bundle. Nothing is written unless the bundle and every
// existing directory pass their checks.
func install(e env, bundleRel string) error {
	if !filepath.IsLocal(bundleRel) || path.Clean(bundleRel) != bundleRel {
		return fmt.Errorf("%w: bundle path must be clean and inside the root", errUnsafe)
	}
	rootFD, err := openDir(unix.AT_FDCWD, e.root, e.root, e.rootUID, 0o022)
	if err != nil {
		return err
	}
	defer closeFD(rootFD)

	bdirFD, err := walk(rootFD, path.Dir(bundleRel), e.rootUID, 0o022)
	if err != nil {
		return err
	}
	defer closeFD(bdirFD)
	data, st, err := readBundle(bdirFD, path.Base(bundleRel), e.rootUID)
	if err != nil {
		return err
	}
	defer clear(data)
	b, err := decodeBundle(data, e.now())
	if err != nil {
		return err
	}
	defer b.wipe()

	d, err := openTargets(rootFD, e)
	if err != nil {
		return err
	}
	defer d.close()
	if err := d.preflight(e); err != nil {
		return err
	}
	if err := d.create(e); err != nil {
		return err
	}
	if err := writeAll(d, e, b); err != nil {
		return err
	}
	return removeBundle(bdirFD, path.Base(bundleRel), st)
}

// writeAll writes the seed first, so the binding is computed over the key
// actually stored, then the trust files, the binding, the marker, the
// token files and the unit.
func writeAll(d *targets, e env, b *bundle) error {
	seed := make([]byte, seedSize)
	defer clear(seed)
	if _, err := io.ReadFull(e.rand, seed); err != nil {
		return fmt.Errorf("lab-install: result-key seed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := append([]byte(nil), priv[seedSize:]...)
	clear(priv)
	mac := bindingMAC(b.secret, b.ServerID, pub)
	b.wipe() // R52: the secret is not kept after the MAC is computed

	endpoints, err := json.Marshal(struct {
		Enroll     string `json:"enroll_endpoint"`
		Agent      string `json:"agent_endpoint"`
		ServerName string `json:"server_name"`
	}{b.Endpoints.Enroll, b.Endpoints.Agent, b.Endpoints.ServerName})
	if err != nil {
		return fmt.Errorf("lab-install: endpoints.json: %w", err)
	}
	r, a := e.rootUID, e.agentUID
	rg, ag := e.rootGID, e.agentGID
	outs := []output{
		{&d.exec, dirExecutor, fileSeed, r, rg, 0o400, seed},
		{&d.exec, dirExecutor, identity.FileServerID, r, rg, 0o400, []byte(b.ServerID)},
		{&d.conf, dirAgentConf, identity.FileServerID, r, rg, 0o644, []byte(b.ServerID)},
		{&d.conf, dirAgentConf, identity.FileEndpoints, r, rg, 0o644, endpoints},
		{&d.conf, dirAgentConf, identity.FileAgentCA, r, rg, 0o644, b.AgentCA},
		{&d.conf, dirAgentConf, identity.FileControlPlaneCA, r, rg, 0o644, b.ControlPlaneCA},
	}
	outs = append(outs,
		output{&d.conf, dirAgentConf, identity.FileExecutorBinding, r, rg, 0o644, append(pub, mac[:]...)},
		output{&d.conf, dirAgentConf, path.Base(labtrust.MarkerPath), r, rg, 0o644, []byte(labtrust.MarkerContent)},
		output{&d.state, dirStatePath, identity.FileToken, a, ag, 0o600, []byte(b.Token)},
		output{&d.state, dirStatePath, identity.FileTokenExpires, a, ag, 0o600, []byte(strconv.FormatInt(b.ExpiresAt, 10))},
		output{&d.systemd, dirSystemd, fileUnit, r, rg, 0o644, []byte(labUnit)},
		output{&d.systemd, dirSystemd, fileMountUnit, r, rg, 0o644, []byte(mountUnit)},
	)
	for _, o := range outs {
		if err := writeNoReplace(*o.dir, o.dirName, o.name, o.uid, o.gid, o.mode, o.data); err != nil {
			return err
		}
	}
	return nil
}

const (
	dirStatePath  = dirAgentVar + "/" + dirState
	dirOutboxPath = dirAgentVar + "/" + dirOutbox
)

// checkOutboxFS confirms the outbox filesystem: a separate mount from its
// parent, no larger than OUTBOX_STORAGE_BUDGET. The agent checks the size
// again at every start (outbox.Open).
func checkOutboxFS(e env, parentFD, fd int) error {
	if e.outboxFS == nil {
		return fmt.Errorf("%w: %s: outbox filesystem not confirmed", errUnsafe, dirOutboxPath)
	}
	fs, err := e.outboxFS(parentFD, fd)
	if err != nil {
		return fmt.Errorf("lab-install: %s: %w", dirOutboxPath, err)
	}
	if !fs.separate {
		return fmt.Errorf("%w: %s is not a separate filesystem; mount the outbox image first", errUnsafe, dirOutboxPath)
	}
	if fs.totalBytes == 0 || fs.totalBytes > outboxBudget {
		return fmt.Errorf("%w: %s filesystem is %d bytes, want 1 to %d", errUnsafe, dirOutboxPath, fs.totalBytes, outboxBudget)
	}
	return nil
}

// statOutboxFS is the production outboxFS: fstat of both directories for
// the device, fstatfs of the mount point for the size.
func statOutboxFS(parentFD, fd int) (outboxFS, error) {
	var p, m unix.Stat_t
	if err := unix.Fstat(parentFD, &p); err != nil {
		return outboxFS{}, err
	}
	if err := unix.Fstat(fd, &m); err != nil {
		return outboxFS{}, err
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return outboxFS{}, err
	}
	total := st.Blocks * uint64(st.Bsize) // #nosec G115 -- Bsize is a positive block size
	return outboxFS{totalBytes: total, separate: p.Dev != m.Dev}, nil
}

// targets holds the checked directory descriptors; -1 means the directory
// does not exist yet and create makes it.
type targets struct {
	etc, varLib, systemd        int
	exec, conf, agentVar, state int
	outbox, queue               int // the outbox mount point (required) and the queue in it
	outboxParent                int // agentVar, kept for the separate-mount check
}

func openTargets(rootFD int, e env) (*targets, error) {
	d := &targets{etc: -1, varLib: -1, systemd: -1, exec: -1, conf: -1, agentVar: -1, state: -1, outbox: -1, queue: -1, outboxParent: -1}
	var err error
	open := func(dst *int, parent int, rel string) {
		if err == nil {
			*dst, err = walk(parent, rel, e.rootUID, 0o022)
		}
	}
	optional := func(dst *int, parent int, name, display string, owner int, forbidden uint32) {
		if err == nil && parent >= 0 {
			*dst, err = openOptional(parent, name, display, owner, forbidden)
		}
	}
	open(&d.etc, rootFD, "etc")
	open(&d.varLib, rootFD, "var/lib")
	open(&d.systemd, rootFD, dirSystemd)
	optional(&d.exec, d.etc, "warden-executor", dirExecutor, e.rootUID, 0o077)
	optional(&d.conf, d.etc, "warden-agent", dirAgentConf, e.rootUID, 0o022)
	optional(&d.agentVar, d.varLib, "warden-agent", dirAgentVar, e.agentUID, 0o077)
	optional(&d.state, d.agentVar, dirState, dirStatePath, e.agentUID, 0o077)
	// The outbox filesystem is mounted by the admin before the installer
	// runs, so its mount point must already exist (agent-api R33 "Storage").
	if err == nil && d.agentVar < 0 {
		err = fmt.Errorf("%w: %s/%s: mount the outbox filesystem first", errUnsafe, dirAgentVar, dirOutbox)
	}
	if err == nil {
		d.outbox, err = openDir(d.agentVar, dirOutbox, dirOutboxPath, e.rootUID, 0o022)
		d.outboxParent = d.agentVar
	}
	if err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

func (d *targets) close() {
	for _, fd := range []int{d.etc, d.varLib, d.systemd, d.exec, d.conf, d.agentVar, d.state, d.outbox, d.queue} {
		closeFD(fd)
	}
}

// preflight refuses, before anything is written, when the outbox
// filesystem is not confirmed or any target name is already taken (a
// file, a directory or a symlink). An existing queue is refused too: a
// reinstall must never give the agent a fresh outbox whose message_seq
// restarts (R29).
func (d *targets) preflight(e env) error {
	if err := checkOutboxFS(e, d.outboxParent, d.outbox); err != nil {
		return err
	}
	names := []struct {
		fd      int
		dir     string
		entries []string
	}{
		{d.exec, dirExecutor, []string{fileSeed, identity.FileServerID}},
		{d.conf, dirAgentConf, []string{identity.FileServerID, identity.FileEndpoints, identity.FileAgentCA,
			identity.FileControlPlaneCA, identity.FileExecutorBinding, path.Base(labtrust.MarkerPath)}},
		{d.state, dirStatePath, []string{identity.FileToken, identity.FileTokenExpires}},
		{d.systemd, dirSystemd, []string{fileUnit, fileMountUnit}},
		{d.outbox, dirOutboxPath, []string{dirQueue}},
	}
	for _, n := range names {
		if n.fd < 0 {
			continue
		}
		for _, name := range n.entries {
			var st unix.Stat_t
			err := unix.Fstatat(n.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if err == nil {
				return fmt.Errorf("%w: %s/%s", errExists, n.dir, name)
			}
			if !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("lab-install: stat %s/%s: %w", n.dir, name, err)
			}
		}
	}
	return nil
}

// create makes the missing directories with their final owner and mode.
// Each is created by mkdirat in a checked parent, then opened without
// following a symlink and re-checked on the descriptor.
func (d *targets) create(e env) error {
	steps := []struct {
		dst      *int
		parent   *int
		name     string
		display  string
		uid, gid int
		mode     uint32
	}{
		{&d.exec, &d.etc, "warden-executor", dirExecutor, e.rootUID, e.rootGID, 0o700},
		{&d.conf, &d.etc, "warden-agent", dirAgentConf, e.rootUID, e.rootGID, 0o755},
		{&d.agentVar, &d.varLib, "warden-agent", dirAgentVar, e.agentUID, e.agentGID, 0o700},
		{&d.state, &d.agentVar, dirState, dirStatePath, e.agentUID, e.agentGID, 0o700},
		{&d.queue, &d.outbox, dirQueue, dirOutboxPath + "/" + dirQueue, e.agentUID, e.agentGID, 0o700},
	}
	for _, s := range steps {
		if *s.dst >= 0 {
			continue
		}
		fd, err := makeDir(*s.parent, s.name, s.display, s.uid, s.gid, s.mode)
		if err != nil {
			return err
		}
		*s.dst = fd
	}
	return nil
}

func makeDir(parent int, name, display string, uid, gid int, mode uint32) (int, error) {
	if err := unix.Mkdirat(parent, name, 0o700); err != nil {
		return -1, fmt.Errorf("lab-install: mkdir %s: %w", display, err)
	}
	fd, err := unix.Openat(parent, name, dirFlags, 0)
	if err != nil {
		return -1, openErr(display, err)
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		closeFD(fd)
		return -1, fmt.Errorf("lab-install: chown %s: %w", display, err)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		closeFD(fd)
		return -1, fmt.Errorf("lab-install: chmod %s: %w", display, err)
	}
	if err := checkFD(fd, display, unix.S_IFDIR, uid, ^mode&0o7777); err != nil {
		closeFD(fd)
		return -1, err
	}
	if err := unix.Fsync(parent); err != nil {
		closeFD(fd)
		return -1, fmt.Errorf("lab-install: fsync parent of %s: %w", display, err)
	}
	return fd, nil
}

// writeNoReplace writes data under a random O_EXCL temporary name, sets
// owner and mode on the descriptor, fsyncs, then renames it into place
// with RENAME_NOREPLACE, so an existing file or a symlink planted at name
// is never overwritten or followed (agent-identity R3, R34b; executor-ipc
// R28). The directory is fsynced last.
func writeNoReplace(dfd int, dir, name string, uid, gid int, mode uint32, data []byte) error {
	display := dir + "/" + name
	tmp, err := tempName()
	if err != nil {
		return err
	}
	if err := writeTemp(dfd, tmp, uid, gid, mode, data); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("lab-install: write %s: %w", display, err)
	}
	if err := unix.Renameat2(dfd, tmp, dfd, name, unix.RENAME_NOREPLACE); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s", errExists, display)
		}
		return fmt.Errorf("lab-install: rename into %s: %w", display, err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("lab-install: fsync %s: %w", dir, err)
	}
	return nil
}

func writeTemp(dfd int, name string, uid, gid int, mode uint32, data []byte) error {
	fd, err := unix.Openat(dfd, name, tmpFlags, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	if err := unix.Fchown(fd, uid, gid); err != nil {
		_ = f.Close()
		return err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
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
		return "", fmt.Errorf("lab-install: temporary name: %w", err)
	}
	return ".tmp-" + hex.EncodeToString(b[:]), nil
}

// readBundle opens the bundle without following a symlink and checks the
// descriptor: a regular file owned by root, no group or other permission
// bits (a root-only file, R11), one hard link, at most maxBundleBytes.
func readBundle(dfd int, name string, owner int) ([]byte, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat(dfd, name, readFlags, 0)
	if err != nil {
		return nil, st, openErr("bundle", err)
	}
	f := os.NewFile(uintptr(fd), "bundle")
	defer func() { _ = f.Close() }()
	if err := checkFD(fd, "bundle", unix.S_IFREG, owner, 0o077); err != nil {
		return nil, st, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, st, fmt.Errorf("lab-install: stat bundle: %w", err)
	}
	if st.Size > maxBundleBytes {
		return nil, st, fmt.Errorf("%w: over %d bytes", errBundle, maxBundleBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBundleBytes+1))
	if err != nil {
		clear(data)
		return nil, st, fmt.Errorf("lab-install: read bundle: %w", err)
	}
	if len(data) > maxBundleBytes {
		clear(data)
		return nil, st, fmt.Errorf("%w: over %d bytes", errBundle, maxBundleBytes)
	}
	return data, st, nil
}

// removeBundle unlinks the bundle only if the name still refers to the
// file that was read (same device and inode), then fsyncs the directory.
func removeBundle(dfd int, name string, read unix.Stat_t) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("lab-install: stat bundle before removal: %w", err)
	}
	if st.Dev != read.Dev || st.Ino != read.Ino {
		return fmt.Errorf("%w: bundle was replaced while installing; remove it by hand", errUnsafe)
	}
	if err := unix.Unlinkat(dfd, name, 0); err != nil {
		return fmt.Errorf("lab-install: remove bundle: %w", err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("lab-install: fsync bundle directory: %w", err)
	}
	return nil
}

// walk opens rel below dfd one component at a time, never following a
// symlink, and checks each directory: owner, and none of the forbidden
// mode bits. rel "." returns a duplicate of dfd.
func walk(dfd int, rel string, owner int, forbidden uint32) (int, error) {
	cur, err := unix.Dup(dfd)
	if err != nil {
		return -1, fmt.Errorf("lab-install: dup: %w", err)
	}
	if rel == "." {
		return cur, nil
	}
	display := ""
	for _, part := range strings.Split(rel, "/") {
		display = path.Join(display, part)
		next, err := openDir(cur, part, display, owner, forbidden)
		closeFD(cur)
		if err != nil {
			return -1, err
		}
		cur = next
	}
	return cur, nil
}

// openOptional is openDir that returns -1 without error when name does not
// exist.
func openOptional(dfd int, name, display string, owner int, forbidden uint32) (int, error) {
	fd, err := openDir(dfd, name, display, owner, forbidden)
	if errors.Is(err, os.ErrNotExist) {
		return -1, nil
	}
	return fd, err
}

func openDir(dfd int, name, display string, owner int, forbidden uint32) (int, error) {
	fd, err := unix.Openat(dfd, name, dirFlags, 0)
	if err != nil {
		return -1, openErr(display, err)
	}
	if err := checkFD(fd, display, unix.S_IFDIR, owner, forbidden); err != nil {
		closeFD(fd)
		return -1, err
	}
	return fd, nil
}

func checkFD(fd int, display string, kind uint32, owner int, forbidden uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("lab-install: stat %s: %w", display, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != kind:
		return fmt.Errorf("%w: %s has the wrong file type", errUnsafe, display)
	case int64(st.Uid) != int64(owner):
		return fmt.Errorf("%w: %s is owned by uid %d, want %d", errUnsafe, display, st.Uid, owner)
	case st.Mode&forbidden != 0:
		return fmt.Errorf("%w: %s has mode %04o", errUnsafe, display, st.Mode&0o7777)
	case kind == unix.S_IFREG && st.Nlink != 1:
		return fmt.Errorf("%w: %s has %d hard links", errUnsafe, display, st.Nlink)
	}
	return nil
}

// openErr reports a symlink (ELOOP, or ENOTDIR for a symlink opened as a
// directory) as errUnsafe and keeps "does not exist" testable with
// errors.Is(err, os.ErrNotExist).
func openErr(display string, err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("%w: %s is a symlink or not a directory", errUnsafe, display)
	}
	return &os.PathError{Op: "open", Path: display, Err: err}
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}
