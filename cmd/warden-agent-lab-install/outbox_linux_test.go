package main

// Attack and failure tests for the outbox filesystem the installer checks
// and prepares (agent-api R29, R33 "Storage", issue #42). The outbox must
// live on its own small filesystem so a full outbox can never fill the
// server's disk: the installer refuses, writing nothing, unless the mount
// point is already there, is a separate filesystem, and is within
// OUTBOX_STORAGE_BUDGET.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// assertOutboxInstalled checks the queue directory and the mount unit of a
// successful install.
func assertOutboxInstalled(t *testing.T, root string) {
	t.Helper()
	queue := filepath.Join(root, "var/lib/warden-agent/outbox/queue")
	assertDir(t, root, "var/lib/warden-agent/outbox/queue", 0o700)
	if fi, err := os.Lstat(queue); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && (int(st.Uid) != os.Getuid() || int(st.Gid) != os.Getgid()) {
			t.Errorf("queue owned by %d:%d, want the agent user", st.Uid, st.Gid)
		}
	}
	// The agent writes the first watermark on its first enrollment; the
	// installer leaves the queue empty.
	if ents, err := os.ReadDir(queue); err != nil || len(ents) != 0 {
		t.Errorf("queue not empty: %d entries, %v", len(ents), err)
	}
	unit := string(readFile(t, root, "etc/systemd/system/"+fileMountUnit, 0o644))
	for _, want := range []string{
		"What=/var/lib/warden-agent-outbox.img",
		"Where=/var/lib/warden-agent/outbox",
		"Type=ext4",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("mount unit lacks %q", want)
		}
	}
	var opts string
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "Options=") {
			opts = strings.TrimPrefix(line, "Options=")
		}
	}
	have := map[string]bool{}
	for _, o := range strings.Split(opts, ",") {
		have[strings.TrimSpace(o)] = true
	}
	for _, want := range []string{"loop", "nodev", "nosuid", "noexec"} {
		if !have[want] {
			t.Errorf("mount unit Options=%q lacks %q", opts, want)
		}
	}
}

// TestInstallRefusesOutboxFS: without a confirmed dedicated outbox
// filesystem, or with a queue already there (a reinstall must never reset
// message_seq, R29), nothing at all is written.
func TestInstallRefusesOutboxFS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		env   func(e *env)
	}{
		{"outbox mount point missing", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "var/lib/warden-agent/outbox")); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"outbox on the parent filesystem", nil, func(e *env) {
			e.outboxFS = func(int, int) (outboxFS, error) {
				return outboxFS{totalBytes: outboxBudget, separate: false}, nil
			}
		}},
		{"outbox filesystem one byte over budget", nil, func(e *env) {
			e.outboxFS = func(int, int) (outboxFS, error) {
				return outboxFS{totalBytes: outboxBudget + 1, separate: true}, nil
			}
		}},
		{"queue already exists", func(t *testing.T, root string) {
			mkdir(t, filepath.Join(root, "var/lib/warden-agent/outbox/queue"), 0o700)
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, false)
			root := newRoot(t, fx)
			if tc.setup != nil {
				tc.setup(t, root)
			}
			e := testEnv(root)
			if tc.env != nil {
				tc.env(&e)
			}
			before := snapshot(t, root)
			err := install(e, bundleRel)
			if err == nil {
				t.Fatal("install = nil, want a refusal")
			}
			assertNoSecretInError(t, fx, err)
			assertUnchanged(t, before, snapshot(t, root))
		})
	}
}
