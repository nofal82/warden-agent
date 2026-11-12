//go:build linux

package agent_test

// Attack tests for the boot instance ID (agent-identity R31d, §4.8;
// issue #42). The ID tells the control plane that two streams come from
// two different processes, so a planted or edited file must be refused and
// never silently replaced by a fresh ID.

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nofal82/warden-agent/internal/agent"
)

var instanceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func runtimeDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadInstanceIDCreatesStableID(t *testing.T) {
	t.Parallel()
	dir := runtimeDir(t, 0o700)
	id, err := agent.LoadInstanceID(dir)
	if err != nil {
		t.Fatalf("LoadInstanceID: %v", err)
	}
	if !instanceIDPattern.MatchString(id) {
		t.Fatalf("id = %q, want 32 lowercase hex", id)
	}
	fi, err := os.Lstat(filepath.Join(dir, agent.InstanceIDFile))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("instance-id file: %v %v, want regular 0600", fi, err)
	}
	again, err := agent.LoadInstanceID(dir)
	if err != nil || again != id {
		t.Fatalf("second LoadInstanceID = %q, %v; want %q (one ID per boot)", again, err, id)
	}
}

func TestLoadInstanceIDRefuses(t *testing.T) {
	t.Parallel()
	valid := strings.Repeat("ab", 16)
	cases := []struct {
		name  string
		setup func(t *testing.T) (dir, file string)
	}{
		{"runtime dir group-readable", func(t *testing.T) (string, string) {
			return runtimeDir(t, 0o750), ""
		}},
		{"instance-id is a symlink to a valid ID", func(t *testing.T) (string, string) {
			dir := runtimeDir(t, 0o700)
			target := filepath.Join(t.TempDir(), "planted")
			if err := os.WriteFile(target, []byte(valid), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, agent.InstanceIDFile)); err != nil {
				t.Fatal(err)
			}
			return dir, ""
		}},
		{"uppercase hex", func(t *testing.T) (string, string) {
			return withIDFile(t, strings.ToUpper(valid), 0o600)
		}},
		{"trailing newline", func(t *testing.T) (string, string) {
			return withIDFile(t, valid+"\n", 0o600)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, content := tc.setup(t)
			p := filepath.Join(dir, agent.InstanceIDFile)
			beforeLink, _ := os.Readlink(p)
			id, err := agent.LoadInstanceID(dir)
			if !errors.Is(err, agent.ErrInstanceID) {
				t.Fatalf("LoadInstanceID = %q, %v; want ErrInstanceID", id, err)
			}
			if id != "" {
				t.Errorf("refusal returned id %q", id)
			}
			// Never replaced: the file (or link) is exactly as planted.
			if content != "" {
				got, rerr := os.ReadFile(p) // #nosec G304 -- the test's own temporary directory
				if rerr != nil || string(got) != content {
					t.Errorf("instance-id rewritten: %q, %v", got, rerr)
				}
			}
			if content == "" && beforeLink == "" {
				if _, serr := os.Lstat(p); !errors.Is(serr, os.ErrNotExist) {
					t.Errorf("instance-id created in an unsafe directory: %v", serr)
				}
			}
			if afterLink, _ := os.Readlink(p); afterLink != beforeLink {
				t.Errorf("symlink changed: %q -> %q", beforeLink, afterLink)
			}
		})
	}
}

func withIDFile(t *testing.T, content string, mode os.FileMode) (string, string) {
	t.Helper()
	dir := runtimeDir(t, 0o700)
	if err := os.WriteFile(filepath.Join(dir, agent.InstanceIDFile), []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return dir, content
}
