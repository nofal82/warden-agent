package main

// Attack and failure tests for the lab installer's file handling
// (agent-identity R3, §4.7, R34b; executor-ipc R28, R52). Every test runs
// under a t.TempDir() root with the test user standing in for root and
// for the warden-agent user.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nofal82/warden-agent/internal/identity"
)

const bundleRel = "root/bundle.json"

func testEnv(root string) env {
	return env{
		root:     root,
		rootUID:  os.Getuid(),
		rootGID:  os.Getgid(),
		agentUID: os.Getuid(),
		agentGID: os.Getgid(),
		now:      func() time.Time { return testNow },
		rand:     rand.Reader,
		// The admin mounted a dedicated filesystem within the outbox
		// budget (agent-api R33 "Storage").
		outboxFS: func(int, int) (outboxFS, error) {
			return outboxFS{totalBytes: outboxBudget, separate: true}, nil
		},
	}
}

func mkdir(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(p, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// newRoot creates the base directories install expects and writes the
// encoded fixture as root/bundle.json, mode 0600.
func newRoot(t *testing.T, fx *fixture) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "etc/systemd/system", "var/lib"} {
		mkdir(t, filepath.Join(root, d), 0o755)
	}
	mkdir(t, filepath.Join(root, "root"), 0o700)
	// The outbox mount point exists before the installer runs: the admin
	// creates and mounts the image first (root-owned, no group/other write).
	mkdir(t, filepath.Join(root, "var/lib/warden-agent"), 0o700)
	mkdir(t, filepath.Join(root, "var/lib/warden-agent/outbox"), 0o755)
	if err := os.WriteFile(filepath.Join(root, bundleRel), fx.encode(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

type entry struct {
	mode os.FileMode
	data string // file content or symlink target
}

// snapshot records every path under dir, so a test can prove nothing was
// written, changed or removed.
func snapshot(t *testing.T, dir string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := entry{mode: fi.Mode()}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			e.data, err = os.Readlink(p)
		case fi.Mode().IsRegular():
			var b []byte
			b, err = os.ReadFile(p) // #nosec G304 G122 -- reads files under the test's own temporary root, which only this test writes
			e.data = string(b)
		}
		out[p] = e
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertUnchanged(t *testing.T, before, after map[string]entry) {
	t.Helper()
	for p, a := range after {
		if b, ok := before[p]; !ok || b != a {
			t.Errorf("%s written or changed", p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("%s removed", p)
		}
	}
}

// readFile returns a regular file's content after checking its mode.
func readFile(t *testing.T, root, rel string, perm os.FileMode) []byte {
	t.Helper()
	p := filepath.Join(root, rel)
	fi, err := os.Lstat(p)
	if err != nil {
		t.Errorf("%s: %v", rel, err)
		return nil
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != perm {
		t.Errorf("%s: mode %v, want regular %v", rel, fi.Mode(), perm)
	}
	b, err := os.ReadFile(p) // #nosec G304 -- reads files under the test's own temporary root
	if err != nil {
		t.Errorf("%s: %v", rel, err)
	}
	return b
}

func assertDir(t *testing.T, root, rel string, perm os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(filepath.Join(root, rel))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != perm {
		t.Errorf("%s: %v %v, want directory %v", rel, fi, err, perm)
	}
}

func TestInstallWritesTrustAndState(t *testing.T) {
	t.Parallel()
	for _, withManifest := range []bool{false} {
		t.Run("manifest="+strconv.FormatBool(withManifest), func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, withManifest)
			root := newRoot(t, fx)
			if err := install(testEnv(root), bundleRel); err != nil {
				t.Fatalf("install = %v", err)
			}

			assertDir(t, root, "etc/warden-executor", 0o700)
			assertDir(t, root, "etc/warden-agent", 0o755)
			assertDir(t, root, "var/lib/warden-agent", 0o700)
			assertDir(t, root, "var/lib/warden-agent/identity", 0o700)

			if got := readFile(t, root, "etc/warden-executor/server-id", 0o400); string(got) != fx.serverID {
				t.Errorf("executor server-id = %q", got)
			}
			seed := readFile(t, root, "etc/warden-executor/result-key.seed", 0o400)
			if len(seed) != ed25519.SeedSize || bytes.Equal(seed, make([]byte, 32)) || bytes.Equal(seed, fx.secret) {
				t.Fatalf("seed: %d bytes, zero or equal to the secret", len(seed))
			}
			if got := readFile(t, root, "etc/warden-agent/server-id", 0o644); string(got) != fx.serverID {
				t.Errorf("agent server-id = %q", got)
			}
			ep, err := identity.ParseEndpoints(readFile(t, root, "etc/warden-agent/endpoints.json", 0o644))
			if err != nil || ep != (identity.Endpoints{Enroll: "enroll.lab.example.test:8443",
				Agent: "[2001:db8::1]:9443", ServerName: "cp.lab.example.test"}) {
				t.Errorf("endpoints.json = %+v, %v", ep, err)
			}
			agentCA := readFile(t, root, "etc/warden-agent/agent-ca.pem", 0o644)
			if _, err := identity.ParseAgentCA(agentCA); err != nil || !bytes.Equal(agentCA, fx.agentCA) {
				t.Errorf("agent-ca.pem: %v", err)
			}
			cpCA := readFile(t, root, "etc/warden-agent/controlplane-ca.pem", 0o644)
			if cas, err := identity.ParseControlPlaneCAs(cpCA); err != nil || len(cas) != 1 {
				t.Errorf("controlplane-ca.pem: %d CAs, %v", len(cas), err)
			}

			bin, err := identity.ParseExecutorBinding(readFile(t, root, "etc/warden-agent/executor-binding", 0o644))
			if err != nil {
				t.Fatalf("executor-binding: %v", err)
			}
			pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			if !bytes.Equal(bin.PublicKey[:], pub) {
				t.Errorf("binding public key is not the seed's")
			}
			m := hmac.New(sha256.New, fx.secret)
			m.Write([]byte("warden/v1/executor-key-binding\x00" + fx.serverID))
			m.Write(pub)
			if !hmac.Equal(bin.MAC[:], m.Sum(nil)) {
				t.Errorf("binding MAC does not verify with the bundle secret")
			}

			if got := readFile(t, root, "etc/warden-agent/lab-trust", 0o644); string(got) != "warden-lab-trust-m1\n" {
				t.Errorf("lab-trust = %q", got)
			}
			manifestPath := filepath.Join(root, "etc/warden-agent/bundle-manifest")
			if withManifest {
				if got := readFile(t, root, "etc/warden-agent/bundle-manifest", 0o644); !bytes.Equal(got, fx.manifest) {
					t.Errorf("bundle-manifest = %q", got)
				}
			} else if _, err := os.Lstat(manifestPath); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("bundle-manifest written without a manifest: %v", err)
			}
			if got := readFile(t, root, "var/lib/warden-agent/identity/token", 0o600); string(got) != fx.token {
				t.Errorf("token file is not exactly the 48-byte token")
			}
			if got := readFile(t, root, "var/lib/warden-agent/identity/token-expires", 0o600); string(got) != strconv.FormatInt(fx.expiresAt, 10) {
				t.Errorf("token-expires = %q", got)
			}
			unit := string(readFile(t, root, "etc/systemd/system/warden-agent-lab.service", 0o644))
			for _, want := range []string{"Restart=on-failure", "User=warden-agent", "ExecStart=/usr/local/bin/warden-agent-lab"} {
				if !strings.Contains(unit, want) {
					t.Errorf("unit lacks %q", want)
				}
			}
			for _, want := range []string{"RequiresMountsFor=/var/lib/warden-agent/outbox",
				"RuntimeDirectory=warden-agent", "RuntimeDirectoryPreserve=yes"} {
				if !strings.Contains(unit, want) {
					t.Errorf("unit lacks %q", want)
				}
			}
			assertOutboxInstalled(t, root)
			if _, err := os.Lstat(filepath.Join(root, bundleRel)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("bundle not removed: %v", err)
			}

			// R52: the secret is written nowhere; the token only to `token`.
			tokenPath := filepath.Join(root, "var/lib/warden-agent/identity/token")
			for p, e := range snapshot(t, root) {
				for _, s := range []string{fx.secretB64, string(fx.secret)} {
					if strings.Contains(e.data, s) {
						t.Errorf("%s contains the binding secret", p)
					}
				}
				if p != tokenPath && strings.Contains(e.data, fx.token[5:]) {
					t.Errorf("%s contains the token", p)
				}
			}
		})
	}
}

// TestInstallRefusesUnsafeBundle: the bundle holds the token and secret,
// so only a root-owned, private, unshared file is read (R34b).
func TestInstallRefusesUnsafeBundle(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, root string, e *env)
	}{
		{"bundle is a symlink", func(t *testing.T, root string, _ *env) {
			p := filepath.Join(root, bundleRel)
			if err := os.Rename(p, filepath.Join(root, "root/real.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.json", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"bundle group-readable", func(t *testing.T, root string, _ *env) {
			if err := os.Chmod(filepath.Join(root, bundleRel), 0o640); err != nil { // #nosec G302 -- deliberately unsafe mode: the case under test
				t.Fatal(err)
			}
		}},
		{"bundle hard-linked", func(t *testing.T, root string, _ *env) {
			if err := os.Link(filepath.Join(root, bundleRel), filepath.Join(root, "root/copy.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"bundle directory world-writable", func(t *testing.T, root string, _ *env) {
			if err := os.Chmod(filepath.Join(root, "root"), 0o777); err != nil { // #nosec G302 -- deliberately unsafe mode: the case under test
				t.Fatal(err)
			}
		}},
		{"bundle not owned by root", func(_ *testing.T, _ string, e *env) {
			e.rootUID = os.Getuid() + 1
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, false)
			root := newRoot(t, fx)
			e := testEnv(root)
			tc.setup(t, root, &e)
			before := snapshot(t, root)
			err := install(e, bundleRel)
			if !errors.Is(err, errUnsafe) {
				t.Fatalf("install = %v, want errUnsafe", err)
			}
			assertNoSecretInError(t, fx, err)
			assertUnchanged(t, before, snapshot(t, root))
		})
	}
}

// TestInstallRefusesExistingTargets: R3 and R28 forbid overwriting a
// server-ID file, a result seed or agent state; a second run changes nothing.
func TestInstallRefusesExistingTargets(t *testing.T) {
	t.Parallel()
	cases := []struct{ dir, file string }{
		{"etc/warden-executor", "server-id"},
		{"etc/warden-executor", "result-key.seed"},
		{"var/lib/warden-agent/identity", "token"},
		{"etc/systemd/system", "warden-agent-lab.service"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, false)
			root := newRoot(t, fx)
			mkdir(t, filepath.Join(root, "etc/warden-executor"), 0o700)
			mkdir(t, filepath.Join(root, "etc/warden-agent"), 0o755)
			mkdir(t, filepath.Join(root, "var/lib/warden-agent"), 0o700)
			mkdir(t, filepath.Join(root, "var/lib/warden-agent/identity"), 0o700)
			if err := os.WriteFile(filepath.Join(root, tc.dir, tc.file), []byte("FAKE-EXISTING"), 0o400); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, root)
			err := install(testEnv(root), bundleRel)
			if !errors.Is(err, errExists) {
				t.Fatalf("install = %v, want errExists", err)
			}
			assertNoSecretInError(t, fx, err)
			assertUnchanged(t, before, snapshot(t, root))
		})
	}
}

// TestInstallRefusesPlantedLinks: a symlink or a loose directory at a
// target name must not redirect a root write (R34b).
func TestInstallRefusesPlantedLinks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, root, outside string)
	}{
		{"executor-binding symlink to outside file", func(t *testing.T, root, outside string) {
			mkdir(t, filepath.Join(root, "etc/warden-agent"), 0o755)
			victim := filepath.Join(outside, "shadow")
			if err := os.WriteFile(victim, []byte("FAKE-VICTIM"), 0o644); err != nil { // #nosec G306 -- decoy file outside the root; its mode is irrelevant
				t.Fatal(err)
			}
			if err := os.Symlink(victim, filepath.Join(root, "etc/warden-agent/executor-binding")); err != nil {
				t.Fatal(err)
			}
		}},
		{"identity state dir symlink to outside dir", func(t *testing.T, root, outside string) {
			mkdir(t, filepath.Join(root, "var/lib/warden-agent"), 0o700)
			if err := os.Symlink(outside, filepath.Join(root, "var/lib/warden-agent/identity")); err != nil {
				t.Fatal(err)
			}
		}},
		{"executor dir group and other readable", func(t *testing.T, root, _ string) {
			mkdir(t, filepath.Join(root, "etc/warden-executor"), 0o755)
		}},
		{"agent config dir group-writable (R10e)", func(t *testing.T, root, _ string) {
			mkdir(t, filepath.Join(root, "etc/warden-agent"), 0o775)
		}},
		{"identity state dir mode 0755 (R34b)", func(t *testing.T, root, _ string) {
			mkdir(t, filepath.Join(root, "var/lib/warden-agent"), 0o700)
			mkdir(t, filepath.Join(root, "var/lib/warden-agent/identity"), 0o755)
		}},
		{"token symlink planted in state dir (R34b)", func(t *testing.T, root, outside string) {
			mkdir(t, filepath.Join(root, "var/lib/warden-agent"), 0o700)
			mkdir(t, filepath.Join(root, "var/lib/warden-agent/identity"), 0o700)
			if err := os.Symlink(filepath.Join(outside, "token"), filepath.Join(root, "var/lib/warden-agent/identity/token")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, false)
			root := newRoot(t, fx)
			outside := t.TempDir()
			tc.setup(t, root, outside)
			before, beforeOut := snapshot(t, root), snapshot(t, outside)
			err := install(testEnv(root), bundleRel)
			if !errors.Is(err, errUnsafe) && !errors.Is(err, errExists) {
				t.Fatalf("install = %v, want errUnsafe or errExists", err)
			}
			assertUnchanged(t, before, snapshot(t, root))
			assertUnchanged(t, beforeOut, snapshot(t, outside))
		})
	}
}

// TestInstallInvalidBundleWritesNothing: a refused bundle (here expired)
// leaves the server untouched and the bundle in place.
func TestInstallInvalidBundleWritesNothing(t *testing.T) {
	t.Parallel()
	fx := newFixture(t, false)
	fx.fields["expires_at"] = testNow.Add(-time.Second).Unix()
	root := newRoot(t, fx)
	before := snapshot(t, root)
	err := install(testEnv(root), bundleRel)
	if !errors.Is(err, errBundle) {
		t.Fatalf("install = %v, want errBundle", err)
	}
	assertNoSecretInError(t, fx, err)
	assertUnchanged(t, before, snapshot(t, root))
}
