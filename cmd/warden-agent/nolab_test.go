package main

// Decision 0013, "Two independent switches" and "Guards that fail closed":
// the default agent binary must not contain the lab trust path, so a build
// flag typo or a copied marker file can never turn it on. Two proofs:
//   - static: no package reachable from cmd/warden-agent is a lab package,
//     and no reachable source file names the marker path or content;
//   - binary: this test binary contains none of the lab strings. A test
//     binary's entry point is the generated test main, so the linker would
//     drop this package's main and everything only it reaches; the test
//     takes main's address (never calls it) to keep it linked, and checks
//     that internal/agent really is in the binary.
//
// The needles are stored reversed and reversed at run time, so neither
// this file nor the test binary carries them in plain form. No tool is
// run: go/build.ImportDir reads directories only.

import (
	"bufio"
	"bytes"
	"go/build"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var (
	revMarkerPath    = "tsurt-bal/tnega-nedraw/cte/"
	revMarkerContent = "\n1m-tsurt-bal-nedraw"
	revLabPkg        = "tsurtbal/tnega/lanretni/"
)

func reversed(s string) string {
	b := []byte(s)
	slices.Reverse(b)
	return string(b)
}

// repoRoot walks up from the test's directory to the directory of go.mod
// and returns it with the module path.
func repoRoot(t *testing.T) (string, string) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod")) // #nosec G304 -- go.mod of the test's own module, found from the working directory
		if err == nil {
			sc := bufio.NewScanner(bytes.NewReader(data))
			for sc.Scan() {
				if mod, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
					return dir, strings.TrimSpace(mod)
				}
			}
			t.Fatalf("no module line in %s/go.mod", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func TestNoLabPackageReachable(t *testing.T) {
	t.Parallel()
	root, mod := repoRoot(t)
	needles := []string{reversed(revMarkerPath), reversed(revMarkerContent)}
	seen := map[string]bool{}
	var visit func(rel string)
	visit = func(rel string) {
		if seen[rel] {
			return
		}
		seen[rel] = true
		if strings.Contains(strings.ToLower(rel), "lab") {
			t.Errorf("cmd/warden-agent reaches lab package %s/%s", mod, rel)
		}
		dir := filepath.Join(root, filepath.FromSlash(rel))
		pkg, err := build.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("ImportDir(%s): %v", rel, err)
		}
		for _, name := range slices.Concat(pkg.GoFiles, pkg.CgoFiles) {
			src, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- source file of a package under the repo root
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range needles {
				if bytes.Contains(src, []byte(n)) {
					t.Errorf("%s/%s contains a lab marker string", rel, name)
				}
			}
		}
		for _, imp := range pkg.Imports {
			if r, ok := strings.CutPrefix(imp, mod+"/"); ok {
				visit(r)
			}
		}
	}
	visit("cmd/warden-agent")
	// The walk must actually follow imports, or it proves nothing.
	if !seen["internal/agent"] || !seen["internal/identity"] {
		t.Fatalf("walk did not reach internal/agent and internal/identity: %v", seen)
	}
}

func TestBinaryHasNoLabPath(t *testing.T) {
	t.Parallel()
	_, mod := repoRoot(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(exe) // #nosec G304 -- the running test binary itself
	if err != nil {
		t.Fatal(err)
	}
	// Keep main and its whole import graph in this binary.
	if reflect.ValueOf(main).Pointer() == 0 {
		t.Fatal("main has no address")
	}
	if !bytes.Contains(bin, []byte(mod+"/internal/agent.")) {
		t.Fatal("binary does not link internal/agent: the scan would prove nothing")
	}
	for name, n := range map[string]string{
		"marker path":    reversed(revMarkerPath),
		"marker content": reversed(revMarkerContent),
		"lab package":    mod + reversed(revLabPkg),
	} {
		if bytes.Contains(bin, []byte(n)) {
			t.Errorf("default agent binary contains the %s", name)
		}
	}
}
