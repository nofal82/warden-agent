package main

// Positive control for cmd/warden-agent/nolab_test.go: the same byte scan
// of the running test binary finds the lab package path here, so a clean
// result on the default binary means something. It takes main's address
// (never calls it) so the linker keeps main and its imports: the lab
// package must be reached through main.go, not through this test.

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var revLabPkg = "tsurtbal/tnega/lanretni/"

func reversed(s string) string {
	b := []byte(s)
	slices.Reverse(b)
	return string(b)
}

func modulePath(t *testing.T) string {
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
					return strings.TrimSpace(mod)
				}
			}
			t.Fatal("no module line in go.mod")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func TestBinaryScanFindsLabPackage(t *testing.T) {
	t.Parallel()
	if reflect.ValueOf(main).Pointer() == 0 {
		t.Fatal("main has no address")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(exe) // #nosec G304 -- the running test binary itself
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(bin, []byte(modulePath(t)+reversed(revLabPkg))) {
		t.Fatal("lab test binary does not contain the labtrust package path: the scan in nolab_test.go cannot be trusted")
	}
}
