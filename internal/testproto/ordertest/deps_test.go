package ordertest_test

import (
	"errors"
	"go/build"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/nofal82/warden-agent"

// TestNoBinaryImportsTestProto: no binary under cmd/ depends on
// internal/testproto, so these rule-breaking descriptors are never
// registered in a shipped program.
func TestNoBinaryImportsTestProto(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	mains, err := filepath.Glob(filepath.Join(root, "cmd", "*"))
	if err != nil || len(mains) == 0 {
		t.Fatalf("no binaries found under cmd/: %v", err)
	}
	seen := map[string]bool{}
	var walk func(path string)
	walk = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		if strings.HasPrefix(path, module+"/internal/testproto") {
			t.Errorf("a binary depends on %s", path)
		}
		dir := filepath.Join(root, strings.TrimPrefix(path, module))
		pkg, err := build.ImportDir(dir, 0)
		var noGo *build.NoGoError
		if errors.As(err, &noGo) {
			return // a binary not written yet has no dependencies
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, imp := range pkg.Imports {
			if imp == module || strings.HasPrefix(imp, module+"/") {
				walk(imp)
			}
		}
	}
	for _, m := range mains {
		rel, err := filepath.Rel(root, m)
		if err != nil {
			t.Fatal(err)
		}
		walk(module + "/" + filepath.ToSlash(rel))
	}
	if len(seen) < len(mains) {
		t.Fatalf("walked %d packages", len(seen))
	}
}
