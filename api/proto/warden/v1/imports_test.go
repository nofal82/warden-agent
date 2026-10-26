package wardenv1_test

import (
	"errors"
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	module      = "github.com/nofal82/warden-agent"
	wardenv1Pkg = module + "/api/proto/warden/v1"
	agentapiPkg = module + "/api/proto/warden/agentapi/v1"
)

// repoRoot is the module root, three levels above this package.
var repoRoot = filepath.Join("..", "..", "..", "..")

// buildContext resolves packages as a static CGO_ENABLED=0 build does
// (CLAUDE.md), so cgo-only files and their imports are left out.
func buildContext() build.Context {
	ctxt := build.Default
	ctxt.CgoEnabled = false
	return ctxt
}

// resolved caches build.Import results across walks, keyed by import path
// and by whether the importer is in the standard library (which resolves
// golang.org/x packages to its own vendored copies). A nil entry is a
// package with no Go files.
var resolved = map[string]*build.Package{}

// transitiveDeps returns the import paths of path and of everything it
// imports, standard library and other modules included, recursively
// (non-test files only). A package with no Go files (a binary not written
// yet) has no dependencies.
func transitiveDeps(t *testing.T, path string) map[string]bool {
	t.Helper()
	ctxt := buildContext()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	goroot := filepath.Clean(ctxt.GOROOT) + string(filepath.Separator)
	seen := map[string]bool{}
	var walk func(path, srcDir string)
	walk = func(path, srcDir string) {
		if path == "C" || path == "unsafe" {
			seen[path] = true
			return
		}
		key := path
		if strings.HasPrefix(srcDir, goroot) {
			key += "|std"
		}
		pkg, done := resolved[key]
		if !done {
			pkg = resolve(t, ctxt, root, path, srcDir)
			resolved[key] = pkg
		}
		if pkg == nil || seen[pkg.ImportPath] {
			return
		}
		seen[pkg.ImportPath] = true
		for _, imp := range pkg.Imports {
			walk(imp, pkg.Dir)
		}
	}
	walk(path, root)
	return seen
}

// resolve finds one package. This module's own packages are read from
// their directory, like ordertest/deps_test.go does, so a directory
// without Go files is simply empty.
func resolve(t *testing.T, ctxt build.Context, root, path, srcDir string) *build.Package {
	t.Helper()
	var pkg *build.Package
	var err error
	if path == module || strings.HasPrefix(path, module+"/") {
		pkg, err = ctxt.ImportDir(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, module))), 0)
		if pkg != nil {
			pkg.ImportPath = path
		}
	} else {
		pkg, err = ctxt.Import(path, srcDir, 0)
	}
	var noGo *build.NoGoError
	if errors.As(err, &noGo) {
		return nil
	}
	if err != nil {
		t.Fatalf("import %s from %s: %v", path, srcDir, err)
	}
	return pkg
}

// forbiddenForExecutor reports whether an import path may never reach the
// executor (decision 0008 import rule; CLAUDE.md: no network imports under
// the executor; user ruling E15): the agent API, gRPC, genproto and the
// network-facing standard packages.
func forbiddenForExecutor(path string) bool {
	under := func(p string) bool { return path == p || strings.HasPrefix(path, p+"/") }
	return under(module+"/api/proto/warden/agentapi") ||
		under("google.golang.org/grpc") ||
		under("google.golang.org/genproto") ||
		under("net/http") || under("net/rpc") || under("net/smtp") ||
		under("crypto/tls")
}

// isNet reports a package of the standard net tree, vendored copies
// included.
func isNet(path string) bool {
	path = strings.TrimPrefix(path, "vendor/")
	return path == "net" || strings.HasPrefix(path, "net/")
}

func violations(deps map[string]bool, bad func(string) bool) []string {
	var out []string
	for p := range deps {
		if bad(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// executorRoots are the folders whose packages the executor links (decision
// 0008; Nofal, PR #13). required marks a folder that exists today, so its
// absence fails the test instead of silently checking nothing;
// cmd/warden-dbhelper and internal/dbhelper are added when they exist.
var executorRoots = []struct {
	dir      string
	required bool
}{
	{"cmd/warden-executor", false},
	{"internal/executor", false},
	{"internal/envelope", true},
}

// executorPackages lists every Go package that exists today under the
// executor roots, sub-packages included.
func executorPackages(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, root := range executorRoots {
		base := filepath.Join(repoRoot, filepath.FromSlash(root.dir))
		if _, err := os.Stat(base); errors.Is(err, fs.ErrNotExist) {
			if root.required {
				t.Fatalf("%s is missing; it is an executor root that must be checked", root.dir)
			}
			continue
		}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			if name := d.Name(); p != base && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			rel, err := filepath.Rel(repoRoot, p)
			if err != nil {
				return err
			}
			out = append(out, module+"/"+filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestExecutorNeverImportsAgentAPI (decision 0008, user ruling E15, PR
// #13): no package the executor links, through any chain of imports,
// reaches the agent API, gRPC, genproto, net/http, net/rpc, net/smtp or
// crypto/tls. internal/envelope and its wirescan sub-package are walked
// today; the contract package is also checked directly, since no executor
// main exists yet.
func TestExecutorNeverImportsAgentAPI(t *testing.T) {
	pkgs := executorPackages(t)
	for _, want := range []string{module + "/internal/envelope", module + "/internal/envelope/wirescan"} {
		if !slices.Contains(pkgs, want) {
			t.Errorf("executor roots did not yield %s (got %v)", want, pkgs)
		}
	}
	for _, p := range pkgs {
		deps := transitiveDeps(t, p)
		if bad := violations(deps, forbiddenForExecutor); len(bad) > 0 {
			t.Errorf("%s reaches %v", p, bad)
		}
	}
	deps := transitiveDeps(t, wardenv1Pkg)
	if !deps[wardenv1Pkg] || !deps["google.golang.org/protobuf/proto"] {
		t.Fatalf("walk of %s found too little: %d packages", wardenv1Pkg, len(deps))
	}
	if bad := violations(deps, forbiddenForExecutor); len(bad) > 0 {
		t.Errorf("%s reaches %v", wardenv1Pkg, bad)
	}
}

// TestEnvelopeWalkReachesWardenV1: the walk of internal/envelope really
// follows its imports, so a clean result above is not vacuous.
func TestEnvelopeWalkReachesWardenV1(t *testing.T) {
	deps := transitiveDeps(t, module+"/internal/envelope")
	for _, want := range []string{wardenv1Pkg, module + "/internal/envelope/wirescan", "google.golang.org/protobuf/proto"} {
		if !deps[want] {
			t.Errorf("walk of internal/envelope did not reach %s", want)
		}
	}
}

// TestWardenV1HasNoNetworkDeps: the contract package the executor links
// pulls in no package of the net tree at all, and no gRPC, genproto or
// agent API package.
func TestWardenV1HasNoNetworkDeps(t *testing.T) {
	deps := transitiveDeps(t, wardenv1Pkg)
	if bad := violations(deps, isNet); len(bad) > 0 {
		t.Errorf("%s reaches %v", wardenv1Pkg, bad)
	}
	if bad := violations(deps, forbiddenForExecutor); len(bad) > 0 {
		t.Errorf("%s reaches %v", wardenv1Pkg, bad)
	}
}

// TestImportWalkDetectsViolations: the walk is able to see a violation.
// The agent API package itself imports gRPC, which imports net and
// net/http, so walking it must report them.
func TestImportWalkDetectsViolations(t *testing.T) {
	deps := transitiveDeps(t, agentapiPkg)
	bad := violations(deps, forbiddenForExecutor)
	for _, want := range []string{agentapiPkg, "google.golang.org/grpc", "net/http", "crypto/tls"} {
		if !slices.Contains(bad, want) {
			t.Errorf("walk of %s did not report %s (reported %d)", agentapiPkg, want, len(bad))
		}
	}
	if !deps["net"] || len(violations(deps, isNet)) == 0 {
		t.Error("walk of the agent API did not reach net")
	}
	if !deps[wardenv1Pkg] {
		t.Error("walk of the agent API did not reach warden.v1, which it imports")
	}
}

// TestForbiddenMatchesWholeSegments: the rule matches whole path segments,
// so a package that only shares a prefix is not reported.
func TestForbiddenMatchesWholeSegments(t *testing.T) {
	for path, want := range map[string]bool{
		"net/http":                     true,
		"net/http/httptrace":           true,
		"net/rpc/jsonrpc":              true,
		"net/smtp":                     true,
		"crypto/tls":                   true,
		"google.golang.org/grpc":       true,
		"google.golang.org/grpc/codes": true,
		"google.golang.org/genproto/googleapis/rpc/status": true,
		module + "/api/proto/warden/agentapi/v1":           true,
		"net":                                              false,
		"net/netip":                                        false,
		"crypto/tlsx":                                      false,
		"google.golang.org/grpcx":                          false,
		"google.golang.org/protobuf":                       false,
		module + "/api/proto/warden/v1":                    false,
	} {
		if got := forbiddenForExecutor(path); got != want {
			t.Errorf("forbiddenForExecutor(%q) = %v, want %v", path, got, want)
		}
	}
	if !isNet("vendor/net/x") || isNet("netx") {
		t.Error("isNet does not match the net tree")
	}
}

// TestWardenV1ProtoImports (decision 0008): no warden.v1 .proto file
// imports warden/agentapi, and warden.v1 files import only other warden.v1
// files and google/protobuf/descriptor.proto (options.proto, agent-api
// §4.10).
func TestWardenV1ProtoImports(t *testing.T) {
	for _, f := range contractFiles(t, "warden.v1") {
		for i := 0; i < f.Imports().Len(); i++ {
			if bad := protoImportViolation(f.Imports().Get(i).Path()); bad != "" {
				t.Errorf("%s imports %s: %s", f.Path(), f.Imports().Get(i).Path(), bad)
			}
		}
	}
	opts := findFile(t, "warden/v1/options.proto")
	if opts.Imports().Len() != 1 || opts.Imports().Get(0).Path() != "google/protobuf/descriptor.proto" {
		t.Errorf("options.proto imports %d files; want only google/protobuf/descriptor.proto", opts.Imports().Len())
	}
}

func protoImportViolation(path string) string {
	switch {
	case strings.HasPrefix(path, "warden/agentapi/"):
		return "warden.v1 never imports warden.agentapi.v1"
	case strings.HasPrefix(path, "warden/v1/"), path == "google/protobuf/descriptor.proto":
		return ""
	default:
		return "not a warden/v1 file or descriptor.proto"
	}
}

func TestProtoImportViolationDetects(t *testing.T) {
	for path, bad := range map[string]bool{
		"warden/agentapi/v1/stream.proto":  true,
		"google/protobuf/any.proto":        true,
		"google/protobuf/timestamp.proto":  true,
		"warden/v1/typed_request.proto":    false,
		"google/protobuf/descriptor.proto": false,
	} {
		if got := protoImportViolation(path) != ""; got != bad {
			t.Errorf("protoImportViolation(%q) reported %v, want %v", path, got, bad)
		}
	}
}

func findFile(t *testing.T, path string) protoreflect.FileDescriptor {
	t.Helper()
	for _, f := range contractFiles(t, "warden.v1") {
		if f.Path() == path {
			return f
		}
	}
	t.Fatalf("%s not registered", path)
	return nil
}
