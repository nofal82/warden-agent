package wirescan_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// TestUnmarshalIsTheOnlyEntryPoint: the package exports one function,
// Unmarshal, which runs the wire scan, the decode (with its UTF-8 check)
// and the unknown-field check together. A scan-only entry point would let
// a caller accept bytes that are not valid UTF-8 (PR #7 decision 1).
func TestUnmarshalIsTheOnlyEntryPoint(t *testing.T) {
	notTest := func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", notTest, 0)
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() {
					exported = append(exported, fn.Name.Name)
				}
			}
		}
	}
	if !slices.Equal(exported, []string{"Unmarshal"}) {
		t.Fatalf("exported functions = %v, want [Unmarshal]", exported)
	}
}
