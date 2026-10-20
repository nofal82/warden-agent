package wirescan_test

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// TestUnmarshalIsTheOnlyEntryPoint: the package exports Unmarshal and the
// sentinel errors, nothing else. Unmarshal runs the wire scan, the decode
// (with its UTF-8 check) and the unknown-field check together; any other
// exported function, method, type or variable could hand out the scan
// alone and let a caller accept bytes that are not valid UTF-8 (PR #7
// decision 1).
func TestUnmarshalIsTheOnlyEntryPoint(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	var unexpected []string
	allow := func(name string, isErrVar bool) {
		sentinel := isErrVar && strings.HasPrefix(name, "Err")
		if ast.IsExported(name) && name != "Unmarshal" && !sentinel {
			unexpected = append(unexpected, name)
		}
	}
	for _, name := range pkg.GoFiles {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				allow(d.Name.Name, false)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						allow(s.Name.Name, false)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							allow(n.Name, d.Tok == token.VAR)
						}
					}
				}
			}
		}
	}
	if len(unexpected) > 0 {
		slices.Sort(unexpected)
		t.Fatalf("exported identifiers other than Unmarshal and Err* variables: %v", unexpected)
	}
}
