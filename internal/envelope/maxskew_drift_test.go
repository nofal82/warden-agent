package envelope

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// TestAgentMaxSkewMatches: the agent's advisory expiry check carries its
// own copy of MAX_SKEW (action-envelope R16), because depguard keeps the
// verifier out of the agent. This test fails when the two copies drift.
func TestAgentMaxSkewMatches(t *testing.T) {
	path := filepath.Join("..", "agent", "advisory", "advisory.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			v := s.(*ast.ValueSpec)
			for i, n := range v.Names {
				if n.Name != "maxSkew" || i >= len(v.Values) {
					continue
				}
				lit, ok := v.Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("advisory.maxSkew is not a literal")
				}
				got, err := strconv.Atoi(lit.Value)
				if err != nil || got != MaxSkew {
					t.Fatalf("advisory.maxSkew = %s, want %d (MaxSkew)", lit.Value, MaxSkew)
				}
				return
			}
		}
	}
	t.Fatal("advisory.go declares no maxSkew constant")
}
