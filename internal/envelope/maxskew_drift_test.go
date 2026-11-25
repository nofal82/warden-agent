package envelope

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// TestMaxSkewDrift (agent-api AC52): MAX_SKEW (action-envelope R16) has
// three runtime copies in this repository: MaxSkew here, identity.MaxSkew
// (certificate validity, R15) and the agent's advisory copy, which depguard
// keeps out of this package. The contract records the value once, as the
// max_skew_seconds option on EnvelopeBody (agent-api §4.10, 50102). No
// binary reads the option; this test fails when any copy differs from it.
// The two other copies are read from source so no test import crosses the
// boundaries depguard enforces.
func TestMaxSkewDrift(t *testing.T) {
	opts := (&wardenv1.EnvelopeBody{}).ProtoReflect().Descriptor().Options()
	if !proto.HasExtension(opts, wardenv1.E_MaxSkewSeconds) {
		t.Fatal("EnvelopeBody has no max_skew_seconds option (agent-api §4.10, 50102)")
	}
	want := int(proto.GetExtension(opts, wardenv1.E_MaxSkewSeconds).(uint32))
	if want != 60 {
		t.Errorf("EnvelopeBody max_skew_seconds = %d, want 60 (action-envelope R16)", want)
	}
	if MaxSkew != want {
		t.Errorf("envelope.MaxSkew = %d, want %d (max_skew_seconds)", MaxSkew, want)
	}
	if got := constSeconds(t, filepath.Join("..", "agent", "advisory", "advisory.go"), "maxSkew", ""); got != want {
		t.Errorf("advisory.maxSkew = %d, want %d (max_skew_seconds)", got, want)
	}
	if got := constSeconds(t, filepath.Join("..", "identity", "verify.go"), "MaxSkew", "Second"); got != want {
		t.Errorf("identity.MaxSkew = %d s, want %d (max_skew_seconds)", got, want)
	}
}

// constSeconds returns the value of the constant name declared in file. With
// unit "" it must be an integer literal; with unit "Second" it must be
// written as <literal> * time.Second. Any other form fails the test, so a
// rewrite of the constant cannot silently escape the check.
func constSeconds(t *testing.T, file, name, unit string) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
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
				if n.Name != name || i >= len(v.Values) {
					continue
				}
				return secondsOf(t, file, name, unit, v.Values[i])
			}
		}
	}
	t.Fatalf("%s declares no %s constant", file, name)
	return 0
}

func secondsOf(t *testing.T, file, name, unit string, e ast.Expr) int {
	t.Helper()
	if unit != "" {
		lit, ok := scaledBy(e, unit)
		if !ok {
			t.Fatalf("%s: %s is not written as <literal> * time.%s", file, name, unit)
		}
		e = lit
	}
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		t.Fatalf("%s: %s is not an integer literal", file, name)
	}
	n, err := strconv.Atoi(lit.Value)
	if err != nil {
		t.Fatalf("%s: %s: %v", file, name, err)
	}
	return n
}

// scaledBy matches <x> * time.<unit> and returns x.
func scaledBy(e ast.Expr, unit string) (ast.Expr, bool) {
	b, ok := e.(*ast.BinaryExpr)
	if !ok || b.Op != token.MUL {
		return nil, false
	}
	s, ok := b.Y.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != unit {
		return nil, false
	}
	if x, ok := s.X.(*ast.Ident); !ok || x.Name != "time" {
		return nil, false
	}
	return b.X, true
}
