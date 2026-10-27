package redact

// Findings of the security-reviewer and spec-checker round on issue #17,
// fixed before the pull request.

import (
	"strings"
	"testing"
)

// H1 (FuzzRedactTPathSmallLimit seed 6f1d8c522526cc0b): a number never
// starts or ends inside a pseudonym, so a pseudonym whose hex is all
// digits is not cut into "u-" and a marker that the next pass would read
// as a user name.
func TestNumberOverlappingPseudonymKept(t *testing.T) {
	var digits string
	for {
		// 16 digits that, with one more group, form a Luhn-valid card from
		// the pseudonym's first digit.
		c := makeCard("4", 17)
		digits = c[:16] + " " + c[16:]
		if !luhnValid(c[:16]) {
			break
		}
	}
	in := "/home/u-" + digits + "/x"
	for _, c := range []Class{EText, TText, TPath, LValue} {
		out, rep := mustRedact(t, fieldFor(c), in, nil)
		if out != in || rep.Replaced["payment-card"] != 0 {
			t.Errorf("%s: %q became %q", className(c), in, out)
		}
	}
	// A real card after the pseudonym is still found on its own.
	card := makeCard("5", 16)
	in = "/home/u-" + digits[:16] + " " + card + " ok"
	out, _ := mustRedact(t, fieldFor(EText), in, nil)
	if want := "/home/u-" + digits[:16] + " " + Marker("payment-card") + " ok"; out != want {
		t.Errorf("card after a pseudonym: got %q, want %q", out, want)
	}
}

// R12a item 2: the whole first component of a HomeRoot path is the name,
// a space included; only an exact marker that an earlier pass wrote there
// is left as it is (issue #14).
func TestHomeRootWholeFirstComponent(t *testing.T) {
	key := randKey(t)
	p := NewPseudonymizer(key)
	f := Field{Class: TPath, MaxBytes: typedMax, HomeRoot: true}
	name := "john " + c24Name()
	out, _ := mustRedact(t, f, name+"/x", p)
	if want := wantPseudonym(key, labelHomeUser, name) + "/x"; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
	in := "redacted-warden-enrollment-token x/y"
	if out, rep := mustRedact(t, f, in, p); out != in || rep.Pseudonymised != 0 {
		t.Errorf("marker prefix: %q became %q", in, out)
	}
}

// M1: a double-quoted SQL value that does not close on its line is
// replaced to the line end, never sent.
func TestSQLUnterminatedValue(t *testing.T) {
	pw := randFrom(alphaAlnum, 12)
	for _, in := range []string{
		`ALTER USER 'app'@'%' IDENTIFIED BY "` + pw + `\"`,
		`ALTER USER 'app'@'%' IDENTIFIED BY "` + pw,
		"CREATE USER x IDENTIFIED BY '" + pw + "\nnext line",
	} {
		out, _ := redactE(t, in)
		assertNoLeak(t, "unterminated SQL value", out, pw)
	}
	out, _ := redactE(t, "IDENTIFIED BY '"+pw+"\nnext line")
	if !strings.HasSuffix(out, "\nnext line") {
		t.Errorf("next line changed: %q", out)
	}
}

// M2: a unit suffix only protects an sk- form when it ends the name.
func TestSKUnitSuffixMustEndName(t *testing.T) {
	keys := []string{
		skAnt + "api03-" + randFrom(alphaAlnum, 40),
		"sk-" + "proj-" + randFrom(alphaAlnum, 40),
	}
	for _, k := range keys {
		for _, tail := range []string{".paths", ".serviceX", ".services.example.com", ".scoped", ".devices", ".service.d"} {
			out, _ := redactE(t, "key "+k+tail+" ok")
			assertNoLeak(t, "sk- form with "+tail, out, k[8:])
		}
		for _, tail := range []string{".service", ".service.", ".socket,"} {
			in := "unit " + k + tail + " ok"
			if out, _ := redactE(t, in); out != in {
				t.Errorf("unit name %q became %q", in, out)
			}
		}
	}
}
