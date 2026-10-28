package redact

// Issue #24 item 4 (human Go reviewer, 14th review, bucket 2; Nofal's
// ruling of 2026-10-28; R28b, R35, §4.6, AC72): an item dropped by the
// normalisation pass cap gets its own error, ErrNormPasses, and its own
// redact_dropped_total reason, never ERROR, so a crafted alternation of
// escapes shows apart from a redactor fault. DropReason maps every error
// of §4.9 to its §4.6 reason.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// reasonPassCap is the reason of a pass-cap drop (R28b, §4.6; human Go
// reviewer, 14th review, 2026-10-28): its own value, never ERROR.
const reasonPassCap = "PASS_CAP"

// dropReasons is the expected reason of every exported error. A new Err*
// variable that is not listed here fails TestDropReasonCoversEveryError.
var dropReasons = []struct {
	name string
	err  error
	want string
}{
	{"ErrDeadline", ErrDeadline, "TIMEOUT"},
	{"ErrBudget", ErrBudget, "BUDGET"},
	{"ErrInputTooLarge", ErrInputTooLarge, "INPUT_TOO_LARGE"},
	{"ErrOutputTooLarge", ErrOutputTooLarge, "OUTPUT_TOO_LARGE"},
	{"ErrPostCheck", ErrPostCheck, "POSTCHECK"},
	{"ErrRulesUnavailable", ErrRulesUnavailable, "RULES_UNAVAILABLE"},
	{"ErrNormPasses", ErrNormPasses, reasonPassCap},
	{"ErrInternal", ErrInternal, "ERROR"},
	{"ErrPairing", ErrPairing, "ERROR"},
}

func TestDropReasonTable(t *testing.T) {
	for _, c := range dropReasons {
		if got := DropReason(c.err); got != c.want {
			t.Errorf("DropReason(%s) = %q, want %q", c.name, got, c.want)
		}
		// errors.Is, not ==: a wrapped error keeps its reason.
		wrapped := fmt.Errorf("item 7: %w", c.err)
		if got := DropReason(wrapped); got != c.want {
			t.Errorf("DropReason(wrapped %s) = %q, want %q", c.name, got, c.want)
		}
		twice := fmt.Errorf("outer: %w", wrapped)
		if got := DropReason(twice); got != c.want {
			t.Errorf("DropReason(twice-wrapped %s) = %q, want %q", c.name, got, c.want)
		}
	}
	others := map[string]error{
		"nil":                nil,
		"unknown":            errors.New("redact: something else"),
		"wrapped unknown":    fmt.Errorf("x: %w", errors.New("y")),
		"same text, new err": errors.New(ErrNormPasses.Error()),
	}
	for name, err := range others {
		if got := DropReason(err); got != "ERROR" {
			t.Errorf("DropReason(%s) = %q, want ERROR", name, got)
		}
	}
}

// Every reason is one of §4.6's values (plus the issue #24 one), and only
// ErrNormPasses maps to it: the pass cap is never counted as ERROR.
func TestDropReasonValues(t *testing.T) {
	allowed := map[string]bool{
		"TIMEOUT": true, "BUDGET": true, "ERROR": true, "POSTCHECK": true,
		"INPUT_TOO_LARGE": true, "OUTPUT_TOO_LARGE": true, "RULES_UNAVAILABLE": true,
		reasonPassCap: true,
	}
	for _, c := range dropReasons {
		got := DropReason(c.err)
		if !allowed[got] {
			t.Errorf("DropReason(%s) = %q, not a §4.6 reason", c.name, got)
		}
		if got == reasonPassCap && !errors.Is(c.err, ErrNormPasses) {
			t.Errorf("DropReason(%s) = %q: only the pass cap has that reason", c.name, got)
		}
	}
	if errors.Is(ErrNormPasses, ErrInternal) || errors.Is(ErrInternal, ErrNormPasses) {
		t.Errorf("ErrNormPasses and ErrInternal must be distinct errors")
	}
}

// A new Err* variable cannot default to ERROR silently: every one declared
// in the package's non-test code must be in dropReasons (source scan, as
// TestIBANNoCountryTable does).
func TestDropReasonCoversEveryError(t *testing.T) {
	listed := map[string]bool{}
	for _, c := range dropReasons {
		listed[c.name] = true
	}
	pkg := os.DirFS(".")
	files, err := fs.Glob(pkg, "*.go")
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^\s*(?:var\s+)?(Err[A-Za-z0-9_]*)\s*(?:error\s*)?=`)
	found := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := fs.ReadFile(pkg, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range decl.FindAllSubmatch(src, -1) {
			found++
			if name := string(m[1]); !listed[name] {
				t.Errorf("%s declares %s, which has no entry in dropReasons: add its §4.6 reason", f, name)
			}
		}
	}
	if found < len(dropReasons) {
		t.Errorf("the source scan found %d Err* declarations, fewer than the %d listed: is the scan broken?", found, len(dropReasons))
	}
}

// passCapInputs need more than NormMaxPasses passes in E-TEXT and T-TEXT.
func passCapInputs() map[string]string {
	return map[string]string{
		"nested backslash at the cap":   nestedBackslash(NormMaxPasses, "0026"),
		"nested backslash past the cap": nestedBackslash(4*NormMaxPasses, "0026"),
		"alternating at the cap":        adversarialAlternating(NormMaxPasses),
		"alternating, deep":             adversarialAlternating(200),
	}
}

// checkPassCapErr requires ErrNormPasses, not ErrInternal, and the
// PASS_CAP reason.
func checkPassCapErr(t *testing.T, where string, err error) {
	t.Helper()
	if !errors.Is(err, ErrNormPasses) {
		t.Errorf("%s: err %v, want ErrNormPasses", where, err)
	}
	if errors.Is(err, ErrInternal) {
		t.Errorf("%s: err %v is ErrInternal: the pass cap must show apart from a fault", where, err)
	}
	if got := DropReason(err); got != reasonPassCap {
		t.Errorf("%s: DropReason = %q, want %q", where, got, reasonPassCap)
	}
}

// Through every public entry point where R25a decoding runs (E-TEXT and
// T-TEXT: Normalize, Redact, RedactGroup), an item over the pass cap gives
// ErrNormPasses, reason PASS_CAP, and no content at all.
func TestPassCapEveryEntryPoint(t *testing.T) {
	red := testRedactor()
	for name, in := range passCapInputs() {
		for _, c := range []Class{EText, TText} {
			where := name + " " + className(c)
			out, n, err := Normalize(c, "a "+in+" b")
			checkPassCapErr(t, where+" Normalize", err)
			if out != "" || n != (NormCounts{}) {
				t.Errorf("%s Normalize: output %q counts %v with the error", where, out, n)
			}
			rout, rep, err := red.Redact(bg, fieldFor(c), "a "+in+" b", nil)
			checkPassCapErr(t, where+" Redact", err)
			if rout != "" || replacedTotal(rep) != 0 {
				t.Errorf("%s Redact: output %q report %v with the error", where, rout, rep.Replaced)
			}
		}
		gout, rep, err := red.RedactGroup(bg, fieldFor(TText), []string{"first ok", "a " + in + " b", "last ok"}, nil)
		checkPassCapErr(t, name+" RedactGroup", err)
		if gout != nil || replacedTotal(rep) != 0 {
			t.Errorf("%s RedactGroup: output %q report %v with the error", name, gout, rep.Replaced)
		}
	}
}

// RedactUnitName, RedactReleaseVersion, Scan and Redact for T-NAME, T-PATH
// and L-VALUE normalise without R25a's textual escapes (they apply to
// E-TEXT and T-TEXT only). Without decoding, no removal can form a new
// character to remove, so a second pass always confirms and the pass cap
// is unreachable there: these entry points cannot return ErrNormPasses for
// the cap inputs, which stay literal text. This test pins that reasoning;
// if R25a ever extends to these classes, it fails and the entry points
// must get the pass-cap cases of TestPassCapEveryEntryPoint.
func TestPassCapUnreachableWithoutEscapes(t *testing.T) {
	red := testRedactor()
	for name, in := range passCapInputs() {
		for _, c := range []Class{TName, TPath, LValue, NPatterned} {
			if _, _, err := Normalize(c, in); err != nil {
				t.Errorf("%s %s: Normalize error %v: the pass cap is reachable outside E-TEXT and T-TEXT", name, className(c), err)
			}
		}
		for _, c := range []Class{TName, TPath, LValue} {
			if _, _, err := red.Redact(bg, fieldFor(c), in, nil); errors.Is(err, ErrNormPasses) {
				t.Errorf("%s %s: Redact gave ErrNormPasses without R25a", name, className(c))
			}
		}
		if _, _, err := red.RedactUnitName(bg, in+".service"); errors.Is(err, ErrNormPasses) {
			t.Errorf("%s: RedactUnitName gave ErrNormPasses without R25a", name)
		}
		out, _, err := red.RedactReleaseVersion(bg, "1.0.0-"+in)
		if errors.Is(err, ErrNormPasses) {
			t.Errorf("%s: RedactReleaseVersion gave ErrNormPasses without R25a", name)
		}
		if err != nil && out != ReleaseVersionMarker {
			t.Errorf("%s: RedactReleaseVersion error %v with output %q, want the marker", name, err, out)
		}
		if _, err := red.Scan(bg, in); errors.Is(err, ErrNormPasses) {
			t.Errorf("%s: Scan gave ErrNormPasses without R25a", name)
		}
	}
}

// Boundary: an item that needs exactly NormMaxPasses passes (NormMaxPasses-1
// changing passes plus the confirming one) is accepted by every entry
// point that decodes, and its decoded text is scanned.
func TestPassCapBoundaryAcceptedEveryEntryPoint(t *testing.T) {
	red := testRedactor()
	ok := "x" + nestedBackslash(NormMaxPasses-1, "0026") + "y"
	for _, c := range []Class{EText, TText} {
		if out, _, err := Normalize(c, ok); err != nil || out != "x&y" {
			t.Errorf("%s Normalize: (%q, %v), want (x&y, nil)", className(c), out, err)
		}
		if out, _, err := red.Redact(bg, fieldFor(c), ok, nil); err != nil || out != "x&y" {
			t.Errorf("%s Redact: (%q, %v), want (x&y, nil)", className(c), out, err)
		}
	}
	out, _, err := red.RedactGroup(bg, fieldFor(TText), []string{"first", ok}, nil)
	if err != nil || len(out) != 2 || out[1] != "x&y" {
		t.Errorf("RedactGroup: (%q, %v), want [first x&y]", out, err)
	}
}
