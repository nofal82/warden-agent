package redact

// R28b fixed point and pass cap (human Go reviewer, 13th review, OQ12;
// AC72), and the R32 post-check that normalises the final output in
// E-TEXT and T-TEXT (OQ15).

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// nestedBackslash returns an item that needs exactly n changing
// normalisation passes in E-TEXT and T-TEXT, then decodes to inner:
// "&" needs one pass ("&"), and every extra "u005c" layer one more,
// because a pass decodes only the leading "\" to a backslash, which
// with the following "u005c..." forms the next escape. Built at run time.
//
//	n = 1: &
//	n = 2: \u0026 -> & -> &
//	n = 3: \u005cu0026 -> \u0026 -> & -> &
func nestedBackslash(n int, innerHex string) string {
	if n < 1 {
		panic("nestedBackslash: n < 1")
	}
	return bs + strings.Repeat("u005c", n-1) + "u" + innerHex
}

// AC72: the helper's depth arithmetic, checked by decoding one layer at a
// time with R25a's rule as the spec states it (independent of the code).
func TestNestedBackslashDepth(t *testing.T) {
	for n := 1; n <= NormMaxPasses+2; n++ {
		s := nestedBackslash(n, "0026")
		for k := 0; k < n; k++ {
			if strings.HasPrefix(s, bs+"u005c") {
				s = bs + s[len(bs+"u005c"):]
			} else if s == bs+"u0026" {
				s = "&"
			} else {
				t.Fatalf("n=%d: unexpected layer %q after %d decodes", n, s, k)
			}
		}
		if s != "&" {
			t.Errorf("n=%d: %q after %d decodes, want &", n, s, n)
		}
	}
}

// AC72: for every scanned class and every row of §4.4 (and the R25a
// escape rows), normalising the output again changes nothing and counts
// nothing.
func TestNormalizeFixedPointEveryRow(t *testing.T) {
	var inputs []string
	for _, row := range normRows() {
		inputs = append(inputs, row.in)
	}
	u := func(hex4 string) string { return bs + "u" + hex4 }
	inputs = append(inputs,
		"a"+u("0026")+"b", "a"+u("001b")+"[31mb", "a#033[31mb", "a#177b", "a#012b",
		"a"+bs+"e[1mb", "a"+bs+"x1b[0mb", "postgresql:"+bs+"/"+bs+"/db",
		"a#0"+r(0x01)+"33[31mb", "a"+nestedBackslash(2, "0026")+"b",
		"a"+nestedBackslash(NormMaxPasses-1, "0026")+"b",
		bs+bs+"u0026", bs+bs+bs+"u0026", "#"+"#033", bs+"u005c"+bs+"u005c",
		"pa"+r(0x017F)+r(0x017F)+"word", "to"+r(0x212A)+"en",
	)
	for _, in := range inputs {
		for _, c := range allNormClasses {
			once, _, err := Normalize(c, in)
			if err != nil {
				t.Errorf("%s: Normalize(%q) error %v", className(c), in, err)
				continue
			}
			twice, n2, err := Normalize(c, once)
			if err != nil {
				t.Errorf("%s: second Normalize(%q) error %v", className(c), once, err)
				continue
			}
			if twice != once {
				t.Errorf("%s: %q normalises to %q, then to %q (not a fixed point)", className(c), in, once, twice)
			}
			if n2 != (NormCounts{}) {
				t.Errorf("%s: normalising the output of %q again counted %v", className(c), in, n2)
			}
		}
	}
}

// AC72: "#0" U+0001 "33" becomes "#033" once the control character is
// removed, which then decodes to ESC and R26 removes the escape sequence.
// Each change is counted once, in the pass that makes it.
func TestNormalizeRemovalFormsEscape(t *testing.T) {
	for _, c := range []Class{EText, TText} {
		in := "a#0" + r(0x01) + "33[31mb"
		got, n, err := Normalize(c, in)
		if err != nil {
			t.Fatalf("%s: error %v", className(c), err)
		}
		if got != "ab" {
			t.Errorf("%s: Normalize(%q) = %q, want %q", className(c), in, got, "ab")
		}
		if n[NormControl] != 1 {
			t.Errorf("%s: CONTROL count %d, want exactly 1 (counted once, not per pass)", className(c), n[NormControl])
		}
		if n[NormEscape] != 1 {
			t.Errorf("%s: ESCAPE count %d, want 1", className(c), n[NormEscape])
		}
	}
}

// AC72: a decoded backslash starts a new escape: "\u0026" is "&".
func TestNormalizeDecodedBackslash(t *testing.T) {
	for _, c := range []Class{EText, TText} {
		in := "a" + nestedBackslash(2, "0026") + "b"
		got, _, err := Normalize(c, in)
		if err != nil || got != "a&b" {
			t.Errorf("%s: Normalize(%q) = (%q, %v), want a&b", className(c), in, got, err)
		}
	}
	// Not decoded outside E-TEXT and T-TEXT (R25a).
	for _, c := range []Class{TName, TPath, LValue, NPatterned} {
		in := "a" + nestedBackslash(2, "0026") + "b"
		if got, _, err := Normalize(c, in); err != nil || got != in {
			t.Errorf("%s: Normalize(%q) = (%q, %v), want it unchanged", className(c), in, got, err)
		}
	}
}

// R28b, AC72: NormMaxPasses is REDACT_NORM_MAX_PASSES (§7: 8).
func TestNormMaxPassesValue(t *testing.T) {
	if NormMaxPasses != 8 {
		t.Errorf("NormMaxPasses = %d, want 8 (§7 REDACT_NORM_MAX_PASSES)", NormMaxPasses)
	}
}

// R28b, AC72: the pass cap, at the boundary. NormMaxPasses-1 changing
// passes plus the confirming pass fit the cap and are accepted; an item
// still changing in pass NormMaxPasses is dropped with ErrNormPasses
// (reason PASS_CAP, issue #24 item 4), never ErrInternal: a crafted
// alternation must show apart from a redactor fault.
func TestNormalizePassCap(t *testing.T) {
	for _, c := range []Class{EText, TText} {
		ok := "x" + nestedBackslash(NormMaxPasses-1, "0026") + "y"
		got, _, err := Normalize(c, ok)
		if err != nil || got != "x&y" {
			t.Errorf("%s: %d changing passes: (%q, %v), want (x&y, nil)", className(c), NormMaxPasses-1, got, err)
		}
		for _, depth := range []int{NormMaxPasses, NormMaxPasses + 1, 4 * NormMaxPasses} {
			bad := "x" + nestedBackslash(depth, "0026") + "y"
			got, n, err := Normalize(c, bad)
			if !errors.Is(err, ErrNormPasses) || errors.Is(err, ErrInternal) {
				t.Errorf("%s: %d changing passes: err %v, want ErrNormPasses and not ErrInternal", className(c), depth, err)
			}
			if got != "" || n != (NormCounts{}) {
				t.Errorf("%s: %d changing passes: output %q counts %v returned with the error", className(c), depth, got, n)
			}
		}
	}
}

// adversarialAlternating builds an item that alternates control removal
// and escape decoding, so every pass changes it, for depth passes or more:
// a control character splits the first "\" (removed in pass 1, R28),
// and the rest is a nested-backslash chain (one decode per pass).
func adversarialAlternating(depth int) string {
	chain := nestedBackslash(depth, "0026")
	// "\u005" + U+0001 + "c" + rest: pass 1 only removes the control.
	return "k=" + chain[:5] + r(0x01) + chain[5:] + " end"
}

// AC72: an adversarial item deeper than the cap is dropped with
// ErrNormPasses (reason PASS_CAP, issue #24 item 4) by the redactor,
// well before the item deadline. The clock steps 2 ms per read, so a
// redactor without the cap (bounded only by the deadline, which it checks
// between passes) would return ErrDeadline instead.
func TestRedactPassCapFailsFast(t *testing.T) {
	inputs := map[string]string{
		"nested backslash at the cap":    nestedBackslash(NormMaxPasses, "0026"),
		"nested backslash far past cap":  nestedBackslash(64, "0026"),
		"alternating control and escape": adversarialAlternating(NormMaxPasses),
		"alternating, deep":              adversarialAlternating(200),
	}
	for name, in := range inputs {
		for _, c := range []Class{EText, TText} {
			fc := newFakeClock(2 * time.Millisecond)
			red := New(WithClock(fc.now))
			if err := red.Err(); err != nil {
				t.Fatalf("New: %v", err)
			}
			start := time.Now()
			out, _, err := red.Redact(bg, fieldFor(c), in, nil)
			el := time.Since(start)
			if !errors.Is(err, ErrNormPasses) || errors.Is(err, ErrInternal) || out != "" {
				t.Errorf("%s, %s: (%q, %v), want ErrNormPasses (pass cap), not the deadline or ErrInternal", name, className(c), out, err)
			}
			// A loose sanity bound only; the deterministic proof is the
			// error kind above.
			if el > ItemDeadline {
				t.Errorf("%s, %s: %v, over the item deadline %v", name, className(c), el, ItemDeadline)
			}
		}
		if out, _, err := testRedactor().RedactGroup(bg, fieldFor(TText), []string{"ok", in}, nil); !errors.Is(err, ErrNormPasses) || errors.Is(err, ErrInternal) || out != nil {
			t.Errorf("%s: RedactGroup (%v, %v), want ErrNormPasses", name, out, err)
		}
	}
}

// AC72: one changing pass fewer than the cap is accepted and scanned: the
// decoded "&" starts a secret query parameter that url-secret-param only
// sees after the chain is fully decoded.
func TestRedactPassCapBoundaryAcceptedAndScanned(t *testing.T) {
	secret := "FAKE" + randFrom(alphaAlnum, 16)
	for _, c := range []Class{EText, TText} {
		in := "GET https://h.example/x?a=1" + nestedBackslash(NormMaxPasses-1, "0026") + "token=" + secret + " ok"
		out, rep := mustRedact(t, fieldFor(c), in, nil)
		want := "GET https://h.example/x?a=1&token=" + Marker("url-secret-param") + " ok"
		if out != want {
			t.Errorf("%s: got %q, want %q", className(c), out, want)
		}
		assertNoLeak(t, className(c), out, secret)
		if rep.Replaced["url-secret-param"] != 1 {
			t.Errorf("%s: Replaced[url-secret-param] = %d, want 1", className(c), rep.Replaced["url-secret-param"])
		}
		// One more layer is over the cap: dropped, never sent.
		over := "GET https://h.example/x?a=1" + nestedBackslash(NormMaxPasses, "0026") + "token=" + secret + " ok"
		if out, _, err := testRedactor().Redact(bg, fieldFor(c), over, nil); !errors.Is(err, ErrNormPasses) || errors.Is(err, ErrInternal) || out != "" {
			t.Errorf("%s: over the cap: (%q, %v), want ErrNormPasses", className(c), out, err)
		}
	}
}

// R28b: the counters of an item are the sum over its passes; a change
// made in a later pass is counted once.
func TestNormalizeCountsSummedOverPasses(t *testing.T) {
	// Pass 1 removes the control (CONTROL 1) and a bidi mark (BIDI 1);
	// pass 2 decodes "\u001b" and removes the escape (ESCAPE 1).
	in := "a" + r(0x202E) + bs + "u00" + r(0x01) + "1b[31mb"
	got, n, err := Normalize(EText, in)
	if err != nil || got != "ab" {
		t.Fatalf("Normalize(%q) = (%q, %v), want ab", in, got, err)
	}
	want := NormCounts{}
	want[NormControl], want[NormBidi], want[NormEscape] = 1, 1, 1
	if n != want {
		t.Errorf("counts %v, want %v", n, want)
	}
}

// R32 (OQ15): in E-TEXT and T-TEXT the post-check normalises the final
// output; if that would change it, intake would read the item differently
// (R3), so it is dropped with ErrPostCheck.
//
// Construction: a stub kindIP detector (its replacement is free text, like
// public-ip's network) replaces "Q" with a text ending in a backslash, and
// the input has an "e" right after the "Q". The output then holds "\e", an
// R25a escape the input did not hold. The escape is formed with the text
// AFTER the replacement, so the OQ15 rule (which consumes escape characters
// BEFORE a written network) cannot remove it; only the post-check can.
func TestPostCheckNormalisesOutput(t *testing.T) {
	stub := detector{
		id:      "ipstub",
		kind:    kindIP,
		classes: allScanned,
		find: func(s string) ([]span, error) {
			var out []span
			for i := 0; i < len(s); i++ {
				if s[i] == 'Q' {
					out = append(out, span{start: i, end: i + 1, repl: "R" + bs})
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) { return []string{"Q"}, []string{"a"} },
	}
	red := newRedactor([]detector{stub}, WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("self-test: %v", err)
	}
	in := "xQe[31m y"
	for _, c := range []Class{EText, TText} {
		out, _, err := red.Redact(bg, fieldFor(c), in, nil)
		if !errors.Is(err, ErrPostCheck) || out != "" {
			t.Errorf("%s: (%q, %v), want ErrPostCheck and no output", className(c), out, err)
		}
	}
	if out, _, err := red.RedactGroup(bg, fieldFor(TText), []string{"ok", in}, nil); !errors.Is(err, ErrPostCheck) || out != nil {
		t.Errorf("RedactGroup: (%v, %v), want ErrPostCheck", out, err)
	}
	// R25a does not apply outside E-TEXT and T-TEXT: there the same output
	// is a fixed point and is sent.
	for _, c := range []Class{TName, TPath, LValue} {
		out, _, err := red.Redact(bg, fieldFor(c), in, nil)
		if err != nil || out != "xR"+bs+"e[31m y" {
			t.Errorf("%s: (%q, %v), want the replaced text and no error", className(c), out, err)
		}
	}
	// A replacement that forms no escape is sent.
	if out, _, err := red.Redact(bg, fieldFor(EText), "xQz y", nil); err != nil || out != "xR"+bs+"z y" {
		t.Errorf("no escape formed: (%q, %v)", out, err)
	}
}
