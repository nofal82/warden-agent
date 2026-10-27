package redact

// R34 and R31 rulings of the 13th review: the "/N" suffix of an
// IPv4-mapped address (S2), escapes formed before a truncated network
// (OQ15) and four-part versions (OQ16); AC71.

import (
	"regexp"
	"testing"
)

// twoSuffixes finds an output holding two "/N" suffixes in a row
// ("203.0.113.0/24/24" is a defect, R34).
var twoSuffixes = regexp.MustCompile(`/[0-9]+/[0-9]`)

// ipFixedPoint redacts out again, as the post-check and intake (R45, nil
// pseudonymizer) would, and fails unless it is unchanged with zero
// replacements.
func ipFixedPoint(t *testing.T, c Class, where, out string) {
	t.Helper()
	for _, p := range []*Pseudonymizer{fuzzPseudonymizer, nil} {
		again, rep := mustRedact(t, fieldFor(c), out, p)
		if again != out {
			t.Errorf("%s %s: output %q redacted again gives %q (not a fixed point)", className(c), where, out, again)
		}
		if n := replacedTotal(rep); n != 0 || rep.MarkerFired {
			t.Errorf("%s %s: output %q redacted again reported %d replacements", className(c), where, out, n)
		}
		if again2, _, err := Normalize(c, out); err != nil || again2 != out {
			t.Errorf("%s %s: output %q is changed by normalisation: (%q, %v)", className(c), where, out, again2, err)
		}
	}
}

type ipCase struct {
	name, in, want string
	changed        bool // a public-ip replacement is expected
}

func runIPCases(t *testing.T, classes []Class, cases []ipCase) {
	t.Helper()
	for _, c := range cases {
		for _, cl := range classes {
			for _, wrap := range []struct{ pre, post string }{{"", ""}, {"client ", " GET /"}} {
				in := wrap.pre + c.in + wrap.post
				want := wrap.pre + c.want + wrap.post
				out, rep := mustRedact(t, fieldFor(cl), in, nil)
				if out != want {
					t.Errorf("%s %s: Redact(%q)\n got  %q\n want %q", className(cl), c.name, in, out, want)
				}
				if twoSuffixes.MatchString(out) {
					t.Errorf("%s %s: output %q holds two / suffixes", className(cl), c.name, out)
				}
				if got := rep.Replaced["public-ip"]; c.changed && got != 1 {
					t.Errorf("%s %s: Replaced[public-ip] = %d, want 1", className(cl), c.name, got)
				} else if !c.changed && replacedTotal(rep) != 0 {
					t.Errorf("%s %s: unchanged input reported %d replacements", className(cl), c.name, replacedTotal(rep))
				}
				if rep.MarkerFired {
					t.Errorf("%s %s: IP truncation set MarkerFired", className(cl), c.name)
				}
				ipFixedPoint(t, cl, c.name, out)
			}
		}
	}
}

// S2 (R34, AC71): an IPv4-mapped address is unmapped first and its /N is
// read against 32 bits: kept only as a valid prefix no finer than /24
// (masked), otherwise replaced with the address by the /24 network.
func TestMappedAddressSuffix(t *testing.T) {
	const m = "::ffff:"
	runIPCases(t, []Class{EText, TText}, []ipCase{
		{"mapped /24", m + "203.0.113.77/24", "203.0.113.0/24", true},
		{"mapped /0", m + "203.0.113.77/0", "0.0.0.0/0", true},
		{"mapped /120 (a 128-bit length)", m + "203.0.113.77/120", "203.0.113.0/24", true},
		{"mapped /96", m + "203.0.113.77/96", "203.0.113.0/24", true},
		{"mapped /128", m + "203.0.113.77/128", "203.0.113.0/24", true},
		{"mapped /32", m + "203.0.113.77/32", "203.0.113.0/24", true},
		{"mapped /33", m + "203.0.113.77/33", "203.0.113.0/24", true},
		{"mapped /25", m + "203.0.113.77/25", "203.0.113.0/24", true},
		{"mapped /16", m + "203.0.113.77/16", "203.0.0.0/16", true},
		{"mapped /24 then letters", m + "203.0.113.77/24abc", "203.0.113.0/24abc", true},
		{"mapped without suffix", m + "203.0.113.77", "203.0.113.0/24", true},
		{"plain /33", "203.0.113.77/33", "203.0.113.0/24", true},
		{"plain /32", "203.0.113.77/32", "203.0.113.0/24", true},
		{"plain /24 host bits", "203.0.113.77/24", "203.0.113.0/24", true},
		{"plain network /24 kept", "203.0.113.0/24", "203.0.113.0/24", false},
		{"plain network /16 kept", "203.0.0.0/16", "203.0.0.0/16", false},
		{"mapped private kept", m + "10.1.2.3/24", m + "10.1.2.3/24", false},
	})
}

// OQ15 (R31, R34, AC71): when the text before an address and the network
// written for it would form an R25a escape, the escape's characters
// before the network are consumed; text that forms no escape is kept.
func TestEscapeBeforeTruncatedNetwork(t *testing.T) {
	runIPCases(t, []Class{EText, TText}, []ipCase{
		// One backslash: "\e" would form; the backslash is consumed.
		{"one backslash", `x \E::1 y`, `x e::/48 y`, true},
		// Three: the pair "\\" stays text, the third would form "\e".
		{"three backslashes", `x \\\E::1 y`, `x \\e::/48 y`, true},
		// Two: an escaped backslash, no escape formed, nothing consumed.
		{"two backslashes", `x \\E::1 y`, `x \\e::/48 y`, true},
		// "\9" is no R25a escape: kept.
		{"backslash before a digit", `x \9.9.9.9 y`, `x \9.9.9.0/24 y`, true},
		// "#177" (DEL) would form from "#" and the unmapped network.
		{"rsyslog hash and mapped address", `x #::ffff:177.12.2.3 y`, `x 177.12.2.0/24 y`, true},
		// Only the "#" belongs to the escape "#177"; the backslash before
		// it forms none and is kept.
		{"backslash, hash and mapped address", `x \#::ffff:177.12.2.3 y`, `x \177.12.2.0/24 y`, true},
		// "#200" is not an rsyslog escape (only 000-037 and 177): kept.
		{"hash before a non-escape network", `x #::ffff:200.12.2.3 y`, `x #200.12.2.0/24 y`, true},
		// "\x1b"-like: a backslash and "x1b..." cannot come from a network;
		// "\e" with an uppercase source in a 6to4 or plain IPv6 address.
		{"backslash before IPv6 starting with e", `x \EC00::1 y`, `x ec00::/48 y`, true},
	})
}

// Fuzz regression (FuzzRedactEText corpus "\E::"): every form is a fixed
// point after redaction.
func TestEscapeBeforeNetworkFixedPointBare(t *testing.T) {
	for _, in := range []string{`\E::`, `\\\E::`, `\\E::`, `#::ffff:177.12.2.3`, `#::ffff:31.1.1.1`, `\E::1`, `\\\\\E::1`} {
		for _, c := range []Class{EText, TText} {
			out, _ := mustRedact(t, fieldFor(c), in, nil)
			ipFixedPoint(t, c, in, out)
		}
	}
}

// OQ16 (R33 exception, AC71): a four-part version that parses as a public
// IPv4 address is truncated in E-TEXT and T-TEXT; a private one is kept.
func TestFourPartVersion(t *testing.T) {
	for _, c := range []Class{EText, TText} {
		cases := []struct{ in, want string }{
			{"build 1.2.3.4 ok", "build 1.2.3.0/24 ok"},
			{"build 10.2.3.4 ok", "build 10.2.3.4 ok"},
			{"version 4.18.0.553 ok", "version 4.18.0.553 ok"}, // 553 is no IPv4 octet
		}
		for _, cs := range cases {
			out, _ := mustRedact(t, fieldFor(c), cs.in, nil)
			if out != cs.want {
				t.Errorf("%s: Redact(%q) = %q, want %q", className(c), cs.in, out, cs.want)
			}
			ipFixedPoint(t, c, cs.in, out)
		}
	}
	// T-NAME and L-VALUE never see public-ip (§4.2 "Applies to": text).
	for _, c := range []Class{TName, LValue} {
		if out, _ := mustRedact(t, fieldFor(c), "1.2.3.4", nil); out != "1.2.3.4" {
			t.Errorf("%s: a version was truncated outside text classes: %q", className(c), out)
		}
	}
	// release_version is N-PATTERNED and never sees public-ip (R16, R30).
	if out, _, err := testRedactor().RedactReleaseVersion(bg, "1.2.3"); err != nil || out != "1.2.3" {
		t.Errorf("RedactReleaseVersion(1.2.3) = (%q, %v)", out, err)
	}
}
