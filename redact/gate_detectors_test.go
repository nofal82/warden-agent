package redact

// Detector fixes of the human Go reviewer's 13th review: payment-card
// candidates (S3), sk- unit names (S4), single-quoted SQL values (OQ17,
// AC68) and case folding before the keyword detectors (S6, R28a, AC73).

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// S3 (§4.2 payment-card, MA10): candidates start only at the run's first
// digit; after an accepted card the next candidate starts at the first
// group after it. A run is digit groups split by single spaces or '-'.

// cardAfterGroup returns a first group g (leadLen digits, its first digit
// from first) and a 16-digit card c laid out by sizes, such that no
// candidate from the run's first digit passes Luhn: g followed by any whole
// number of the card's groups is invalid at every length 13-19. Without S3
// the card itself (a later group) would match. Both are drawn again until
// that holds: a fixed g can make every g+c valid (Luhn is additive).
func cardAfterGroup(first string, leadLen int, sizes ...int) (g, c, laid string) {
	for {
		g = randDigitsLead(first, leadLen)
		c = makeCard("4", 16)
		laid = group(c, " ", sizes...)
		ok := true
		acc := g
		for _, part := range strings.Split(laid, " ") {
			acc += part
			if len(acc) >= 13 && len(acc) <= 19 && luhnValid(acc) {
				ok = false
			}
		}
		if ok {
			return g, c, laid
		}
	}
}

func TestPaymentCardCandidatesFromRunStart(t *testing.T) {
	m := Marker("payment-card")
	c1, c2 := makeCard("4", 16), makeCard("5", 16)
	var extra string
	for {
		extra = randDigits(3)
		if !luhnValid(c1 + extra) {
			break
		}
	}
	runE(t, []ecase{
		{"extra group after the card (MA10)", "card " + group(c1, " ", 4, 4, 4) + " " + extra + " ok.", "card " + m + " " + extra + " ok.", "payment-card"},
		{"compact card then an extra group", "card " + c1 + " " + extra + " ok.", "card " + m + " " + extra + " ok.", "payment-card"},
		{"letters right after", "card " + c1 + "XYZ ok.", "card " + m + "XYZ ok.", "payment-card"},
		{"two cards joined by a space", "cards " + c1 + " " + c2 + " ok.", "cards " + m + " " + m + " ok.", "payment-card"},
		{"two cards joined by a dash", "cards " + c1 + "-" + c2 + " ok.", "cards " + m + "-" + m + " ok.", "payment-card"},
		{"two grouped cards", "cards " + group(c1, " ", 4, 4, 4) + " " + group(c2, " ", 4, 4, 4) + " ok.", "cards " + m + " " + m + " ok.", "payment-card"},
	})
	// A Luhn-valid 16-digit window that starts at a later group of a run
	// with no card at its start is not a card.
	var cases []ecase
	for _, lead := range []struct {
		first string
		n     int
	}{{"4", 2}, {"3", 1}, {"6", 2}, {"5", 3}, {"2", 2}} {
		g, c, _ := cardAfterGroup(lead.first, lead.n)
		cases = append(cases,
			same("compact card after group "+g+" and a space", "ref "+g+" "+c+" ok."),
			same("compact card after group "+g+" and a dash", "ref "+g+"-"+c+" ok."),
		)
		g, _, grouped := cardAfterGroup(lead.first, lead.n, 4, 4, 4)
		cases = append(cases, same("grouped card after group "+g, "ref "+g+" "+grouped+" ok."))
	}
	g, c, _ := cardAfterGroup("1", 2)
	cases = append(cases, same("card after a group starting with 1", "ref "+g+" "+c+" ok."))
	runE(t, cases)
}

// The rule is the same in every class the detector runs in.
func TestPaymentCardLaterGroupAllClasses(t *testing.T) {
	g, c, _ := cardAfterGroup("4", 2)
	in := "ref " + g + " " + c + " ok"
	for _, cl := range scannedClasses {
		out, rep := mustRedact(t, fieldFor(cl), in, nil)
		if rep.Replaced["payment-card"] != 0 || out != in {
			t.Errorf("%s: %q changed to %q", className(cl), in, out)
		}
	}
}

// ---------------------------------------------------------------------------
// S4 (R33): every sk- vendor-token form skips a systemd unit name, the
// sk-ant- form included. A real-looking sk-ant- token is still redacted.
// The prefix is joined at run time ("sk-" + "ant-").

const skAnt = "sk-" + "ant-"

func TestSKAntUnitNames(t *testing.T) {
	units := []string{
		skAnt + "api-gateway-production.service",
		skAnt + strings.Repeat("payments-", 6) + "db.service", // also 40+ after "sk-"
		skAnt + randFrom(alphaLowerAlnum+"-", 30) + ".service",
	}
	for _, s := range unitSuffixes {
		units = append(units, skAnt+"billing-worker-replica."+s)
	}
	for _, u := range units {
		benignInAllClasses(t, "sk-ant unit", u)
		in := "Oct 25 10:15:30 web1 systemd[1]: Started " + u + "."
		out, rep := redactE(t, in)
		if out != in || replacedTotal(rep) != 0 {
			t.Errorf("E-TEXT %q changed to %q", in, out)
		}
		if strings.HasSuffix(u, ".service") {
			out, rep, err := testRedactor().RedactUnitName(bg, u)
			if err != nil || out != u || replacedTotal(rep) != 0 {
				t.Errorf("RedactUnitName(%q) = (%q, %v)", u, out, err)
			}
			if hit, err := testRedactor().Scan(bg, u); err != nil || hit {
				t.Errorf("Scan(%q) = (%v, %v)", u, hit, err)
			}
		}
	}
}

func TestSKAntTokenStillRedacted(t *testing.T) {
	m := Marker("vendor-token")
	alnumUD := alphaAlnum + "_-"
	tok := skAnt + "api03-" + randFrom(alnumUD, 80)
	short := skAnt + randFrom(alnumUD, 20)
	runE(t, []ecase{
		{"sk-ant token", "using " + tok + " now.", "using " + m + " now.", "vendor-token"},
		{"sk-ant 20 characters", "using " + short + " now.", "using " + m + " now.", "vendor-token"},
		same("sk-ant 19 characters", "using "+skAnt+randFrom(alphaAlnum, 19)+" now."),
		{"generic sk- unchanged", "using sk-" + randFrom(alphaAlnum, 48) + " now.", "using " + m + " now.", "vendor-token"},
		same("generic sk- unit unchanged", "Started sk-payments-db.service ok."),
	})
	// A token followed by a word that is not a unit suffix is redacted.
	out, _ := redactE(t, "using "+tok+".backup now.")
	assertNoLeak(t, "sk-ant then .backup", out, tok[len(skAnt):])
}

// ---------------------------------------------------------------------------
// OQ17 (§4.2 "Escaped quotes", AC68): a single-quoted value replaces the
// longer of the shell-style span (next ') and the SQL-style span (\' and
// '' are quotes inside the value).

func TestSQLSingleQuotedValues(t *testing.T) {
	for _, key := range []string{"IDENTIFIED BY ", "IDENTIFIED WITH mysql_native_password BY ", "PASSWORD ", "PASSWORD = ", "password=", "password: "} {
		for _, c := range []Class{EText, TText, LValue} {
			a, b := "FAKE"+randFrom(alphaAlnum, 12), "FAKE"+randFrom(alphaAlnum, 12)
			for _, v := range []string{
				"'" + a + bs + "'" + b + "'",
				"'" + a + "''" + b + "'",
				"'" + a + bs + "'" + bs + "'" + b + "'",
				"'" + a + "''''" + b + "'",
			} {
				in := "ALTER USER app " + key + v + ";"
				out, rep := mustRedact(t, fieldFor(c), in, nil)
				assertNoLeak(t, className(c)+" "+key+v, out, a, b)
				if rep.Replaced["secret-assignment"] < 1 {
					t.Errorf("%s %q: secret-assignment did not fire: %q", className(c), in, out)
				}
				if !strings.HasPrefix(out, "ALTER USER app ") || !strings.HasSuffix(out, ";") {
					t.Errorf("%s %q: text around the value changed: %q", className(c), in, out)
				}
			}
		}
	}
}

// AC68: a plain single-quoted value ends at its quote; the next pair is
// kept unchanged.
func TestSQLSingleQuotedValueKeepsNextPair(t *testing.T) {
	a := "FAKE" + randFrom(alphaAlnum, 12)
	for _, c := range []Class{EText, TText, LValue} {
		in := "password='" + a + "' user='app'"
		out, _ := mustRedact(t, fieldFor(c), in, nil)
		assertNoLeak(t, className(c), out, a)
		if want := "password='" + Marker("secret-assignment") + "' user='app'"; out != want {
			t.Errorf("%s: got %q, want %q", className(c), out, want)
		}
		// An escaped quote inside, then the next pair.
		b := "FAKE" + randFrom(alphaAlnum, 12)
		in = "password='" + a + bs + "'" + b + "' user='app'"
		out, _ = mustRedact(t, fieldFor(c), in, nil)
		assertNoLeak(t, className(c)+" escaped", out, a, b)
		if !strings.HasSuffix(out, " user='app'") {
			t.Errorf("%s: %q lost the next pair: %q", className(c), in, out)
		}
	}
}

// The double-quote rule is unchanged (OQ17 is single quotes only): a JSON
// value closes at a quote after an even number of backslashes.
func TestDoubleQuotedValueUnchangedByOQ17(t *testing.T) {
	a, b := "FAKE"+randFrom(alphaAlnum, 12), "FAKE"+randFrom(alphaAlnum, 12)
	in := `{"password":"` + a + bs + `"` + b + `","user":"app"}`
	out, _ := redactE(t, in)
	assertNoLeak(t, "json", out, a, b)
	if !strings.HasSuffix(out, `,"user":"app"}`) {
		t.Errorf("%q lost the next pair: %q", in, out)
	}
}

// ---------------------------------------------------------------------------
// S6, R28a, AC73: U+017F and U+212A are folded before detection, so RE2's
// case-insensitive key names cannot hide behind them.

func TestCaseFoldedKeyNames(t *testing.T) {
	longS, kelvin := r(0x017F), r(0x212A)
	cases := []struct {
		key, folded string
		folds       int
	}{
		{"pa" + longS + longS + "word", "password", 2},
		{"to" + kelvin + "en", "token", 1},
		{"api_" + kelvin + "ey", "api_key", 1},
		{"DB_PA" + longS + "SWORD", "DB_PAsSWORD", 1},
		{"x-api-" + kelvin + "ey", "x-api-key", 1},
		{"DB_PASSWORD", "DB_PASSWORD", 0},
	}
	for _, cs := range cases {
		for _, c := range []Class{EText, LValue, TText, TName, TPath} {
			pw := "FAKE" + randFrom(alphaAlnum, 16)
			in := cs.key + "=" + pw
			out, rep := mustRedact(t, fieldFor(c), in, nil)
			assertNoLeak(t, className(c)+" "+cs.folded, out, pw)
			if want := cs.folded + "=" + classMarker(c, "secret-assignment"); out != want {
				t.Errorf("%s: %q -> %q, want %q", className(c), in, out, want)
			}
			if rep.Normalised[NormCaseFold] != cs.folds {
				t.Errorf("%s: %q: CASE_FOLD count %d, want %d", className(c), in, rep.Normalised[NormCaseFold], cs.folds)
			}
		}
	}
}

// Folding also reaches the other keyword detectors that match on
// ASCII-lowercased text.
func TestCaseFoldedOtherKeywords(t *testing.T) {
	kelvin, longS := r(0x212A), r(0x017F)
	secret := randFrom(alphaAlnum, 24)
	for _, in := range []string{
		"Coo" + kelvin + "ie: session=" + secret,
		"Authorization: Bearer " + secret,
		"https://h.example/x?to" + kelvin + "en=" + secret,
		"aws_" + longS + "ecret_access_" + kelvin + "ey = " + secret + randFrom(alphaAWSSecret, 16),
	} {
		out, rep := redactE(t, in)
		if !rep.MarkerFired {
			t.Errorf("%q: no detector fired: %q", in, out)
		}
		assertNoLeak(t, in, out, secret)
	}
}

// AC73: the version is raised for R28a (the rule set's first version was
// 1), and CASE_FOLD is the last normalisation kind (§4.6 order).
func TestRulesVersionRaisedForCaseFold(t *testing.T) {
	if RulesVersion <= 1 {
		t.Errorf("RulesVersion = %d, want > 1 after R28a, B1, S2 and OQ15-OQ17 (R43)", RulesVersion)
	}
	if NormCaseFold <= NormControl || NormCaseFold != numNormKinds-1 {
		t.Errorf("NormCaseFold = %d: want the last kind, after NormControl (§4.6 order)", NormCaseFold)
	}
}
