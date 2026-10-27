package redact

// §4.2 `iban` (B1, AC75): one generic detector for every country, with no
// country table. Two uppercase letters, two digits, then 11-30 letters or
// digits (15-34 characters without spaces), spaces only between groups of
// four, ISO 7064 mod 97 = 1. Every IBAN is built at run time with its
// check digits computed here.

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The BBANs below are chosen so that no digit run of the IBAN can start a
// payment-card candidate (a run's first digit after a hex letter, or a 1,
// or a letter group first), so the iban marker is the one written.

// maIBAN is a Moroccan IBAN (28 characters, all-digit BBAN), a country the
// first per-country table missed.
func maIBAN() string { return makeIBAN("MA", "1"+randDigits(23)) }

// snIBAN is a Senegalese IBAN (28 characters; the BBAN starts with
// letters), also missed by the first table.
func snIBAN() string { return makeIBAN("SN", "SN"+"1"+randDigits(21)) }

// zzIBAN uses a country code that is in no registry: the detector holds no
// country list, so a mod-97-valid value is still an IBAN (§6 residual:
// false positives, never false negatives by country).
func zzIBAN(bbanLen int) string { return makeIBAN("ZZ", "WEST"+"1"+randDigits(bbanLen-5)) }

// stableIBAN draws from build until, in the value grouped by four, no
// candidate other than the whole value passes mod 97 by chance, and no
// candidate at all in its broken form (ibanBreak). A candidate starts at a
// group that begins with two letters and two digits and ends on a group
// boundary, 15-34 characters long (MA10: every start and end is tried), so
// a chance hit would make the expected output depend on the random draw.
func stableIBAN(build func() string) string {
	for {
		v := build()
		// The tests also append " X": when v ends on a full group, "v X"
		// is a longer candidate of its own (MA, 28 characters).
		if ibanValid(v) && !chanceCandidate(v, true) && !chanceCandidate(ibanBreak(v), false) && !ibanValid(v+"X") &&
			!chanceCandidate(v[4:]+"X", false) && // a later start ending on " X"
			cardFree(v) && cardFree(ibanBreak(v)) {
			return v
		}
	}
}

// stableZZ is stableIBAN for a value of n characters that need not be
// valid: lengths outside 15-34 are never IBANs, whatever their check.
func stableZZ(n int) string {
	for {
		v := zzIBAN(n - 4)
		if !chanceCandidate(v, false) && cardFree(v) {
			return v
		}
	}
}

// cardFree reports that neither v nor its groups of four hold a chance
// payment-card match (every digit group start is a card candidate, S3),
// which would merge with the IBAN under the earlier payment-card marker.
func cardFree(v string) bool {
	d := paymentCard()
	for _, s := range []string{v, groupFours(v)} {
		if spans, _ := d.find(s); len(spans) > 0 {
			return false
		}
	}
	return true
}

// chanceCandidate reports a mod-97-valid candidate inside v's groups of
// four, the whole of v excepted when skipWhole is set.
func chanceCandidate(v string, skipWhole bool) bool {
	for p := 0; p+4 <= len(v); p += 4 {
		if !isUpper(v[p]) || !isUpper(v[p+1]) || !isDigitByte(v[p+2]) || !isDigitByte(v[p+3]) {
			continue
		}
		for k := p + 15; k <= len(v) && k-p <= 34; k++ {
			if k != len(v) && (k-p)%4 != 0 {
				continue // ends only on a group boundary or at the end
			}
			if skipWhole && p == 0 && k == len(v) {
				continue
			}
			if ibanValid(v[p:k]) {
				return true
			}
		}
	}
	return false
}

func redactIn(t *testing.T, c Class, in string) (string, Report) {
	t.Helper()
	return mustRedact(t, fieldFor(c), in, nil)
}

// AC75: MA, SN and GB, compact and grouped by four, in E-TEXT, T-TEXT and
// L-VALUE; one check digit changed leaves the value unchanged.
func TestIBANEveryCountry(t *testing.T) {
	values := map[string]string{
		"MA": stableIBAN(maIBAN), "SN": stableIBAN(snIBAN), "GB": stableIBAN(gbIBAN),
		"ZZ": stableIBAN(func() string { return zzIBAN(18) }), "JO": stableIBAN(joIBAN),
	}
	for country, v := range values {
		if !ibanValid(v) {
			t.Fatalf("%s: test IBAN %q is not mod-97 valid", country, v)
		}
		for _, c := range []Class{EText, TText, LValue} {
			m := classMarker(c, "iban")
			for _, form := range []struct{ name, text string }{
				{"compact", v},
				{"grouped", groupFours(v)},
				{"grouped then a token (MA10)", groupFours(v) + " X"},
			} {
				in := "iban " + form.text + " ok."
				want := "iban " + m + " ok."
				if strings.HasSuffix(form.text, " X") {
					want = "iban " + m + " X ok."
				}
				out, rep := redactIn(t, c, in)
				if out != want {
					t.Errorf("%s %s %s: got %q, want %q", country, form.name, className(c), out, want)
				}
				if rep.Replaced["iban"] != 1 {
					t.Errorf("%s %s %s: Replaced[iban] = %d, want 1", country, form.name, className(c), rep.Replaced["iban"])
				}
				assertNoLeak(t, country+" "+form.name, out, v[4:])
			}
			broken := ibanBreak(v)
			for _, form := range []string{broken, groupFours(broken)} {
				in := "iban " + form + " ok."
				out, rep := redactIn(t, c, in)
				if out != in || replacedTotal(rep) != 0 {
					t.Errorf("%s check digit changed %s: %q -> %q (%d replacements), want unchanged",
						country, className(c), in, out, replacedTotal(rep))
				}
			}
		}
	}
}

// The length bounds without spaces: 15 and 34 match, 14 and 35 do not,
// whatever the check digits.
func TestIBANLengthBounds(t *testing.T) {
	for _, c := range []Class{EText, TText, LValue} {
		for _, n := range []int{15, 16, 22, 33, 34} {
			v := stableIBAN(func() string { return zzIBAN(n - 4) })
			if len(v) != n {
				t.Fatalf("built %d characters, want %d", len(v), n)
			}
			for _, form := range []string{v, groupFours(v)} {
				out, _ := redactIn(t, c, "iban "+form+" ok.")
				if want := "iban " + classMarker(c, "iban") + " ok."; out != want {
					t.Errorf("%s: %d characters %q: got %q, want %q", className(c), n, form, out, want)
				}
			}
		}
		for _, n := range []int{9, 13, 14, 35, 36, 40} {
			v := stableZZ(n)
			for _, form := range []string{v, groupFours(v)} {
				in := "iban " + form + " ok."
				if out, rep := redactIn(t, c, in); out != in || replacedTotal(rep) != 0 {
					t.Errorf("%s: %d characters %q changed to %q", className(c), n, form, out)
				}
			}
		}
	}
}

// Spaces are allowed only between groups of four: another layout is not
// an IBAN (and no part of it is one by chance).
func TestIBANOnlyGroupsOfFour(t *testing.T) {
	var gb string
	for {
		gb = gbIBAN() // GBkk WEST 1ddd ...: gb[6:] starts "ST1d"
		if !ibanValid(gb[6:]) && !ibanValid(gb[6:len(gb)-2]) {
			break
		}
	}
	layouts := map[string]string{
		"2-2 then fours":       gb[:4] + " " + gb[4:6] + " " + groupFours(gb[6:]),
		"three then fours":     gb[:4] + " " + gb[4:7] + " " + groupFours(gb[7:]),
		"double space":         strings.Replace(groupFours(gb), " ", "  ", 1),
		"dash between groups":  strings.ReplaceAll(groupFours(gb), " ", "-"),
		"lower case":           strings.ToLower(gb),
		"letter-led BBAN only": gb[4:],
	}
	for name, l := range layouts {
		in := "iban " + l + " ok."
		for _, c := range []Class{EText, TText} {
			out, rep := redactIn(t, c, in)
			if rep.Replaced["iban"] != 0 {
				t.Errorf("%s %s: %q matched as an IBAN: %q", name, className(c), in, out)
			}
		}
	}
}

// A word boundary is required before the country code.
func TestIBANWordBoundary(t *testing.T) {
	v := gbIBAN()
	for _, in := range []string{"x" + v, "_" + v, "9" + v} {
		out, rep := redactE(t, "iban "+in+" ok.")
		if rep.Replaced["iban"] != 0 {
			t.Errorf("%q: matched without a word boundary: %q", in, out)
		}
	}
	for _, in := range []string{"(" + v + ")", "=" + v, `"` + v + `"`} {
		if out, rep := redactE(t, "iban "+in+" ok."); rep.Replaced["iban"] != 1 {
			t.Errorf("%q: not matched after a boundary: %q", in, out)
		}
	}
}

// AC75: the detector holds no country list (source scan of its tables).
// A per-country table would be a map or list of two-letter country codes;
// none may exist in the package's non-test code.
func TestIBANNoCountryTable(t *testing.T) {
	pkg := os.DirFS(".")
	files, err := fs.Glob(pkg, "*.go")
	if err != nil {
		t.Fatal(err)
	}
	mapKey := regexp.MustCompile(`"[A-Z]{2}"\s*:`)
	code := regexp.MustCompile(`"[A-Z]{2}"`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := fs.ReadFile(pkg, f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "ibanLengths") {
			t.Errorf("%s still declares or uses ibanLengths (B1)", f)
		}
		if loc := mapKey.FindIndex(src); loc != nil {
			t.Errorf("%s holds a two-letter country key %s (B1: no country table)", f, src[loc[0]:loc[1]])
		}
		if n := len(code.FindAllIndex(src, -1)); n >= 5 {
			t.Errorf("%s holds %d two-letter uppercase string literals: a country list? (B1)", f, n)
		}
	}
}

// MA10: a candidate is tried from every start, so an earlier IBAN-shaped
// token, or an invalid IBAN, cannot hide a valid one after it.
func TestIBANAfterInvalidIBAN(t *testing.T) {
	ma, sn := stableIBAN(maIBAN), stableIBAN(snIBAN)
	for _, in := range []string{
		groupFours(ibanBreak(ma)) + " " + groupFours(sn),
		ibanBreak(sn) + " " + ma,
		"ZZ00 " + groupFours(ma),
	} {
		out, _ := redactE(t, in)
		for _, v := range []string{ma, sn} {
			if strings.Contains(in, v) || strings.Contains(in, groupFours(v)) {
				if strings.Contains(out, v[4:12]) || strings.Contains(out, groupFours(v)[5:14]) {
					t.Errorf("valid IBAN left in %q -> %q", in, out)
				}
			}
		}
	}
}

// MA10, found as a flake of TestIBANAfterEarlierToken under the generic
// detector: an IBAN-shaped token before a real IBAN ("TXkk IBAN ...") can
// itself pass mod 97 with an end inside the real IBAN. If the search then
// resumes after that match, the real IBAN's start lies inside it and its
// tail is left in the output. Every start is tried and overlapping matches
// merge (R31), so no group of the real IBAN may remain. The leading
// token's check digits are computed here so that it is valid, which makes
// the case deterministic (in random data it happens about once in 97 per
// end).
func TestIBANOverlappingFalseCandidate(t *testing.T) {
	for _, overlap := range []int{8, 12, 16, 20} { // TXkk IBAN + overlap: 16-32 characters
		jo := stableIBAN(joIBAN)
		pre := makeIBAN("TX", "IBAN"+jo[:overlap]) // TXkk IBAN <first groups of jo>
		in := pre[:4] + " IBAN " + groupFours(jo) + " ok"
		for _, c := range []Class{EText, TText, LValue} {
			out, rep := redactIn(t, c, in)
			if rep.Replaced["iban"] < 1 {
				t.Errorf("%s overlap %d: no iban match in %q -> %q", className(c), overlap, in, out)
			}
			body := strings.TrimSuffix(out, " ok")
			if regexp.MustCompile(`[0-9]{2}`).MatchString(body) {
				t.Errorf("%s overlap %d: part of the IBAN left: %q -> %q", className(c), overlap, in, out)
			}
			assertNoLeak(t, className(c), out, jo)
		}
	}
}
