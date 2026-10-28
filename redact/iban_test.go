package redact

// §4.2 `iban` (B1, AC75; issue #24 item 1, human Go reviewer, 14th review,
// 2026-10-28): one generic detector for every country, with no country
// table. Two uppercase letters and two digits at a word-boundary start,
// then runs of letters or digits separated by one or more spaces (any run
// length: the "groups of four only" narrowing was a regression and is
// reversed), 15-34 non-space characters, ending at a run end followed by a
// word boundary, ISO 7064 mod 97 = 1, longest valid end first. Every IBAN
// is built at run time with its check digits computed here.

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

// ibanCandidates is a reference model of the issue #24 rule, written from
// the rule's text and independent of the detector: every start of two
// capitals and two digits on a word boundary, then runs of [A-Z0-9]
// separated by one or more spaces (' ' only); a candidate ends at the end
// of a run that a word boundary follows (end of input or a non-word byte),
// holds 15-34 non-space characters and passes mod 97. A word byte after a
// run (a lowercase letter, '_') ends the scan without an end there. It
// returns every valid [start, end) pair; tests use it to reject random
// draws in which a chance candidate would make the expected output depend
// on the draw.
func ibanCandidates(s string) [][2]int {
	isRun := func(c byte) bool { return isUpper(c) || isDigitByte(c) }
	var out [][2]int
	for i := 0; i+4 <= len(s); i++ {
		if !isUpper(s[i]) || !isUpper(s[i+1]) || !isDigitByte(s[i+2]) || !isDigitByte(s[i+3]) {
			continue
		}
		if i > 0 && isWordByte(s[i-1]) {
			continue
		}
		var buf []byte
		for j := i; ; {
			for j < len(s) && isRun(s[j]) {
				buf = append(buf, s[j])
				j++
			}
			if len(buf) > 34 {
				break
			}
			if j < len(s) && isWordByte(s[j]) {
				break // glued to a word: no end here, and the scan stops
			}
			if len(buf) >= 15 && ibanValid(string(buf)) {
				out = append(out, [2]int{i, j})
			}
			k := j
			for k < len(s) && s[k] == ' ' {
				k++
			}
			if k == j || k == len(s) || !isRun(s[k]) {
				break
			}
			j = k
		}
	}
	return out
}

// ibanOrCardMarker is the marker expected where an IBAN is written: iban,
// or payment-card when a digit run inside it also passes Luhn, since the
// earlier detector names a merged span (R31, §4.2 order).
func ibanOrCardMarker(c Class, in string) string {
	if spans, _ := paymentCard().find(in); len(spans) > 0 {
		return classMarker(c, "payment-card")
	}
	return classMarker(c, "iban")
}

// Issue #24 item 1 (regression fix): spaces between runs of any length, and
// more than one space, are allowed. These layouts were left unredacted by
// the "groups of four only" shape of round 1 (the DE layout is the one
// listed in the PR #18 known limits). Every value is mod-97 valid and is
// built from fragments or at run time.
//
// Recorded residual (§6), deliberately not tested here: an IBAN glued to a
// word ("DE89...3000_ref") has no word boundary after its last run, so it
// does not match. A test asserting that it stays unredacted would lock in
// a leak; a test asserting the opposite would contradict the rule.
func TestIBANAnyRunSpacing(t *testing.T) {
	de := "DE89" + "3704" + "0044" + "0532" + "0130" + "00"
	gbFixed := "GB82" + "WEST" + "1234" + "5698" + "7654" + "32"
	for _, v := range []string{de, gbFixed} {
		if !ibanValid(v) {
			t.Fatalf("fixed example %q is not mod-97 valid", v)
		}
	}
	gb := stableIBAN(gbIBAN) // GBkk WEST 1ddd ...
	zz34 := stableIBAN(func() string { return zzIBAN(30) })
	layouts := []struct{ name, text, iban string }{
		{"DE 4 then 18", de[:4] + " " + de[4:], de},
		{"GB 8 then fours", gbFixed[:8] + " " + groupFours(gbFixed[8:]), gbFixed},
		{"GB 4, 8, fours", gbFixed[:4] + " " + gbFixed[4:12] + " " + groupFours(gbFixed[12:]), gbFixed},
		{"GB 12 then fours", gbFixed[:12] + " " + groupFours(gbFixed[12:]), gbFixed},
		{"GB 4, 4, 8, 4, 2", gbFixed[:4] + " " + gbFixed[4:8] + " " + gbFixed[8:16] + " " + gbFixed[16:20] + " " + gbFixed[20:], gbFixed},
		{"2-2 then fours", gb[:4] + " " + gb[4:6] + " " + groupFours(gb[6:]), gb},
		{"three then fours", gb[:4] + " " + gb[4:7] + " " + groupFours(gb[7:]), gb},
		{"double space", strings.Replace(groupFours(gb), " ", "  ", 1), gb},
		{"double space everywhere", strings.ReplaceAll(groupFours(gb), " ", "  "), gb},
		{"many spaces", strings.Replace(groupFours(gb), " ", strings.Repeat(" ", 9), 2), gb},
		{"34 non-space characters, uneven runs", zz34[:6] + " " + zz34[6:13] + "   " + zz34[13:], zz34},
	}
	for _, l := range layouts {
		if strings.ReplaceAll(l.text, " ", "") != l.iban {
			t.Fatalf("%s: layout %q does not hold %q", l.name, l.text, l.iban)
		}
		in := "x " + l.text + " y"
		for _, c := range []Class{EText, TText, LValue} {
			want := "x " + ibanOrCardMarker(c, in) + " y"
			out, rep := redactIn(t, c, in)
			if out != want {
				t.Errorf("%s %s: %q -> %q, want %q", l.name, className(c), in, out, want)
			}
			if rep.Replaced["iban"]+rep.Replaced["payment-card"] < 1 {
				t.Errorf("%s %s: no iban or payment-card replacement counted", l.name, className(c))
			}
			assertNoLeak(t, l.name+" "+className(c), out, l.iban[4:])
		}
	}
}

// Issue #24 item 1: the longest valid end wins. An IBAN followed by one
// more run whose addition is still mod-97 valid (and at most 34 non-space
// characters) is written as one span; round 1 stopped at the short group.
func TestIBANLongestRunEndWins(t *testing.T) {
	var gb, tail string
	for {
		gb, tail = stableIBAN(gbIBAN), randDigits(4)
		if ibanValid(gb + tail) {
			break
		}
	}
	in := "x " + groupFours(gb) + " " + tail + " y"
	for _, c := range []Class{EText, TText, LValue} {
		out, _ := redactIn(t, c, in)
		if want := "x " + ibanOrCardMarker(c, in) + " y"; out != want {
			t.Errorf("%s: %q -> %q, want %q (the longer valid end)", className(c), in, out, want)
		}
	}
}

// Issue #24 item 1, negatives: only spaces join runs; a dash or a tab (in
// E-TEXT, where a tab is kept, R27) splits the value into short tokens; the
// lower case and the BBAN alone have no country-code start; and more than
// 34 non-space characters is never one IBAN, however it is spaced.
func TestIBANSpacingNegatives(t *testing.T) {
	gb := stableIBAN(gbIBAN)
	type neg struct {
		name, text string
		classes    []Class
	}
	all := []Class{EText, TText, LValue}
	cases := []neg{
		{"dash between groups", strings.ReplaceAll(groupFours(gb), " ", "-"), all},
		{"dash between uneven runs", gb[:4] + "-" + gb[4:12] + "-" + gb[12:], all},
		{"lower case", strings.ToLower(gb), all},
		{"lower case grouped", strings.ToLower(groupFours(gb)), all},
		{"BBAN only, compact", gb[4:], all},
		{"BBAN only, grouped", groupFours(gb[4:]), all},
		// T-TEXT and L-VALUE turn a tab into a space (R27), so there it
		// is a space; E-TEXT keeps the tab.
		{"tab between groups", strings.ReplaceAll(groupFours(gb), " ", "\t"), []Class{EText}},
	}
	for _, n := range []int{35, 36, 40} {
		layout := func(v string) string { return v[:6] + " " + v[6:13] + "   " + v[13:22] + " " + v[22:] }
		var v string
		for {
			v = zzIBAN(n - 4)
			if len(ibanCandidates("iban "+layout(v)+" ok.")) == 0 && len(ibanCandidates("iban "+groupFours(v)+" ok.")) == 0 &&
				cardFree(layout(v)) {
				break
			}
		}
		cases = append(cases,
			neg{"over 34, uneven runs", layout(v), all},
			neg{"over 34, groups of four", groupFours(v), all})
	}
	for _, cs := range cases {
		in := "iban " + cs.text + " ok."
		if got := ibanCandidates(in); len(got) != 0 {
			t.Fatalf("%s: the reference model finds %v in %q: fix the case", cs.name, got, in)
		}
		for _, c := range cs.classes {
			out, rep := redactIn(t, c, in)
			if rep.Replaced["iban"] != 0 || strings.Contains(out, classMarker(c, "iban")) {
				t.Errorf("%s %s: %q matched as an IBAN: %q", cs.name, className(c), in, out)
			}
		}
	}
}

// FuzzIBANDetector compares the detector with the reference model of the
// issue #24 rule: every candidate the model accepts must be covered by a
// detector span (no leak), and every detector span must begin at a start
// the model accepts. Seeds are the layouts and attack shapes above.
func FuzzIBANDetector(f *testing.F) {
	de := "DE89" + "3704" + "0044" + "0532" + "0130" + "00"
	gb := gbIBAN()
	for _, s := range []string{
		de[:4] + " " + de[4:], groupFours(gb), strings.ReplaceAll(groupFours(gb), " ", "  "),
		gb[:4] + " " + gb[4:6] + " " + groupFours(gb[6:]), "GB82" + strings.Repeat(" ", 40) + "WEST",
		strings.ReplaceAll(groupFours(gb), " ", "-"), strings.ToLower(gb), gb + "_ref", gb + " X",
		strings.Repeat("GB82 ", 20), strings.Repeat("GB82 A ", 20), "ZZ00 " + groupFours(gb),
	} {
		f.Add("x " + s + " y")
	}
	d := iban()
	f.Fuzz(func(t *testing.T, s string) {
		spans, err := d.find(s)
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		covered := func(a, b int) bool {
			for _, sp := range spans {
				if sp.start <= a && b <= sp.end {
					return true
				}
			}
			// Overlapping spans merge (R31): accept coverage by a union.
			for p := a; p < b; p++ {
				in := false
				for _, sp := range spans {
					if sp.start <= p && p < sp.end {
						in = true
						break
					}
				}
				if !in {
					return false
				}
			}
			return true
		}
		for _, c := range ibanCandidates(s) {
			if !covered(c[0], c[1]) {
				t.Fatalf("candidate %q at [%d,%d) not covered by %v", s[c[0]:c[1]], c[0], c[1], spans)
			}
		}
		// Longest valid end per start (issue #24 item 1).
		longest := map[int]int{}
		for _, c := range ibanCandidates(s) {
			longest[c[0]] = max(longest[c[0]], c[1])
		}
		for _, sp := range spans {
			if sp.start < 0 || sp.end > len(s) || sp.start >= sp.end {
				t.Fatalf("bad span %v for %d bytes", sp, len(s))
			}
			if end, ok := longest[sp.start]; !ok || end != sp.end {
				t.Fatalf("span %q at [%d,%d): the rule's longest valid end from that start is %d (found %v)",
					s[sp.start:sp.end], sp.start, sp.end, end, ok)
			}
		}
	})
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
