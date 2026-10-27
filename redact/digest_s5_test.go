package redact

// S5 (human Go reviewer, 13th review; R43, §4.5, AC70): the rule-set
// digest is taken from what the detectors run. A change to one compiled
// pattern, one normalisation table row, one validator table entry or the
// pass cap changes it; and R28a's fold table equals the set Go's
// unicode.SimpleFold derives.
//
// The drift cases mutate a package variable and restore it at cleanup;
// none of these tests may call t.Parallel.

import (
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"testing"
	"unicode"
)

func currentDigest() string { return digestOf(canonicalRuleTable(ruleTable())) }

// S5: the detector struct carries no hand-written description of its
// patterns (the old canon field); the digest input is res and tables.
func TestDetectorHasNoDescriptionField(t *testing.T) {
	typ := reflect.TypeOf(detector{})
	if _, ok := typ.FieldByName("canon"); ok {
		t.Errorf("detector still has a canon field: a description beside the patterns (S5)")
	}
	for _, name := range []string{"res", "tables"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("detector has no %s field", name)
		}
	}
}

// Every detector exposes at least one compiled expression it runs, and no
// nil one.
func TestEveryDetectorExposesItsPatterns(t *testing.T) {
	for _, d := range defaultRules() {
		if len(d.res) == 0 {
			t.Errorf("%s: no compiled expression in res", d.id)
		}
		for i, re := range d.res {
			if re == nil {
				t.Errorf("%s: res[%d] is nil", d.id, i)
			}
		}
	}
}

// The digest is a function of the table: stable across calls, and the
// committed constant (TestRulesDigestIsCurrent checks equality).
func TestCanonicalRuleTableStable(t *testing.T) {
	a, b := currentDigest(), currentDigest()
	if a != b {
		t.Fatalf("canonical rule table is not deterministic: %s then %s", a, b)
	}
	if digestOf(canonicalRuleTable(defaultRules())) != a {
		t.Errorf("a copy of the rule table hashes differently")
	}
}

// mutatedSource returns src with a one-character change that still
// compiles: one character replaced in place, or else one appended.
func mutatedSources(src string) []string {
	var out []string
	for i := len(src) / 2; i < len(src); i++ {
		for _, c := range []byte{'Q', 'q', '7'} {
			if src[i] == c {
				continue
			}
			m := src[:i] + string(c) + src[i+1:]
			if _, err := regexp.Compile(m); err == nil && m != src {
				out = append(out, m)
				break
			}
		}
		if len(out) > 0 {
			break
		}
	}
	return append(out, src+"x")
}

// AC70 (S5): a one-character change to any one compiled pattern of any
// detector, made without touching anything else, changes the digest.
func TestDigestMutationEveryPattern(t *testing.T) {
	base := currentDigest()
	rules := defaultRules()
	for k, d := range rules {
		for i, re := range d.res {
			for _, src := range mutatedSources(re.String()) {
				mut := defaultRules()
				mut[k].res = slices.Clone(d.res)
				mut[k].res[i] = regexp.MustCompile(src)
				if digestOf(canonicalRuleTable(mut)) == base {
					t.Errorf("%s res[%d]: changing %q to %q left the digest unchanged", d.id, i, re.String(), src)
				}
			}
		}
		// A validator table entry of the detector, and its flags.
		if len(d.tables) > 0 {
			mut := defaultRules()
			mut[k].tables = slices.Clone(d.tables)
			mut[k].tables[0] += "x"
			if digestOf(canonicalRuleTable(mut)) == base {
				t.Errorf("%s: changing tables[0] left the digest unchanged", d.id)
			}
		}
		mut := defaultRules()
		mut[k].extend = !mut[k].extend
		if digestOf(canonicalRuleTable(mut)) == base {
			t.Errorf("%s: flipping extend left the digest unchanged", d.id)
		}
	}
	// Order is part of the table (§4.2 order decides merges, R31).
	swapped := defaultRules()
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if digestOf(canonicalRuleTable(swapped)) == base {
		t.Errorf("reordering two detectors left the digest unchanged")
	}
}

// drift mutates one package table through set, checks the digest changed,
// and restores the table at cleanup (set returns the restore function).
func drift(t *testing.T, name string, set func() (restore func())) {
	t.Helper()
	base := currentDigest()
	restore := set()
	t.Cleanup(restore)
	if currentDigest() == base {
		t.Errorf("%s: changing it left the digest unchanged (R43)", name)
	}
	restore()
	if currentDigest() != base {
		t.Fatalf("%s: restoring it did not restore the digest", name)
	}
}

// AC70: the drift test fails when one R25a escape, one R26 removed range,
// one R27 line end, one R28a fold, the pass cap, one unit suffix, one
// keyword or one kept IP range changes without regenerating.
func TestDigestDriftTables(t *testing.T) {
	drift(t, "R25a escape", func() func() {
		old := simpleEscapes
		simpleEscapes = slices.Clone(old)
		simpleEscapes[0].text = bs + "|"
		return func() { simpleEscapes = old }
	})
	drift(t, "R25a escape byte", func() func() {
		old := simpleEscapes
		simpleEscapes = slices.Clone(old)
		simpleEscapes[1].b++
		return func() { simpleEscapes = old }
	})
	drift(t, "R25a rsyslog escape", func() func() {
		old := rsyslogEscapes
		rsyslogEscapes = slices.Clone(old)
		rsyslogEscapes[len(rsyslogEscapes)-1] = "176"
		return func() { rsyslogEscapes = old }
	})
	drift(t, "R26 bidi range", func() func() {
		old := bidiRanges
		bidiRanges = slices.Clone(old)
		bidiRanges[0].hi++
		return func() { bidiRanges = old }
	})
	drift(t, "R26 zero-width range", func() func() {
		old := zeroWidthRanges
		zeroWidthRanges = slices.Clone(old)
		zeroWidthRanges[len(zeroWidthRanges)-1].lo--
		return func() { zeroWidthRanges = old }
	})
	drift(t, "R26 tag and filler range removed", func() func() {
		old := tagFillerRanges
		tagFillerRanges = slices.Clone(old)[:len(old)-1]
		return func() { tagFillerRanges = old }
	})
	drift(t, "R27 line end", func() func() {
		old := lineEnds
		lineEnds = slices.Clone(old)[:len(old)-1]
		return func() { lineEnds = old }
	})
	drift(t, "R28a fold", func() func() {
		old := caseFolds
		caseFolds = slices.Clone(old)
		caseFolds[0].to = 't'
		return func() { caseFolds = old }
	})
	drift(t, "unit suffix", func() func() {
		old := unitSuffixes
		unitSuffixes = slices.Clone(old)
		unitSuffixes[0] = "servic"
		return func() { unitSuffixes = old }
	})
	drift(t, "secret keyword", func() func() {
		old := secretKeyWords
		secretKeyWords = slices.Clone(old)[1:]
		return func() { secretKeyWords = old }
	})
	drift(t, "url secret parameter", func() func() {
		old := urlSecretParams
		urlSecretParams = slices.Clone(old)[1:]
		return func() { urlSecretParams = old }
	})
	drift(t, "AWS prefix", func() func() {
		old := awsKeyPrefixes
		awsKeyPrefixes = slices.Clone(old)[1:]
		return func() { awsKeyPrefixes = old }
	})
	drift(t, "kept IP range", func() func() {
		old := keptPrefixes
		keptPrefixes = slices.Clone(old)
		keptPrefixes[1] = netip.MustParsePrefix("10.0.0.0/9")
		return func() { keptPrefixes = old }
	})
	drift(t, "vendor-token form", func() func() {
		old := vendorPatterns
		vendorPatterns = slices.Clone(old)
		vendorPatterns[0].body += "x"
		return func() { vendorPatterns = old }
	})
	// REDACT_NORM_MAX_PASSES is a constant: a test cannot mutate it, so
	// canonicalTable takes it as a parameter and the drift is shown there.
	if digestOf(canonicalTable(ruleTable(), NormMaxPasses+1)) == currentDigest() {
		t.Errorf("REDACT_NORM_MAX_PASSES is not hashed")
	}
	if digestOf(canonicalTable(ruleTable(), NormMaxPasses)) != currentDigest() {
		t.Errorf("canonicalRuleTable does not hash NormMaxPasses as canonicalTable does")
	}
}

// R43, AC70: the R28a table equals the set derived from Go's
// unicode.SimpleFold, so a Go upgrade that changes the folding fails the
// build instead of changing behaviour silently: every non-ASCII rune whose
// simple case-folding orbit holds an ASCII letter, mapped to that letter
// in lowercase.
func TestCaseFoldsMatchSimpleFold(t *testing.T) {
	want := map[rune]byte{}
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if f := unicode.SimpleFold(r); f == r {
			continue // no orbit: the common case, skipped quickly
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < 0x80 && unicode.IsLetter(f) {
				want[r] = "abcdefghijklmnopqrstuvwxyz"[unicode.ToLower(f)-'a']
				break
			}
		}
	}
	got := map[rune]byte{}
	for _, f := range caseFolds {
		if _, dup := got[f.r]; dup {
			t.Errorf("caseFolds lists %U twice", f.r)
		}
		got[f.r] = f.to
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("caseFolds = %v, want the SimpleFold set %v", got, want)
	}
	// Today that is exactly U+017F and U+212A (R28a).
	if len(want) != 2 || want[0x017F] != 's' || want[0x212A] != 'k' {
		t.Errorf("SimpleFold set changed in this Go release: %v (review R28a)", want)
	}
}

// The other normalisation tables hold what R25a–R27 state.
func TestNormalisationTablesMatchSpec(t *testing.T) {
	esc := map[string]byte{}
	for _, e := range simpleEscapes {
		esc[e.text] = e.b
	}
	wantEsc := map[string]byte{bs + "/": '/', bs + "e": 0x1b, bs + "x1b": 0x1b, bs + "x1B": 0x1b}
	if !reflect.DeepEqual(esc, wantEsc) {
		t.Errorf("simpleEscapes = %v, want %v (R25a)", esc, wantEsc)
	}
	if unicodeEscapeMax != 0x7f {
		t.Errorf("unicodeEscapeMax = %#x, want 0x7f (R25a)", unicodeEscapeMax)
	}
	if len(rsyslogEscapes) != 33 || rsyslogEscapes[0] != "000" || rsyslogEscapes[31] != "037" || rsyslogEscapes[32] != "177" {
		t.Errorf("rsyslogEscapes = %v, want 000-037 and 177 (R25a)", rsyslogEscapes)
	}
	if !slices.Equal(lineEnds, []rune{'\r', 0x2028, 0x2029}) {
		t.Errorf("lineEnds = %U, want CR, U+2028, U+2029 (R27)", lineEnds)
	}
	in := func(rs []runeRange, r rune) bool {
		for _, x := range rs {
			if r >= x.lo && r <= x.hi {
				return true
			}
		}
		return false
	}
	for _, r := range []rune{0x061C, 0x200E, 0x200F, 0x202A, 0x202E, 0x2066, 0x2069} {
		if !in(bidiRanges, r) {
			t.Errorf("bidiRanges misses %U (R26)", r)
		}
	}
	for _, r := range []rune{0x200B, 0x200D, 0x2060, 0x2064, 0xFEFF, 0x00AD} {
		if !in(zeroWidthRanges, r) {
			t.Errorf("zeroWidthRanges misses %U (R26)", r)
		}
	}
	for _, r := range []rune{0xE0000, 0xE007F, 0x180E, 0x034F, 0xFE00, 0xFE0F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0xFFF9, 0xFFFB} {
		if !in(tagFillerRanges, r) {
			t.Errorf("tagFillerRanges misses %U (R26)", r)
		}
	}
}
