package redact

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// digitClass is a "digit" of §4.2 for phone and the national IDs: ASCII,
// Arabic-Indic and Eastern Arabic-Indic, in any mix (MA11).
const digitClass = `[0-9\x{0660}-\x{0669}\x{06F0}-\x{06F9}]`

// digitValue maps a digit of digitClass to 0–9, or returns -1.
func digitValue(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 0x0660 && r <= 0x0669:
		return int(r - 0x0660)
	case r >= 0x06f0 && r <= 0x06f9:
		return int(r - 0x06f0)
	}
	return -1
}

// asciiDigits maps every digit of s to ASCII and drops everything else.
func asciiDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if v := digitValue(r); v >= 0 {
			b.WriteByte("0123456789"[v])
		}
	}
	return b.String()
}

func isLocalPart(c byte) bool {
	return isAlnum(c) || strings.IndexByte("._%+-", c) >= 0
}

// digitBefore and digitAt implement the "digit boundary" of §4.2.
func digitBefore(s string, i int) bool {
	r, size := utf8.DecodeLastRuneInString(s[:i])
	return size > 0 && digitValue(r) >= 0
}

func digitAt(s string, i int) bool {
	r, size := utf8.DecodeRuneInString(s[i:])
	return size > 0 && digitValue(r) >= 0
}

// letterBefore and letterAt implement the whole-word rule of §4.2: RE2's
// \b is ASCII-only and never matches around Arabic letters.
func letterBefore(s string, i int) bool {
	r, size := utf8.DecodeLastRuneInString(s[:i])
	return size > 0 && unicode.IsLetter(r)
}

func letterAt(s string, i int) bool {
	r, size := utf8.DecodeRuneInString(s[i:])
	return size > 0 && unicode.IsLetter(r)
}

// The e-mail pattern of §4.2 is `[A-Za-z0-9._%+-]{1,64}` + domainPattern.
// It is searched from each '@': the local part is the run of up to 64
// local-part characters before it (what the leftmost match takes), and
// the domain is matched anchored after it.
const domainPattern = `@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,24})\b`

func email() detector {
	domain := anchored(domainPattern)
	return detector{
		id:      "email",
		kind:    kindMarker,
		classes: allClasses,
		res:     []*regexp.Regexp{domain},
		tables:  []string{"anchor:@", "local-part:[A-Za-z0-9._%+-]{1,64}", "last-label-not-unit-suffix"},
		find: func(s string) ([]span, error) {
			var out []span
			for from := 0; ; {
				i := strings.IndexByte(s[from:], '@')
				if i < 0 {
					break
				}
				i += from
				from = i + 1
				a := i
				for a > 0 && i-a < 64 && isLocalPart(s[a-1]) {
					a--
				}
				work(i - a + 1)
				if a == i {
					continue
				}
				m := matchAt(domain, s, i)
				if m == nil || isUnitSuffix(s[m[2]:m[3]]) {
					continue
				}
				out = append(out, span{start: a, end: m[1]})
				from = m[1]
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"user" + "@" + "example.org"}, []string{"getty@tty1.service"}
		},
	}
}

// digitRunPattern finds runs of digit groups split by single spaces or
// dashes. The fixed-shape numbers (a Jordanian mobile, an Emirates ID) are
// then read from whole groups, which gives the digit boundaries of §4.2
// without re-running a pattern at every digit.
const digitRunPattern = digitClass + `+(?:[ \-]` + digitClass + `+)*`

// digitGroup is one maximal run of digits inside a digit run.
type digitGroup struct {
	start, end int
	digits     string // ASCII
}

func digitGroups(s string, a, b int) []digitGroup {
	var gs []digitGroup
	for i := a; i < b; {
		j := i
		for j < b {
			r, size := utf8.DecodeRuneInString(s[j:])
			if digitValue(r) < 0 {
				break
			}
			j += size
		}
		gs = append(gs, digitGroup{start: i, end: j, digits: asciiDigits(s[i:j])})
		i = j + 1 // the single separator
	}
	return gs
}

// joined reports whether groups g and h are next to each other with one
// separator from seps between them.
func joined(s string, g, h digitGroup, seps string) bool {
	return h.start == g.end+1 && strings.IndexByte(seps, s[g.end]) >= 0
}

func phone() detector {
	const intl = `\+[1-9\x{0661}-\x{0669}\x{06F1}-\x{06F9}](?:\)?[ .\-]?\(?` + digitClass + `){7,14}`
	ri := regexp.MustCompile(intl)
	runs := regexp.MustCompile(digitRunPattern)
	return detector{
		id:      "phone",
		kind:    kindMarker,
		numeric: true,
		classes: allClasses,
		res:     []*regexp.Regexp{ri, runs},
		tables:  []string{"jordan-mobile-prefix", "jordan-groups:whole|split", "jordan-separators: -", "digit-boundaries"},
		find: func(s string) ([]span, error) {
			var out []span
			if strings.IndexByte(s, '+') >= 0 {
				out = matchSpans(ri, s)
			}
			p := validatorParams
			for _, m := range digitRuns(s, runs, p.JOMobileDigits) {
				gs := digitGroups(s, m[0], m[1])
				for i, g := range gs {
					switch {
					case len(g.digits) == p.JOMobileDigits && jordanMobile(g.digits):
						out = append(out, span{start: g.start, end: g.end})
					case len(g.digits) == p.JOMobileSplit && i+1 < len(gs) && len(gs[i+1].digits) == p.JOMobileDigits-p.JOMobileSplit &&
						joined(s, g, gs[i+1], " -") && jordanMobile(g.digits+gs[i+1].digits):
						out = append(out, span{start: g.start, end: gs[i+1].end})
					}
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"+962 7" + "91234567", "07" + "91234567"}, []string{"pid 12345", "0612345678"}
		},
	}
}

func jordanMobile(d string) bool {
	p := validatorParams
	rest, ok := strings.CutPrefix(d, p.JOMobilePrefix)
	return ok && rest != "" && strings.IndexByte(p.JOMobileThird, rest[0]) >= 0
}

// idWindow is the distance, in characters from the end of a context
// keyword to the first digit, within which a national number counts.
const idWindow = 32

// arabicMarks are the diacritics and the tatweel accepted between the
// letters of an Arabic keyword (MA11).
const arabicMarks = `[\x{064B}-\x{0652}\x{0670}\x{0640}]*`

// keywordPattern builds a keyword's pattern: lowercase (it is matched on
// the ASCII-lowercased text, so English keywords are case-insensitive),
// words separated by spaces, and Arabic diacritics allowed after every
// letter except the last.
func keywordPattern(kw string) string {
	var b strings.Builder
	rs := []rune(strings.ToLower(kw))
	for i, r := range rs {
		if r == ' ' {
			b.WriteString(" +")
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
		if r >= 0x0600 && r <= 0x06ff && i < len(rs)-1 {
			b.WriteString(arabicMarks)
		}
	}
	return b.String()
}

// idRule is a 10-digit national number found after a whole-word context
// keyword, or after a short keyword (nid, nin) that is followed directly
// by the number.
type idRule struct {
	keywords []*regexp.Regexp
	literals []string // lowercase keyword, the filter for an English keyword
	short    *regexp.Regexp
	first    string // allowed first digits; empty for any
}

func newIDRule(keywords []string, short, first string) idRule {
	r := idRule{short: regexp.MustCompile(short), first: first}
	for _, kw := range keywords {
		r.keywords = append(r.keywords, regexp.MustCompile(keywordPattern(kw)))
		r.literals = append(r.literals, strings.Fields(strings.ToLower(kw))[0])
	}
	return r
}

// res and tables of an idRule, for the rule-set digest (§4.5).
func (k idRule) res() []*regexp.Regexp {
	return append(append([]*regexp.Regexp(nil), k.keywords...), k.short)
}

func (k idRule) tables() []string {
	return []string{"whole-word-keyword", "ten-digits-in-window", "short-keyword-direct", "first:" + k.first,
		"literals:" + strings.Join(k.literals, ",")}
}

func (k idRule) find(s string) []span {
	var out []span
	lower := asciiLower(s)
	arabic := hasArabic(s)
	work(len(s))
	for i, kw := range k.keywords {
		if !arabic && !strings.Contains(lower, k.literals[i]) {
			continue // an English keyword's literal, or no Arabic letter at all
		}
		work(len(s))
		for _, m := range kw.FindAllStringIndex(lower, -1) {
			if letterBefore(s, m[0]) || letterAt(s, m[1]) {
				continue
			}
			out = append(out, k.numbersAfter(s, m[1])...)
		}
	}
	if !containsAny(lower, "nid", "nin") {
		return out
	}
	work(len(s))
	for _, m := range k.short.FindAllStringSubmatchIndex(lower, -1) {
		if letterBefore(s, m[2]) || digitAt(s, m[5]) || !k.firstOK(s[m[4]:m[5]]) {
			continue
		}
		out = append(out, span{start: m[4], end: m[5]})
	}
	return out
}

// numbersAfter returns the national numbers (NationalIDDigits digits) that start within idWindow
// characters after from.
func (k idRule) numbersAfter(s string, from int) []span {
	var out []span
	i := from
	for n := 0; n < idWindow && i < len(s); n++ {
		r, size := utf8.DecodeRuneInString(s[i:])
		if digitValue(r) >= 0 && !digitBefore(s, i) {
			j, count := i, 0
			for j < len(s) {
				r2, size2 := utf8.DecodeRuneInString(s[j:])
				if digitValue(r2) < 0 {
					break
				}
				j += size2
				count++
			}
			if count == validatorParams.NationalIDDigits && k.firstOK(s[i:j]) {
				out = append(out, span{start: i, end: j})
			}
		}
		i += size
	}
	work(i - from)
	return out
}

func hasArabic(s string) bool {
	for _, r := range s {
		if r >= 0x0600 && r <= 0x06ff {
			return true
		}
	}
	return false
}

func (k idRule) firstOK(num string) bool {
	return k.first == "" || strings.IndexByte(k.first, asciiDigits(num)[0]) >= 0
}

func nationalIDJO() detector {
	rule := newIDRule(
		[]string{"national id", "national number", "national_no", "الرقم الوطني", "رقم وطني"},
		`(ni[dn])[:=#\- ]{0,3}(`+digitClass+`{`+strconv.Itoa(validatorParams.NationalIDDigits)+`})`, "")
	return detector{
		id:      "national-id-jo",
		kind:    kindMarker,
		numeric: true,
		classes: allClasses,
		res:     rule.res(),
		tables:  rule.tables(),
		find:    func(s string) ([]span, error) { return rule.find(s), nil },
		samples: func() ([]string, []string) {
			return []string{"national number: " + "1234567890"}, []string{"1234567890", "warning 1761385200"}
		},
	}
}

func nationalIDSA() detector {
	rule := newIDRule(
		[]string{"national id", "iqama", "هوية", "الهوية", "رقم الهوية", "إقامة", "الإقامة", "رقم الإقامة", "الرقم الوطني"},
		`(nid)[:=#\- ]{0,3}(`+digitClass+`{`+strconv.Itoa(validatorParams.NationalIDDigits)+`})`, "12")
	return detector{
		id:      "national-id-sa",
		kind:    kindMarker,
		numeric: true,
		classes: allClasses,
		res:     rule.res(),
		tables:  rule.tables(),
		find:    func(s string) ([]span, error) { return rule.find(s), nil },
		samples: func() ([]string, []string) {
			return []string{"iqama: 2" + "123456789"}, []string{"iqama: 3" + "123456789"}
		},
	}
}

func nationalIDAE() detector {
	runs := regexp.MustCompile(digitRunPattern)
	return detector{
		id:      "national-id-ae",
		kind:    kindMarker,
		numeric: true,
		classes: allClasses,
		res:     []*regexp.Regexp{runs},
		tables:  []string{"prefix", "groups:whole|prefix-then-groups", "separator:-", "digit-boundaries"},
		find: func(s string) ([]span, error) {
			var out []span
			p := validatorParams
			for _, m := range digitRuns(s, runs, p.AEDigits) {
				gs := digitGroups(s, m[0], m[1])
				for i, g := range gs {
					switch {
					case len(g.digits) == p.AEDigits && strings.HasPrefix(g.digits, p.AEPrefix):
						out = append(out, span{start: g.start, end: g.end})
					case g.digits == p.AEPrefix:
						if end, ok := dashedGroups(s, gs[i:], p.AEGroups); ok {
							out = append(out, span{start: g.start, end: end})
						}
					}
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"784" + "123456789012", "784-" + "1234-1234567-1"}, []string{"785" + "123456789012"}
		},
	}
}

// dashedGroups reports whether gs[0] is followed by groups of the given
// lengths, each joined to the one before by a dash, and returns the end of
// the last.
func dashedGroups(s string, gs []digitGroup, lengths []int) (int, bool) {
	if len(gs) <= len(lengths) {
		return 0, false
	}
	for k, n := range lengths {
		if len(gs[k+1].digits) != n || !joined(s, gs[k], gs[k+1], "-") {
			return 0, false
		}
	}
	return gs[len(lengths)].end, true
}

func paymentCard() detector {
	const pattern = `[0-9]+(?:[ \-][0-9]+)*`
	re := regexp.MustCompile(pattern)
	return detector{
		id:      "payment-card",
		kind:    kindMarker,
		numeric: true,
		classes: allClasses,
		res:     []*regexp.Regexp{re},
		tables:  []string{"first-digit", "digit-count", "start-at-every-group-start", "merge-overlaps", "every-group-end", "luhn", "longest", "no-hex-before"},
		find: func(s string) ([]span, error) {
			var out []span
			for _, m := range digitRuns(s, re, validatorParams.CardMinDigits) {
				out = append(out, cardsInRun(s, m[0], m[1])...)
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"4111" + "1111" + "1111" + "1111"}, []string{"4111" + "1111" + "1111" + "1112"}
		},
	}
}

// cardsInRun tries the candidates that start at the first digit of a
// group and end at a group end (MA10; S3 as ruled by Nofal, 2026-10-27),
// so an extra group or letters after the number cannot make a real card
// fail the Luhn check, a card after a date or a quantity in the same run
// is found, and a window that starts inside a group is never tried. The
// run's first group may not follow a hex letter (it would be part of a
// longer hex run).
func cardsInRun(s string, a, b int) []span {
	type group struct{ start, end int }
	var gs []group
	for i := a; i < b; {
		j := i
		for j < b && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		gs = append(gs, group{i, j})
		i = j + 1
	}
	work(b - a)
	p := validatorParams
	var out []span
	for i := 0; i < len(gs); {
		best := -1
		first := s[gs[i].start]
		if (i > 0 || a == 0 || !isHexByte(s[a-1])) && strings.IndexByte(p.CardFirst, first) >= 0 {
			var digits []byte
			for j := i; j < len(gs); j++ {
				digits = append(digits, s[gs[j].start:gs[j].end]...)
				if len(digits) > p.CardMaxDigits {
					break
				}
				if len(digits) >= p.CardMinDigits && luhn(digits) {
					best = j
				}
			}
		}
		// Every group start is tried, also inside an earlier match:
		// a chance Luhn match that starts at a date must not hide the
		// card after it. Overlapping matches are merged (R31).
		if best >= 0 {
			out = append(out, span{start: gs[i].start, end: gs[best].end})
		}
		i++
	}
	return out
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func luhn(digits []byte) bool {
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if (len(digits)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// ibanStart is the first run of an IBAN (§4.2, B1; no country table):
// two capitals, two digits, then letters or digits. Later runs of letters
// and digits may follow after one or more spaces each (human Go reviewer,
// 14th review: spacing is not limited to groups of four).
const ibanStart = `[A-Z]{2}[0-9]{2}[A-Z0-9]*`

func iban() detector {
	re := anchored(ibanStart)
	return detector{
		id:      "iban",
		kind:    kindMarker,
		classes: allClasses,
		res:     []*regexp.Regexp{re},
		tables:  []string{"start-on-word-boundary", "runs-split-by-spaces", "every-run-end", "end-on-word-boundary", "length", "mod97"},
		find: func(s string) ([]span, error) {
			// Every start of two capitals and two digits on a word boundary
			// is tried (MA10), including starts inside an earlier match: an
			// IBAN-shaped token whose chance mod 97 end falls inside a real
			// IBAN must not hide that IBAN's tail (security review H2).
			// Overlapping matches are merged (R31). A start reads at most
			// IBANMax letters and digits, and every start holds at least
			// four of them, so a byte is read from a bounded number of
			// starts and the scan stays linear however many spaces there are.
			var out []span
			for i := 0; i+4 <= len(s); i++ {
				if !isUpper(s[i]) || !isUpper(s[i+1]) || !isDigitByte(s[i+2]) || !isDigitByte(s[i+3]) {
					continue
				}
				if i > 0 && isWordByte(s[i-1]) {
					continue
				}
				m := matchAt(re, s[:min(len(s), i+validatorParams.IBANMax+1)], i)
				if sp, ok := ibanAt(s, m); ok {
					out = append(out, sp)
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"GB82" + "WEST" + "1234" + "5698" + "7654" + "32", "GB82 " + "WEST1234 " + "5698  " + "765432"},
				[]string{"GB82" + "WEST" + "1234" + "5698" + "7654" + "33"}
		},
	}
}

// ibanAt reads the runs of letters and digits from the start of m, split
// by one or more spaces, and tries every run end that a word boundary
// follows, longest first (MA10). A run that goes on into another word
// character (a lower-case letter, '_', or past IBANMax) ends the reading
// with no end there. A candidate of IBANMin–IBANMax letters and digits
// that passes mod 97 is an IBAN.
func ibanAt(s string, m []int) (span, bool) {
	if m == nil {
		return span{}, false
	}
	p := validatorParams
	var buf []byte
	var ends []int // candidate ends, and the number of letters and digits at each
	e := m[0]
	for len(buf) < p.IBANMax {
		for e < len(s) && len(buf) < p.IBANMax && (isUpper(s[e]) || isDigitByte(s[e])) {
			buf = append(buf, s[e])
			e++
		}
		if e < len(s) && isWordByte(s[e]) {
			break
		}
		ends = append(ends, e, len(buf))
		j := e
		for j < len(s) && s[j] == ' ' {
			j++
		}
		if j == e || j == len(s) || (!isUpper(s[j]) && !isDigitByte(s[j])) {
			break
		}
		e = j
	}
	work(e - m[0])
	for k := len(ends) - 2; k >= 0; k -= 2 {
		end, l := ends[k], ends[k+1]
		if l >= p.IBANMin && l <= p.IBANMax && ibanMod97(buf[:l]) {
			return span{start: m[0], end: end}, true
		}
	}
	return span{}, false
}

func isUpper(c byte) bool     { return c >= 'A' && c <= 'Z' }
func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

// ibanMod97 checks ISO 7064 mod 97: the country code and check digits move
// to the end, letters become 10–35, and the number mod 97 must be 1.
func ibanMod97(c []byte) bool {
	m := 0
	for k := range c {
		ch := c[(k+4)%len(c)]
		switch {
		case isDigitByte(ch):
			m = (m*10 + int(ch-'0')) % 97
		case isUpper(ch):
			m = (m*100 + int(ch-'A') + 10) % 97
		default:
			return false
		}
	}
	return m == 1
}
