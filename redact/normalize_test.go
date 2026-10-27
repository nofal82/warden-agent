package redact

// Normalisation tests: every row of section 4.4 for E-TEXT and for the other
// classes (R25-R28, AC11, AC58), and the R25a textual escapes.
//
// Code points are written as \U escapes and escape texts are built from bs
// (one backslash), so the source holds no invisible characters.

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

var allNormClasses = []Class{TName, TPath, TText, EText, LValue, NPatterned}

// mustNormalize calls Normalize (R28b signature) and fails on an error.
func mustNormalize(t testing.TB, c Class, in string) (string, NormCounts) {
	t.Helper()
	out, n, err := Normalize(c, in)
	if err != nil {
		t.Fatalf("%s: Normalize(%q) error: %v", className(c), in, err)
	}
	return out, n
}

type normRow struct {
	name      string
	in        string
	wantE     string // E-TEXT
	wantOther string // every other scanned class
	kind      NormKind
	count     int // expected count of kind; 0 = not asserted
}

func r(c rune) string { return string(c) }

func normRows() []normRow {
	rows := []normRow{
		// R25: invalid UTF-8 is removed, never replaced by U+FFFD.
		{"invalid single byte", "ab\xffcd", "abcd", "abcd", NormInvalidUTF8, 1},
		{"invalid continuation byte", "ab\x80cd", "abcd", "abcd", NormInvalidUTF8, 1},
		{"truncated 3-byte sequence", "ab\xe2\x82cd", "abcd", "abcd", NormInvalidUTF8, 0},
		{"overlong slash", "ab\xc0\xafcd", "abcd", "abcd", NormInvalidUTF8, 0},
		{"UTF-16 surrogate", "ab\xed\xa0\x80cd", "abcd", "abcd", NormInvalidUTF8, 0},
		{"invalid at end", "abcd\xf0\x9f", "abcd", "abcd", NormInvalidUTF8, 0},
		{"real U+FFFD kept", "a" + r(0xFFFD) + "b", "a" + r(0xFFFD) + "b", "a" + r(0xFFFD) + "b", 0, 0},

		// R26: terminal escape sequences.
		{"CSI colour", "a\x1b[31mred\x1b[0mb", "aredb", "aredb", NormEscape, 2},
		{"CSI params", "a\x1b[1;2;3Hb", "ab", "ab", NormEscape, 1},
		{"CSI tilde final", "a\x1b[2~b", "ab", "ab", NormEscape, 1},
		{"CSI private", "a\x1b[?25lb", "ab", "ab", NormEscape, 1},
		{"OSC with BEL", "a\x1b]0;title\x07b", "ab", "ab", NormEscape, 1},
		{"OSC with ST", "a\x1b]8;;http://x.example/\x1b" + bs + "b", "ab", "ab", NormEscape, 1},
		{"DCS", "a\x1bPq0;2;0;0\x1b" + bs + "b", "ab", "ab", NormEscape, 1},
		{"SOS", "a\x1bXdata\x1b" + bs + "b", "ab", "ab", NormEscape, 1},
		{"PM", "a\x1b^data\x1b" + bs + "b", "ab", "ab", NormEscape, 1},
		{"APC", "a\x1b_data\x1b" + bs + "b", "ab", "ab", NormEscape, 1},
		{"ESC plus one ASCII char", "a\x1bcb", "ab", "ab", NormEscape, 1},
		{"ESC plus 2-byte char", "a\x1b" + r(0xE9) + " b", "a b", "a b", NormEscape, 1},
		{"ESC plus 3-byte char", "a\x1b" + r(0x20AC) + "b", "ab", "ab", NormEscape, 1},
		{"ESC plus 4-byte char", "a\x1b" + r(0x1F600) + "b", "ab", "ab", NormEscape, 1},
		{"lone ESC at end", "ab\x1b", "ab", "ab", NormEscape, 1},

		// R27: line ends.
		{"CRLF", "a\r\nb", "a\nb", "a b", 0, 0},
		{"lone CR", "a\rb", "a\nb", "a b", 0, 0},
		{"U+2028", "a" + r(0x2028) + "b", "a\nb", "a b", NormLineSeparator, 1},
		{"U+2029", "a" + r(0x2029) + "b", "a\nb", "a b", NormLineSeparator, 1},
		{"LF", "a\nb", "a\nb", "a b", 0, 0},
		{"TAB", "a\tb", "a\tb", "a b", 0, 0},

		// R28: other controls.
		{"DEL", "a\x7fb", "ab", "ab", NormControl, 1},
		{"NUL", "a\x00b", "ab", "ab", NormControl, 1},

		// R28a: case folding to the ASCII letter of the SimpleFold orbit.
		{"long s U+017F", "a" + r(0x017F) + "b", "asb", "asb", NormCaseFold, 1},
		{"Kelvin sign U+212A", "a" + r(0x212A) + "b", "akb", "akb", NormCaseFold, 1},
		{"two folds", r(0x017F) + r(0x212A), "sk", "sk", NormCaseFold, 2},
		// Not folded: ASCII letters, and non-ASCII letters whose orbit holds
		// no ASCII letter (U+0130 has no simple fold; U+00DF folds to U+1E9E).
		{"ASCII upper K kept", "aKb", "aKb", "aKb", 0, 0},
		{"dotted capital I kept", "a" + r(0x0130) + "b", "a" + r(0x0130) + "b", "a" + r(0x0130) + "b", 0, 0},
		{"dotless i kept", "a" + r(0x0131) + "b", "a" + r(0x0131) + "b", "a" + r(0x0131) + "b", 0, 0},
		{"sharp s kept", "a" + r(0x00DF) + "b", "a" + r(0x00DF) + "b", "a" + r(0x00DF) + "b", 0, 0},
		{"Angstrom sign kept", "a" + r(0x212B) + "b", "a" + r(0x212B) + "b", "a" + r(0x212B) + "b", 0, 0},
	}
	for _, c := range []rune{0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069} {
		rows = append(rows, normRow{fmt.Sprintf("bidi %U", c), "a" + r(c) + "b", "ab", "ab", NormBidi, 1})
	}
	for _, c := range []rune{0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x00AD} {
		rows = append(rows, normRow{fmt.Sprintf("zero-width %U", c), "a" + r(c) + "b", "ab", "ab", NormZeroWidth, 1})
	}
	rows = append(rows, normRow{"BOM at start", r(0xFEFF) + "ab", "ab", "ab", NormZeroWidth, 1})
	for _, c := range []rune{0xE0000, 0xE0001, 0xE0041, 0xE007F, 0x180E, 0x034F, 0xFE00, 0xFE07, 0xFE0F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0xFFF9, 0xFFFA, 0xFFFB} {
		rows = append(rows, normRow{fmt.Sprintf("tag or filler %U", c), "a" + r(c) + "b", "ab", "ab", NormTagOrFiller, 1})
	}
	for c := rune(0x01); c < 0x20; c++ {
		if c == '\t' || c == '\n' || c == '\r' || c == 0x1b {
			continue
		}
		rows = append(rows, normRow{fmt.Sprintf("C0 %U", c), "a" + r(c) + "b", "ab", "ab", NormControl, 1})
	}
	for c := rune(0x80); c <= 0x9f; c++ {
		rows = append(rows, normRow{fmt.Sprintf("C1 %U", c), "a" + r(c) + "b", "ab", "ab", NormControl, 1})
	}
	return rows
}

func TestNormalizeTable(t *testing.T) {
	for _, row := range normRows() {
		t.Run(row.name, func(t *testing.T) {
			for _, c := range allNormClasses {
				want := row.wantOther
				if c == EText {
					want = row.wantE
				}
				got, counts := mustNormalize(t, c, row.in)
				if got != want {
					t.Errorf("%s: Normalize(%q) = %q, want %q", className(c), row.in, got, want)
				}
				if row.count > 0 && counts[row.kind] != row.count {
					t.Errorf("%s: count[%d] = %d, want %d", className(c), row.kind, counts[row.kind], row.count)
				}
				if row.count > 0 {
					for k := NormKind(0); k < numNormKinds; k++ {
						if k != row.kind && counts[k] != 0 {
							t.Errorf("%s: unexpected count[%d] = %d", className(c), k, counts[k])
						}
					}
				}
				if !utf8.ValidString(row.in) && row.in != want && counts[NormInvalidUTF8] == 0 {
					t.Errorf("%s: invalid UTF-8 removed but not counted", className(c))
				}
			}
		})
	}
}

func TestNormalizePlainTextUnchanged(t *testing.T) {
	in := "GET /index.html HTTP/1.1 200 5123 " + r(0xE9) + r(0x4E2D) + r(0x0627) + r(0x0644)
	for _, c := range allNormClasses {
		got, counts := mustNormalize(t, c, in)
		if got != in {
			t.Errorf("%s: plain text changed: %q", className(c), got)
		}
		if counts != (NormCounts{}) {
			t.Errorf("%s: counts for plain text: %v", className(c), counts)
		}
	}
}

// R25a: textual escapes are decoded in E-TEXT and T-TEXT only.
func TestNormalizeTextualEscapes(t *testing.T) {
	type row struct {
		name, in string
		wantE    string // E-TEXT
		wantT    string // T-TEXT
	}
	u := func(hex4 string) string { return bs + "u" + hex4 }
	rows := []row{
		{"JSON slash", "postgresql:" + bs + "/" + bs + "/db" + bs + "/x", "postgresql://db/x", "postgresql://db/x"},
		{"u0026 ampersand", "a" + u("0026") + "b", "a&b", "a&b"},
		{"u003d equals", "a" + u("003d") + "b", "a=b", "a=b"},
		{"u0041 letter", u("0041") + "B", "AB", "AB"},
		{"u001b starts CSI", "a" + u("001b") + "[31mb", "ab", "ab"},
		{"u0000 removed", "a" + u("0000") + "b", "ab", "ab"},
		{"x1b starts CSI", "a" + bs + "x1b[0mb", "ab", "ab"},
		{"e starts CSI", "a" + bs + "e[1mb", "ab", "ab"},
		{"rsyslog 033 starts CSI", "a#033[31mb", "ab", "ab"},
		{"rsyslog 177 DEL", "a#177b", "ab", "ab"},
		{"rsyslog 000 NUL", "a#000b", "ab", "ab"},
		{"rsyslog 011 TAB", "a#011b", "a\tb", "a b"},
		{"rsyslog 012 LF", "a#012b", "a\nb", "a b"},
		{"rsyslog 001 control", "a#001b", "ab", "ab"},
		{"rsyslog 037 control", "a#037b", "ab", "ab"},
		// Left as text.
		{"escaped quote stays", "a" + bs + "\"b", "a" + bs + "\"b", "a" + bs + "\"b"},
		{"escaped backslash stays", "a" + bs + bs + "b", "a" + bs + bs + "b", "a" + bs + bs + "b"},
		{"escaped n stays", "a" + bs + "nb", "a" + bs + "nb", "a" + bs + "nb"},
		{"non-ASCII u-escape stays", "a" + u("00e9") + "b", "a" + u("00e9") + "b", "a" + u("00e9") + "b"},
		{"u2028 escape stays", "a" + u("2028") + "b", "a" + u("2028") + "b", "a" + u("2028") + "b"},
		{"x41 stays", "a" + bs + "x41b", "a" + bs + "x41b", "a" + bs + "x41b"},
		{"rsyslog 040 stays", "a#040b", "a#040b", "a#040b"},
		{"rsyslog 176 stays", "a#176b", "a#176b", "a#176b"},
		{"rsyslog two digits stays", "a#03b", "a#03b", "a#03b"},
		{"rsyslog non-octal stays", "a#089b", "a#089b", "a#089b"},
		{"nginx pid#tid stays", "1234#1234: *5", "1234#1234: *5", "1234#1234: *5"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got, _ := mustNormalize(t, EText, row.in); got != row.wantE {
				t.Errorf("EText: Normalize(%q) = %q, want %q", row.in, got, row.wantE)
			}
			if got, _ := mustNormalize(t, TText, row.in); got != row.wantT {
				t.Errorf("TText: Normalize(%q) = %q, want %q", row.in, got, row.wantT)
			}
			// Not decoded in the other classes. These inputs hold no real
			// control character, so they stay unchanged there.
			for _, c := range []Class{TName, TPath, LValue, NPatterned} {
				if got, _ := mustNormalize(t, c, row.in); got != row.in {
					t.Errorf("%s: Normalize(%q) = %q, want it unchanged (R25a is E-TEXT and T-TEXT only)", className(c), row.in, got)
				}
			}
		})
	}
}

func TestNormalizeEscapeCountsAnsi(t *testing.T) {
	for _, c := range []Class{EText, TText} {
		_, counts := mustNormalize(t, c, "x"+bs+"u001b[31my")
		if counts[NormEscape] < 1 {
			t.Errorf("%s: an escape sequence produced by R25a was not counted as ESCAPE", className(c))
		}
	}
}

// AC11/AC58: after normalisation a string holds no NUL and no control
// character other than LF and TAB in E-TEXT (none at all elsewhere), is valid
// UTF-8 and holds no U+FFFD that was not in the input.
func TestNormalizeOutputProperty(t *testing.T) {
	inputs := []string{
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f",
		r(0x80) + r(0x85) + r(0x9b) + "[31m" + r(0x9f),
		"\x1b", "\x1b\x1b\x1b", "\x1b[", "\x1b]", "\x1bP", "\x1b\xff", "\x1b\xc3",
		"\xff\xfe\xfd", "\xc3", "\xe2\x82", "\xf0\x9f\x98",
		bs + "u0000" + bs + "u0001" + bs + "u001b" + bs + "u007f" + bs + "x1b" + bs + "e#000#033#177",
		"a\r\r\nb\r", r(0x2028) + r(0x2029) + "\r\n\t",
		"#0", "#03", "#033", bs + "u00", bs + "u001", bs + "x1", bs, bs + "e",
		strings.Repeat("\x1b[", 100) + "m",
		strings.Repeat(r(0x202E)+r(0x200B)+r(0xE0041), 50),
	}
	for _, in := range inputs {
		for _, c := range allNormClasses {
			got, _ := mustNormalize(t, c, in)
			if !utf8.ValidString(got) {
				t.Errorf("%s: output for %q is not valid UTF-8", className(c), in)
			}
			if strings.Count(got, r(0xFFFD)) > strings.Count(in, r(0xFFFD)) {
				t.Errorf("%s: output for %q holds a new U+FFFD", className(c), in)
			}
			for _, x := range got {
				if !isControl(x) {
					continue
				}
				if c == EText && (x == '\n' || x == '\t') {
					continue
				}
				t.Errorf("%s: output for %q holds control %U", className(c), in, x)
				break
			}
		}
	}
}
