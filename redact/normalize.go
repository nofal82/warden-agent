package redact

import (
	"strings"
	"unicode/utf8"
)

const esc = 0x1b

// Normalize applies the textual escapes of R25a (EText and TText only)
// and R25–R28 for class c (§4.4).
func Normalize(c Class, in string) (string, NormCounts) {
	var n NormCounts
	out, _ := normalise(c, in, &n, nil)
	return out, n
}

// normalise repeats one pass until nothing changes. A single pass is not
// enough: removing a control character can join the halves of an escape
// ("#0\x0133"), and a decoded "\" starts a new one. Every pass after
// the first that changes the text makes it shorter, so the loop ends;
// check (the item deadline, R36) bounds a crafted deep nesting.
func normalise(c Class, s string, n *NormCounts, check func() error) (string, error) {
	if hooks.normalise != nil {
		hooks.normalise(c, len(s))
	}
	for {
		next := normalisePass(c, s, n)
		if next == s {
			return s, nil
		}
		s = next
		if check != nil {
			if err := check(); err != nil {
				return "", err
			}
		}
	}
}

func normalisePass(c Class, s string, n *NormCounts) string {
	if c == EText || c == TText {
		s = decodeEscapes(s)
	}
	if !utf8.ValidString(s) {
		// R25: remove each maximal invalid subsequence, so the halves of a
		// token split by a bad byte join up for the detectors.
		n[NormInvalidUTF8] += invalidRuns(s)
		s = strings.ToValidUTF8(s, "")
	}
	keepLines := c == EText
	special := func(r rune) bool {
		if r < 0x20 {
			return !keepLines || (r != '\n' && r != '\t')
		}
		return r == 0x7f || (r >= 0x80 && (r <= 0x9f || r == 0x2028 || r == 0x2029 ||
			isBidi(r) || isZeroWidth(r) || isTagOrFiller(r)))
	}
	if strings.IndexFunc(s, special) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		// Copy the run of ordinary characters in one step.
		j := strings.IndexFunc(s[i:], special)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+j])
		i += j
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == esc:
			i = skipEscape(s, i)
			n[NormEscape]++
			continue
		case r == '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				size = 2
			}
			n[NormLineSeparator]++
			lineBreak(&b, keepLines)
		case r == 0x2028 || r == 0x2029:
			n[NormLineSeparator]++
			lineBreak(&b, keepLines)
		case r == '\n' || r == '\t':
			if keepLines {
				b.WriteByte(s[i])
			} else {
				b.WriteByte(' ')
			}
		case isBidi(r):
			n[NormBidi]++
		case isZeroWidth(r):
			n[NormZeroWidth]++
		case isTagOrFiller(r):
			n[NormTagOrFiller]++
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			n[NormControl]++
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func lineBreak(b *strings.Builder, keepLines bool) {
	if keepLines {
		b.WriteByte('\n')
	} else {
		b.WriteByte(' ')
	}
}

// invalidRuns counts the maximal invalid UTF-8 subsequences of s, the
// units strings.ToValidUTF8 replaces.
func invalidRuns(s string) int {
	runs, inRun := 0, false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		bad := r == utf8.RuneError && size == 1
		if bad && !inRun {
			runs++
		}
		inRun = bad
		i += size
	}
	return runs
}

// skipEscape returns the index after the terminal escape sequence that
// starts with the ESC at s[i] (R26). s is valid UTF-8.
func skipEscape(s string, i int) int {
	j := i + 1
	if j >= len(s) {
		return j // lone ESC at the end
	}
	switch s[j] {
	case '[': // CSI: parameter and intermediate bytes, then one final byte
		j++
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
			j++
		}
		if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
			j++
		}
		return j
	case ']': // OSC, ended by BEL or ST
		return skipControlString(s, j+1, true)
	case 'P', 'X', '^', '_': // DCS, SOS, PM, APC, ended by ST
		return skipControlString(s, j+1, false)
	}
	// Any other ESC takes the whole next character with it, never one byte
	// of a multi-byte character.
	_, size := utf8.DecodeRuneInString(s[j:])
	return j + size
}

// skipControlString skips to the string terminator (ESC \, or BEL when bel
// is set). An unterminated string stops at the line end, so one stray
// ESC cannot erase the following lines of an extract.
func skipControlString(s string, j int, bel bool) int {
	for ; j < len(s); j++ {
		switch {
		case bel && s[j] == 0x07:
			return j + 1
		case s[j] == esc && j+1 < len(s) && s[j+1] == '\\':
			return j + 2
		case s[j] == '\n' || s[j] == '\r':
			return j
		}
	}
	return j
}

// decodeEscapes applies R25a: the JSON and rsyslog escapes that hide
// characters from the detectors become those characters. "\\" stays as
// text so an escaped backslash is never read as the start of an escape.
func decodeEscapes(s string) string {
	if !strings.ContainsAny(s, `\#`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteString(`\\`)
				i += 2
				continue
			case '/':
				b.WriteByte('/')
				i += 2
				continue
			case 'e':
				b.WriteByte(esc)
				i += 2
				continue
			case 'x':
				if i+4 <= len(s) && strings.EqualFold(s[i+2:i+4], "1b") {
					b.WriteByte(esc)
					i += 4
					continue
				}
			case 'u':
				if v, ok := asciiEscape(s[i+2:]); ok {
					b.WriteByte(v)
					i += 6
					continue
				}
			}
		}
		if s[i] == '#' {
			if v, ok := rsyslogEscape(s[i+1:]); ok {
				b.WriteByte(v)
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// asciiEscape decodes the four hex digits of a \uXXXX escape when the code
// point is U+0000–U+007F.
func asciiEscape(s string) (byte, bool) {
	if len(s) < 4 || s[0] != '0' || s[1] != '0' {
		return 0, false
	}
	hi, ok1 := hexValue(s[2])
	lo, ok2 := hexValue(s[3])
	if !ok1 || !ok2 || hi > 7 {
		return 0, false
	}
	return hi<<4 | lo, true
}

// rsyslogEscape decodes rsyslog's "#ddd" octal escape for 000–037 and 177.
func rsyslogEscape(s string) (byte, bool) {
	if len(s) < 3 {
		return 0, false
	}
	for k := 0; k < 3; k++ {
		if s[k] < '0' || s[k] > '7' {
			return 0, false
		}
	}
	if s[:3] == "177" {
		return 0x7f, true
	}
	if s[0] != '0' || s[1] > '3' {
		return 0, false
	}
	return (s[1]-'0')<<3 | (s[2] - '0'), true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func isBidi(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

func isZeroWidth(r rune) bool {
	return (r >= 0x200b && r <= 0x200d) || (r >= 0x2060 && r <= 0x2064) ||
		r == 0xfeff || r == 0x00ad
}

func isTagOrFiller(r rune) bool {
	return (r >= 0xe0000 && r <= 0xe007f) || r == 0x180e || r == 0x034f ||
		(r >= 0xfe00 && r <= 0xfe0f) || r == 0x115f || r == 0x1160 ||
		r == 0x3164 || r == 0xffa0 || (r >= 0xfff9 && r <= 0xfffb)
}
