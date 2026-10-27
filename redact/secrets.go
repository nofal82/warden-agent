package redact

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// PEM markers of §4.2. The fragments keep the source free of anything that
// looks like a key header to the repository's secret scanners.
const (
	pemBeginPattern = `-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`
	pemEndPattern   = `-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`
	pemAnyPattern   = `-----(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`
)

func pemPrivateKey() detector {
	begin := regexp.MustCompile(pemBeginPattern)
	end := regexp.MustCompile(pemEndPattern)
	return detector{
		id:      "pem-private-key",
		kind:    kindMarker,
		classes: allClasses,
		res:     []*regexp.Regexp{begin, end},
		tables:  []string{"pair-to-end-or-input-end", "orphan-end"},
		find: func(s string) ([]span, error) {
			blocks, orphans := pemBlocks(begin, end, s)
			return mergeSorted(blocks, orphans), nil
		},
		samples: func() ([]string, []string) {
			key := "-----BEGIN " + "PRIVATE" + " KEY-----\nMIIB\n-----END " + "PRIVATE" + " KEY-----"
			return []string{key, "x -----BEGIN " + "RSA PRIVATE" + " KEY-----\nMIIB"},
				[]string{"-----BEGIN CERTIFICATE-----"}
		},
	}
}

// pemBlocks pairs each begin marker with the next end marker; a block
// without an end marker runs to the end of the input (R13). It also
// returns the end markers that no begin marker precedes.
func pemBlocks(begin, end *regexp.Regexp, s string) (blocks, orphans []span) {
	work(2 * len(s))
	bs := begin.FindAllStringIndex(s, -1)
	es := end.FindAllStringIndex(s, -1)
	covered, ei := 0, 0
	for _, b := range bs {
		if b[0] < covered {
			continue
		}
		for ; ei < len(es) && es[ei][0] < b[1]; ei++ {
			if es[ei][0] >= covered {
				orphans = append(orphans, span{start: es[ei][0], end: es[ei][1]})
			}
		}
		if ei == len(es) {
			blocks = append(blocks, span{start: b[0], end: len(s)})
			return blocks, orphans
		}
		blocks = append(blocks, span{start: b[0], end: es[ei][1]})
		covered = es[ei][1]
		ei++
	}
	for ; ei < len(es); ei++ {
		if es[ei][0] >= covered {
			orphans = append(orphans, span{start: es[ei][0], end: es[ei][1]})
		}
	}
	return blocks, orphans
}

// mergeSorted joins two span lists that are each in order.
func mergeSorted(a, b []span) []span {
	out := make([]span, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if a[0].start <= b[0].start {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	return append(append(out, a...), b...)
}

const (
	bodyLineMin      = 60 // a key-body part this long is a body line on its own
	bodyLineMax      = 76
	bodyLineShortMin = 4 // shorter lines count only next to a body line or a marker
)

func pemBodyLine() detector {
	begin := regexp.MustCompile(pemBeginPattern)
	end := regexp.MustCompile(pemEndPattern)
	marker := regexp.MustCompile(pemAnyPattern)
	return detector{
		id:      "pem-body-line",
		kind:    kindMarker,
		classes: textClasses,
		res:     []*regexp.Regexp{begin, end, marker},
		tables:  []string{"key-body:[A-Za-z0-9+/]+={0,2}", "prefix-ws-or-colon", "primary-not-lower-hex", "short-next-to-body-or-marker", "orphan-end-run"},
		find: func(s string) ([]span, error) {
			return bodyLines(s, begin, end, marker), nil
		},
		samples: func() ([]string, []string) {
			return []string{strings.Repeat("Ab3+", 16)}, []string{strings.Repeat("0a1b", 16)}
		},
	}
}

type textLine struct {
	start, end int
	kb         int // start of the key-body part, or -1
	marker     bool
}

func (l textLine) kbLen() int {
	if l.kb < 0 {
		return 0
	}
	return l.end - l.kb
}

// bodyLines implements pem-body-line (§4.2, R13). Lines are LF-separated;
// a line's prefix (syslog, journal, YAML indentation, "key:") is kept and
// only its key-body part is replaced.
func bodyLines(s string, begin, end, marker *regexp.Regexp) []span {
	work(len(s))
	var lines []textLine
	for off := 0; ; {
		e := len(s)
		if i := strings.IndexByte(s[off:], '\n'); i >= 0 {
			e = off + i
		}
		l := textLine{start: off, end: e, kb: -1, marker: marker.MatchString(s[off:e])}
		if k := keyBodyStart(s[off:e]); k >= 0 {
			l.kb = off + k
		}
		lines = append(lines, l)
		if e == len(s) {
			break
		}
		off = e + 1
	}
	primary := func(i int) bool {
		if i < 0 || i >= len(lines) {
			return false
		}
		n := lines[i].kbLen()
		return n >= bodyLineMin && n <= bodyLineMax && !allLowerHex(s[lines[i].kb:lines[i].end])
	}
	near := func(i int) bool {
		return primary(i) || (i >= 0 && i < len(lines) && lines[i].marker)
	}
	pick := make([]bool, len(lines))
	for i, l := range lines {
		n := l.kbLen()
		pick[i] = primary(i) || (n >= bodyLineShortMin && n <= bodyLineMax && (near(i-1) || near(i+1)))
	}
	// An end marker without its begin marker: the unbroken run of body
	// lines directly above it (ruling on issue #9, point 2).
	_, orphans := pemBlocks(begin, end, s)
	for _, o := range orphans {
		li := lineOf(lines, o.start)
		for k := li - 1; k >= 0; k-- {
			work(1)
			if n := lines[k].kbLen(); n < 1 || n > bodyLineMax {
				break
			}
			pick[k] = true
		}
	}
	var out []span
	for i, l := range lines {
		if pick[i] {
			out = append(out, span{start: l.kb, end: l.end})
		}
	}
	return out
}

func lineOf(lines []textLine, off int) int {
	for i, l := range lines {
		if off <= l.end {
			return i
		}
	}
	return len(lines) - 1
}

// keyBodyStart returns the offset of a line's key-body part: its trailing
// run of [A-Za-z0-9+/] ending in 0–2 '=', after an optional prefix that
// ends in whitespace or ':'. It returns -1 when the line has none.
func keyBodyStart(line string) int {
	j := len(line)
	for j > 0 && line[j-1] == '=' {
		j--
	}
	if len(line)-j > 2 {
		return -1
	}
	k := j
	for k > 0 && isStdBase64(line[k-1]) {
		k--
	}
	if k == j {
		return -1
	}
	if k > 0 && line[k-1] != ' ' && line[k-1] != '\t' && line[k-1] != ':' {
		return -1
	}
	return k
}

func isStdBase64(c byte) bool {
	return isAlnum(c) || c == '+' || c == '/'
}

func isAlnum(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func allLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// b64DecodeMax bounds the base64 decoded per candidate: 96 characters, 72
// bytes, enough for the longest PEM private-key header (§4.2).
const b64DecodeMax = 96

func pemPrivateKeyB64() detector {
	const runPattern = `LS0tLS1CRUdJTi[A-Za-z0-9+/_-]*`
	const headPattern = `^-----BEGIN [A-Z0-9 ]*PRIVATE KEY`
	run := regexp.MustCompile(runPattern)
	head := regexp.MustCompile(headPattern)
	return detector{
		id:      "pem-private-key-b64",
		kind:    kindMarker,
		extend:  true,
		classes: allClasses,
		res:     []*regexp.Regexp{run, head},
		tables:  []string{"run-start", "decode-bounded"},
		find: func(s string) ([]span, error) {
			var out []span
			work(len(s))
			for _, m := range run.FindAllStringIndex(s, -1) {
				if m[0] > 0 && isBase64Run(s[m[0]-1]) {
					continue // inside a longer token, not its start
				}
				if decodesToKeyHeader(s[m[0]:m[1]], head) {
					out = append(out, span{start: m[0], end: m[1]})
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			enc := base64.StdEncoding.EncodeToString
			return []string{enc([]byte("-----BEGIN " + "RSA PRIVATE" + " KEY-----\nMIIB"))},
				[]string{enc([]byte("-----BEGIN CERTIFICATE-----\nMIIB"))}
		},
	}
}

func isBase64Run(c byte) bool { return isStdBase64(c) || c == '_' || c == '-' }

// decodesToKeyHeader decodes at most the first b64DecodeMax characters of
// run (standard or URL-safe alphabet), so the cost per candidate is fixed.
func decodesToKeyHeader(run string, head *regexp.Regexp) bool {
	n := min(len(run), b64DecodeMax) &^ 3
	if hooks.b64 != nil {
		hooks.b64(n)
	}
	std := strings.NewReplacer("-", "+", "_", "/").Replace(run[:n])
	dec, err := base64.StdEncoding.DecodeString(std)
	if err != nil {
		return false
	}
	return head.Match(dec)
}

func wardenEnrollmentToken() detector {
	const pattern = `wdn1_[A-Za-z0-9_-]{43}`
	re := regexp.MustCompile(pattern)
	return detector{
		id:      "warden-enrollment-token",
		kind:    kindMarker,
		extend:  true,
		classes: allClasses,
		res:     []*regexp.Regexp{re},
		find: func(s string) ([]span, error) {
			if !strings.Contains(s, "wdn1_") {
				return nil, nil
			}
			return matchSpans(re, s), nil
		},
		samples: func() ([]string, []string) {
			return []string{"wdn1" + "_" + strings.Repeat("A", 43)}, []string{"wdn1" + "_short"}
		},
	}
}

// awsKeyPrefixes are the literal prefixes of aws-access-key-id, where the
// anchored pattern runs.
var awsKeyPrefixes = []string{"AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AIPA", "ANPA", "ANVA", "AROA", "APKA"}

func awsAccessKeyID() detector {
	const body = `(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[A-Z2-7]{16}\b`
	re := anchored(body)
	return detector{
		id:      "aws-access-key-id",
		kind:    kindMarker,
		classes: allClasses,
		res:     []*regexp.Regexp{re},
		tables:  []string{"word-start", "anchor:aws-prefixes"},
		find: func(s string) ([]span, error) {
			return literalSpans(s, awsKeyPrefixes, re, true, false), nil
		},
		samples: func() ([]string, []string) {
			return []string{"AKIA" + strings.Repeat("Q", 16)}, []string{"AKIA" + strings.Repeat("Q", 15)}
		},
	}
}

func awsSecretKey() detector {
	// A quote may carry any number of backslashes (escaped JSON, ruling
	// on PR #10).
	const pattern = `(?i)(?:aws_secret_access_key|secret_access_key|secretaccesskey)(?:\\*["'])?\s*(?:=>|[:=]|\s)\s*(?:\\*["'])?([A-Za-z0-9/+=]{40})`
	re := regexp.MustCompile(pattern)
	return detector{
		id:      "aws-secret-key",
		kind:    kindValue,
		extend:  true,
		classes: allClasses,
		res:     []*regexp.Regexp{re},
		find: func(s string) ([]span, error) {
			if !containsAny(asciiLower(s), "secret_access_key", "secretaccesskey") {
				return nil, nil
			}
			return groupSpans(re, s), nil
		},
		samples: func() ([]string, []string) {
			return []string{"aws_secret_access_key = " + strings.Repeat("a", 40)},
				[]string{"aws_secret_access_key = short"}
		},
	}
}

// vendorPatterns are the prefix forms of §4.2 vendor-token, one regexp
// each so one form's alternation cannot shadow another's. Every form starts
// at \b with a fixed prefix; the pattern runs anchored at each occurrence
// of its prefix literals. Every form that starts with "sk-" refuses a match
// followed by a unit suffix, so a unit name such as
// "sk-ant-api-gateway.service" is kept (R33, S4).
var vendorPatterns = []struct {
	body     string // the pattern after its leading \b
	literals []string
}{
	{`gh[pousr]_[A-Za-z0-9]{36,}`, []string{"gh"}},
	{`github_pat_[A-Za-z0-9_]{22,}`, []string{"github_pat_"}},
	{`glpat-[A-Za-z0-9_-]{20,}`, []string{"glpat-"}},
	{`xox[abposr]-[A-Za-z0-9-]{10,}`, []string{"xox"}},
	{`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`, []string{"sk_", "rk_"}},
	{`AIza[0-9A-Za-z_-]{35}`, []string{"AIza"}},
	{`npm_[A-Za-z0-9]{36}`, []string{"npm_"}},
	{`dckr_pat_[A-Za-z0-9_-]{20,}`, []string{"dckr_pat_"}},
	{`sk-ant-[A-Za-z0-9_-]{20,}`, []string{"sk-ant-"}},
	{`AGE-SECRET-KEY-1[0-9A-Z]{58}`, []string{"AGE-SECRET-KEY-1"}},
	{`hooks\.slack\.com/services/[A-Za-z0-9/]+`, []string{"hooks.slack.com/services/"}},
	{`sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}`, []string{"sk-"}},
}

func vendorToken() detector {
	res := make([]*regexp.Regexp, len(vendorPatterns))
	for i, p := range vendorPatterns {
		res[i] = anchored(p.body)
	}
	return detector{
		id:      "vendor-token",
		kind:    kindMarker,
		extend:  true,
		classes: allClasses,
		res:     res,
		tables:  []string{"word-start", "anchor:vendor-literals", "sk-dash-not-before-unit-suffix"},
		find: func(s string) ([]span, error) {
			var out []span
			for i, re := range res {
				skipUnit := strings.HasPrefix(vendorPatterns[i].body, "sk-")
				for _, sp := range literalSpans(s, vendorPatterns[i].literals, re, true, false) {
					if !skipUnit || !startsWithUnitSuffix(s[sp.end:]) {
						out = append(out, sp)
					}
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"gh" + "p_" + strings.Repeat("a", 36), "sk" + "-proj-" + strings.Repeat("b", 40)},
				[]string{"sk-payments-db.service", "sk" + "-" + strings.Repeat("c", 40) + ".service",
					"sk" + "-ant-" + strings.Repeat("d", 20) + ".service"}
		},
	}
}

func jwtToken() detector {
	const pattern = `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`
	re := regexp.MustCompile(pattern)
	return detector{
		id:      "jwt",
		kind:    kindMarker,
		extend:  true,
		classes: allClasses,
		res:     []*regexp.Regexp{re},
		tables:  []string{"header-json-object-with-alg"},
		find: func(s string) ([]span, error) {
			if !strings.Contains(s, "eyJ") {
				return nil, nil
			}
			return retrySpans(re, s, func(m []int) (span, bool) {
				header := s[m[0] : m[0]+strings.IndexByte(s[m[0]:m[1]], '.')]
				return span{start: m[0], end: m[1]}, jwtHeaderHasAlg(header)
			}), nil
		},
		samples: func() ([]string, []string) {
			enc := base64.RawURLEncoding.EncodeToString
			sig := "." + strings.Repeat("a", 8) + "." + strings.Repeat("b", 8)
			return []string{enc([]byte(`{"alg":"HS256"}`)) + sig},
				[]string{enc([]byte(`{"xxxxxx":1`)) + sig}
		},
	}
}

func jwtHeaderHasAlg(header string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(header, "="))
	if err != nil {
		return false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	_, ok := obj["alg"]
	return ok
}

// urlStopBytes end the run of a URL with credentials.
const urlStopBytes = " \t\n\r\v\f\"'"

func urlCredentials() detector {
	scheme := anchored(`[a-zA-Z][a-zA-Z0-9+.-]*://`)
	return detector{
		id:      "url-credentials",
		kind:    kindValue,
		classes: allClasses,
		res:     []*regexp.Regexp{scheme},
		tables:  []string{"anchor:://", "userinfo-to-last-at", "userinfo-has-colon", "token-once", "token-end:" + urlStopBytes},
		find: func(s string) ([]span, error) {
			var out []span
			// The token (up to whitespace or a quote), its last '@' and the
			// last ':' before it are found once per token, so a token of
			// many "://" costs linear time (security review H1). This is
			// what the anchored pattern rest would match from each "://".
			tokEnd, lastAt, lastColon := -1, -1, -1
			eachIndex(s, "://", func(i int) {
				k := i
				for k > 0 && isSchemeByte(s[k-1]) {
					k--
				}
				for k < i && !isLetter(s[k]) {
					k++
				}
				work(i - k + 1)
				if k == i || matchAt(scheme, s, k) == nil {
					return
				}
				if i >= tokEnd {
					tokEnd = len(s)
					if j := strings.IndexAny(s[i:], urlStopBytes); j >= 0 {
						tokEnd = i + j
					}
					work(tokEnd - i)
					lastAt = strings.LastIndexByte(s[i:tokEnd], '@')
					if lastAt >= 0 {
						lastAt += i
						lastColon = strings.LastIndexByte(s[i:lastAt], ':') + i
					}
				}
				if lastAt > i+3 && lastColon >= i+3 {
					out = append(out, span{start: i + 3, end: lastAt})
				}
			})
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"postgresql://app:" + "pw1" + "@db/x"}, []string{"https://example.com/x@y"}
		},
	}
}

func isSchemeByte(c byte) bool { return isAlnum(c) || c == '+' || c == '.' || c == '-' }
func isLetter(c byte) bool     { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

// urlSecretParams are the parameter names of §4.2 url-secret-param.
var urlSecretParams = []string{
	"password", "passwd", "pwd", "pass", "token", "access_token", "refresh_token",
	"id_token", "api_key", "apikey", "key", "secret", "client_secret", "sig",
	"signature", "auth", "x-amz-signature", "x-amz-credential",
	"x-amz-security-token", "sessionid",
}

func urlSecretParam() detector {
	value := anchored(`=([^&\s#"']+)`)
	names := map[string]bool{}
	for _, n := range urlSecretParams {
		names[n] = true
	}
	return detector{
		id:      "url-secret-param",
		kind:    kindValue,
		classes: allClasses,
		res:     []*regexp.Regexp{value},
		tables:  []string{"anchor:=", "name-after:?&;", "names:url-secret-params", "ascii-case-insensitive"},
		find: func(s string) ([]span, error) {
			var out []span
			lower := asciiLower(s)
			valueEnd := 0
			eachIndex(s, "=", func(i int) {
				if i < valueEnd {
					return // inside the previous value: same end, merged anyway (H1)
				}
				k := i
				for k > 0 && (isAlnum(s[k-1]) || s[k-1] == '_' || s[k-1] == '-') {
					k--
				}
				if k == 0 || strings.IndexByte("?&;", s[k-1]) < 0 || !names[lower[k:i]] {
					return
				}
				if m := matchAt(value, s, i); m != nil {
					out = append(out, span{start: m[2], end: m[3]})
					valueEnd = m[3]
				}
			})
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"https://h/?access_token=" + "abc"}, []string{"https://h/?page=2"}
		},
	}
}

// headerSeparator ends a header key: an optional closing quote (with any
// number of backslashes, for escaped JSON), then ':' or '='. The value
// after it is a quoted value up to its closing quote, or the rest of the
// line (headerValueAt).
const headerSeparator = `(?:\\*["'])?\s*[:=]\s*`

// headerSpans finds each keyword (on the lowercased text, at \b) followed
// by headerSeparator and returns its value. An occurrence inside an
// earlier value is not tried again (security review H1).
func headerSpans(s string, keyword string, sep *regexp.Regexp) []span {
	lower := asciiLower(s)
	var out []span
	covered := 0
	eachIndex(lower, keyword, func(i int) {
		if i < covered || !wordStart(lower, i) {
			return
		}
		m := matchAt(sep, lower, i+len(keyword))
		if m == nil {
			return
		}
		if sp, ok := headerValueAt(s, m[1]); ok {
			out = append(out, sp)
			covered = sp.end
		}
	})
	return out
}

// headerValueAt reads a header value at s[v:]: a quoted value up to its
// closing quote (quotedValue), else to the end of the line. Trailing
// blanks are left out, so a value that is only blanks is not a match.
func headerValueAt(s string, v int) (span, bool) {
	start, end := v, lineEnd(s, v)
	if qs, qe, quoted, closed := quotedValue(s, v); quoted {
		start = qs
		if closed {
			end = qe
		} else {
			end = lineEnd(s, qs)
		}
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return span{start: start, end: end}, end > start
}

func lineEnd(s string, i int) int {
	j := strings.IndexByte(s[i:], '\n')
	if j < 0 {
		j = len(s) - i
	}
	work(j)
	return i + j
}

// quotedValue reads a quoted value at s[v:]. The opening quote may follow
// k backslashes (a JSON document logged inside a JSON string, at any
// depth; ruling on PR #10). It closes at the same quote character
// preceded by exactly k backslashes, or, at k = 0, for a double quote, by
// an even number (a plain JSON string, where \" is part of the value). A
// single-quoted value at k = 0 has two candidate ends and the longer span
// is taken (§4.2 "Escaped quotes", OQ17): the shell-style end, the next
// single quote, and the SQL-style end, the first single quote after an
// even number of backslashes that is not doubled ("\'" and "”" are
// quotes inside the value). It returns the content span, whether the
// value is quoted, and whether it closed on its line.
func quotedValue(s string, v int) (start, end int, quoted, closed bool) {
	k := 0
	for v+k < len(s) && s[v+k] == '\\' {
		k++
	}
	if v+k >= len(s) || (s[v+k] != '"' && s[v+k] != '\'') {
		return 0, 0, false, false
	}
	q := s[v+k]
	start = v + k + 1
	shell := -1
	i := start
	for ; i < len(s) && s[i] != '\n'; i++ {
		if s[i] != q {
			continue
		}
		m := 0
		for i-m-1 >= start && s[i-m-1] == '\\' {
			m++
		}
		switch {
		case k > 0 || q == '"':
			if m == k || (k == 0 && m%2 == 0) {
				work(i - start)
				return start, i - m, true, true
			}
		case shell < 0:
			shell = i
			fallthrough
		default:
			if m%2 == 1 {
				continue
			}
			if i+1 < len(s) && s[i+1] == '\'' {
				i++ // a doubled quote inside an SQL value
				continue
			}
			work(i - start)
			return start, i, true, true
		}
	}
	work(i - start)
	if shell >= 0 {
		return start, shell, true, true
	}
	return start, len(s), true, false
}

func authorizationHeader() detector {
	sep := anchored(headerSeparator)
	st := anchored(`(?:bearer|basic|token)\s+([A-Za-z0-9._~+/-]{8,}=*)`)
	return detector{
		id:      "authorization-header",
		kind:    kindValue,
		extend:  true,
		classes: allClasses,
		res:     []*regexp.Regexp{sep, st},
		tables:  []string{"keyword:authorization", "standalone:bearer|basic|token", "word-start", "ascii-case-insensitive", "value:quoted-by-level-or-line"},
		find: func(s string) ([]span, error) {
			// The anchored patterns run on the ASCII-lowercased text, which
			// keeps every offset, in place of (?i).
			out := headerSpans(s, "authorization", sep)
			return append(out, literalSpans(asciiLower(s), []string{"bearer", "basic", "token"}, st, true, true)...), nil
		},
		samples: func() ([]string, []string) {
			return []string{"Authorization: Bearer " + strings.Repeat("a", 12)},
				[]string{"Authorization header missing"}
		},
	}
}

func cookieHeader() detector {
	sep := anchored(headerSeparator)
	return detector{
		id:      "cookie-header",
		kind:    kindValue,
		classes: textClasses,
		res:     []*regexp.Regexp{sep},
		tables:  []string{"keyword:cookie", "word-start", "ascii-case-insensitive", "value:quoted-by-level-or-line"},
		find: func(s string) ([]span, error) {
			// "Set-Cookie": '-' is not a word character, so \b holds before
			// "cookie" there too.
			return headerSpans(s, "cookie", sep), nil
		},
		samples: func() ([]string, []string) {
			return []string{"Cookie: session=" + "abc"}, []string{"cookie jar empty"}
		},
	}
}

// secretKeyWords are the key-name fragments of §4.2 secret-assignment.
var secretKeyWords = []string{
	"password", "passwd", "passphrase", "pwd", "secret", "token", "apikey",
	"api_key", "api-key", "accesskey", "access_key", "privatekey", "private_key",
	"credential", "authkey", "auth_key", "sessionkey", "session_key",
	"masterauth", "requirepass",
}

// assignmentBare is an unquoted value: up to whitespace, ';', ',', '&' or
// '}'. A quoted value (JSON, YAML, shell, and escaped JSON at any depth)
// is read by quotedValue.
const assignmentBare = `[^\s;,&}]+`

// After a key, its separator: an optional closing quote (with any number
// of backslashes), spaces, and "=", ":" or "=>" (or only whitespace for
// requirepass and masterauth). Anchored: the key itself is found by
// keyword search.
const (
	assignAfterKey      = `^(?:\\*["'])?[ \t]*(?:=>|=|:)[ \t]*`
	assignAfterSpaceKey = `^(?:\\*["'])?[ \t]+`
)

// secretSQLPatterns are the SQL and Azure forms of secret-assignment,
// with the lowercase literal each needs. An SQL form's pattern ends where
// its quoted value starts, and quotes lists the quote characters that may
// open it; the value is read by quotedValue, so "\'" and "”" inside it
// are handled as for any other key (OQ17). The Azure form captures its
// value in group 1.
var secretSQLPatterns = []struct {
	body     string // matched on the lowercased text, after \b
	literals []string
	quotes   string
}{
	{`identified[ \t]+(?:with[ \t]+[a-z0-9_]+[ \t]+)?by[ \t]+`, []string{"identified"}, `'"`},
	{`password[ \t]*=?[ \t]*`, []string{"password"}, `'`},
	{`(?:accountkey|sharedaccesskey)=([^;\s"']+)`, []string{"accountkey", "sharedaccesskey"}, ""},
}

func secretAssignment() detector {
	after := regexp.MustCompile(assignAfterKey)
	afterSpace := regexp.MustCompile(assignAfterSpaceKey)
	bare := anchored(assignmentBare)
	res := []*regexp.Regexp{after, afterSpace, bare}
	tables := []string{"anchor:keywords", "key-bytes:[A-Za-z0-9_.-]", "space-separator:requirepass,masterauth",
		"value:quoted-by-level-or-bare", "ascii-case-insensitive"}
	for _, p := range secretSQLPatterns {
		res = append(res, anchored(p.body))
		tables = append(tables, "sql-quotes:"+p.quotes)
	}
	return detector{
		id:      "secret-assignment",
		kind:    kindValue,
		classes: allClasses,
		res:     res,
		tables:  tables,
		find: func(s string) ([]span, error) {
			lower := asciiLower(s)
			out := secretKeyValues(s, lower, after, afterSpace, bare)
			for i, p := range secretSQLPatterns {
				re := res[3+i]
				if p.quotes == "" {
					out = append(out, literalSpans(lower, p.literals, re, true, true)...)
					continue
				}
				for _, m := range literalSpans(lower, p.literals, re, true, false) {
					if sp, ok := sqlValueAt(s, m.end, p.quotes); ok {
						out = append(out, sp)
					}
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"DB_PASSWORD=" + "x1", "requirepass " + "x2", "IDENTIFIED BY '" + "x3'"},
				[]string{"password reset requested"}
		},
	}
}

// sqlValueAt reads the quoted value of an SQL form at s[v:]: it must open
// with one of quotes (after any backslashes). A value that does not close
// on its line runs to the line end (recall first, R33).
func sqlValueAt(s string, v int, quotes string) (span, bool) {
	k := v
	for k < len(s) && s[k] == '\\' {
		k++
	}
	if k >= len(s) || strings.IndexByte(quotes, s[k]) < 0 {
		return span{}, false
	}
	start, end, quoted, closed := quotedValue(s, v)
	if !quoted {
		return span{}, false
	}
	if !closed {
		end = lineEnd(s, start)
	}
	return span{start: start, end: end}, end > start
}

// secretKeyValues finds each key that contains a keyword (the whole run of
// [A-Za-z0-9_.-] around it, as the §4.2 pattern's leftmost match would)
// and returns the value after its separator.
func secretKeyValues(s, lower string, after, afterSpace, bare *regexp.Regexp) []span {
	var out []span
	seen := map[int]bool{}
	for _, kw := range secretKeyWords {
		// An occurrence inside the previous key or value of this keyword
		// is not tried again: same key, or a value already covered (H1).
		covered := 0
		for from := 0; ; {
			i := strings.Index(lower[from:], kw)
			if i < 0 {
				break
			}
			i += from
			from = i + len(kw)
			if i < covered {
				continue
			}
			ks, ke := i, i+len(kw)
			for ks > 0 && isKeyByte(s[ks-1]) {
				ks--
			}
			for ke < len(s) && isKeyByte(s[ke]) {
				ke++
			}
			work(ke - ks)
			covered = ke
			if seen[ks] {
				continue
			}
			seen[ks] = true
			res := []*regexp.Regexp{after}
			if key := lower[ks:ke]; strings.Contains(key, "requirepass") || strings.Contains(key, "masterauth") {
				res = append(res, afterSpace)
			}
			for _, re := range res {
				m := re.FindStringIndex(s[ke:])
				if m == nil {
					continue
				}
				if sp, ok := assignmentValueAt(s, ke+m[1], bare); ok {
					out = append(out, sp)
					covered = max(covered, sp.end)
					break
				}
			}
		}
	}
	return out
}

func isKeyByte(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == '-' }

// assignmentValueAt reads a secret-assignment value at s[v:]: a quoted
// value that closes on its line, else a bare value. An empty value is not
// a match (§4.2).
func assignmentValueAt(s string, v int, bare *regexp.Regexp) (span, bool) {
	if start, end, quoted, closed := quotedValue(s, v); quoted && closed {
		return span{start: start, end: end}, end > start
	}
	if m := bare.FindStringIndex(s[v:]); m != nil {
		return span{start: v, end: v + m[1]}, true
	}
	return span{}, false
}

// asciiLower lowercases ASCII letters only, so byte offsets are unchanged.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
