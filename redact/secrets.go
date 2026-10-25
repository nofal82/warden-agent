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
		canon:   canon(pemBeginPattern, pemEndPattern, "pair-to-end-or-input-end", "orphan-end"),
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
		canon:   canon(`[A-Za-z0-9+/]+={0,2}`, "prefix-ws-or-colon", "60-76-not-lower-hex", "4-76-next-to-body-or-marker", "orphan-end-run-1-76", pemAnyPattern),
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
		canon:   canon(runPattern, "run-start", "decode-max-96", headPattern),
		find: func(s string) ([]span, error) {
			var out []span
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
		canon:   canon(pattern),
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
		canon:   canon(`\b`+body, "anchor:prefixes"),
		find: func(s string) ([]span, error) {
			return literalSpans(s, awsKeyPrefixes, re, true, false), nil
		},
		samples: func() ([]string, []string) {
			return []string{"AKIA" + strings.Repeat("Q", 16)}, []string{"AKIA" + strings.Repeat("Q", 15)}
		},
	}
}

func awsSecretKey() detector {
	const pattern = `(?i)(?:aws_secret_access_key|secret_access_key|secretaccesskey)["']?\s*(?:=>|[:=]|\s)\s*["']?([A-Za-z0-9/+=]{40})`
	re := regexp.MustCompile(pattern)
	return detector{
		id:      "aws-secret-key",
		kind:    kindValue,
		extend:  true,
		classes: allClasses,
		canon:   canon(pattern),
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
// of its prefix literals.
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
}

// vendorSKBody is the generic sk- form; its validator refuses a match
// followed by a unit suffix (gate item, 2026-10-25).
const vendorSKBody = `sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}`

func vendorToken() detector {
	res := make([]*regexp.Regexp, len(vendorPatterns))
	pats := make([]string, 0, len(vendorPatterns)+2)
	for i, p := range vendorPatterns {
		res[i] = anchored(p.body)
		pats = append(pats, `\b`+p.body)
	}
	sk := anchored(vendorSKBody)
	return detector{
		id:      "vendor-token",
		kind:    kindMarker,
		extend:  true,
		classes: allClasses,
		canon:   canon(append(pats, `\b`+vendorSKBody, "sk-not-before-unit-suffix", "anchor:prefixes")...),
		find: func(s string) ([]span, error) {
			var out []span
			for i, re := range res {
				out = append(out, literalSpans(s, vendorPatterns[i].literals, re, true, false)...)
			}
			for _, sp := range literalSpans(s, []string{"sk-"}, sk, true, false) {
				if !startsWithUnitSuffix(s[sp.end:]) {
					out = append(out, sp)
				}
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"gh" + "p_" + strings.Repeat("a", 36), "sk" + "-proj-" + strings.Repeat("b", 40)},
				[]string{"sk-payments-db.service", "sk" + "-" + strings.Repeat("c", 40) + ".service"}
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
		canon:   canon(pattern, "header-json-object-with-alg"),
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

func urlCredentials() detector {
	const pattern = `[a-zA-Z][a-zA-Z0-9+.-]*://([^\s"']*)@`
	rest := anchored(`://([^\s"']*)@`)
	return detector{
		id:      "url-credentials",
		kind:    kindValue,
		classes: allClasses,
		canon:   canon(pattern, "userinfo-has-colon", "anchor:://"),
		find: func(s string) ([]span, error) {
			var out []span
			eachIndex(s, "://", func(i int) {
				// The scheme is the leftmost letter-led run of scheme
				// characters before "://", as the pattern's leftmost match.
				k := i
				for k > 0 && isSchemeByte(s[k-1]) {
					k--
				}
				for k < i && !isLetter(s[k]) {
					k++
				}
				if k == i {
					return
				}
				if m := matchAt(rest, s, i); m != nil && m[3] > m[2] && strings.Contains(s[m[2]:m[3]], ":") {
					out = append(out, span{start: m[2], end: m[3]})
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
	pattern := `(?i)[?&;](?:` + strings.Join(urlSecretParams, "|") + `)=([^&\s#"']+)`
	value := anchored(`=([^&\s#"']+)`)
	names := map[string]bool{}
	for _, n := range urlSecretParams {
		names[n] = true
	}
	return detector{
		id:      "url-secret-param",
		kind:    kindValue,
		classes: allClasses,
		canon:   canon(pattern, "anchor:="),
		find: func(s string) ([]span, error) {
			var out []span
			lower := asciiLower(s)
			eachIndex(s, "=", func(i int) {
				k := i
				for k > 0 && (isAlnum(s[k-1]) || s[k-1] == '_' || s[k-1] == '-') {
					k--
				}
				if k == 0 || strings.IndexByte("?&;", s[k-1]) < 0 || !names[lower[k:i]] {
					return
				}
				if m := matchAt(value, s, i); m != nil {
					out = append(out, span{start: m[2], end: m[3]})
				}
			})
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"https://h/?access_token=" + "abc"}, []string{"https://h/?page=2"}
		},
	}
}

// headerValue is the value part shared by the header detectors: a quoted
// value up to its closing quote, or the rest of the line.
const headerValue = `\s*[:=]\s*(?:"([^"\n]*)"?|'([^'\n]*)'?|([^\n]*))`

func authorizationHeader() detector {
	const header = `(?i)\b(?:proxy-)?authorization["']?` + headerValue
	const standalone = `(?i)\b(?:bearer|basic|token)\s+([A-Za-z0-9._~+/-]{8,}=*)`
	h := anchored(`authorization["']?` + headerValue)
	st := anchored(`(?:bearer|basic|token)\s+([A-Za-z0-9._~+/-]{8,}=*)`)
	return detector{
		id:      "authorization-header",
		kind:    kindValue,
		extend:  true,
		classes: allClasses,
		canon:   canon(header, standalone, "anchor:keywords"),
		find: func(s string) ([]span, error) {
			// The anchored patterns run on the ASCII-lowercased text, which
			// keeps every offset, in place of (?i).
			lower := asciiLower(s)
			out := trimSpans(s, literalSpans(lower, []string{"authorization"}, h, true, true))
			return append(out, literalSpans(lower, []string{"bearer", "basic", "token"}, st, true, true)...), nil
		},
		samples: func() ([]string, []string) {
			return []string{"Authorization: Bearer " + strings.Repeat("a", 12)},
				[]string{"Authorization header missing"}
		},
	}
}

func cookieHeader() detector {
	const header = `(?i)\b(?:set-)?cookie["']?` + headerValue
	h := anchored(`cookie["']?` + headerValue)
	return detector{
		id:      "cookie-header",
		kind:    kindValue,
		classes: textClasses,
		canon:   canon(header, "anchor:cookie"),
		find: func(s string) ([]span, error) {
			// "Set-Cookie": '-' is not a word character, so \b holds before
			// "cookie" there too.
			return trimSpans(s, literalSpans(asciiLower(s), []string{"cookie"}, h, true, true)), nil
		},
		samples: func() ([]string, []string) {
			return []string{"Cookie: session=" + "abc"}, []string{"cookie jar empty"}
		},
	}
}

// trimSpans leaves trailing spaces and tabs out of header values, so a
// value that is only blanks is not a match.
func trimSpans(s string, spans []span) []span {
	var out []span
	for _, sp := range spans {
		for sp.end > sp.start && (s[sp.end-1] == ' ' || s[sp.end-1] == '\t') {
			sp.end--
		}
		if sp.end > sp.start {
			out = append(out, sp)
		}
	}
	return out
}

// secretKeyWords are the key-name fragments of §4.2 secret-assignment.
var secretKeyWords = []string{
	"password", "passwd", "passphrase", "pwd", "secret", "token", "apikey",
	"api_key", "api-key", "accesskey", "access_key", "privatekey", "private_key",
	"credential", "authkey", "auth_key", "sessionkey", "session_key",
	"masterauth", "requirepass",
}

// assignmentValue is a quoted string (JSON, YAML, shell) or a bare value up to
// whitespace, ';', ',', '&' or '}'.
const assignmentValue = `(?:"((?:[^"\\\n]|\\.)*)"|'([^'\n]*)'|([^\s;,&}]+))`

// After a key, its separator and value: an optional closing quote, spaces,
// and "=", ":" or "=>" (or only whitespace for requirepass and
// masterauth). Anchored: the key itself is found by keyword search.
const (
	secretAfterKey      = `^["']?[ \t]*(?:=>|=|:)[ \t]*` + assignmentValue
	secretAfterSpaceKey = `^["']?[ \t]+` + assignmentValue
)

// secretSQLPatterns are the SQL and Azure forms of secret-assignment, with
// the lowercase literal each needs.
var secretSQLPatterns = []struct {
	body     string // matched on the lowercased text, after \b
	literals []string
}{
	{`identified[ \t]+(?:with[ \t]+[a-z0-9_]+[ \t]+)?by[ \t]+(?:'([^'\n]*)'|"([^"\n]*)")`, []string{"identified"}},
	{`password[ \t]*=?[ \t]*'([^'\n]*)'`, []string{"password"}},
	{`(?:accountkey|sharedaccesskey)=([^;\s"']+)`, []string{"accountkey", "sharedaccesskey"}},
}

func secretAssignment() detector {
	after := regexp.MustCompile(secretAfterKey)
	afterSpace := regexp.MustCompile(secretAfterSpaceKey)
	sql := make([]*regexp.Regexp, len(secretSQLPatterns))
	pats := []string{"anchor:keywords",
		`["']?[A-Za-z0-9_.-]*(?i:` + strings.Join(secretKeyWords, "|") + `)[A-Za-z0-9_.-]*` + strings.TrimPrefix(secretAfterKey, "^"),
		`[A-Za-z0-9_.-]*(?i:requirepass|masterauth)[A-Za-z0-9_.-]*` + strings.TrimPrefix(secretAfterSpaceKey, "^"),
	}
	for i, p := range secretSQLPatterns {
		sql[i] = anchored(p.body)
		pats = append(pats, `(?i)\b`+p.body)
	}
	return detector{
		id:      "secret-assignment",
		kind:    kindValue,
		classes: allClasses,
		canon:   canon(pats...),
		find: func(s string) ([]span, error) {
			lower := asciiLower(s)
			out := secretKeyValues(s, lower, after, afterSpace)
			for i, re := range sql {
				out = append(out, literalSpans(lower, secretSQLPatterns[i].literals, re, true, true)...)
			}
			return out, nil
		},
		samples: func() ([]string, []string) {
			return []string{"DB_PASSWORD=" + "x1", "requirepass " + "x2", "IDENTIFIED BY '" + "x3'"},
				[]string{"password reset requested"}
		},
	}
}

// secretKeyValues finds each key that contains a keyword (the whole run of
// [A-Za-z0-9_.-] around it, as the §4.2 pattern's leftmost match would)
// and returns the value after its separator.
func secretKeyValues(s, lower string, after, afterSpace *regexp.Regexp) []span {
	var out []span
	seen := map[int]bool{}
	for _, kw := range secretKeyWords {
		for from := 0; ; {
			i := strings.Index(lower[from:], kw)
			if i < 0 {
				break
			}
			i += from
			from = i + len(kw)
			ks, ke := i, i+len(kw)
			for ks > 0 && isKeyByte(s[ks-1]) {
				ks--
			}
			for ke < len(s) && isKeyByte(s[ke]) {
				ke++
			}
			if seen[ks] {
				continue
			}
			seen[ks] = true
			res := []*regexp.Regexp{after}
			if key := lower[ks:ke]; strings.Contains(key, "requirepass") || strings.Contains(key, "masterauth") {
				res = append(res, afterSpace)
			}
			for _, re := range res {
				if sp, ok := firstGroup(re, s, ke); ok {
					out = append(out, sp)
					break
				}
			}
		}
	}
	return out
}

func isKeyByte(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == '-' }

// firstGroup matches the anchored re at s[at:] and returns its first
// non-empty capture group as an absolute span.
func firstGroup(re *regexp.Regexp, s string, at int) (span, bool) {
	m := re.FindStringSubmatchIndex(s[at:])
	for g := 2; m != nil && g+1 < len(m); g += 2 {
		if m[g] >= 0 && m[g+1] > m[g] {
			return span{start: at + m[g], end: at + m[g+1]}, true
		}
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
