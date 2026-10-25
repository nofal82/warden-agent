package redact

// In-process canary test (section 4.7, R58-R63, AC19, AC30 partial, AC32,
// AC37). Every canary in scope is built at run time; the lab-only aspects
// (real agent, executor and control plane) are out of scope here.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"testing"
)

// path is one way into the redactor.
type path uint8

const (
	pE path = 1 << iota // Redact E-TEXT
	pT                  // Redact T-TEXT
	pG                  // RedactGroup (P4 messages[], one message per line)
	pN                  // Redact T-NAME
	pP                  // Redact T-PATH
	pL                  // Redact L-VALUE

	textPaths = pE | pT | pG
	allPaths  = pE | pT | pG | pN | pP | pL
)

var pathNames = map[path]string{pE: "EText", pT: "TText", pG: "Group", pN: "TName", pP: "TPath", pL: "LValue"}

func (p path) class() Class {
	switch p {
	case pE:
		return EText
	case pT, pG:
		return TText
	case pN:
		return TName
	case pP:
		return TPath
	default:
		return LValue
	}
}

type canary struct {
	name    string
	text    string
	secrets []string // R61 secret parts
	id      string   // detector whose marker must appear ("" = see want)
	want    []string // other expected substrings (pseudonym, truncated network)
	paths   path
	// wholeOnly searches each secret only as a whole (R61's own condition
	// for C23: the truncated network legitimately shares a prefix with it).
	wholeOnly bool
}

func checkCanaryLeak(t *testing.T, where, hay string, c canary) {
	t.Helper()
	if !c.wholeOnly {
		assertNoLeak(t, where, hay, c.secrets...)
		return
	}
	for i, s := range c.secrets {
		if strings.Contains(strings.ToLower(hay), strings.ToLower(s)) {
			t.Errorf("%s: full address %d kept", where, i)
		}
	}
}

func runPath(red *Redactor, p path, in string, pz *Pseudonymizer) (string, Report, error) {
	if p == pG {
		out, rep, err := red.RedactGroup(bg, fieldFor(TText), strings.Split(in, "\n"), pz)
		return strings.Join(out, "\n"), rep, err
	}
	return red.Redact(bg, fieldFor(p.class()), in, pz)
}

func randInt(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic(err)
	}
	return v.Int64()
}

// buildCanaries returns every in-scope canary of section 4.7, freshly random.
func buildCanaries(t *testing.T, key [32]byte) []canary {
	t.Helper()
	k := getKeys(t)
	var cs []canary
	add := func(c canary) { cs = append(cs, c) }

	// C1-C4: key material.
	add(canary{name: "C1 RSA PEM", text: k.rsaPEM, secrets: pemBody(k.rsaPEM), id: "pem-private-key", paths: allPaths})
	add(canary{name: "C2 OpenSSH PEM", text: k.opensshPEM, secrets: pemBody(k.opensshPEM), id: "pem-private-key", paths: allPaths})
	doc, err := json.Marshal(map[string]string{"type": "service_account", "project_id": "lab-project", "private_key": k.pkcs8PEM + "\n"})
	if err != nil {
		t.Fatal(err)
	}
	add(canary{name: "C3 service-account JSON", text: string(doc), secrets: pemBody(k.pkcs8PEM), id: "pem-private-key", paths: allPaths})
	add(canary{name: "C4 body lines alone", text: strings.Join(pemBody(k.rsaPEM), "\n"), secrets: pemBody(k.rsaPEM), id: "pem-body-line", paths: pE | pG})

	// C5, C6.
	c5 := akia()
	add(canary{name: "C5 AWS key ID", text: "key " + c5 + " used", secrets: []string{c5}, id: "aws-access-key-id", paths: allPaths})
	c6 := randFrom(alphaAWSSecret, 40)
	add(canary{name: "C6 AWS secret", text: "aws_secret_access_key = " + c6, secrets: []string{c6}, id: "aws-secret-key", paths: allPaths})

	// C7: one vendor token each.
	for name, tok := range map[string]string{
		"GitHub":        "gh" + "p_" + randFrom(alphaAlnum, 36),
		"GitLab":        "glpat" + "-" + randFrom(alphaAlnum, 20),
		"Slack":         "xo" + "xb-" + randFrom(alphaAlnum, 24),
		"Stripe":        "sk" + "_live_" + randFrom(alphaAlnum, 24),
		"Google":        "AI" + "za" + randFrom(alphaAlnum, 35),
		"npm":           "npm" + "_" + randFrom(alphaAlnum, 36),
		"Docker":        "dckr" + "_pat_" + randFrom(alphaAlnum, 24),
		"Anthropic":     "sk-" + "ant-" + randFrom(alphaAlnum, 40),
		"age":           "AGE-" + "SECRET-KEY-1" + randFrom(alphaUpperAlnum, 58),
		"Slack webhook": "https://hooks.slack" + ".com/services/T" + randFrom(alphaUpperAlnum, 8) + "/B" + randFrom(alphaUpperAlnum, 8) + "/" + randFrom(alphaAlnum, 24),
	} {
		add(canary{name: "C7 " + name, text: "using " + tok + " now", secrets: []string{tok}, id: "vendor-token", paths: allPaths})
	}

	// C8-C14.
	jwt := makeJWT()
	add(canary{name: "C8 JWT", text: "jwt " + jwt + " ok", secrets: []string{jwt}, id: "jwt", paths: allPaths})
	pw := randFrom(alphaAlnum, 16)
	for _, u := range []string{"postgresql://app:" + pw + "@db:5432/x", "mongodb+srv://u:" + pw + "@c/x", "mysql://u:" + pw + "@h/x"} {
		add(canary{name: "C9 " + u[:5], text: "dsn " + u, secrets: []string{pw}, id: "url-credentials", paths: allPaths})
	}
	tk := randFrom(alphaAlnum, 24)
	add(canary{name: "C10 access_token", text: "GET https://h/cb?code=1&access_token=" + tk, secrets: []string{tk}, id: "url-secret-param", paths: allPaths})
	add(canary{name: "C10 S3 token", text: "GET https://b.s3.example/o?X-Amz-Security-Token=" + tk, secrets: []string{tk}, id: "url-secret-param", paths: allPaths})
	bt := randFrom(alphaAlnum, 32)
	add(canary{name: "C11 bearer", text: "Authorization: Bearer " + bt, secrets: []string{bt}, id: "authorization-header", paths: allPaths})
	basic := base64.StdEncoding.EncodeToString([]byte("app:" + randFrom(alphaAlnum, 16)))
	add(canary{name: "C11 basic", text: "Authorization: Basic " + basic, secrets: []string{basic}, id: "authorization-header", paths: allPaths})
	sv := randFrom(alphaAlnum, 16)
	ak := randFrom(alphaAlnum, 86) + "=="
	for name, text := range map[string]string{
		"DB_PASSWORD":   "DB_PASSWORD=" + sv,
		"YAML password": `password: "` + sv + `"`,
		"requirepass":   "requirepass " + sv,
		"IDENTIFIED BY": "CREATE USER app IDENTIFIED BY '" + sv + "';",
	} {
		add(canary{name: "C12 " + name, text: text, secrets: []string{sv}, id: "secret-assignment", paths: allPaths})
	}
	add(canary{name: "C12 AccountKey", text: "AccountName=lab;Account" + "Key=" + ak + ";EndpointSuffix=core.example", secrets: []string{ak}, id: "secret-assignment", paths: allPaths})
	c13 := wdnToken()
	add(canary{name: "C13 enrollment token", text: "enrolling with " + c13, secrets: []string{c13}, id: "warden-enrollment-token", paths: allPaths})
	ck := randFrom(alphaAlnum, 24)
	add(canary{name: "C14 cookie", text: "Cookie: session=" + ck, secrets: []string{ck}, id: "cookie-header", paths: textPaths})

	// C15-C19: personal data. Numeric secrets are their digits.
	em := randFrom(alphaLower, 10) + "@" + randFrom(alphaLower, 8) + ".example"
	add(canary{name: "C15 e-mail", text: "mail to " + em, secrets: []string{em}, id: "email", paths: allPaths})
	ph1 := randDigits(8)
	add(canary{name: "C16 +962", text: "call +962 7" + ph1, secrets: []string{"7" + ph1}, id: "phone", paths: allPaths})
	ph2 := "079" + randDigits(7)
	add(canary{name: "C16 07x", text: "call " + ph2, secrets: []string{ph2}, id: "phone", paths: allPaths})
	jo := joDigits()
	add(canary{name: "C17 national number", text: "national number: " + jo, secrets: []string{jo}, id: "national-id-jo", paths: allPaths})
	kwJO := "الر" + r(0x064E) + "قم الوط" + r(0x0640) + "ني: "
	for form, f := range map[string]func(string) string{"ASCII": func(s string) string { return s }, "Arabic-Indic": arabicIndic, "Eastern": easternDigits} {
		d := joDigits()
		add(canary{name: "C17 Arabic " + form, text: kwJO + f(d), secrets: []string{d, f(d)}, id: "national-id-jo", paths: allPaths})
		s1, s2, s3 := saDigits(), "1"+randDigits(9), "2"+randDigits(9)
		add(canary{name: "C18 iqama " + form, text: "iqama: " + f(s1), secrets: []string{s1, f(s1)}, id: "national-id-sa", paths: allPaths})
		add(canary{name: "C18 raqm al-hawiya " + form, text: "رقم الهوية " + f(s2), secrets: []string{s2, f(s2)}, id: "national-id-sa", paths: allPaths})
		add(canary{name: "C18 al-iqama " + form, text: "الإقامة: " + f(s3), secrets: []string{s3, f(s3)}, id: "national-id-sa", paths: allPaths})
	}
	ae := luhnComplete("784" + randDigits(11))
	aeBad := luhnBreak("784" + randDigits(12))
	for name, d := range map[string]string{"valid": ae, "not Luhn": aeBad} {
		add(canary{name: "C18 Emirates undashed " + name, text: "id " + d, secrets: []string{d}, id: "national-id-ae", paths: allPaths})
		dashed := d[:3] + "-" + d[3:7] + "-" + d[7:14] + "-" + d[14:]
		add(canary{name: "C18 Emirates dashed " + name, text: "id " + dashed, secrets: []string{d, dashed}, id: "national-id-ae", paths: allPaths})
	}
	card := makeCard("4", 16)
	add(canary{name: "C19 card", text: "card " + card, secrets: []string{card}, id: "payment-card", paths: allPaths})
	iban := joIBAN()
	add(canary{name: "C19 JO IBAN", text: "iban " + iban, secrets: []string{iban}, id: "iban", paths: allPaths})

	// C20, C21: unit-id-shaped.
	c20tok := wdnToken()
	add(canary{name: "C20", text: "postgresql@" + c20tok + ".service", secrets: []string{c20tok}, id: "warden-enrollment-token", paths: allPaths})
	c21 := akia()
	add(canary{name: "C21", text: c21 + ".service", secrets: []string{c21}, id: "aws-access-key-id", paths: allPaths})

	// C22: evasion and structured-log variants.
	type split struct {
		name  string
		sep   string
		paths path
	}
	splits := []split{
		{"ANSI colour", "\x1b[31m", allPaths},
		{"U+200B", r(0x200B), allPaths},
		{"rsyslog escape", "#033[31m", textPaths},
		{"tag U+E0041", r(0xE0041), allPaths},
		{"invalid UTF-8", "\xff", allPaths},
		{"U+0001", "\x01", allPaths},
	}
	for _, s := range splits {
		k5 := akia()
		add(canary{name: "C22 C5 split by " + s.name, text: "key " + k5[:12] + s.sep + k5[12:] + " used", secrets: []string{k5}, id: "aws-access-key-id", paths: s.paths})
		pw24 := randFrom(alphaAlnum, 24)
		add(canary{name: "C22 C12 split by " + s.name, text: "DB_PASSWORD=" + pw24[:12] + s.sep + pw24[12:], secrets: []string{pw24}, id: "secret-assignment", paths: s.paths})
		t13 := wdnToken()
		add(canary{name: "C22 C13 split by " + s.name, text: "enrolling with " + t13[:20] + s.sep + t13[20:], secrets: []string{t13}, id: "warden-enrollment-token", paths: s.paths})
	}
	k5 := akia()
	add(canary{name: "C22 C5 next to U+2028", text: "x" + r(0x2028) + k5 + r(0x2028) + "y", secrets: []string{k5}, id: "aws-access-key-id", paths: allPaths})
	jp := randFrom(alphaAlnum, 16)
	add(canary{name: "C22 C12 JSON camelCase", text: `{"dbPassword":"` + jp + `"}`, secrets: []string{jp}, id: "secret-assignment", paths: allPaths})
	add(canary{name: "C22 C9 JSON-escaped", text: "dsn postgresql:" + bs + "/" + bs + "/app:" + jp + "@db", secrets: []string{jp}, id: "url-credentials", paths: textPaths})
	add(canary{name: "C22 C10 u0026", text: "GET https://h/cb?code=1" + bs + "u0026access_token=" + jp, secrets: []string{jp}, id: "url-secret-param", paths: textPaths})
	add(canary{name: "C22 C11 JSON member", text: `{"Authorization":"Bearer ` + jp + `"}`, secrets: []string{jp}, id: "authorization-header", paths: allPaths})
	add(canary{name: "C22 C14 JSON member", text: `{"Cookie":"session=` + jp + `"}`, secrets: []string{jp}, id: "cookie-header", paths: textPaths})
	add(canary{name: "C22 C1 CRLF", text: strings.ReplaceAll(k.rsaPEM, "\n", "\r\n"), secrets: pemBody(k.rsaPEM), id: "pem-private-key", paths: pE})
	var pre []string
	for _, l := range pemLines(k.rsaPEM) {
		pre = append(pre, journalPrefix+l)
	}
	add(canary{name: "C22 C1 journal prefix", text: strings.Join(pre, "\n"), secrets: pemBody(k.rsaPEM), id: "pem-private-key", paths: pE | pG})
	mid := append(append([]string{}, pemBody(k.rsaPEM)[4:]...), pemEndLine(k.rsaPEM))
	add(canary{name: "C22 C1 mid-block start", text: strings.Join(mid, "\n"), secrets: pemBody(k.rsaPEM)[4:], paths: pE | pG})

	// C23: public addresses, truncated.
	v4 := fmt.Sprintf("198.51.100.%d", 1+randInt(254))
	v6 := "2001:db8:" + randFrom(alphaHexLower, 4) + ":" + randFrom(alphaHexLower, 4) + "::" + randFrom("123456789abcdef", 1) + randFrom(alphaHexLower, 3)
	s6 := "2002:c000:02" + randFrom(alphaHexLower, 2) + ":" + randFrom("123456789abcdef", 1) + randFrom(alphaHexLower, 3) + "::1"
	mp := fmt.Sprintf("203.0.113.%d", 1+randInt(254))
	pfx := func(a string, n int) string {
		p, err := netip.MustParseAddr(a).Unmap().Prefix(n)
		if err != nil {
			t.Fatal(err)
		}
		return p.String()
	}
	add(canary{
		name:      "C23 access log",
		text:      v4 + " - - \"GET / HTTP/1.1\" 200 via " + v6 + " and " + s6 + " mapped ::ffff:" + mp + " end",
		secrets:   []string{v4, v6, s6, mp},
		want:      []string{pfx(v4, 24), pfx(v6, 48), pfx(s6, 40), pfx(mp, 24)},
		paths:     textPaths,
		wholeOnly: true,
	})

	// C24: a home-directory user name.
	n24 := c24Name()
	add(canary{name: "C24 home path", text: "/home/" + n24 + "/notes.txt", secrets: []string{n24},
		want: []string{"/home/" + wantPseudonym(key, homeLabel, n24) + "/notes.txt"}, paths: allPaths})

	// C25: base64 of C1.
	for name, enc := range map[string]*base64.Encoding{"standard": base64.StdEncoding, "URL-safe": base64.URLEncoding} {
		b := enc.EncodeToString([]byte(k.rsaPEM))
		add(canary{name: "C25 " + name + " alone", text: b, secrets: []string{b}, id: "pem-private-key-b64", paths: allPaths})
		add(canary{name: "C25 " + name + " JSON", text: `{"blob":"` + b + `"}`, secrets: []string{b}, id: "pem-private-key-b64", paths: allPaths})
	}
	return cs
}

// R61 pass condition for every in-scope canary through every applicable
// path, with R62's positive control and AC37's fixed point at intake.
func TestCanariesLeaveNoTrace(t *testing.T) {
	key := randKey(t)
	pz := NewPseudonymizer(key)
	red := testRedactor()
	for _, c := range buildCanaries(t, key) {
		for p := pE; p <= pL; p <<= 1 {
			if c.paths&p == 0 {
				continue
			}
			t.Run(c.name+"/"+pathNames[p], func(t *testing.T) {
				out, rep, err := runPath(red, p, c.text, pz)
				if err != nil {
					checkCanaryLeak(t, "error", err.Error(), c)
					tooLong := len(c.text) > fieldFor(p.class()).MaxBytes && p != pE
					if !tooLong || !errors.Is(err, ErrInputTooLarge) {
						t.Fatalf("unexpected error %v", err)
					}
					if out != "" {
						t.Errorf("output returned with the error")
					}
					return
				}
				checkCanaryLeak(t, "output", out, c)
				checkCanaryLeak(t, "report", fmt.Sprintf("%+v", rep), c)
				if c.id != "" && !strings.Contains(out, classMarker(p.class(), c.id)) {
					t.Errorf("positive control: output lacks %s: %q", classMarker(p.class(), c.id), lastN(out, 120))
				}
				for _, w := range c.want {
					if !strings.Contains(out, w) {
						t.Errorf("positive control: output lacks %q: %q", w, out)
					}
				}
				// Intake (no key) over the agent's output: zero matches, and
				// redacting twice equals redacting once.
				again, rep2, err := runPath(red, p, out, nil)
				if err != nil {
					t.Fatalf("second pass error %v", err)
				}
				if again != out {
					t.Errorf("second pass changed the output:\n %q\n %q", lastN(out, 120), lastN(again, 120))
				}
				if replacedTotal(rep2) != 0 || rep2.MarkerFired || rep2.UserNameMarkers != 0 || rep2.Pseudonymised != 0 {
					t.Errorf("second pass reported changes: %+v", rep2)
				}
			})
		}
	}
}

// R18: every marker-replacing canary makes Scan report a match.
func TestCanariesScan(t *testing.T) {
	red := testRedactor()
	for _, c := range buildCanaries(t, randKey(t)) {
		if c.id == "" || c.id == "cookie-header" || c.id == "pem-body-line" || c.paths&pN == 0 {
			continue
		}
		hit, err := red.Scan(bg, c.text)
		if err != nil || !hit {
			t.Errorf("%s: Scan = (%v, %v), want true", c.name, hit, err)
		}
	}
}

// C20 and C21 as LogEvent.unit_id (R11, AC6).
func TestCanaryUnitNames(t *testing.T) {
	tok := wdnToken()
	k := akia()
	for in, want := range map[string]string{
		"postgresql@" + tok + ".service": "postgresql@REDACTED-warden-enrollment-token.service",
		k + ".service":                   "REDACTED-aws-access-key-id.service",
	} {
		out, _, err := testRedactor().RedactUnitName(bg, in)
		if err != nil || out != want {
			t.Errorf("RedactUnitName: (%q, %v), want %q", out, err, want)
		}
		assertNoLeak(t, "unit", out, tok, k)
	}
}

// AC32: the R61 search finds a planted canary raw, as a 12-byte substring,
// upper-cased, in base64, base64url and hex.
func TestR61SearchSelfTest(t *testing.T) {
	s := randFrom(alphaLowerAlnum, 24) + "/+?"
	found := map[string]string{
		"raw":         "x " + s + " y",
		"substring":   "x " + s[5:17] + " y",
		"upper-cased": "x " + strings.ToUpper(s) + " y",
		"base64":      "x " + base64.StdEncoding.EncodeToString([]byte(s)) + " y",
		"base64url":   "x " + base64.URLEncoding.EncodeToString([]byte(s)) + " y",
		"raw b64url":  "x " + base64.RawURLEncoding.EncodeToString([]byte(s)) + " y",
		"hex":         "x " + hex.EncodeToString([]byte(s)) + " y",
	}
	for name, hay := range found {
		if !leakFound(hay, s) {
			t.Errorf("%s: planted canary not found", name)
		}
	}
	for name, hay := range map[string]string{
		"absent":       "x " + randFrom(alphaLowerAlnum, 24) + " y",
		"11-byte part": "x " + s[3:14] + " y",
		"marker":       Marker("aws-access-key-id"),
	} {
		if leakFound(hay, s) {
			t.Errorf("%s: false hit", name)
		}
	}
}
