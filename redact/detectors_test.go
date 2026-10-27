package redact

// Detector tests (section 4.2, AC10): positive cases for every pattern
// variant and negative near misses, run through the full E-TEXT pipeline
// with the real rule table.

import (
	"encoding/base64"
	"strings"
	"testing"
)

// ecase is an E-TEXT case with an exact expected output. An empty id means
// the input must pass unchanged with no replacement reported.
type ecase struct {
	name string
	in   string
	want string
	id   string
}

func runE(t *testing.T, cases []ecase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, rep := redactE(t, c.in)
			if out != c.want {
				t.Errorf("Redact(EText, %q)\n got  %q\n want %q", c.in, out, c.want)
			}
			checkReportKeys(t, rep)
			if c.id == "" {
				if n := replacedTotal(rep); n != 0 || rep.MarkerFired {
					t.Errorf("unchanged input reported %d replacements (MarkerFired %v)", n, rep.MarkerFired)
				}
				return
			}
			if rep.Replaced[c.id] < 1 {
				t.Errorf("Report.Replaced[%q] = %d, want >= 1", c.id, rep.Replaced[c.id])
			}
			if c.id != "public-ip" && !rep.MarkerFired {
				t.Errorf("MarkerFired is false after a %s replacement", c.id)
			}
		})
	}
}

// ccase is an E-TEXT case whose exact output is not fixed by the spec (for
// example whether quotes around a value are kept): the marker must be
// present, the kept parts present and the secret parts absent.
type ccase struct {
	name    string
	in      string
	id      string
	keep    []string
	secrets []string
}

func runC(t *testing.T, cases []ccase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, rep := redactE(t, c.in)
			if !strings.Contains(out, Marker(c.id)) {
				t.Errorf("output %q lacks %s", out, Marker(c.id))
			}
			for _, k := range c.keep {
				if !strings.Contains(out, k) {
					t.Errorf("output %q lost the kept part %q", out, k)
				}
			}
			assertNoLeak(t, c.name, out, c.secrets...)
			if rep.Replaced[c.id] < 1 {
				t.Errorf("Report.Replaced[%q] = %d, want >= 1", c.id, rep.Replaced[c.id])
			}
			checkReportKeys(t, rep)
		})
	}
}

func same(name, in string) ecase { return ecase{name: name, in: in, want: in} }

// ---------------------------------------------------------------------------
// Rule identity (section 4.5, ruling 8).

func TestDetectorIDsAndOrder(t *testing.T) {
	got := Detectors()
	if len(got) != len(specDetectorIDs) {
		t.Fatalf("Detectors() has %d IDs, want %d", len(got), len(specDetectorIDs))
	}
	for i := range got {
		if got[i] != specDetectorIDs[i] {
			t.Errorf("Detectors()[%d] = %q, want %q", i, got[i], specDetectorIDs[i])
		}
	}
	// The returned slice is a copy: a caller cannot reorder the rules (R43).
	got[0] = "tampered"
	if again := Detectors(); len(again) == 0 || again[0] != specDetectorIDs[0] {
		t.Errorf("mutating the result of Detectors() changed the rule table")
	}
	rules := defaultRules()
	if len(rules) != len(specDetectorIDs) {
		t.Fatalf("defaultRules() has %d detectors, want %d", len(rules), len(specDetectorIDs))
	}
	for i, d := range rules {
		if d.id != specDetectorIDs[i] {
			t.Errorf("defaultRules()[%d].id = %q, want %q", i, d.id, specDetectorIDs[i])
		}
	}
}

func TestRulesIdentity(t *testing.T) {
	// Raised from 1 by the 13th review's rule changes (R28a, B1, S2,
	// OQ15-OQ17; R43, AC73).
	if RulesVersion < 2 {
		t.Errorf("RulesVersion = %d, want at least 2", RulesVersion)
	}
	d1, d2 := RulesDigest(), RulesDigest()
	if d1 == ([32]byte{}) {
		t.Errorf("RulesDigest() is all zero")
	}
	if d1 != d2 {
		t.Errorf("RulesDigest() is not stable across calls")
	}
	if err := New().Err(); err != nil {
		t.Errorf("New().Err() = %v, want nil with the real rule table", err)
	}
}

// The table's attributes match section 4.2: kind, extend and "applies to".
func TestDetectorTableAttributes(t *testing.T) {
	valueKind := map[string]bool{
		"aws-secret-key": true, "secret-assignment": true, "authorization-header": true,
		"cookie-header": true, "url-secret-param": true, "url-credentials": true,
	}
	extend := map[string]bool{
		"pem-private-key-b64": true, "warden-enrollment-token": true, "aws-secret-key": true,
		"vendor-token": true, "jwt": true, "authorization-header": true,
	}
	textOnly := map[string]bool{"cookie-header": true, "public-ip": true}
	if len(defaultRules()) != len(specDetectorIDs) {
		t.Fatalf("defaultRules() has %d detectors, want %d", len(defaultRules()), len(specDetectorIDs))
	}
	for _, d := range defaultRules() {
		wantKind := kindMarker
		switch {
		case d.id == "public-ip":
			wantKind = kindIP
		case valueKind[d.id]:
			wantKind = kindValue
		}
		if d.kind != wantKind {
			t.Errorf("%s: kind = %d, want %d", d.id, d.kind, wantKind)
		}
		if d.extend != extend[d.id] {
			t.Errorf("%s: extend = %v, want %v", d.id, d.extend, extend[d.id])
		}
		if d.find == nil || d.samples == nil {
			t.Errorf("%s: find or samples is nil", d.id)
		}
		switch {
		case textOnly[d.id]:
			if d.classes&bit(EText) == 0 || d.classes&bit(TText) == 0 {
				t.Errorf("%s: must apply to EText and TText", d.id)
			}
			if d.classes&(bit(TName)|bit(TPath)|bit(LValue)|bit(NPatterned)) != 0 {
				t.Errorf("%s: is a text detector, must not apply to TName, TPath, LValue or NPatterned", d.id)
			}
		case d.id == "pem-body-line":
			if d.classes&bit(EText) == 0 || d.classes&bit(TText) == 0 {
				t.Errorf("%s: must apply to EText and the P4 T-TEXT group", d.id)
			}
			if d.classes&(bit(TName)|bit(TPath)|bit(LValue)|bit(NPatterned)) != 0 {
				t.Errorf("%s: must not apply to TName, TPath, LValue or NPatterned", d.id)
			}
		default:
			for _, c := range []Class{TName, TPath, TText, EText, LValue, NPatterned} {
				if d.classes&bit(c) == 0 {
					t.Errorf("%s: applies to all, but not to %s", d.id, className(c))
				}
			}
		}
	}
}

// R42: every detector's built-in samples pass its own check. The positive
// samples match and the negative ones do not.
func TestDetectorSelfTestSamples(t *testing.T) {
	rules := defaultRules()
	if len(rules) == 0 {
		t.Fatal("no rules")
	}
	for _, d := range rules {
		pos, neg := d.samples()
		if len(pos) == 0 || len(neg) == 0 {
			t.Errorf("%s: needs positive and negative samples (got %d, %d)", d.id, len(pos), len(neg))
		}
		for i, s := range pos {
			sp, err := d.find(s)
			if err != nil || len(sp) == 0 {
				t.Errorf("%s: positive sample %d did not match (err %v)", d.id, i, err)
			}
		}
		for i, s := range neg {
			sp, err := d.find(s)
			if err != nil || len(sp) != 0 {
				t.Errorf("%s: negative sample %d matched (err %v)", d.id, i, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Secrets.

func TestWardenEnrollmentToken(t *testing.T) {
	tok := wdnToken()
	runE(t, []ecase{
		{"plain", "enrolling with " + tok + " now.", "enrolling with " + Marker("warden-enrollment-token") + " now.", "warden-enrollment-token"},
		{"extends to token boundary", "arg x" + tok + "y ok.", "arg " + Marker("warden-enrollment-token") + " ok.", "warden-enrollment-token"},
		{"extends across '=' (not a boundary)", "arg k=" + tok + " ok.", "arg " + Marker("warden-enrollment-token") + " ok.", "warden-enrollment-token"},
		same("42 characters", "enrolling with "+tok[:len(tok)-1]+" now."),
		same("wrong version prefix", "enrolling with wdn2"+tok[4:]+" now."),
	})
}

func TestAWSAccessKeyID(t *testing.T) {
	var cases []ecase
	for _, p := range []string{"AK" + "IA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AIPA", "ANPA", "ANVA", "AROA", "APKA"} {
		k := p + randFrom(alphaUpperB32, 16)
		cases = append(cases, ecase{"prefix " + p, "key " + k + " used.", "key " + Marker("aws-access-key-id") + " used.", "aws-access-key-id"})
	}
	k := akia()
	cases = append(cases,
		ecase{"inside a path", "/srv/" + k + "/x ok.", "/srv/" + Marker("aws-access-key-id") + "/x ok.", "aws-access-key-id"},
		ecase{"no extension", "app-" + k + "-1 ok.", "app-" + Marker("aws-access-key-id") + "-1 ok.", "aws-access-key-id"},
		same("15 characters", "key "+k[:19]+" used."),
		same("17 characters", "key "+k+"Q used."),
		same("lower case", "key "+strings.ToLower(k)+" used."),
		same("no word boundary before", "key X"+k+" used."),
		same("digit outside base32", "key "+k[:19]+"1 used."),
	)
	runE(t, cases)
}

func TestAWSSecretKey(t *testing.T) {
	s := randFrom(alphaAWSSecret, 40)
	m := Marker("aws-secret-key")
	runE(t, []ecase{
		{"spaced equals", "aws_secret_access_key = " + s, "aws_secret_access_key = " + m, "aws-secret-key"},
		{"upper env", "AWS_SECRET_ACCESS_KEY=" + s, "AWS_SECRET_ACCESS_KEY=" + m, "aws-secret-key"},
		{"colon", "secret_access_key: " + s, "secret_access_key: " + m, "aws-secret-key"},
		{"whitespace separator", "SecretAccessKey " + s, "SecretAccessKey " + m, "aws-secret-key"},
	})
	runC(t, []ccase{
		{"JSON", `{"aws_secret_access_key": "` + s + `"}`, "aws-secret-key", []string{`{"aws_secret_access_key"`}, []string{s}},
		{"fat arrow", "aws_secret_access_key => '" + s + "'", "aws-secret-key", []string{"aws_secret_access_key"}, []string{s}},
	})
}

func TestVendorTokens(t *testing.T) {
	alnumU := alphaAlnum + "_"
	alnumD := alphaAlnum + "-"
	alnumUD := alphaAlnum + "_-"
	tokens := map[string]string{
		"github ghp":    "gh" + "p_" + randFrom(alphaAlnum, 36),
		"github gho":    "gh" + "o_" + randFrom(alphaAlnum, 36),
		"github ghu":    "gh" + "u_" + randFrom(alphaAlnum, 40),
		"github ghs":    "gh" + "s_" + randFrom(alphaAlnum, 36),
		"github ghr":    "gh" + "r_" + randFrom(alphaAlnum, 36),
		"github pat":    "github" + "_pat_" + randFrom(alnumU, 82),
		"gitlab":        "glpat" + "-" + randFrom(alnumUD, 20),
		"slack xoxb":    "xo" + "xb-" + randFrom(alnumD, 24),
		"slack xoxa":    "xo" + "xa-" + randFrom(alnumD, 24),
		"slack xoxp":    "xo" + "xp-" + randFrom(alnumD, 24),
		"slack xoxo":    "xo" + "xo-" + randFrom(alnumD, 24),
		"slack xoxs":    "xo" + "xs-" + randFrom(alnumD, 24),
		"slack xoxr":    "xo" + "xr-" + randFrom(alnumD, 24),
		"stripe live":   "sk" + "_live_" + randFrom(alphaAlnum, 24),
		"stripe rk":     "rk" + "_test_" + randFrom(alphaAlnum, 24),
		"google":        "AI" + "za" + randFrom(alnumUD, 35),
		"npm":           "npm" + "_" + randFrom(alphaAlnum, 36),
		"docker":        "dckr" + "_pat_" + randFrom(alnumUD, 27),
		"anthropic":     "sk-" + "ant-" + randFrom(alnumUD, 40),
		"openai proj":   "sk-" + "proj-" + randFrom(alnumUD, 48),
		"openai svc":    "sk-" + "svcacct-" + randFrom(alnumUD, 48),
		"openai admin":  "sk-" + "admin-" + randFrom(alnumUD, 48),
		"openai legacy": "sk-" + randFrom(alphaAlnum, 48),
		"age":           "AGE-" + "SECRET-KEY-1" + randFrom(alphaUpperAlnum, 58),
		"slack webhook": "https://hooks.slack" + ".com/services/T" + randFrom(alphaUpperAlnum, 8) + "/B" + randFrom(alphaUpperAlnum, 8) + "/" + randFrom(alphaAlnum, 24),
	}
	var cases []ecase
	for name, tok := range tokens {
		cases = append(cases, ecase{name, "using " + tok + " now.", "using " + Marker("vendor-token") + " now.", "vendor-token"})
	}
	long := randFrom(alphaAlnum, 48)
	cases = append(cases,
		same("unit name starting sk- (AC43)", "Started sk-payments-db.service ok."),
		same("sk- key followed by .service", "Started sk-"+long+".service ok."),
		same("sk- key followed by .socket", "Started sk-"+long+".socket ok."),
		same("sk- key followed by .timer", "Started sk-"+long+".timer ok."),
		same("sk- 39 characters", "using sk-"+long[:39]+" now."),
		same("ghp 35 characters", "using gh"+"p_"+long[:35]+" now."),
		same("ghp without word boundary", "using xgh"+"p_"+long[:36]+" now."),
		same("npm 35 characters", "using npm"+"_"+long[:35]+" now."),
		ecase{"AC43 unit and key in one extract",
			"unit sk-payments-db.service started; loaded key sk-" + "proj-" + long + " ok.",
			"unit sk-payments-db.service started; loaded key " + Marker("vendor-token") + " ok.", "vendor-token"},
	)
	runE(t, cases)
}

func TestJWT(t *testing.T) {
	tok := makeJWT()
	parts := strings.Split(tok, ".")
	enc := base64.RawURLEncoding.EncodeToString
	runE(t, []ecase{
		{"three parts", "jwt " + tok + " ok.", "jwt " + Marker("jwt") + " ok.", "jwt"},
		{"empty signature", "jwt " + parts[0] + "." + parts[1] + ". ok.", "jwt " + Marker("jwt") + " ok.", "jwt"},
		same("header not JSON", "jwt "+enc([]byte(`{"alg broken`))+"."+parts[1]+"."+parts[2]+" ok."),
		same("header JSON without alg", "jwt "+enc([]byte(`{"typ":"JWT"}`))+"."+parts[1]+"."+parts[2]+" ok."),
		same("two parts only", "jwt "+parts[0]+"."+parts[1]+" ok."),
	})
}

func TestURLCredentials(t *testing.T) {
	pw := randFrom(alphaAlnum, 16)
	m := Marker("url-credentials")
	runE(t, []ecase{
		{"postgresql", "dsn postgresql://app:" + pw + "@db:5432/x ok.", "dsn postgresql://" + m + "@db:5432/x ok.", "url-credentials"},
		{"mongodb+srv", "dsn mongodb+srv://u:" + pw + "@c/x ok.", "dsn mongodb+srv://" + m + "@c/x ok.", "url-credentials"},
		{"mysql", "dsn mysql://u:" + pw + "@h/x ok.", "dsn mysql://" + m + "@h/x ok.", "url-credentials"},
		{"redis empty user", "dsn redis://:" + pw + "@cache:6379/0 ok.", "dsn redis://" + m + "@cache:6379/0 ok.", "url-credentials"},
		{"amqps", "dsn amqps://u:" + pw + "@mq/vh ok.", "dsn amqps://" + m + "@mq/vh ok.", "url-credentials"},
		{"https", "url https://u:" + pw + "@host/p ok.", "url https://" + m + "@host/p ok.", "url-credentials"},
		{"password holds / and @", "url https://u:" + pw[:6] + "/" + pw[6:10] + "@" + pw[10:] + "@host/p ok.", "url https://" + m + "@host/p ok.", "url-credentials"},
		{"JSON-escaped (AC38)", "dsn postgresql:" + bs + "/" + bs + "/app:" + pw + "@db ok.", "dsn postgresql://" + m + "@db ok.", "url-credentials"},
		same("no user-info", "url https://example.org/path ok."),
		same("user without password", "url ssh://git@host/repo ok."),
		same("no at sign", "dsn postgresql://db:5432/x ok."),
	})
}

func TestURLSecretParam(t *testing.T) {
	v := randFrom(alphaAlnum, 24)
	m := Marker("url-secret-param")
	var cases []ecase
	for _, p := range []string{"password", "passwd", "pwd", "pass", "token", "access_token", "refresh_token",
		"id_token", "api_key", "apikey", "key", "secret", "client_secret", "sig", "signature", "auth",
		"X-Amz-Signature", "X-Amz-Credential", "X-Amz-Security-Token", "sessionid", "TOKEN"} {
		cases = append(cases, ecase{"param " + p, "GET https://h/p?" + p + "=" + v + "&next=1 ok.", "GET https://h/p?" + p + "=" + m + "&next=1 ok.", "url-secret-param"})
	}
	cases = append(cases,
		ecase{"after ampersand", "GET https://h/cb?code=1&access_token=" + v + " ok.", "GET https://h/cb?code=1&access_token=" + m + " ok.", "url-secret-param"},
		ecase{"S3 security token (AC60)", "GET https://b.s3.example/o?X-Amz-Security-Token=" + v + " ok.", "GET https://b.s3.example/o?X-Amz-Security-Token=" + m + " ok.", "url-secret-param"},
		ecase{"semicolon", "GET https://h/p;sig=" + v + " ok.", "GET https://h/p;sig=" + m + " ok.", "url-secret-param"},
		// The url-secret-param value stops at '#', but secret-assignment's
		// value (key "token") runs on to the space; R31 merges the two
		// overlapping matches into one span under the earlier detector.
		ecase{"merged with secret-assignment past fragment", "GET https://h/p?token=" + v + "#top ok.", "GET https://h/p?token=" + m + " ok.", "url-secret-param"},
		ecase{"JSON-escaped ampersand (AC38)", "GET https://h/cb?code=1" + bs + "u0026access_token=" + v + " ok.", "GET https://h/cb?code=1&access_token=" + m + " ok.", "url-secret-param"},
		same("benign query", "GET https://h/search?page=2&sort=asc ok."),
		same("empty value", "GET https://h/p?token=&page=2 ok."),
	)
	runE(t, cases)
}

func TestAuthorizationHeader(t *testing.T) {
	tok := randFrom(alphaAlnum, 32)
	basic := base64.StdEncoding.EncodeToString([]byte("app:" + randFrom(alphaAlnum, 16)))
	m := Marker("authorization-header")
	runE(t, []ecase{
		{"bearer", "Authorization: Bearer " + tok, "Authorization: " + m, "authorization-header"},
		{"basic", "authorization: Basic " + basic, "authorization: " + m, "authorization-header"},
		{"proxy", "Proxy-Authorization: Basic " + basic, "Proxy-Authorization: " + m, "authorization-header"},
		{"equals", "Authorization=Bearer " + tok, "Authorization=" + m, "authorization-header"},
		{"JSON member", `{"Authorization":"Bearer ` + tok + `"}`, `{"Authorization":"` + m + `"}`, "authorization-header"},
		{"YAML quoted", "authorization: 'Bearer " + tok + "'", "authorization: '" + m + "'", "authorization-header"},
		{"to end of line only", "Authorization: Bearer " + tok + "\nnext line ok.", "Authorization: " + m + "\nnext line ok.", "authorization-header"},
		{"standalone bearer", "curl sent bearer " + tok + " ok.", "curl sent bearer " + m + " ok.", "authorization-header"},
		{"standalone token", "using Token " + tok + " ok.", "using Token " + m + " ok.", "authorization-header"},
		{"standalone basic with padding", "using basic " + basic + " ok.", "using basic " + m + " ok.", "authorization-header"},
		same("no separator", "Authorization required ok."),
		same("short bearer value", "bearer abc ok."),
		same("marker value", "Authorization: "+m),
	})
}

func TestCookieHeader(t *testing.T) {
	v := randFrom(alphaAlnum, 24)
	m := Marker("cookie-header")
	runE(t, []ecase{
		{"cookie", "Cookie: session=" + v, "Cookie: " + m, "cookie-header"},
		{"set-cookie", "Set-Cookie: id=" + v + "; Path=/; HttpOnly", "Set-Cookie: " + m, "cookie-header"},
		{"JSON member", `{"Cookie":"session=` + v + `"}`, `{"Cookie":"` + m + `"}`, "cookie-header"},
		same("no separator", "cookie consent banner shown ok."),
		same("marker value", "Cookie: "+m),
	})
}

func TestSecretAssignment(t *testing.T) {
	v := randFrom(alphaAlnum, 16)
	v2 := randFrom(alphaAlnum, 16)
	k := randFrom(alphaAlnum+"+/", 86) + "=="
	m := Marker("secret-assignment")
	var cases []ecase
	for _, key := range []string{"DB_PASSWORD=", "SECRET_KEY=", "secret_key_base: ", "x-api-key: ", "dbPassword=",
		"PGPASSWORD=", "api-key=", "passphrase=", "credential=", "authkey=", "auth_key=", "session_key=",
		"sessionkey=", "private_key=", "privatekey=", "accesskey=", "access_key=", "pwd=", "passwd: ",
		"my.app.token => ", "requirepass ", "masterauth ", "x-amz-security-token: "} {
		cases = append(cases, ecase{"key " + strings.TrimSpace(key), key + v, key + m, "secret-assignment"})
	}
	cases = append(cases,
		ecase{"value ends at comma", "password=" + v + ",user=app", "password=" + m + ",user=app", "secret-assignment"},
		ecase{"value ends at brace", "{password=" + v + "}", "{password=" + m + "}", "secret-assignment"},
		ecase{"value ends at ampersand", "password=" + v + "&x=1", "password=" + m + "&x=1", "secret-assignment"},
		ecase{"value ends at semicolon", "password=" + v + ";x=1", "password=" + m + ";x=1", "secret-assignment"},
		ecase{"Azure AccountKey",
			"DefaultEndpointsProtocol=https;AccountName=lab;Account" + "Key=" + k + ";EndpointSuffix=core.example",
			"DefaultEndpointsProtocol=https;AccountName=lab;Account" + "Key=" + m + ";EndpointSuffix=core.example", "secret-assignment"},
		ecase{"api_key holding a UUID (ruling 12)", "api_key=" + randUUID(), "api_key=" + m, "secret-assignment"},
		same("empty value", "password=;"),
		same("empty quoted value", `password: ""`),
		same("password as a word", "FATAL: password authentication failed for user app ok."),
		same("marker value", "DB_PASSWORD="+m),
		same("short marker value", "DB_PASSWORD="+ShortMarker),
	)
	runE(t, cases)
	runC(t, []ccase{
		{"YAML quoted", `password: "` + v + `"`, "secret-assignment", []string{"password: "}, []string{v}},
		{"JSON camelCase", `{"dbPassword":"` + v + `"}`, "secret-assignment", []string{`{"dbPassword":`}, []string{v}},
		{"JSON clientSecret", `"clientSecret": "` + v + `"`, "secret-assignment", []string{`"clientSecret": `}, []string{v}},
		{"JSON accessToken", `"accessToken": "` + v + `"`, "secret-assignment", []string{`"accessToken": `}, []string{v}},
		{"SQL IDENTIFIED BY", "CREATE USER app IDENTIFIED BY '" + v + "';", "secret-assignment", []string{"CREATE USER app IDENTIFIED BY "}, []string{v}},
		{"SQL IDENTIFIED WITH plugin BY", "ALTER USER app IDENTIFIED WITH caching_sha2_password BY '" + v + "';", "secret-assignment", []string{"ALTER USER app IDENTIFIED WITH caching_sha2_password BY "}, []string{v}},
		{"SQL PASSWORD quoted", "ALTER ROLE app PASSWORD '" + v + "';", "secret-assignment", []string{"ALTER ROLE app PASSWORD "}, []string{v}},
		{"SQL PASSWORD equals", "ALTER ROLE app PASSWORD = '" + v + "';", "secret-assignment", []string{"ALTER ROLE app PASSWORD "}, []string{v}},
		{"shell quoted with space", "export TOKEN='" + v + " " + v2 + "'", "secret-assignment", []string{"export TOKEN="}, []string{v, v2}},
		{"Azure SharedAccessKey", "Endpoint=sb://ns.example/;SharedAccessKeyName=root;SharedAccess" + "Key=" + k, "secret-assignment", []string{"Endpoint=sb://ns.example/;"}, []string{k}},
	})
}

// ---------------------------------------------------------------------------
// Personal data.

func TestEmail(t *testing.T) {
	e := randFrom(alphaLower, 10) + "@" + randFrom(alphaLower, 8) + ".example"
	m := Marker("email")
	runE(t, []ecase{
		{"plain", "mail to " + e + " ok.", "mail to " + m + " ok.", "email"},
		{"plus and dots", "mail to a.b+tag%x@mail.sub.example ok.", "mail to " + m + " ok.", "email"},
		{"angle brackets", "From: <" + e + "> ok.", "From: <" + m + "> ok.", "email"},
		same("unit suffix service", "Started user@1000.service ok."),
		same("template unit", "Starting postgresql@14-main.service ok."),
		same("unit suffix socket", "Listening on app@host.socket ok."),
		same("unit suffix timer", "Started x@y.timer ok."),
		same("no TLD", "mail a@b ok."),
		same("one-letter TLD", "mail a@b.c ok."),
	})
}

func TestPhone(t *testing.T) {
	m := Marker("phone")
	runE(t, []ecase{
		{"Jordan international spaced", "call +962 7" + randDigits(8) + " ok.", "call " + m + " ok.", "phone"},
		{"Jordan international compact", "call +9627" + randDigits(8) + " ok.", "call " + m + " ok.", "phone"},
		{"UK spaced", "call +44 20 " + randDigits(4) + " " + randDigits(4) + " ok.", "call " + m + " ok.", "phone"},
		{"dashes", "call +1-555-" + randDigits(3) + "-" + randDigits(4) + " ok.", "call " + m + " ok.", "phone"},
		{"dots", "call +49.30." + randDigits(7) + " ok.", "call " + m + " ok.", "phone"},
		{"Jordan mobile 077", "call 077" + randDigits(7) + " ok.", "call " + m + " ok.", "phone"},
		{"Jordan mobile 078", "call 078" + randDigits(7) + " ok.", "call " + m + " ok.", "phone"},
		{"Jordan mobile 079", "call 079" + randDigits(7) + " ok.", "call " + m + " ok.", "phone"},
		{"Jordan mobile space", "call 079 " + randDigits(7) + " ok.", "call " + m + " ok.", "phone"},
		{"Jordan mobile dash", "call 078-" + randDigits(7) + " ok.", "call " + m + " ok.", "phone"},
		// "+0" is no country code; the next digit is fixed so the run is
		// never also a Jordanian mobile (07[789]…), which is redacted.
		same("plus zero", "call +01"+randDigits(8)+" ok."),
		same("too short", "call +12345 ok."),
		same("not a mobile prefix", "call 076"+randDigits(7)+" ok."),
		same("11 digits", "call 079"+randDigits(8)+" ok."),
		same("preceded by a digit", "call 1079"+randDigits(7)+" ok."),
	})
}

func joDigits() string { return randDigitsLead("9", 10) } // never 07x, never [12]
func saDigits() string { return randDigitsLead("12", 10) }

func TestNationalIDJordan(t *testing.T) {
	m := Marker("national-id-jo")
	d := joDigits()
	var cases []ecase
	for _, kw := range []string{"national number: ", "national number ", "NATIONAL NUMBER: ", "national id: ",
		"National_No=", "nid: ", "NID#", "nid - ", "nin ", "NIN ", "nin=", "nid "} {
		cases = append(cases, ecase{"keyword " + kw, "rec " + kw + d + " ok.", "rec " + kw + m + " ok.", "national-id-jo"})
	}
	cases = append(cases,
		ecase{"within 32 runes", "national number" + strings.Repeat(" ", 30) + d + " ok.", "national number" + strings.Repeat(" ", 30) + m + " ok.", "national-id-jo"},
		ecase{"window counted in runes, not bytes", "national number " + strings.Repeat(r(0x2014), 25) + " " + d, "national number " + strings.Repeat(r(0x2014), 25) + " " + m, "national-id-jo"},
		same("no keyword (AC44)", "order "+d+" shipped ok."),
		same("beyond 32 runes", "national number"+strings.Repeat(" ", 34)+d+" ok."),
		same("nid with four separators", "nid    "+d+" ok."),
		same("nid inside a word", "snid: "+d+" ok."),
		same("warning (AC44)", "warning 1761385200"),
		same("running since (AC44)", "running since 1761385200"),
		same("eleven digits", "national number: "+d+"7 ok."),
	)
	runE(t, cases)
}

func TestNationalIDSaudi(t *testing.T) {
	m := Marker("national-id-sa")
	var cases []ecase
	for _, kw := range []string{"iqama: ", "Iqama ", "IQAMA=", "هوية ", "الهوية: ", "رقم الهوية ", "إقامة ", "الإقامة: ", "رقم الإقامة "} {
		d := saDigits()
		cases = append(cases, ecase{"keyword " + kw, "rec " + kw + d + " ok.", "rec " + kw + m + " ok.", "national-id-sa"})
	}
	cases = append(cases,
		same("iqama with a 3 (AC44)", "rec iqama: "+randDigitsLead("3", 10)+" ok."),
		same("iqama with 9 digits", "rec iqama: "+saDigits()[:9]+" ok."),
	)
	runE(t, cases)
}

func TestNationalIDEmirates(t *testing.T) {
	m := Marker("national-id-ae")
	valid := luhnComplete("784" + randDigits(11))
	invalid := luhnBreak(valid)
	dash := func(s string) string { return s[:3] + "-" + s[3:7] + "-" + s[7:14] + "-" + s[14:] }
	runE(t, []ecase{
		{"undashed Luhn-valid", "id " + valid + " ok.", "id " + m + " ok.", "national-id-ae"},
		{"undashed not Luhn-valid", "id " + invalid + " ok.", "id " + m + " ok.", "national-id-ae"},
		{"dashed Luhn-valid", "id " + dash(valid) + " ok.", "id " + m + " ok.", "national-id-ae"},
		{"dashed not Luhn-valid", "id " + dash(invalid) + " ok.", "id " + m + " ok.", "national-id-ae"},
		same("wrong prefix", "id 785"+randDigits(12)+" ok."),
		same("14 digits", "id 784"+randDigits(11)+" ok."),
		same("16 digits", "id 784"+randDigits(13)+" ok."),
	})
}

// AC57: Arabic keywords with diacritics and tatweel, and Arabic-Indic digits.
func TestNationalIDArabic(t *testing.T) {
	jo := Marker("national-id-jo")
	sa := Marker("national-id-sa")
	fatha, sukun, damma, alef, tatweel := r(0x064E), r(0x0652), r(0x064F), r(0x0670), r(0x0640)
	kwJO := "الرقم الوطني: "
	kwJODiacritics := "الر" + fatha + "ق" + sukun + "م الوط" + alef + "ني: "
	kwJOTatweel := "الرق" + tatweel + "م الوطني: "
	kwJO2 := "رقم وطني "
	kwSA := "رقم الهوية "
	kwSADiacritics := "رق" + damma + "م اله" + damma + "وية "
	kwSATatweel := "رقم اله" + tatweel + "وية "
	var cases []ecase
	digitForms := map[string]func(string) string{
		"ASCII":        func(s string) string { return s },
		"Arabic-Indic": arabicIndic,
		"Eastern":      easternDigits,
		"mixed":        mixedDigits,
	}
	for form, f := range digitForms {
		for name, kw := range map[string]string{"plain": kwJO, "diacritics": kwJODiacritics, "tatweel": kwJOTatweel, "short": kwJO2} {
			cases = append(cases, ecase{"JO " + name + " " + form, kw + f(joDigits()) + " ok.", kw + jo + " ok.", "national-id-jo"})
		}
		for name, kw := range map[string]string{"plain": kwSA, "diacritics": kwSADiacritics, "tatweel": kwSATatweel} {
			cases = append(cases, ecase{"SA " + name + " " + form, kw + f(saDigits()) + " ok.", kw + sa + " ok.", "national-id-sa"})
		}
	}
	cases = append(cases,
		ecase{"Jordan mobile in Arabic-Indic digits", "اتصل " + arabicIndic("079"+randDigits(7)) + " ok.", "اتصل " + Marker("phone") + " ok.", "phone"},
		same("keyword inside a longer word", "والهوية "+saDigits()+" ok."),
		same("keyword inside a longer word, Arabic-Indic", "والهوية "+arabicIndic(saDigits())+" ok."),
	)
	runE(t, cases)
}

func TestPaymentCard(t *testing.T) {
	m := Marker("payment-card")
	v16 := makeCard("4", 16)
	var extra string
	for {
		extra = randDigits(3)
		if !luhnValid(v16 + extra) {
			break
		}
	}
	runE(t, []ecase{
		{"16 compact", "card " + v16 + " ok.", "card " + m + " ok.", "payment-card"},
		{"16 spaces", "card " + group(v16, " ", 4, 4, 4) + " ok.", "card " + m + " ok.", "payment-card"},
		{"16 dashes", "card " + group(v16, "-", 4, 4, 4) + " ok.", "card " + m + " ok.", "payment-card"},
		{"mastercard", "card " + makeCard("5", 16) + " ok.", "card " + m + " ok.", "payment-card"},
		{"2-series", "card " + makeCard("22", 16) + " ok.", "card " + m + " ok.", "payment-card"},
		{"amex grouped 4-6-5", "card " + group(makeCard("37", 15), " ", 4, 6) + " ok.", "card " + m + " ok.", "payment-card"},
		{"13 digits", "card " + makeCard("4", 13) + " ok.", "card " + m + " ok.", "payment-card"},
		{"19 digits", "card " + makeCard("6", 19) + " ok.", "card " + m + " ok.", "payment-card"},
		{"after equals", "id=" + v16 + " ok.", "id=" + m + " ok.", "payment-card"},
		{"extra group (AC56)", "card " + group(v16, " ", 4, 4, 4, 4) + " " + extra + " ok.", "card " + m + " " + extra + " ok.", "payment-card"},
		{"letters right after (AC56)", "card " + v16 + "XYZ ok.", "card " + m + "XYZ ok.", "payment-card"},
		same("Luhn-invalid", "card "+luhnBreak(v16)+" ok."),
		same("starts with 7", "card "+makeCard("71", 16)+" ok."),
		same("12 digits", "card "+makeCard("4", 12)+" ok."),
		same("inside a longer digit run", "card 1"+v16+" ok."),
		same("after a hex run", "card ff"+v16+" ok."),
	})
}

// Ruling 12: a match entirely inside a canonical UUID is discarded, except
// for the detectors that replace a value after a key.
func TestUUIDExclusion(t *testing.T) {
	head := makeCard("4", 16) // first three UUID groups form a Luhn-valid grouped card
	u := head[:8] + "-" + head[8:12] + "-" + head[12:16] + "-" + randDigits(4) + "-" + randDigits(12)
	runE(t, []ecase{
		same("all-digit UUID", "request "+u+" done."),
		same("random UUID", "request "+randUUID()+" done."),
		{"same digits outside a UUID", "ref " + head[:8] + "-" + head[8:12] + "-" + head[12:16] + " ok.", "ref " + Marker("payment-card") + " ok.", "payment-card"},
		{"api_key holding the UUID", "api_key=" + u, "api_key=" + Marker("secret-assignment"), "secret-assignment"},
		{"bearer holding a UUID", "Authorization: Bearer " + u, "Authorization: " + Marker("authorization-header"), "authorization-header"},
	})
}

func TestIBAN(t *testing.T) {
	m := Marker("iban")
	// stableIBAN: no group-boundary prefix of the value or of its broken
	// form passes mod 97 by chance (the generic detector tries every end).
	gb, jo := stableIBAN(gbIBAN), stableIBAN(joIBAN)
	de := stableIBAN(func() string { return makeIBAN("DE", "1"+randDigits(17)) })
	gbLong := makeIBAN("GB", "WEST"+"1"+randDigits(14))
	runE(t, []ecase{
		{"GB compact", "iban " + gb + " ok.", "iban " + m + " ok.", "iban"},
		{"GB grouped", "iban " + groupFours(gb) + " ok.", "iban " + m + " ok.", "iban"},
		{"GB grouped then a token (AC56)", "iban " + groupFours(gb) + " X ok.", "iban " + m + " X ok.", "iban"},
		{"JO compact", "iban " + jo + " ok.", "iban " + m + " ok.", "iban"},
		{"JO grouped", "iban " + groupFours(jo) + " ok.", "iban " + m + " ok.", "iban"},
		{"DE compact", "iban " + de + " ok.", "iban " + m + " ok.", "iban"},
		same("mod-97-invalid", "iban "+ibanBreak(gb)+" ok."),
		same("mod-97-invalid grouped", "iban "+groupFours(ibanBreak(gb))+" ok."),
		// B1: no per-country length; a GB value of 23 characters with valid
		// check digits is an IBAN for the generic detector.
		{"GB of another length (no country table)", "iban " + gbLong + " ok.", "iban " + m + " ok.", "iban"},
		same("lower case", "iban "+strings.ToLower(gb)+" ok."),
	})
}

// AC14, AC45, AC59, ruling 13.
func TestPublicIP(t *testing.T) {
	trunc := func(name, in, want string) ecase {
		return ecase{name, "client " + in + " GET /", "client " + want + " GET /", "public-ip"}
	}
	runE(t, []ecase{
		trunc("IPv4 documentation 203", "203.0.113.77", "203.0.113.0/24"),
		trunc("IPv4 documentation 192", "192.0.2.10", "192.0.2.0/24"),
		trunc("IPv4 documentation 198", "198.51.100.7", "198.51.100.0/24"),
		trunc("IPv4 public", "8.8.4.4", "8.8.4.0/24"),
		trunc("IPv4 with port", "203.0.113.77:443", "203.0.113.0/24:443"),
		trunc("IPv6 public", "2a00:1450:4001:82a::200e", "2a00:1450:4001::/48"),
		trunc("IPv6 documentation", "2001:db8:1234:5678::1", "2001:db8:1234::/48"),
		trunc("IPv6 bracketed with port", "[2001:db8:1234:5678::1]:443", "[2001:db8:1234::/48]:443"),
		trunc("6to4 to /40", "2002:c000:0221::1", "2002:c000:200::/40"),
		trunc("IPv4-mapped", "::ffff:203.0.113.77", "203.0.113.0/24"),
		trunc("NAT64", "64:ff9b::203.0.113.77", "64:ff9b::/48"),
		trunc("Teredo", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:0:4136::/48"),
		same("private 10", "client 10.1.2.3 GET /"),
		same("private 172", "client 172.16.0.1 GET /"),
		same("private 192", "client 192.168.1.1 GET /"),
		same("loopback", "client 127.0.0.1 GET /"),
		same("loopback v6", "client ::1 GET /"),
		same("link-local v6", "client fe80::1 GET /"),
		same("link-local v4", "client 169.254.1.1 GET /"),
		same("ULA", "client fd00::1 GET /"),
		same("CGNAT", "client 100.64.0.1 GET /"),
		same("unspecified", "client 0.0.0.0 GET /"),
		same("this network", "client 0.1.2.3 GET /"),
		same("multicast v4", "client 224.0.0.1 GET /"),
		same("reserved", "client 240.0.0.1 GET /"),
		same("broadcast", "client 255.255.255.255 GET /"),
		same("multicast v6", "client ff02::1 GET /"),
		same("site-local", "client fec0::1 GET /"),
		same("already a /24 network", "client 203.0.113.0/24 GET /"),
		same("already a /16 network", "client 203.0.0.0/16 GET /"),
		same("already a /48 network", "client 2001:db8:1234::/48 GET /"),
		same("already a /40 6to4 network", "client 2002:c000:200::/40 GET /"),
		same("C++ scope", "error in std::vector ok."),
		same("MAC address", "link 00:1a:2b:3c:4d:5e up."),
		same("three-part version", "nginx/1.24.0 ok."),
	})
}

func TestPublicIPHostPrefixTruncated(t *testing.T) {
	out, rep := redactE(t, "route 203.0.113.77/32 ok.")
	if strings.Contains(out, "203.0.113.77") {
		t.Errorf("a /32 host prefix kept the full address: %q", out)
	}
	if !strings.Contains(out, "203.0.113.0/24") {
		t.Errorf("output %q lacks the /24 network", out)
	}
	if rep.MarkerFired {
		t.Errorf("IP truncation set MarkerFired")
	}
}

// IP truncation is not a "marker fired" (ruling 13, R55).
func TestPublicIPIsNotMarkerFired(t *testing.T) {
	_, rep := redactE(t, "client 203.0.113.77 GET /")
	if rep.MarkerFired {
		t.Errorf("MarkerFired set by public-ip alone")
	}
	if rep.Replaced["public-ip"] != 1 {
		t.Errorf("Replaced[public-ip] = %d, want 1 (truncations are counted)", rep.Replaced["public-ip"])
	}
}

// ---------------------------------------------------------------------------
// Merging and class applicability.

func TestOverlapMergedUnderEarliestDetector(t *testing.T) {
	k := akia()
	runE(t, []ecase{
		{"secret-assignment value is an AWS ID", "DB_PASSWORD=" + k, "DB_PASSWORD=" + Marker("aws-access-key-id"), "aws-access-key-id"},
		{"url password is an AWS ID", "dsn postgresql://app:" + k + "@db/x ok.", "dsn postgresql://" + Marker("aws-access-key-id") + "@db/x ok.", "aws-access-key-id"},
		{"email local part is an AWS ID", "mail " + k + "@mail.example ok.", "mail " + Marker("aws-access-key-id") + " ok.", "aws-access-key-id"},
	})
}

func TestClassApplicability(t *testing.T) {
	cookie := "Cookie: session=" + randFrom(alphaAlnum, 24)
	body := randFrom(alphaLetters, 64)
	for _, c := range []Class{TName, TPath, LValue} {
		for name, in := range map[string]string{
			"cookie-header is text only": cookie,
			"public-ip is text only":     "198.51.100.7:27017",
			"public-ip v6 is text only":  "2001:db8:1234:5678::1",
			"pem-body-line is not here":  body,
		} {
			out, rep := mustRedact(t, fieldFor(c), in, nil)
			if out != in {
				t.Errorf("%s %s: %q changed to %q", className(c), name, in, out)
			}
			if replacedTotal(rep) != 0 {
				t.Errorf("%s %s: replacements reported", className(c), name)
			}
		}
	}
	for _, c := range []Class{EText, TText} {
		out, _ := mustRedact(t, fieldFor(c), cookie, nil)
		if out != "Cookie: "+Marker("cookie-header") {
			t.Errorf("%s: cookie not redacted: %q", className(c), out)
		}
		out, _ = mustRedact(t, fieldFor(c), "198.51.100.7:27017", nil)
		if out != "198.51.100.0/24:27017" {
			t.Errorf("%s: public IP not truncated: %q", className(c), out)
		}
	}
	out, _ := redactE(t, body)
	if out != Marker("pem-body-line") {
		t.Errorf("EText: a 64-character key-body line alone was not redacted: %q", out)
	}
}

func TestB64PrivateKeyNegativeCertificate(t *testing.T) {
	cert := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("-", 5) + "BEGIN CERTIFICATE" + strings.Repeat("-", 5)))
	if !strings.HasPrefix(cert, b64BeginPrefix()) {
		t.Fatalf("test setup: %q does not start with the BEGIN prefix", cert)
	}
	runE(t, []ecase{same("base64 of a certificate header", "blob "+cert+" ok.")})
}
