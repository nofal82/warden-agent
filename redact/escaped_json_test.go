package redact

import (
	"strings"
	"testing"
)

// Security review H3, ruled by Nofal on PR #10: the credential-pair
// detectors treat a quote preceded by any number of backslashes as a quote
// delimiter, so a secret inside JSON logged as a string inside JSON (and
// deeper) is caught. Spec change for redaction.md to follow in warden.

// escapeJSON quotes s as the body of a JSON string, as a logger does when
// it writes a JSON document into a string field.
func escapeJSON(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func TestCredentialPairsInEscapedJSON(t *testing.T) {
	pw := "pw" + randFrom(alphaAlnum, 16)
	aws := randFrom(alphaAlnum, 40)
	tok := randFrom(alphaAlnum, 24)
	ck := randFrom(alphaAlnum, 20)

	inner := map[string]struct {
		doc    string
		secret string
		id     string
	}{
		"password": {`{"password":"` + pw + `"}`, pw, "secret-assignment"},
		"camel":    {`{"dbPassword": "` + pw + `", "user": "app"}`, pw, "secret-assignment"},
		"aws":      {`{"aws_secret_access_key":"` + aws + `"}`, aws, "aws-secret-key"},
		"auth":     {`{"Authorization":"Basic ` + tok + `"}`, tok, "authorization-header"},
		"cookie":   {`{"Cookie":"session=` + ck + `"}`, ck, "cookie-header"},
	}
	for name, c := range inner {
		once := `{"body":"` + escapeJSON(c.doc) + `"}`
		twice := `{"outer":"` + escapeJSON(once) + `"}`
		for level, in := range map[string]string{"plain": c.doc, "escaped": once, "doubly escaped": twice} {
			for _, cls := range []Class{EText, TText, LValue} {
				f := fieldFor(cls)
				if cls == LValue && (len(in) > LabelValueMaxBytes || c.id == "cookie-header") {
					continue // over the label limit, or a text-only detector (§4.2)
				}
				out, rep := mustRedact(t, f, in, nil)
				where := name + "/" + level + "/" + className(cls)
				assertNoLeak(t, where, out, c.secret)
				if rep.Replaced[c.id] == 0 {
					t.Errorf("%s: %s did not fire: %q -> %q", where, c.id, in, out)
				}
			}
		}
	}
}

// AC-style: the documented example keeps its structure, with only the
// value replaced at the right escape level.
func TestEscapedJSONStructureKept(t *testing.T) {
	pw := "x" + randFrom(alphaAlnum, 12)
	m := Marker("secret-assignment")
	cases := []struct{ in, want string }{
		{`{"body":"{\"password\":\"` + pw + `\"}"}`, `{"body":"{\"password\":\"` + m + `\"}"}`},
		{`{"o":"{\"body\":\"{\\\"password\\\":\\\"` + pw + `\\\"}\"}"}`, `{"o":"{\"body\":\"{\\\"password\\\":\\\"` + m + `\\\"}\"}"}`},
	}
	for _, c := range cases {
		out, _ := redactE(t, c.in)
		if out != c.want {
			t.Errorf("redact(%q)\n got  %q\n want %q", c.in, out, c.want)
		}
	}
}

// An escaped quote inside an ordinary JSON value is part of the value: no
// part of a password that contains a quote may be left.
func TestQuoteInsidePlainJSONValue(t *testing.T) {
	a, b := randFrom(alphaAlnum, 8), randFrom(alphaAlnum, 8)
	out, _ := redactE(t, `{"password":"`+a+`\"`+b+`","user":"app"}`)
	assertNoLeak(t, "quote inside value", out, a, b)
	if !strings.HasSuffix(out, `","user":"app"}`) {
		t.Errorf("rest of the document changed: %q", out)
	}
}
