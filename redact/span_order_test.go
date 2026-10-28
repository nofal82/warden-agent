package redact

import (
	"strings"
	"testing"
)

// Issue #21: a detector's find must return its spans in text order (the
// FuzzDetectors invariant, redaction.md AC18). literalSpans searched one
// literal at a time, so a detector with several literals returned its
// spans grouped by literal. Key-like values are built from fragments
// (CLAUDE.md: no secret literals).

// fakeAWS returns an AWS-access-key-shaped value with the given prefix.
func fakeAWS(prefix string) string { return prefix + strings.Repeat("Q", 16) }

// fakeVendor returns a Stripe-shaped token ("sk"/"rk" + "_live_" + 16+ alnum).
func fakeVendor(kind string) string { return kind + "_" + "live" + "_" + strings.Repeat("Q", 20) }

func assertSpansOrdered(t *testing.T, where string, spans []span) {
	t.Helper()
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].start {
			t.Fatalf("%s: spans not in text order: %v", where, spans)
		}
	}
}

func ruleByID(t *testing.T, id string) detector {
	t.Helper()
	for _, d := range defaultRules() {
		if d.id == id {
			return d
		}
	}
	t.Fatalf("no detector %q", id)
	return detector{}
}

func TestLiteralSpansTextOrder(t *testing.T) {
	re := anchored(`foo|bar`)
	cases := map[string]struct {
		in   string
		lits []string
		want int
	}{
		"later literal first in text": {"bar foo", []string{"foo", "bar"}, 2},
		"interleaved":                 {"bar foo bar foo", []string{"foo", "bar"}, 4},
		"three literals reversed":     {"baz bar foo", []string{"foo", "bar", "baz"}, 2},
		"empty input":                 {"", []string{"foo", "bar"}, 0},
		"no literals":                 {"bar foo", nil, 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := literalSpans(c.in, c.lits, re, true, false)
			if len(got) != c.want {
				t.Fatalf("literalSpans(%q) = %v, want %d spans", c.in, got, c.want)
			}
			assertSpansOrdered(t, "literalSpans", got)
		})
	}
}

func TestMultiLiteralDetectorsTextOrder(t *testing.T) {
	cases := []struct {
		name, id, in string
		want         int
	}{
		// awsKeyPrefixes lists AKIA before ABIA and ASIA.
		{"aws ABIA before AKIA", "aws-access-key-id", fakeAWS("AB"+"IA") + " " + fakeAWS("AK"+"IA"), 2},
		{"aws ASIA before AKIA", "aws-access-key-id", fakeAWS("AS"+"IA") + "\n" + fakeAWS("AK"+"IA"), 2},
		{"aws APKA ABIA AKIA", "aws-access-key-id",
			fakeAWS("AP"+"KA") + " " + fakeAWS("AB"+"IA") + " " + fakeAWS("AK"+"IA"), 3},
		{"aws interleaved", "aws-access-key-id",
			fakeAWS("AB"+"IA") + " " + fakeAWS("AK"+"IA") + " " + fakeAWS("AB"+"IA") + " " + fakeAWS("AK"+"IA"), 4},
		// The (?:sk|rk) vendor form lists "sk_" before "rk_".
		{"vendor rk_ before sk_", "vendor-token", fakeVendor("rk") + " " + fakeVendor("sk"), 2},
		// The Azure SQL form lists "accountkey" before "sharedaccesskey".
		{"azure SharedAccessKey before AccountKey", "secret-assignment",
			"SharedAccess" + "Key=" + strings.Repeat("Q", 20) + ";Account" + "Key=" + strings.Repeat("R", 20), 2},
		// The standalone authorization form lists "bearer" before "token".
		{"auth token before bearer", "authorization-header",
			"token " + strings.Repeat("Q", 12) + " bearer " + strings.Repeat("R", 12), 2},
		// find also loops over several patterns: the order across patterns
		// must hold too (vendor "gh" form is tried before the sk/rk form;
		// secret-assignment's key=value spans before its SQL forms).
		{"vendor sk_ before gh form", "vendor-token",
			fakeVendor("sk") + " " + "gh" + "p_" + strings.Repeat("Q", 36), 2},
		{"sql IDENTIFIED BY before key=value", "secret-assignment",
			"IDENTIFIED" + " BY '" + strings.Repeat("Q", 12) + "' DB_PASSWORD=" + strings.Repeat("R", 12), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ruleByID(t, c.id).find(c.in)
			if err != nil {
				t.Fatalf("find: %v", err)
			}
			if len(got) < c.want {
				t.Fatalf("%s.find(%q) = %v, want at least %d spans", c.id, c.in, got, c.want)
			}
			assertSpansOrdered(t, c.id, got)
		})
	}
}

// Sorting the spans must not change what Redact produces: every key is
// still replaced by its marker in place.
func TestMultiLiteralRedactUnchanged(t *testing.T) {
	aws := Marker("aws-access-key-id")
	vt := Marker("vendor-token")
	sa := Marker("secret-assignment")
	cases := []ecase{
		{"aws ABIA before AKIA", fakeAWS("AB"+"IA") + " " + fakeAWS("AK"+"IA"), aws + " " + aws, "aws-access-key-id"},
		{"aws three prefixes reversed",
			"k1=" + fakeAWS("AP"+"KA") + " k2=" + fakeAWS("AB"+"IA") + " k3=" + fakeAWS("AK"+"IA") + " ok",
			"k1=" + aws + " k2=" + aws + " k3=" + aws + " ok", "aws-access-key-id"},
		{"vendor rk_ before sk_", fakeVendor("rk") + " " + fakeVendor("sk"), vt + " " + vt, "vendor-token"},
		{"azure SharedAccessKey before AccountKey",
			"SharedAccess" + "Key=" + strings.Repeat("Q", 20) + ";Account" + "Key=" + strings.Repeat("R", 20) + ";x=1",
			"SharedAccess" + "Key=" + sa + ";Account" + "Key=" + sa + ";x=1", "secret-assignment"},
	}
	runE(t, cases)
}
