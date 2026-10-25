package redact

import (
	"strings"
	"testing"
	"time"
)

// Security review H1: one crafted line repeated across a maximum-size
// event must cost linear work in every detector, because the deadline
// (R36) is only checked between detector calls.
func repetitionEvent(unit string) string {
	line := strings.Repeat(unit, MaxLine/len(unit))
	return strings.TrimSuffix(strings.Repeat(line+"\n", MaxEventInput/(len(line)+1)), "\n")
}

func TestHomogeneousRepetitionIsLinear(t *testing.T) {
	limit := ItemDeadline
	if raceEnabled {
		limit *= 10
	}
	units := map[string]string{
		"jwt":                  "eyJ",
		"jwt-tail":             "eyJ" + strings.Repeat("A", 8) + ".",
		"url-credentials":      "a://",
		"url-secret-param":     ";key=",
		"secret-assignment":    "pwd:",
		"secret-key-run":       "pwd",
		"public-ip":            "a:",
		"authorization-header": "authorization:",
		"cookie-header":        "cookie:",
		"vendor-token":         "xoxa-",
		"vendor-sk":            "sk-",
		"email":                "a@a.",
		"card":                 "4111 ",
		"iban":                 "GB82 ",
	}
	red := New(WithClock(frozenClock))
	for name, unit := range units {
		in := repetitionEvent(unit)
		best := time.Duration(1 << 62)
		for i := 0; i < 2; i++ {
			start := time.Now()
			_, _, err := red.Redact(bg, Field{Class: EText, MaxBytes: ExtractMaxBytes}, in, nil)
			best = min(best, time.Since(start))
			if err != nil && !isKnownErr(err) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if best > limit {
			t.Errorf("%s: %v for a %d-byte event, over %v", name, best, len(in), limit)
		}
	}
}

// Security review H2 (MA10): an IBAN is found even when an earlier
// IBAN-shaped token starts a greedy match that ends inside it.
func TestIBANAfterEarlierToken(t *testing.T) {
	jo := joIBAN()
	grouped := groupBy4(jo)
	for _, in := range []string{
		"TX01 IBAN " + grouped,
		"REF AB12 FROM ACCOUNT " + grouped,
		groupBy4(gbIBAN()) + " " + grouped,
	} {
		out, _ := redactE(t, in)
		if strings.Contains(strings.ReplaceAll(out, " ", ""), jo) || strings.Contains(out, grouped[len(grouped)-9:]) {
			t.Errorf("IBAN left in %q -> %q", in, out)
		}
	}
}

func groupBy4(s string) string {
	var parts []string
	for len(s) > 4 {
		parts, s = append(parts, s[:4]), s[4:]
	}
	return strings.Join(append(parts, s), " ")
}
