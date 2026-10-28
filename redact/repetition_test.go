package redact

import (
	"strings"
	"testing"
)

// Security review H1: one crafted line repeated across a maximum-size
// event must cost linear work in every detector, because the deadline
// (R36) is only checked between detector calls.
func repetitionEvent(unit string) string {
	line := strings.Repeat(unit, MaxLine/len(unit))
	return strings.TrimSuffix(strings.Repeat(line+"\n", MaxEventInput/(len(line)+1)), "\n")
}

// S1 (human Go reviewer, 13th review): the check is on work, not wall
// time, so it is deterministic under the race detector, coverage and a
// loaded machine. Every detector's scanning helper reports the bytes each
// step examined through hooks.work; a full event of n identical lines must
// cost at most 2n times one line (linear, with slack for line ends), and
// one line must cost something (the hook is wired). The wall-clock bound
// of a whole event is held only by TestWorstCaseTime (fuzz_test.go): an
// uninstrumented wall-clock check here was a second, flaky copy of it
// (issue #24 item 2).
func repetitionUnits() map[string]string {
	return map[string]string{
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
		"vendor-sk-ant":        "sk-" + "ant-",
		"email":                "a@a.",
		"card":                 "4111 ",
		"iban":                 "GB82 ",
		// Issue #24 item 1: runs may be split by any number of spaces, so
		// a start followed by long space gaps must not rescan them.
		"iban-spaces":      "GB82" + strings.Repeat(" ", 40),
		"iban-short-runs":  "GB82 A ",
		"sql-identified":   "IDENTIFIED BY '",
		"sql-password":     "password='",
		"rsyslog-hash":     "#",
		"escape-before-ip": bs + "E::",
	}
}

func TestHomogeneousRepetitionIsLinear(t *testing.T) {
	red := New(WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("New: %v", err)
	}
	var work int64
	setWorkHook(t, func(n int) {
		if n < 0 {
			t.Errorf("work hook called with %d bytes", n)
		}
		work += int64(n)
	})
	workOf := func(name, in string) int64 {
		work = 0
		_, _, err := red.Redact(bg, Field{Class: EText, MaxBytes: ExtractMaxBytes}, in, nil)
		if err != nil && !isKnownErr(err) {
			t.Fatalf("%s: %v", name, err)
		}
		return work
	}
	for name, unit := range repetitionUnits() {
		full := repetitionEvent(unit)
		line := full[:strings.IndexByte(full, '\n')]
		lines := int64(strings.Count(full, "\n") + 1)
		wLine, wFull := workOf(name, line), workOf(name, full)
		if wLine <= 0 {
			t.Errorf("%s: one line reported no work: the work hook is not wired into the detectors", name)
			continue
		}
		if wFull > 2*lines*wLine {
			t.Errorf("%s: %d bytes of work for %d lines, %d for one line: over %dx (quadratic?)",
				name, wFull, lines, wLine, 2*lines)
		}
	}
}

// The work hook sees every detector: each one reports some work on a
// line that holds its trigger, so a detector cannot escape the S1 check
// by not calling the hook.
func TestWorkHookCoversEveryDetector(t *testing.T) {
	var cur string
	got := map[string]int64{}
	old := hooks
	t.Cleanup(func() { hooks = old })
	hooks.detect = func(id string, _ int) { cur = id }
	hooks.work = func(n int) { got[cur] += int64(n) }
	k := getKeys(t)
	in := strings.Join([]string{
		k.rsaPEM, b64BeginPrefix() + randFrom(alphaAlnum, 40), wdnToken(), akia(),
		"aws_secret_access_key = " + randFrom(alphaAWSSecret, 40), "gh" + "p_" + randFrom(alphaAlnum, 36),
		makeJWT(), "postgresql://app:" + randFrom(alphaAlnum, 8) + "@db/x", "https://h/?token=" + randFrom(alphaAlnum, 8),
		"Authorization: Bearer " + randFrom(alphaAlnum, 16), "Cookie: s=" + randFrom(alphaAlnum, 8),
		"DB_PASSWORD=" + randFrom(alphaAlnum, 8), "mail a@mail.example", "+962 7" + randDigits(8),
		"national number: " + joDigits(), "iqama: " + saDigits(), "784" + randDigits(12),
		"card " + makeCard("4", 16), "iban " + gbIBAN(), "client 203.0.113.77",
	}, "\n")
	if _, _, err := New(WithClock(frozenClock)).Redact(bg, Field{Class: EText, MaxBytes: ExtractMaxBytes}, in, nil); err != nil {
		t.Fatalf("Redact: %v", err)
	}
	for _, id := range specDetectorIDs {
		if got[id] <= 0 {
			t.Errorf("%s reported no work through hooks.work", id)
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

// Fuzz finding (FuzzRedactEText): a truncated IPv6 network is written in
// lowercase, so "\E::" became "\e::/48", an R25a escape that a second pass
// (intake) decodes. The output must be a fixed point.
func TestIPTruncationMakesNoEscape(t *testing.T) {
	for _, in := range []string{`\E::`, `x \EC00::1 y`, `\\\E::`, `\\E::`} {
		once, _ := redactE(t, in)
		twice, _ := redactE(t, once)
		if once != twice {
			t.Errorf("%q: not a fixed point: %q then %q", in, once, twice)
		}
	}
}
