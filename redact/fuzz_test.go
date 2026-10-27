package redact

// Native fuzz targets (AC18): Normalize per class, every detector's find,
// and the full pipeline per class and entry point. Invariants: no panic
// escapes; an error is a section 4.9 value; a success is valid UTF-8, within
// its limit, holds only the class's allowed controls and is a fixed point.
// The time bound is checked once, deterministically, in TestWorstCaseTime.

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// fuzzSeeds are attack cases and canaries, built at run time.
func fuzzSeeds() []string {
	k := akia()
	tok := wdnToken()
	begin := strings.Repeat("-", 5) + "BEGIN " + pemType("RSA") + strings.Repeat("-", 5)
	end := strings.Repeat("-", 5) + "END " + pemType("RSA") + strings.Repeat("-", 5)
	body := randFrom(alphaAlnum+"+/", 64)
	return []string{
		"", " ", "\n", "\t", "\r\n", "\x00", "\x1b", "\xff\xfe",
		"../../etc/shadow", "..%2f..%2fetc%2fshadow", "/etc/shadow" + "\x00.txt", "./a/./b/",
		"a;b&&c|d$(e)`f`", "\n--config=/tmp/x", "-rf", strings.Repeat("A", 10<<10),
		"key " + k + " used", "key " + k[:12] + "\x1b[31m" + k[12:], k[:12] + r(0x200B) + k[12:], k[:12] + "#033[0m" + k[12:],
		k + ".service", "postgresql@" + tok + ".service", "enrolling with " + tok,
		"DB_PASSWORD=" + randFrom(alphaAlnum, 16), `{"dbPassword":"` + randFrom(alphaAlnum, 16) + `"}`,
		"Authorization: Bearer " + randFrom(alphaAlnum, 32), "Cookie: session=" + randFrom(alphaAlnum, 16),
		"postgresql:" + bs + "/" + bs + "/app:" + randFrom(alphaAlnum, 12) + "@db",
		"https://h/cb?code=1" + bs + "u0026access_token=" + randFrom(alphaAlnum, 16),
		"jwt " + makeJWT(), "card " + makeCard("4", 16), "iban " + groupFours(gbIBAN()) + " X",
		"national number: " + joDigits(), "رقم الهوية " + arabicIndic(saDigits()), "784-" + randDigits(4) + "-" + randDigits(7) + "-1",
		"+962 7" + randDigits(8), "mail " + randFrom(alphaLower, 8) + "@x.example", "user@1000.service",
		"client 203.0.113.77 GET /", "::ffff:203.0.113.77", "2002:c000:0221::1", "203.0.113.0/24", "std::vector",
		"/home/" + c24Name() + "/x", "/home/u-0123456789abcdef/x", "/root/x",
		begin + "\n" + body + "\n" + end, body + "\n" + body + "\n" + end, b64BeginPrefix() + randFrom(alphaAlnum, 200),
		Marker("aws-access-key-id"), "redacted-email", ShortMarker, LineDroppedText, ReleaseVersionMarker,
		"1.4.2-rc.1+build.7", "[REDACTED-", "redacted-aws", strings.Repeat("x ", 2000),
		strings.Repeat(r(0x202E)+r(0xE0041)+"a", 100), strings.Repeat("\x1b[", 500),
		// 13th review: R28a folds, R28b depth, S2 suffixes, OQ15 escapes,
		// OQ16 versions, OQ17 quotes, S3 cards, S4 sk- units, B1 IBANs, #14.
		"pa" + r(0x017F) + r(0x017F) + "word=" + randFrom(alphaAlnum, 12), "to" + r(0x212A) + "en=" + randFrom(alphaAlnum, 12),
		nestedBackslash(NormMaxPasses-1, "0026"), nestedBackslash(NormMaxPasses, "0026"), "#0" + r(0x01) + "33[31m",
		"::ffff:203.0.113.77/24abc", "::ffff:203.0.113.77/120", "203.0.113.77/33", "::ffff:203.0.113.77/0",
		`x \E::1 y`, `x \\\E::1 y`, `x #::ffff:177.12.2.3 y`, "build 1.2.3.4 ok",
		"IDENTIFIED BY '" + randFrom(alphaAlnum, 6) + bs + "'" + randFrom(alphaAlnum, 6) + "'", "password='a''b' user='app'",
		"ref 42 " + makeCard("4", 16) + " ok", makeCard("4", 16) + " " + makeCard("5", 16),
		"sk-" + "ant-" + "api-gateway-production.service", "iban " + groupFours(makeIBAN("MA", "1"+randDigits(23))) + " X",
		"/" + "wdn1" + "_" + strings.Repeat("0", 43), "redacted-warden-enrollment-token", "DB_PASSWORD=" + Marker("public-ip"),
	}
}

func catchPanic(t *testing.T, what string) {
	t.Helper()
	if p := recover(); p != nil {
		t.Fatalf("%s: panic escaped", what)
	}
}

func FuzzNormalize(f *testing.F) {
	for i, s := range fuzzSeeds() {
		f.Add(s, uint8(i))
	}
	f.Fuzz(func(t *testing.T, s string, ci uint8) {
		c := allNormClasses[int(ci)%len(allNormClasses)]
		defer catchPanic(t, "Normalize")
		out, counts, err := Normalize(c, s)
		if err != nil {
			// R28b: only the pass cap fails, and then nothing is returned.
			if !errors.Is(err, ErrInternal) || out != "" || counts != (NormCounts{}) {
				t.Fatalf("%s: error %v with output or counts", className(c), err)
			}
			return
		}
		// R28b, AC72: the output is a fixed point in every class.
		if again, n2, err := Normalize(c, out); err != nil || again != out || n2 != (NormCounts{}) {
			t.Fatalf("%s: output is not a fixed point: (%q, %v, %v)", className(c), again, n2, err)
		}
		if !utf8.ValidString(out) {
			t.Fatalf("%s: invalid UTF-8 output", className(c))
		}
		if len(out) > len(s) {
			t.Fatalf("%s: normalisation grew the input from %d to %d bytes", className(c), len(s), len(out))
		}
		if strings.Count(out, r(0xFFFD)) > strings.Count(s, r(0xFFFD)) {
			t.Fatalf("%s: new U+FFFD", className(c))
		}
		for _, x := range out {
			allowed := c == EText && (x == '\n' || x == '\t')
			if isControl(x) && !allowed {
				t.Fatalf("%s: control %U in output", className(c), x)
			}
		}
		for k, n := range counts {
			if n < 0 {
				t.Fatalf("negative count for kind %d", k)
			}
		}
	})
}

// FuzzDetectors runs every detector's find on arbitrary input.
func FuzzDetectors(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	rules := defaultRules()
	f.Fuzz(func(t *testing.T, s string) {
		if len(rules) == 0 {
			t.Fatal("no rules")
		}
		norm, _, err := Normalize(EText, s)
		if err != nil {
			norm = ""
		}
		for _, d := range rules {
			func() {
				defer catchPanic(t, d.id)
				_, _ = d.find(s) // raw input: no panic
				spans, err := d.find(norm)
				if err != nil {
					return
				}
				last := -1
				for _, sp := range spans {
					if sp.start < 0 || sp.end > len(norm) || sp.start >= sp.end {
						t.Fatalf("%s: span [%d,%d) out of bounds for %d bytes", d.id, sp.start, sp.end, len(norm))
					}
					if sp.start < last {
						t.Fatalf("%s: spans not ordered", d.id)
					}
					last = sp.start
					if !utf8.RuneStart(norm[sp.start]) || (sp.end < len(norm) && !utf8.RuneStart(norm[sp.end])) {
						t.Fatalf("%s: span [%d,%d) splits a UTF-8 sequence", d.id, sp.start, sp.end)
					}
					if d.kind == kindIP && (sp.repl == "" || !utf8.ValidString(sp.repl)) {
						t.Fatalf("%s: IP span without a valid replacement", d.id)
					}
				}
			}()
		}
	})
}

var fuzzPseudonymizer = NewPseudonymizer([32]byte{0x5a, 0xa5})

func fuzzRedactOne(t *testing.T, f Field, s string) {
	t.Helper()
	red := testRedactor()
	defer catchPanic(t, "Redact")
	out, rep, err := red.Redact(bg, f, s, fuzzPseudonymizer)
	if err != nil {
		if !isKnownErr(err) {
			t.Fatalf("%s: error %v is not a section 4.9 error", className(f.Class), err)
		}
		if out != "" {
			t.Fatalf("%s: output returned with an error", className(f.Class))
		}
		return
	}
	checkOutput(t, f.Class, f.MaxBytes, out)
	checkReportKeys(t, rep)
	again, rep2, err := red.Redact(bg, f, out, fuzzPseudonymizer)
	if err != nil {
		t.Fatalf("%s: second pass error %v", className(f.Class), err)
	}
	if again != out {
		t.Fatalf("%s: not a fixed point:\n %q\n %q", className(f.Class), out, again)
	}
	if replacedTotal(rep2) != 0 || rep2.MarkerFired || rep2.Pseudonymised != 0 || rep2.UserNameMarkers != 0 {
		t.Fatalf("%s: second pass reported changes %+v", className(f.Class), rep2)
	}
}

func addSeeds(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
}

func FuzzRedactEText(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) { fuzzRedactOne(t, fieldFor(EText), s) })
}

func FuzzRedactTText(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) { fuzzRedactOne(t, fieldFor(TText), s) })
}

func FuzzRedactTName(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) { fuzzRedactOne(t, fieldFor(TName), s) })
}

func FuzzRedactTPath(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		fuzzRedactOne(t, fieldFor(TPath), s)
		fuzzRedactOne(t, Field{Class: TPath, MaxBytes: typedMax, HomeRoot: true}, s)
	})
}

func FuzzRedactLValue(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) { fuzzRedactOne(t, fieldFor(LValue), s) })
}

// FuzzRedactSmallLimit exercises the output limit and the short marker.
func FuzzRedactSmallLimit(f *testing.F) {
	for i, s := range fuzzSeeds() {
		f.Add(s, uint8(i))
	}
	f.Fuzz(func(t *testing.T, s string, n uint8) {
		fuzzRedactOne(t, Field{Class: EText, MaxBytes: int(n)}, s)
		fuzzRedactOne(t, Field{Class: TName, MaxBytes: int(n), DBUser: n%2 == 0}, s)
	})
}

// FuzzRedactTPathSmallLimit exercises T-PATH with small output limits, with
// and without the HomeRoot user-name rule (issue #14: a marker written by
// the first pass must not be pseudonymised by the second).
func FuzzRedactTPathSmallLimit(f *testing.F) {
	for i, s := range fuzzSeeds() {
		f.Add(s, uint8(i))
	}
	f.Add("/"+"wdn1"+"_"+strings.Repeat("0", 43), uint8(32))
	f.Add("/"+"wdn1"+"_"+strings.Repeat("0", 43), uint8(8))
	f.Fuzz(func(t *testing.T, s string, n uint8) {
		fuzzRedactOne(t, Field{Class: TPath, MaxBytes: int(n), HomeRoot: n%2 == 0}, s)
	})
}

func FuzzRedactGroup(f *testing.F) {
	seeds := fuzzSeeds()
	for i := range seeds {
		f.Add(seeds[i], seeds[(i+1)%len(seeds)], seeds[(i+7)%len(seeds)])
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		red := testRedactor()
		in := []string{a, b, c}
		defer catchPanic(t, "RedactGroup")
		out, _, err := red.RedactGroup(bg, fieldFor(TText), in, fuzzPseudonymizer)
		if err != nil {
			if !isKnownErr(err) || out != nil {
				t.Fatalf("error %v (output %v)", err, out != nil)
			}
			return
		}
		if len(out) != len(in) {
			t.Fatalf("%d messages in, %d out", len(in), len(out))
		}
		for _, m := range out {
			checkOutput(t, TText, typedMax, m)
		}
		again, rep2, err := red.RedactGroup(bg, fieldFor(TText), out, fuzzPseudonymizer)
		if err != nil {
			t.Fatalf("second pass error %v", err)
		}
		for i := range out {
			if again[i] != out[i] {
				t.Fatalf("message %d not a fixed point:\n %q\n %q", i, out[i], again[i])
			}
		}
		if replacedTotal(rep2) != 0 || rep2.MarkerFired {
			t.Fatalf("second pass reported changes")
		}
	})
}

func FuzzRedactUnitName(f *testing.F) {
	addSeeds(f)
	f.Add("nginx.service")
	f.Add("getty@tty1.service")
	f.Fuzz(func(t *testing.T, s string) {
		red := testRedactor()
		defer catchPanic(t, "RedactUnitName")
		out, _, err := red.RedactUnitName(bg, s)
		if err != nil {
			if !isKnownErr(err) || out != "" {
				t.Fatalf("error %v with output %q", err, out)
			}
			return
		}
		if len(out) > UnitNameMaxBytes || !unitPattern.MatchString(out) {
			t.Fatalf("output %q fails the unit pattern", out)
		}
		again, _, err := red.RedactUnitName(bg, out)
		if err != nil || again != out {
			t.Fatalf("not a fixed point: (%q, %v)", again, err)
		}
	})
}

func FuzzRedactReleaseVersion(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		red := testRedactor()
		defer catchPanic(t, "RedactReleaseVersion")
		out, _, err := red.RedactReleaseVersion(bg, s)
		if err != nil {
			if !isKnownErr(err) {
				t.Fatalf("error %v is not a section 4.9 error", err)
			}
			if out != ReleaseVersionMarker {
				t.Fatalf("error without the fixed value: %q", out)
			}
			return
		}
		if len(out) > ReleaseVersionMaxBytes || !utf8.ValidString(out) {
			t.Fatalf("unsafe output %q", out)
		}
		for _, x := range out {
			if isControl(x) {
				t.Fatalf("control in output %q", out)
			}
		}
		if hit, err := red.Scan(bg, out); err != nil || hit {
			t.Fatalf("output %q still matches a detector", out)
		}
		again, _, err := red.RedactReleaseVersion(bg, out)
		if err != nil || again != out {
			t.Fatalf("not a fixed point: (%q, %v)", again, err)
		}
	})
}

func FuzzScan(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		defer catchPanic(t, "Scan")
		_, err := testRedactor().Scan(bg, s)
		if err != nil && !isKnownErr(err) {
			t.Fatalf("error %v is not a section 4.9 error", err)
		}
	})
}

// ---------------------------------------------------------------------------
// AC18 time bound, deterministic and outside the fuzz loop.

// adversarialEvent builds a maximum-size E-TEXT event packed with partial
// detector triggers: many candidates, few or no matches.
func adversarialEvent() string {
	frags := []string{
		"AK" + "IA", "+9 ", "a@b.", b64BeginPrefix(), "eyJ", "://a:", "password=", "4111 ", "1.2.3.",
		"::", "07", "784-", "GB82 ", "national id ", "#033", bs + "u00", "\x1b[", "/home/", "wdn1" + "_",
		"sk-", "Bearer ", "?token", "Cookie:", "nid ", "رقم ", "-----", "IDENTIFIED ", "\x00",
	}
	var line strings.Builder
	for i := 0; line.Len() < MaxLine-64; i++ {
		line.WriteString(frags[i%len(frags)])
	}
	l := line.String()
	var ev strings.Builder
	for ev.Len()+len(l)+1 <= MaxEventInput {
		if ev.Len() > 0 {
			ev.WriteByte('\n')
		}
		ev.WriteString(l)
	}
	return ev.String()
}

func benignEvent(t *testing.T) string {
	var lines []string
	for _, f := range logFiles() {
		lines = append(lines, readLines(t, f)...)
	}
	var ev strings.Builder
	for i := 0; ; i++ {
		l := lines[i%len(lines)]
		if ev.Len()+len(l)+1 > MaxEventInput {
			break
		}
		if ev.Len() > 0 {
			ev.WriteByte('\n')
		}
		ev.WriteString(l)
	}
	return ev.String()
}

func TestWorstCaseTime(t *testing.T) {
	limit := ItemDeadline
	if raceEnabled {
		limit *= 10
	}
	red := New(WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("New: %v", err)
	}
	k := getKeys(t)
	cases := []struct {
		name    string
		f       Field
		in      string
		mustNil bool
	}{
		{"adversarial E-TEXT 64 KiB", Field{Class: EText, MaxBytes: ExtractMaxBytes}, adversarialEvent(), false},
		{"benign E-TEXT 64 KiB", Field{Class: EText, MaxBytes: ExtractMaxBytes}, benignEvent(t), true},
		{"key blocks E-TEXT", Field{Class: EText, MaxBytes: ExtractMaxBytes}, strings.Repeat(k.rsaPEM+"\n", 30), true},
		{"adversarial T-NAME", Field{Class: TName, MaxBytes: typedMax}, adversarialEvent()[:typedMax-8], false},
		{"adversarial L-VALUE", Field{Class: LValue, MaxBytes: LabelValueMaxBytes}, adversarialEvent()[:200], false},
	}
	for _, c := range cases {
		best := time.Duration(1 << 62)
		for i := 0; i < 3; i++ {
			start := time.Now()
			_, _, err := red.Redact(bg, c.f, c.in, fuzzPseudonymizer)
			el := time.Since(start)
			best = min(best, el)
			if err != nil && (c.mustNil || !isKnownErr(err)) {
				t.Fatalf("%s: error %v", c.name, err)
			}
		}
		if best > limit {
			t.Errorf("%s: %v per item, over %v", c.name, best, limit)
		}
	}
	// With the real clock, a benign maximum-size event finishes inside the
	// deadline (not asserted under the race detector, which is 5-10x slower).
	if !raceEnabled {
		if _, _, err := New().Redact(bg, Field{Class: EText, MaxBytes: ExtractMaxBytes}, benignEvent(t), nil); err != nil {
			t.Errorf("benign 64 KiB event with the real clock: %v", err)
		}
	}
}
