package redact

// Pipeline tests: span replacement (R31), output limit (R40), post-check
// (R32), input limits (R39), fail closed (R35-R36, R42), unit names (R11),
// release versions (R16), Scan (R18) and MarkersOnly (R55).

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var bg = context.Background()

// ---------------------------------------------------------------------------
// Span replacement and marker shapes.

// AC3, ruling 6: a match replaces only its span; an extend=yes match in a
// name or path widens to R31's token boundaries.
func TestSpanReplacementKeepsRest(t *testing.T) {
	k := akia()
	tok := wdnToken()
	cases := []struct {
		name string
		f    Field
		in   string
		want string
	}{
		{"P2 path (AC3)", fieldFor(TPath), "srv/" + k + "/data.db", "srv/redacted-aws-access-key-id/data.db"},
		{"container name (AC3)", fieldFor(TName), "app-" + k + "-1", "app-redacted-aws-access-key-id-1"},
		{"extend=yes takes the whole path (ruling 6)", fieldFor(TPath), "srv/" + tok + "/data.db", "redacted-warden-enrollment-token"},
		{"extend=yes in a name", fieldFor(TName), "job-" + tok + "-x", "redacted-warden-enrollment-token"},
		{"label value", fieldFor(LValue), "/mnt/" + k, "/mnt/" + Marker("aws-access-key-id")},
		{"T-TEXT", fieldFor(TText), "bad key " + k + " in config", "bad key " + Marker("aws-access-key-id") + " in config"},
		{"E-TEXT", fieldFor(EText), "bad key " + k + " in config", "bad key " + Marker("aws-access-key-id") + " in config"},
		{"two matches", fieldFor(EText), k + " and " + akia(), Marker("aws-access-key-id") + " and " + Marker("aws-access-key-id")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, rep := mustRedact(t, c.f, c.in, nil)
			if out != c.want {
				t.Errorf("got %q, want %q", out, c.want)
			}
			if !rep.MarkerFired {
				t.Errorf("MarkerFired false")
			}
			checkOutput(t, c.f.Class, c.f.MaxBytes, out)
		})
	}
}

func TestMarkerShapesPerClass(t *testing.T) {
	for _, c := range scannedClasses {
		k := akia()
		out, rep := mustRedact(t, fieldFor(c), "x "+k+" y", nil)
		if want := "x " + classMarker(c, "aws-access-key-id") + " y"; out != want {
			t.Errorf("%s: got %q, want %q", className(c), out, want)
		}
		if rep.Replaced["aws-access-key-id"] != 1 {
			t.Errorf("%s: Replaced = %v", className(c), rep.Replaced)
		}
	}
}

// R31, AC3: the short marker when the full marker does not fit, and an
// empty field when even that does not fit (comm is 15 bytes).
func TestShortMarkerAndEmptyField(t *testing.T) {
	const e = "a@b.cd" // 6 bytes, an e-mail address
	cases := []struct {
		c    Class
		max  int
		want string
	}{
		{TName, 15, "redacted-email"},
		{TName, 13, NameShortMarker},
		{TName, 8, NameShortMarker},
		{TName, 7, ""},
		{TPath, 13, NameShortMarker},
		{TPath, 7, ""},
		{EText, 16, Marker("email")},
		{EText, 12, ShortMarker},
		{EText, 9, ""},
		{TText, 12, ShortMarker},
		{LValue, 12, ShortMarker},
		{LValue, 9, ""},
	}
	for _, c := range cases {
		out, rep, err := testRedactor().Redact(bg, Field{Class: c.c, MaxBytes: c.max}, e, nil)
		if err != nil {
			t.Errorf("%s/%d: error %v", className(c.c), c.max, err)
			continue
		}
		if out != c.want {
			t.Errorf("%s/%d: got %q, want %q", className(c.c), c.max, out, c.want)
		}
		if rep.Replaced["email"] < 1 {
			t.Errorf("%s/%d: replacement not counted", className(c.c), c.max)
		}
		if strings.Contains(out, "b.cd") {
			t.Errorf("%s/%d: part of the match kept", className(c.c), c.max)
		}
	}
}

// AC12, AC51, R40: an output limit inside a marker yields an output that
// ends before the marker or carries the short marker; never part of one.
func TestOutputLimitNeverInsideMarker(t *testing.T) {
	for _, c := range scannedClasses {
		prefix := "aaaa "
		in := prefix + akia()
		m := classMarker(c, "aws-access-key-id")
		lo := len(in) // T-* and L-VALUE: the input limit is MaxBytes too
		if c == EText {
			lo = len(prefix) + 1
		}
		for limit := lo; limit < len(prefix)+len(m); limit++ {
			out, _, err := testRedactor().Redact(bg, Field{Class: c, MaxBytes: limit}, in, nil)
			if err != nil {
				t.Errorf("%s/%d: error %v", className(c), limit, err)
				continue
			}
			ok := out == prefix || out == prefix+classShortMarker(c)
			if !ok {
				t.Errorf("%s/%d: got %q, want %q or %q", className(c), limit, out, prefix, prefix+classShortMarker(c))
			}
			checkOutput(t, c, limit, out)
			checkNoPartialMarker(t, out)
		}
	}
}

func TestOutputLimitUTF8Boundary(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{strings.Repeat(r(0xE9), 5), 5, strings.Repeat(r(0xE9), 2)},
		{strings.Repeat(r(0x20AC), 3), 4, r(0x20AC)},
		{strings.Repeat(r(0x20AC), 3), 8, strings.Repeat(r(0x20AC), 2)},
		{r(0x1F600) + "x", 3, ""},
		{"ab" + r(0x1F600), 5, "ab"},
	}
	for _, c := range cases {
		out, _ := mustRedact(t, Field{Class: EText, MaxBytes: c.max}, c.in, nil)
		if out != c.want {
			t.Errorf("limit %d: got %q, want %q", c.max, out, c.want)
		}
	}
	// A growing T-NAME whose marker is preceded by multi-byte text.
	in := strings.Repeat(r(0xE9), 3) + akia()
	out, _ := mustRedact(t, Field{Class: TName, MaxBytes: len(in)}, in, nil)
	if out != strings.Repeat(r(0xE9), 3) && out != strings.Repeat(r(0xE9), 3)+NameShortMarker {
		t.Errorf("T-NAME growth cut: got %q", out)
	}
}

// AC53: a detector that matches every other byte of a 64 KiB input stops at
// the growth cap with ErrOutputTooLarge, within a memory bound. (Adjacent
// matches are merged by R31, so every other byte is the worst case.)
func TestGrowthCap(t *testing.T) {
	var mu sync.Mutex
	var spanBytes uint64
	find := func(s string) ([]span, error) {
		out := make([]span, 0, strings.Count(s, "x"))
		var own uint64
		for i := 0; i < len(s); i++ {
			if s[i] == 'x' {
				out = append(out, span{start: i, end: i + 1})
				own += 48 // generous size of one span
			}
		}
		mu.Lock()
		spanBytes += own
		mu.Unlock()
		return out, nil
	}
	red := newRedactor([]detector{stubDetector("stub", find, []string{"x"}, []string{" "})}, WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("stub rule set failed its self-test: %v", err)
	}
	line := strings.Repeat("x ", 3999) + "x"
	in := strings.TrimSuffix(strings.Repeat(line+"\n", 8), "\n")
	if len(in) > MaxEventInput {
		t.Fatalf("test setup: input %d bytes", len(in))
	}
	mu.Lock()
	spanBytes = 0
	mu.Unlock()
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	out, _, err := red.Redact(bg, fieldFor(EText), in, nil)
	runtime.ReadMemStats(&m1)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("E-TEXT: err = %v, want ErrOutputTooLarge", err)
	}
	if out != "" {
		t.Errorf("E-TEXT: output returned with the error (%d bytes)", len(out))
	}
	alloc := m1.TotalAlloc - m0.TotalAlloc
	mu.Lock()
	own := spanBytes
	mu.Unlock()
	if alloc > own+4<<20 {
		t.Errorf("E-TEXT: allocated %d bytes beyond the stub's own %d, want under 4 MiB", alloc-own, own)
	}

	tn := strings.Repeat("x ", typedMax/2)
	out, _, err = red.Redact(bg, Field{Class: TName, MaxBytes: typedMax}, tn, nil)
	if !errors.Is(err, ErrOutputTooLarge) || out != "" {
		t.Errorf("T-NAME: (%d bytes, %v), want ErrOutputTooLarge and no output", len(out), err)
	}
}

// AC40, AC50: text that becomes a match only through the cut is replaced in
// the second pass and the item is still sent.
func TestPostCheckAfterTruncation(t *testing.T) {
	k := akia() + randFrom(alphaUpperB32, 4)
	in := "key " + k
	out, _, err := testRedactor().Redact(bg, Field{Class: EText, MaxBytes: len("key ") + 20}, in, nil)
	if err != nil {
		t.Fatalf("AWS: err %v (the item must be sent, AC50)", err)
	}
	if strings.Contains(out, k[:20]) || regexp.MustCompile(`AKIA[A-Z2-7]{16}`).MatchString(out) {
		t.Errorf("AWS: output %q still holds the key ID", out)
	}
	checkNoPartialMarker(t, out)

	card := makeCard("4", 16)
	var run string
	for {
		run = card + randDigits(4)
		if !luhnValid(run) {
			break
		}
	}
	in = "id " + run
	out, _, err = testRedactor().Redact(bg, Field{Class: EText, MaxBytes: len("id ") + 16}, in, nil)
	if err != nil {
		t.Fatalf("card: err %v", err)
	}
	if strings.Contains(out, card[:13]) || regexp.MustCompile(`[0-9]{13}`).MatchString(out) {
		t.Errorf("card: output %q still holds the number", out)
	}
	checkNoPartialMarker(t, out)
}

// AC13: a replacement that creates a new match is replaced again in the
// second pass and the item is sent without the match.
func TestPostCheckSecondPass(t *testing.T) {
	hash := stubDetector("hash", findAll("#"), []string{"#"}, []string{"a"})
	bang := stubDetector("bang", findAll("]!"), []string{"]!"}, []string{"!"})
	red := newRedactor([]detector{hash, bang}, WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("self-test: %v", err)
	}
	out, rep, err := red.Redact(bg, fieldFor(EText), "#!", nil)
	if err != nil {
		t.Fatalf("err %v", err)
	}
	for _, d := range []detector{hash, bang} {
		if sp, _ := d.find(out); len(sp) != 0 {
			t.Errorf("output %q still matches %s", out, d.id)
		}
	}
	if !rep.MarkerFired {
		t.Errorf("MarkerFired false")
	}
}

// AC50: a constructed input that still matches after the second pass is
// dropped with ErrPostCheck. The stub's ID contains its own match, so every
// marker it writes matches again.
func TestPostCheckFailure(t *testing.T) {
	red := newRedactor([]detector{stubDetector("qq", findAll("q"), []string{"q"}, []string{"a"})}, WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("self-test: %v", err)
	}
	out, _, err := red.Redact(bg, fieldFor(EText), "q", nil)
	if !errors.Is(err, ErrPostCheck) {
		t.Errorf("err = %v, want ErrPostCheck", err)
	}
	if out != "" {
		t.Errorf("output %q returned with the error", out)
	}
}

// AC37, section 4.3: every value-replacing detector's output passes again
// with no change and no replacement.
func TestMarkerIdempotence(t *testing.T) {
	forms := func(m func(string) string, short string) []string {
		return []string{
			"DB_PASSWORD=" + m("secret-assignment"),
			"password: " + m("secret-assignment"),
			`{"password":"` + m("secret-assignment") + `"}`,
			"requirepass " + m("secret-assignment"),
			"IDENTIFIED BY '" + m("secret-assignment") + "'",
			"Account" + "Key=" + m("secret-assignment"),
			"aws_secret_access_key = " + m("aws-secret-key"),
			"Authorization: " + m("authorization-header"),
			`{"Authorization":"` + m("authorization-header") + `"}`,
			"Cookie: " + m("cookie-header"),
			"https://h/x?token=" + m("url-secret-param"),
			"https://h/x?a=1&access_token=" + m("url-secret-param"),
			"postgresql://" + m("url-credentials") + "@db/x",
			"DB_PASSWORD=" + short,
			"Authorization: " + short,
			"https://h/x?token=" + short,
			"postgresql://" + short + "@db/x",
		}
	}
	for _, c := range scannedClasses {
		for _, in := range forms(func(id string) string { return classMarker(c, id) }, classShortMarker(c)) {
			out, rep := mustRedact(t, fieldFor(c), in, nil)
			if out != in {
				t.Errorf("%s: %q changed to %q", className(c), in, out)
			}
			if replacedTotal(rep) != 0 || rep.MarkerFired {
				t.Errorf("%s: %q reported a replacement", className(c), in)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Input limits (R39, AC17).

func TestLineTooLongIsNeverScanned(t *testing.T) {
	red := testRedactor()
	var mu sync.Mutex
	largest := 0
	setHooks(t, func(_ string, n int) {
		mu.Lock()
		largest = max(largest, n)
		mu.Unlock()
	}, nil, nil)
	in := strings.Repeat("a", 1<<20)
	out, rep, err := red.Redact(bg, Field{Class: EText, MaxBytes: ExtractMaxBytes}, in, nil)
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if out != LineDroppedText {
		t.Errorf("got %q, want %q", lastN(out, 40), LineDroppedText)
	}
	if rep.LinesDropped != 1 {
		t.Errorf("LinesDropped = %d, want 1", rep.LinesDropped)
	}
	if largest >= MaxLine {
		t.Errorf("a detector saw %d bytes: the long line reached a detector", largest)
	}
}

func TestLineLimitBoundary(t *testing.T) {
	f := Field{Class: EText, MaxBytes: MaxEventInput}
	exact := strings.Repeat("a", MaxLine)
	out, rep := mustRedact(t, f, exact, nil)
	if out != exact || rep.LinesDropped != 0 {
		t.Errorf("a line of exactly MaxLine bytes was dropped or changed")
	}
	out, rep = mustRedact(t, f, exact+"a", nil)
	if out != LineDroppedText || rep.LinesDropped != 1 {
		t.Errorf("a line of MaxLine+1 bytes: got %q, LinesDropped %d", lastN(out, 30), rep.LinesDropped)
	}
	in := "first.\n" + exact + "a\nlast."
	out, rep = mustRedact(t, f, in, nil)
	if want := "first.\n" + LineDroppedText + "\nlast."; out != want || rep.LinesDropped != 1 {
		t.Errorf("long middle line: got %q, LinesDropped %d", lastN(out, 60), rep.LinesDropped)
	}
}

// R39: when an event's lines exceed the event limit, whole lines from the
// end are left out before scanning, never a partial line.
func TestEventOverLimitDropsTailLines(t *testing.T) {
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, fmt.Sprintf("event %04d status=ok size=%s done.", i, strings.Repeat("z", 950)))
	}
	in := strings.Join(lines, "\n")
	if len(in) <= MaxEventInput {
		t.Fatalf("test setup: %d bytes", len(in))
	}
	out, rep := mustRedact(t, Field{Class: EText, MaxBytes: MaxEventInput}, in, nil)
	got := strings.Split(out, "\n")
	k := len(got)
	if k == 0 || k >= len(lines) {
		t.Fatalf("kept %d of %d lines", k, len(lines))
	}
	for i := 0; i < k; i++ {
		if got[i] != lines[i] {
			t.Fatalf("line %d is not the input's line %d (partial or reordered)", i, i)
		}
	}
	if rep.LinesOmitted != len(lines)-k {
		t.Errorf("LinesOmitted = %d, want %d", rep.LinesOmitted, len(lines)-k)
	}
	if len(out) > MaxEventInput {
		t.Errorf("kept %d bytes, over the event limit", len(out))
	}
	if next := len(strings.Join(lines[:k+1], "\n")); next <= MaxEventInput-1 {
		t.Errorf("line %d (total %d bytes) fit but was left out", k, next)
	}
}

// R39, AC17, AC63: a T-* or L-VALUE field over its limit is dropped with
// ErrInputTooLarge, checked on the raw bytes before normalisation; the
// normaliser and the detectors never see it.
func TestTypedInputTooLarge(t *testing.T) {
	red := testRedactor()
	var normCalls, detectCalls int
	setHooks(t, func(string, int) { detectCalls++ }, nil, func(Class, int) { normCalls++ })
	for _, c := range []Class{TName, TPath, TText, LValue} {
		for name, in := range map[string]string{
			"one over":                    strings.Repeat("a", 11),
			"raw bytes counted (invalid)": strings.Repeat("a", 10) + "\xff",
			"raw bytes counted (ZWSP)":    strings.Repeat("a", 8) + r(0x200B),
			"canary over":                 akia(),
		} {
			normCalls, detectCalls = 0, 0
			out, _, err := red.Redact(bg, Field{Class: c, MaxBytes: 10}, in, nil)
			if !errors.Is(err, ErrInputTooLarge) {
				t.Errorf("%s %s: err = %v, want ErrInputTooLarge", className(c), name, err)
			}
			if out != "" {
				t.Errorf("%s %s: output returned with the error", className(c), name)
			}
			if normCalls != 0 || detectCalls != 0 {
				t.Errorf("%s %s: normaliser called %d times, detectors %d times", className(c), name, normCalls, detectCalls)
			}
		}
		out, _, err := red.Redact(bg, Field{Class: c, MaxBytes: 10}, strings.Repeat("a", 10), nil)
		if err != nil || out != strings.Repeat("a", 10) {
			t.Errorf("%s: exactly at the limit: (%q, %v)", className(c), out, err)
		}
	}
	out, _, err := red.RedactGroup(bg, Field{Class: TText, MaxBytes: 10}, []string{"ok", strings.Repeat("a", 11)}, nil)
	if !errors.Is(err, ErrInputTooLarge) || out != nil {
		t.Errorf("group with a message over the limit: (%v, %v)", out, err)
	}
	_, _, err = red.Redact(bg, Field{Class: LValue, MaxBytes: LabelValueMaxBytes}, strings.Repeat("a", LabelValueMaxBytes+1), nil)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("label value of %d bytes: err = %v", LabelValueMaxBytes+1, err)
	}
}

func TestEmptyInput(t *testing.T) {
	for _, c := range scannedClasses {
		out, rep := mustRedact(t, fieldFor(c), "", nil)
		if out != "" || replacedTotal(rep) != 0 {
			t.Errorf("%s: empty input gave %q", className(c), out)
		}
	}
	out, _, err := testRedactor().RedactGroup(bg, fieldFor(TText), []string{"", "a", ""}, nil)
	if err != nil || len(out) != 3 || out[0] != "" || out[1] != "a" || out[2] != "" {
		t.Errorf("group with empty messages: (%q, %v)", out, err)
	}
}

// Fail closed on a field the caller got wrong: an unknown class, a class that
// has its own entry point, or a negative limit is an error, never a pass.
func TestInvalidField(t *testing.T) {
	in := "key " + akia()
	for _, f := range []Field{
		{Class: 0, MaxBytes: 100},
		{Class: NPatterned, MaxBytes: 100},
		{Class: 99, MaxBytes: 100},
		{Class: TName, MaxBytes: -1},
		{Class: EText, MaxBytes: -1},
	} {
		out, _, err := testRedactor().Redact(bg, f, in, nil)
		if err == nil || !isKnownErr(err) {
			t.Errorf("Field %+v: err = %v, want a section 4.9 error", f, err)
		}
		if out != "" {
			t.Errorf("Field %+v: output %q returned", f, out)
		}
	}
}

// ---------------------------------------------------------------------------
// Deadline, cancellation and broken detectors (R35, R36, AC15).

func TestDeadlineWithSteppingClock(t *testing.T) {
	fc := newFakeClock(10 * time.Millisecond) // 21 detector checks pass 50 ms
	red := New(WithClock(fc.now))
	if err := red.Err(); err != nil {
		t.Fatalf("New: %v", err)
	}
	in := "key " + akia() + " used."
	for _, c := range scannedClasses {
		out, _, err := red.Redact(bg, fieldFor(c), in, nil)
		if !errors.Is(err, ErrDeadline) || out != "" {
			t.Errorf("%s: (%q, %v), want ErrDeadline and no output", className(c), out, err)
		}
	}
	if out, _, err := red.RedactGroup(bg, fieldFor(TText), []string{in}, nil); !errors.Is(err, ErrDeadline) || out != nil {
		t.Errorf("RedactGroup: (%v, %v)", out, err)
	}
	if out, _, err := red.RedactUnitName(bg, "nginx.service"); !errors.Is(err, ErrDeadline) || out != "" {
		t.Errorf("RedactUnitName: (%q, %v)", out, err)
	}
	if out, _, err := red.RedactReleaseVersion(bg, "1.2.3"); !errors.Is(err, ErrDeadline) || out != ReleaseVersionMarker {
		t.Errorf("RedactReleaseVersion: (%q, %v)", out, err)
	}
	if _, err := red.Scan(bg, "nginx.service"); !errors.Is(err, ErrDeadline) {
		t.Errorf("Scan: %v", err)
	}
}

func TestFrozenClockNeverTimesOut(t *testing.T) {
	fc := newFakeClock(0)
	red := New(WithClock(fc.now))
	out, _, err := red.Redact(bg, fieldFor(EText), "plain line.", nil)
	if err != nil || out != "plain line." {
		t.Errorf("(%q, %v)", out, err)
	}
}

func TestDefaultClock(t *testing.T) {
	red := New()
	if err := red.Err(); err != nil {
		t.Fatalf("New().Err() = %v", err)
	}
	out, _, err := red.Redact(bg, fieldFor(EText), "plain line.", nil)
	if err != nil || out != "plain line." {
		t.Errorf("(%q, %v)", out, err)
	}
}

// AC15: a detector that blocks past the deadline drops the item.
func TestDetectorPastDeadline(t *testing.T) {
	fc := newFakeClock(0)
	slow := stubDetector("slow", func(s string) ([]span, error) {
		if strings.Contains(s, "SLOW") {
			fc.advance(2 * ItemDeadline)
		}
		return findAll("zz")(s)
	}, []string{"zz"}, []string{"a"})
	after := stubDetector("after", findAll("yy"), []string{"yy"}, []string{"a"})
	red := newRedactor([]detector{slow, after}, WithClock(fc.now))
	if err := red.Err(); err != nil {
		t.Fatalf("self-test: %v", err)
	}
	in := "SLOW zz " + akia()
	out, _, err := red.Redact(bg, fieldFor(EText), in, nil)
	if !errors.Is(err, ErrDeadline) || out != "" {
		t.Errorf("(%q, %v), want ErrDeadline and no output", out, err)
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	cancel()
	red := testRedactor()
	in := "key " + akia()
	for _, c := range scannedClasses {
		if out, _, err := red.Redact(ctx, fieldFor(c), in, nil); !errors.Is(err, ErrDeadline) || out != "" {
			t.Errorf("%s: (%q, %v), want ErrDeadline", className(c), out, err)
		}
	}
	if _, _, err := red.RedactGroup(ctx, fieldFor(TText), []string{in}, nil); !errors.Is(err, ErrDeadline) {
		t.Errorf("RedactGroup: %v", err)
	}
	if _, _, err := red.RedactUnitName(ctx, "nginx.service"); !errors.Is(err, ErrDeadline) {
		t.Errorf("RedactUnitName: %v", err)
	}
	if out, _, err := red.RedactReleaseVersion(ctx, "1.2.3"); !errors.Is(err, ErrDeadline) || out != ReleaseVersionMarker {
		t.Errorf("RedactReleaseVersion: (%q, %v)", out, err)
	}
	if _, err := red.Scan(ctx, "x"); !errors.Is(err, ErrDeadline) {
		t.Errorf("Scan: %v", err)
	}
	dctx, dcancel := context.WithDeadline(bg, time.Now().Add(-time.Second))
	defer dcancel()
	if _, _, err := red.Redact(dctx, fieldFor(EText), in, nil); !errors.Is(err, ErrDeadline) {
		t.Errorf("expired context deadline: %v", err)
	}
}

// AC15, R4: a panicking detector gives ErrInternal; no panic escapes and the
// error holds none of the input.
func TestPanickingDetector(t *testing.T) {
	boom := stubDetector("boom", func(s string) ([]span, error) {
		if strings.Contains(s, "PANIC") {
			panic("stub saw: " + s)
		}
		return findAll("zz")(s)
	}, []string{"zz"}, []string{"a"})
	red := newRedactor([]detector{boom}, WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("self-test: %v", err)
	}
	k := akia()
	in := "PANIC " + k
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("a detector panic escaped the redactor")
		}
	}()
	for _, c := range scannedClasses {
		out, _, err := red.Redact(bg, fieldFor(c), in, nil)
		if !errors.Is(err, ErrInternal) || out != "" {
			t.Errorf("%s: (%q, %v), want ErrInternal", className(c), out, err)
		}
		if err != nil {
			assertNoLeak(t, "panic error", err.Error(), k)
		}
	}
	if _, _, err := red.RedactGroup(bg, fieldFor(TText), []string{in}, nil); !errors.Is(err, ErrInternal) {
		t.Errorf("RedactGroup: %v", err)
	}
	if _, _, err := red.RedactUnitName(bg, "PANIC.service"); !errors.Is(err, ErrInternal) {
		t.Errorf("RedactUnitName: %v", err)
	}
	if out, _, err := red.RedactReleaseVersion(bg, "1.0.0-PANIC"); !errors.Is(err, ErrInternal) || out != ReleaseVersionMarker {
		t.Errorf("RedactReleaseVersion: (%q, %v)", out, err)
	}
	if _, err := red.Scan(bg, in); !errors.Is(err, ErrInternal) {
		t.Errorf("Scan: %v", err)
	}
}

// AC15: a detector error drops the item with a section 4.9 error that holds
// none of the detector's own message.
func TestErroringDetector(t *testing.T) {
	k := akia()
	bad := stubDetector("bad", func(s string) ([]span, error) {
		if strings.Contains(s, "FAIL") {
			return nil, fmt.Errorf("stub saw %s", s)
		}
		return findAll("zz")(s)
	}, []string{"zz"}, []string{"a"})
	red := newRedactor([]detector{bad}, WithClock(frozenClock))
	if err := red.Err(); err != nil {
		t.Fatalf("self-test: %v", err)
	}
	for _, c := range scannedClasses {
		out, _, err := red.Redact(bg, fieldFor(c), "FAIL "+k, nil)
		if err == nil || !isKnownErr(err) || out != "" {
			t.Errorf("%s: (%q, %v), want a section 4.9 error and no output", className(c), out, err)
		}
		if err != nil {
			assertNoLeak(t, "detector error", err.Error(), k)
			if strings.Contains(err.Error(), "stub saw") {
				t.Errorf("%s: the detector's own error text was returned", className(c))
			}
		}
	}
}

// R42, AC20: a rule set whose self-test fails gives ErrRulesUnavailable from
// Err and from every method, and building it never panics.
func TestSelfTestFailure(t *testing.T) {
	none := func(string) ([]span, error) { return nil, nil }
	sets := map[string][]detector{
		"positive sample does not match": {stubDetector("s", none, []string{"x"}, []string{"y"})},
		"negative sample matches":        {stubDetector("s", findAll("y"), []string{"y"}, []string{"yy"})},
		"sample returns an error": {stubDetector("s", func(string) ([]span, error) {
			return nil, errors.New("broken")
		}, []string{"x"}, []string{"y"})},
		"sample panics": {stubDetector("s", func(string) ([]span, error) {
			panic("broken")
		}, []string{"x"}, []string{"y"})},
		"real rules plus a broken one": append(defaultRules(), stubDetector("s", none, []string{"x"}, []string{"y"})),
	}
	for name, rules := range sets {
		t.Run(name, func(t *testing.T) {
			var red *Redactor
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("newRedactor panicked")
					}
				}()
				red = newRedactor(rules, WithClock(frozenClock))
			}()
			if !errors.Is(red.Err(), ErrRulesUnavailable) {
				t.Errorf("Err() = %v, want ErrRulesUnavailable", red.Err())
			}
			for _, c := range scannedClasses {
				if out, _, err := red.Redact(bg, fieldFor(c), "plain", nil); !errors.Is(err, ErrRulesUnavailable) || out != "" {
					t.Errorf("Redact %s: (%q, %v)", className(c), out, err)
				}
			}
			if out, _, err := red.RedactGroup(bg, fieldFor(TText), []string{"plain"}, nil); !errors.Is(err, ErrRulesUnavailable) || out != nil {
				t.Errorf("RedactGroup: (%v, %v)", out, err)
			}
			if out, _, err := red.RedactUnitName(bg, "nginx.service"); !errors.Is(err, ErrRulesUnavailable) || out != "" {
				t.Errorf("RedactUnitName: (%q, %v)", out, err)
			}
			if out, _, err := red.RedactReleaseVersion(bg, "1.2.3"); !errors.Is(err, ErrRulesUnavailable) || out != ReleaseVersionMarker {
				t.Errorf("RedactReleaseVersion: (%q, %v)", out, err)
			}
			if hit, err := red.Scan(bg, "plain"); !errors.Is(err, ErrRulesUnavailable) || hit {
				t.Errorf("Scan: (%v, %v)", hit, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit names (R11, ruling 5, AC6, AC43).

var unitPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,240}\.service$`)

func TestRedactUnitName(t *testing.T) {
	k := akia()
	tok := wdnToken()
	zw := r(0x200B)
	ok := []struct{ name, in, want, id string }{
		{"C21 (AC6)", k + ".service", "REDACTED-aws-access-key-id.service", "aws-access-key-id"},
		{"C20 template instance", "postgresql@" + tok + ".service", "postgresql@REDACTED-warden-enrollment-token.service", "warden-enrollment-token"},
		{"no extension in unit names", tok + "-worker.service", "REDACTED-warden-enrollment-token-worker.service", "warden-enrollment-token"},
		{"C21 split by a zero-width char", k[:12] + zw + k[12:] + ".service", "REDACTED-aws-access-key-id.service", "aws-access-key-id"},
		{"zero-width char removed", "ngi" + zw + "nx.service", "nginx.service", ""},
		{"nginx", "nginx.service", "nginx.service", ""},
		{"getty template", "getty@tty1.service", "getty@tty1.service", ""},
		{"user manager", "user@1000.service", "user@1000.service", ""},
		{"postgresql cluster", "postgresql@14-main.service", "postgresql@14-main.service", ""},
		{"sk- unit (AC43)", "sk-payments-db.service", "sk-payments-db.service", ""},
		{"sk- long name before .service", "sk-" + randFrom(alphaAlnum, 48) + ".service", "", ""},
		{"e-mail-shaped unit", "x@y.service", "x@y.service", ""},
		{"longest valid name", "a" + strings.Repeat("b", 240) + ".service", "", ""},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			out, rep, err := testRedactor().RedactUnitName(bg, c.in)
			if err != nil {
				t.Fatalf("err %v", err)
			}
			want := c.want
			if want == "" {
				want = c.in
			}
			if out != want {
				t.Errorf("got %q, want %q", out, want)
			}
			if !unitPattern.MatchString(out) || len(out) > UnitNameMaxBytes {
				t.Errorf("output %q fails the unit pattern", out)
			}
			if c.id != "" && rep.Replaced[c.id] != 1 {
				t.Errorf("Replaced[%s] = %d, want 1", c.id, rep.Replaced[c.id])
			}
			if c.id == "" && replacedTotal(rep) != 0 {
				t.Errorf("benign unit reported replacements: %v", rep.Replaced)
			}
		})
	}
	var parts []string
	for i := 0; i < 11; i++ {
		parts = append(parts, akia())
	}
	grows := strings.Join(parts, "-") + ".service"
	bad := []struct {
		name string
		in   string
		want error
	}{
		{"over 256 bytes", strings.Repeat("a", 249) + ".service", ErrInputTooLarge},
		{"one name part too long", "a" + strings.Repeat("b", 241) + ".service", ErrInternal},
		{"space", "bad name.service", ErrInternal},
		{"newline becomes a space", "ngi\nnx.service", ErrInternal},
		{"no suffix", "nginx", ErrInternal},
		{"other suffix", "nginx.socket", ErrInternal},
		{"empty", "", ErrInternal},
		{"leading dash (option-like)", "-nginx.service", ErrInternal},
		{"path traversal", "../etc.service", ErrInternal},
		{"shell metacharacters", "a;b$(c).service", ErrInternal},
		{"markers grow it over 256", grows, ErrOutputTooLarge},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "markers grow it over 256" && len(c.in) > UnitNameMaxBytes {
				t.Fatalf("test setup: %d bytes", len(c.in))
			}
			out, _, err := testRedactor().RedactUnitName(bg, c.in)
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
			if out != "" {
				t.Errorf("output %q returned with the error", out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Release version (R16, AC62).

func TestRedactReleaseVersion(t *testing.T) {
	k := akia()
	for _, in := range []string{"1.4.2-rc.1+build.7", "1.0.0", "0.1.0-alpha", "10.20.30"} {
		out, rep, err := testRedactor().RedactReleaseVersion(bg, in)
		if err != nil || out != in || replacedTotal(rep) != 0 {
			t.Errorf("benign %q: (%q, %v, %v)", in, out, err, rep.Replaced)
		}
	}
	for name, in := range map[string]string{
		"AWS ID in pre-release": "1.0.0-" + k,
		"e-mail in build":       "1.0.0+a@b.cd",
	} {
		out, rep, err := testRedactor().RedactReleaseVersion(bg, in)
		if err != nil {
			t.Errorf("%s: a match is not an error: %v", name, err)
		}
		if out != ReleaseVersionMarker {
			t.Errorf("%s: got %q, want %q", name, out, ReleaseVersionMarker)
		}
		if replacedTotal(rep) == 0 {
			t.Errorf("%s: match not counted", name)
		}
	}
	out, _, err := testRedactor().RedactReleaseVersion(bg, "1.0.0-"+strings.Repeat("a", 27))
	if out != ReleaseVersionMarker || err == nil || !isKnownErr(err) {
		t.Errorf("over 32 bytes: (%q, %v), want the marker and an error", out, err)
	}
	for _, in := range []string{"1.0.0\x00", "1.0.0\x1b[31m", "1.0.\xff0", "1.0.0" + r(0x202E)} {
		out, _, err := testRedactor().RedactReleaseVersion(bg, in)
		if err != nil && out != ReleaseVersionMarker {
			t.Errorf("%q: error %v without the marker", in, err)
		}
		for _, x := range out {
			if isControl(x) || x == 0x202E {
				t.Errorf("%q: output %q holds an unsafe character", in, out)
			}
		}
		if len(out) > ReleaseVersionMaxBytes {
			t.Errorf("%q: output over 32 bytes", in)
		}
	}
}

// ---------------------------------------------------------------------------
// Scan (R18) and MarkersOnly (R55, ruling 7).

func TestScan(t *testing.T) {
	tok := wdnToken()
	for name, in := range map[string]string{
		"C5":  akia(),
		"C12": "DB_PASSWORD=" + randFrom(alphaAlnum, 16),
		"C13": tok,
		"C20": "postgresql@" + tok + ".service",
		"C15": randFrom(alphaLower, 8) + "@" + randFrom(alphaLower, 6) + ".example",
		"C19": makeCard("4", 16),
	} {
		hit, err := testRedactor().Scan(bg, in)
		if err != nil || !hit {
			t.Errorf("%s: Scan = (%v, %v), want true", name, hit, err)
		}
	}
	for name, in := range map[string]string{
		"unit":      "nginx.service",
		"public IP": "203.0.113.77",
		"home path": "/home/alice/notes.txt",
		"version":   "1.4.2",
		"UUID":      randUUID(),
		"empty":     "",
		"marker":    Marker("aws-access-key-id"),
	} {
		hit, err := testRedactor().Scan(bg, in)
		if err != nil || hit {
			t.Errorf("%s: Scan = (%v, %v), want false", name, hit, err)
		}
	}
}

func TestMarkersOnly(t *testing.T) {
	p := NewPseudonymizer([32]byte{1, 2, 3})
	in := "client 203.0.113.77 read /home/alice/notes.txt"
	f := fieldFor(EText)
	f.MarkersOnly = true
	for _, pz := range []*Pseudonymizer{nil, p} {
		out, rep := mustRedact(t, f, in, pz)
		if out != in {
			t.Errorf("MarkersOnly changed %q to %q", in, out)
		}
		if rep.MarkerFired || replacedTotal(rep) != 0 || rep.Pseudonymised != 0 || rep.UserNameMarkers != 0 {
			t.Errorf("MarkersOnly reported changes: %+v", rep)
		}
	}
	out, rep := mustRedact(t, f, "reason: DB_PASSWORD="+randFrom(alphaAlnum, 16), nil)
	if out != "reason: DB_PASSWORD="+Marker("secret-assignment") || !rep.MarkerFired {
		t.Errorf("MarkersOnly with C12: (%q, MarkerFired %v)", out, rep.MarkerFired)
	}
	out, rep = mustRedact(t, f, "a"+r(0x200B)+"b", nil)
	if out != "ab" || rep.MarkerFired {
		t.Errorf("normalisation alone set MarkerFired or failed: %q", out)
	}
	// Without MarkersOnly the IP is truncated and the name replaced, but
	// neither is a marker-replacing detector.
	out, rep = mustRedact(t, fieldFor(EText), in, nil)
	if want := "client 203.0.113.0/24 read /home/" + UserNameMarker + "/notes.txt"; out != want {
		t.Errorf("without MarkersOnly: got %q, want %q", out, want)
	}
	if rep.MarkerFired {
		t.Errorf("IP truncation or a user-name marker set MarkerFired")
	}
}

// ---------------------------------------------------------------------------
// R4, AC19: no error string and no Report holds canary bytes.

func TestErrorsAndReportsHoldNoCanary(t *testing.T) {
	k := akia()
	tok := wdnToken()
	secrets := []string{k, tok}
	var errs []error
	var reps []Report
	red := testRedactor()
	collect := func(_ string, rep Report, err error) {
		if err != nil {
			errs = append(errs, err)
		}
		reps = append(reps, rep)
	}
	collect(red.Redact(bg, Field{Class: TName, MaxBytes: 5}, k, nil))
	collect(red.Redact(bg, Field{Class: LValue, MaxBytes: 5}, tok, nil))
	collect(red.RedactUnitName(bg, strings.Repeat(k, 13)+".service"))
	collect(red.RedactReleaseVersion(bg, "1.0.0-"+k+k))
	fc := newFakeClock(time.Second)
	collect(New(WithClock(fc.now)).Redact(bg, fieldFor(EText), k, nil))
	broken := newRedactor([]detector{stubDetector("s", func(string) ([]span, error) { return nil, nil }, []string{"x"}, []string{"y"})})
	collect(broken.Redact(bg, fieldFor(EText), tok, nil))
	for _, c := range scannedClasses {
		collect(red.Redact(bg, fieldFor(c), "x "+k+" "+tok, nil))
	}
	if len(errs) < 5 {
		t.Errorf("expected at least 5 errors, got %d", len(errs))
	}
	for _, err := range errs {
		if !isKnownErr(err) {
			t.Errorf("error %v is not a section 4.9 error", err)
		}
		assertNoLeak(t, "error string", err.Error(), secrets...)
		assertNoLeak(t, "error %+v", fmt.Sprintf("%+v", err), secrets...)
	}
	for _, rep := range reps {
		assertNoLeak(t, "report", fmt.Sprintf("%+v", rep), secrets...)
		checkReportKeys(t, rep)
	}
}

// ---------------------------------------------------------------------------
// Groups, reports and concurrency.

func TestRedactGroupBasics(t *testing.T) {
	k := akia()
	in := []string{"a\tb\nc", "client 203.0.113.77 failed", "/home/" + c24Name() + "/x", "key " + k, ""}
	want := []string{"a b c", "client 203.0.113.0/24 failed", "/home/" + UserNameMarker + "/x", "key " + Marker("aws-access-key-id"), ""}
	out, rep, err := testRedactor().RedactGroup(bg, fieldFor(TText), in, nil)
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if len(out) != len(want) {
		t.Fatalf("got %d messages, want %d", len(out), len(want))
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("message %d = %q, want %q", i, out[i], want[i])
		}
	}
	if rep.Replaced["aws-access-key-id"] != 1 || rep.Replaced["public-ip"] != 1 || rep.UserNameMarkers != 1 {
		t.Errorf("report %+v", rep)
	}
}

func TestNormalisationReported(t *testing.T) {
	out, rep := redactE(t, "a"+r(0x200B)+"b\x1b[31mc")
	if out != "abc" {
		t.Errorf("got %q", out)
	}
	if rep.Normalised[NormZeroWidth] != 1 || rep.Normalised[NormEscape] != 1 {
		t.Errorf("Normalised = %v", rep.Normalised)
	}
	if rep.MarkerFired || replacedTotal(rep) != 0 {
		t.Errorf("normalisation reported as a replacement")
	}
}

func TestDetectorHookSeesEveryDetector(t *testing.T) {
	red := testRedactor()
	seen := map[string]int{}
	var mu sync.Mutex
	setHooks(t, func(id string, n int) {
		mu.Lock()
		seen[id]++
		mu.Unlock()
	}, nil, nil)
	if _, _, err := red.Redact(bg, fieldFor(EText), "plain line.", nil); err != nil {
		t.Fatalf("err %v", err)
	}
	for _, id := range specDetectorIDs {
		if seen[id] == 0 {
			t.Errorf("detector %s never ran on an E-TEXT item", id)
		}
	}
	seen = map[string]int{}
	if _, _, err := red.Redact(bg, fieldFor(TName), "plain", nil); err != nil {
		t.Fatalf("err %v", err)
	}
	for _, id := range []string{"cookie-header", "public-ip", "pem-body-line"} {
		if seen[id] != 0 {
			t.Errorf("detector %s ran on a T-NAME item", id)
		}
	}
}

// The Redactor is safe for concurrent use and keeps no state between items
// (R3); run with -race.
func TestConcurrentUse(t *testing.T) {
	red := testRedactor()
	const workers = 2000
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := akia()
			c := scannedClasses[i%len(scannedClasses)]
			out, _, err := red.Redact(bg, fieldFor(c), "key "+k+" used", nil)
			if want := "key " + classMarker(c, "aws-access-key-id") + " used"; err != nil || out != want {
				errs <- fmt.Sprintf("%s: (%q, %v)", className(c), out, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	n := 0
	for e := range errs {
		if n < 5 {
			t.Error(e)
		}
		n++
	}
	if n > 0 {
		t.Errorf("%d of %d concurrent items failed", n, workers)
	}
}
