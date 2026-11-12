package redact_test

// Attack and failure tests for the agent redaction pipeline (issue #44;
// redaction.md R1, R2, R4, R9, R11, R35–R42, §4.6a, §4.7 canaries C5, C6,
// C9, C11, C12, C13, C21, C22). Every canary is built at run time from
// fragments and crypto/rand (R58); none is written as a literal.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/redact"
	pubredact "github.com/nofal82/warden-agent/redact"
)

const (
	alphaUpper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphaDigits    = "0123456789"
	alphaAlnum     = alphaUpper + "abcdefghijklmnopqrstuvwxyz" + alphaDigits
	alphaUpperB32  = alphaUpper + "234567"
	alphaB64URL    = alphaAlnum + "-_"
	alphaAWSSecret = alphaAlnum + "/+"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func randFrom(alphabet string, n int) string {
	b := make([]byte, n)
	m := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, m)
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

func akia() string     { return "AK" + "IA" + randFrom(alphaUpperB32, 16) }
func wdnToken() string { return "wdn1" + "_" + randFrom(alphaB64URL, 43) }

// leakFound is the R61 search: the whole secret, any 12-byte window of it,
// case-insensitive, and its base64 and hex encodings.
func leakFound(hay, secret string) bool {
	if secret == "" {
		return false
	}
	lh, ls := strings.ToLower(hay), strings.ToLower(secret)
	if strings.Contains(lh, ls) {
		return true
	}
	for i := 0; i+12 <= len(ls); i++ {
		if strings.Contains(lh, ls[i:i+12]) {
			return true
		}
	}
	for _, e := range []string{
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
		hex.EncodeToString([]byte(secret)),
	} {
		if strings.Contains(hay, e) {
			return true
		}
	}
	return false
}

type stepClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *stepClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.t
	c.t = c.t.Add(c.step)
	return t
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newPipeline(t *testing.T, opts ...redact.Option) *redact.Pipeline {
	t.Helper()
	pub := pubredact.New()
	if err := pub.Err(); err != nil {
		t.Fatalf("public redactor unavailable: %v", err)
	}
	return redact.New(pub, nil, opts...)
}

func logIn(lines ...string) redact.LogInput {
	return redact.LogInput{RuleID: "nginx-error", UnitID: "nginx.service", Lines: lines, ObservedAt: t0}
}

// assertNoContent checks R4: an error never carries input content.
func assertNoContent(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	if !errors.Is(err, redact.ErrDropped) {
		t.Errorf("error %q does not wrap ErrDropped", "(hidden)")
	}
	for i, s := range secrets {
		if leakFound(err.Error(), s) {
			t.Errorf("error text carries input part %d (R4)", i)
		}
	}
}

type canary struct {
	name    string
	line    string
	secrets []string
	id      string
}

// buildCanaries returns C5, C6, C9, C11, C12, C13 and C22's split variants
// of C5, C12, C13, each inside a realistic Nginx error-log line.
func buildCanaries() []canary {
	pre := "2026/11/12 10:00:00 [error] 812#812: *41 "
	var cs []canary
	c5 := akia()
	cs = append(cs, canary{"C5", pre + "key " + c5 + " used", []string{c5, c5[4:]}, "aws-access-key-id"})
	c6 := randFrom(alphaAWSSecret, 40)
	cs = append(cs, canary{"C6", pre + "aws_secret_access_key = " + c6, []string{c6}, "aws-secret-key"})
	pw := randFrom(alphaAlnum, 16)
	cs = append(cs, canary{"C9", pre + "dsn postgresql://app:" + pw + "@db:5432/x", []string{pw}, "url-credentials"})
	bt := randFrom(alphaAlnum, 32)
	cs = append(cs, canary{"C11", pre + "upstream sent Authorization: Bearer " + bt, []string{bt}, "authorization-header"})
	sv := randFrom(alphaAlnum, 16)
	cs = append(cs, canary{"C12", pre + "env DB_PASSWORD=" + sv, []string{sv}, "secret-assignment"})
	c13 := wdnToken()
	cs = append(cs, canary{"C13", pre + "enrolling with " + c13, []string{c13, c13[5:]}, "warden-enrollment-token"})
	for _, s := range []struct{ name, sep string }{
		{"ANSI", "\x1b[31m"},
		{"U+200B", string(rune(0x200B))},
		{"invalid UTF-8", "\xff"},
	} {
		k := akia()
		cs = append(cs, canary{"C22 C5 " + s.name, pre + "key " + k[:12] + s.sep + k[12:] + " used", []string{k}, "aws-access-key-id"})
		p := randFrom(alphaAlnum, 24)
		cs = append(cs, canary{"C22 C12 " + s.name, pre + "DB_PASSWORD=" + p[:12] + s.sep + p[12:], []string{p}, "secret-assignment"})
		w := wdnToken()
		cs = append(cs, canary{"C22 C13 " + s.name, pre + "enrolling with " + w[:20] + s.sep + w[20:], []string{w}, "warden-enrollment-token"})
	}
	return cs
}

// R9, §4.7: every canary is redacted in E-TEXT, the event is kept with
// the detector's marker, count 1, the rule and unit copied, the extract
// within 4,096 bytes, valid UTF-8 and without NUL.
func TestRedactLogCanaries(t *testing.T) {
	t.Parallel()
	p := newPipeline(t)
	for _, c := range buildCanaries() {
		t.Run(c.name, func(t *testing.T) {
			ev, err := p.RedactLog(context.Background(), logIn(c.line))
			if err != nil {
				assertNoContent(t, err, c.secrets...)
				t.Fatalf("RedactLog dropped a canary line: %v", err)
			}
			if ev == nil {
				t.Fatal("RedactLog = nil, nil")
			}
			for i, s := range c.secrets {
				if leakFound(ev.GetExtract(), s) {
					t.Errorf("secret part %d in the extract", i)
				}
			}
			if !strings.Contains(ev.GetExtract(), pubredact.Marker(c.id)) {
				t.Errorf("extract has no %s marker", c.id)
			}
			if ev.GetCount() != 1 || ev.GetRuleId() != "nginx-error" || ev.GetUnitId() != "nginx.service" ||
				ev.GetObservedAtMs() != t0.UnixMilli() {
				t.Errorf("event fields = %q %q %d %d", ev.GetRuleId(), ev.GetUnitId(), ev.GetCount(), ev.GetObservedAtMs())
			}
			x := ev.GetExtract()
			if len(x) > pubredact.ExtractMaxBytes || !utf8.ValidString(x) || strings.ContainsRune(x, 0) {
				t.Errorf("extract breaks agent-api §4.7: len %d, utf8 %v", len(x), utf8.ValidString(x))
			}
		})
	}
	if p.Replaced(pubredact.EText, "aws-access-key-id") == 0 {
		t.Error("redact_replaced_total{E_TEXT,aws-access-key-id} = 0 after C5 (R41)")
	}
}

// R11, C21: a unit-id-shaped secret is replaced span-only and the event
// kept; a unit name that cannot meet the pattern after redaction drops the
// event, and the error carries no content.
func TestRedactLogUnitID(t *testing.T) {
	t.Parallel()
	k := akia()
	cases := []struct {
		name, unit, want string
		drop             bool
	}{
		{"plain unit", "postgresql@14-main.service", "postgresql@14-main.service", false},
		{"C21 AKIA unit", k + ".service", "REDACTED-aws-access-key-id.service", false},
		{"C20 token template", "postgresql@" + wdnToken() + ".service", "postgresql@REDACTED-warden-enrollment-token.service", false},
		{"no .service suffix", "nginx", "", true},
		{"dot-dot", "a..b.service", "", true},
		{"slash", "../etc/passwd.service", "", true},
		{"shell chars", "nginx;reboot.service", "", true},
		{"newline", "nginx\n.service", "", true},
		{"leading dash", "--config=x.service", "", true},
		{"over 256 bytes", strings.Repeat("a", 250) + ".service", "", true},
		{"NUL", "ng\x00inx.service", "", true},
	}
	p := newPipeline(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := logIn("2026/11/12 10:00:00 [error] 1#1: failed")
			in.UnitID = tc.unit
			ev, err := p.RedactLog(context.Background(), in)
			if tc.drop {
				if err == nil || ev != nil {
					t.Fatalf("RedactLog kept an event with unit %q", ev.GetUnitId())
				}
				assertNoContent(t, err, tc.unit)
				return
			}
			if err != nil {
				t.Fatalf("RedactLog: %v", err)
			}
			if ev.GetUnitId() != tc.want {
				t.Errorf("unit_id = %q, want %q", ev.GetUnitId(), tc.want)
			}
			if leakFound(ev.GetUnitId(), k[4:]) {
				t.Error("C21 random part kept in unit_id")
			}
			if !agentapiv1.ValidUnitID(ev.GetUnitId()) {
				t.Errorf("unit_id %q fails the contract pattern", ev.GetUnitId())
			}
		})
	}
}

// R11 last sentence: rule_id is structural, copied as is when it matches
// the contract pattern; anything else is an ERROR drop, never sent.
func TestRedactLogRuleID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id string
		ok bool
	}{
		{"nginx-error", true},
		{"ab", true},
		{"a" + strings.Repeat("b", 62), true},
		{"", false},
		{"a", false},
		{"a" + strings.Repeat("b", 63), false},
		{"Nginx-error", false},
		{"-nginx", false},
		{"9nginx", false},
		{"nginx_error", false},
		{"nginx-error\n", false},
		{"nginx error", false},
		{"nginx;reboot", false},
		{"$(id)", false},
		{"../x", false},
		{"ngínx", false},
		{strings.Repeat("a", 10<<10), false},
	}
	for _, tc := range cases {
		t.Run(tc.id[:min(len(tc.id), 20)], func(t *testing.T) {
			t.Parallel()
			p := newPipeline(t)
			in := logIn("2026/11/12 10:00:00 [error] 1#1: failed")
			in.RuleID = tc.id
			ev, err := p.RedactLog(context.Background(), in)
			if tc.ok {
				if err != nil || ev.GetRuleId() != tc.id {
					t.Fatalf("RedactLog = %v, %v; want rule_id copied", ev, err)
				}
				return
			}
			if err == nil || ev != nil {
				t.Fatal("bad rule_id accepted")
			}
			assertNoContent(t, err)
			if got := p.Dropped(pubredact.EText, "ERROR"); got != 1 {
				t.Errorf("Dropped(E_TEXT, ERROR) = %d, want 1", got)
			}
		})
	}
}

// R37: the item that would take the minute over the budget is dropped
// whole (BUDGET) before scanning; a later item that fits still passes; the
// window resets after a minute.
func TestRedactLogBudget(t *testing.T) {
	t.Parallel()
	clk := &stepClock{t: t0}
	p := newPipeline(t, redact.WithClock(clk.now))
	line := strings.Repeat("upstream timed out ", 900)[:15<<10]
	lines := []string{line, line, line, line}
	size := 4*len(line) + 3
	n := redact.BytesPerMinute / size
	for i := 0; i < n; i++ {
		if _, err := p.RedactLog(context.Background(), logIn(lines...)); err != nil {
			t.Fatalf("item %d of %d inside the budget dropped: %v", i, n, err)
		}
	}
	k := akia()
	over := append(append([]string(nil), lines[:3]...), line+" "+k)
	ev, err := p.RedactLog(context.Background(), logIn(over...))
	if err == nil || ev != nil {
		t.Fatal("item over the minute budget was sent")
	}
	assertNoContent(t, err, k)
	if got := p.Dropped(pubredact.EText, "BUDGET"); got != 1 {
		t.Errorf("Dropped(E_TEXT, BUDGET) = %d, want 1", got)
	}
	if p.Replaced(pubredact.EText, "aws-access-key-id") != 0 {
		t.Error("an item over budget was scanned (replacement counted)")
	}
	if _, err := p.RedactLog(context.Background(), logIn("[error] small")); err != nil {
		t.Errorf("small item that still fits dropped: %v", err)
	}
	clk.advance(time.Minute)
	if _, err := p.RedactLog(context.Background(), logIn(lines...)); err != nil {
		t.Errorf("item after the window reset dropped: %v", err)
	}
}

// R36, R35: a clock that jumps past REDACT_ITEM_DEADLINE drops the item
// (TIMEOUT), returns no event and no content.
func TestRedactLogDeadline(t *testing.T) {
	t.Parallel()
	clk := &stepClock{t: t0, step: time.Second}
	pub := pubredact.New(pubredact.WithClock(clk.now))
	p := redact.New(pub, nil)
	k := akia()
	ev, err := p.RedactLog(context.Background(), logIn("[error] key "+k))
	if err == nil || ev != nil {
		t.Fatal("item past the deadline was sent")
	}
	assertNoContent(t, err, k)
	if got := p.Dropped(pubredact.EText, "TIMEOUT"); got != 1 {
		t.Errorf("Dropped(E_TEXT, TIMEOUT) = %d, want 1", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ev, err := newPipeline(t).RedactLog(ctx, logIn("[error] key "+k)); err == nil || ev != nil {
		t.Error("RedactLog with a cancelled context sent the item")
	}
}

// R39: a line over REDACT_MAX_LINE is replaced by the fixed text and never
// scanned or sent; the event is kept with the other lines redacted.
func TestRedactLogOversizedLine(t *testing.T) {
	t.Parallel()
	p := newPipeline(t)
	k1, k2 := akia(), akia()
	long := "[error] " + k1 + " " + strings.Repeat("x", pubredact.MaxLine)
	cases := []struct {
		name  string
		lines []string
	}{
		{"exactly MaxLine+1 (tailer cut)", []string{"[error] first " + k2, long[:pubredact.MaxLine+1]}},
		{"far over MaxLine", []string{"[error] first " + k2, long + long}},
		{"oversized alone", []string{long}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := p.RedactLog(context.Background(), logIn(tc.lines...))
			if err != nil {
				t.Fatalf("RedactLog dropped the event: %v", err)
			}
			x := ev.GetExtract()
			if !strings.Contains(x, pubredact.LineDroppedText) {
				t.Error("extract lacks the LINE DROPPED text")
			}
			if leakFound(x, k1) || leakFound(x, k2) || strings.Contains(x, strings.Repeat("x", 64)) {
				t.Error("oversized line content or a secret reached the extract")
			}
			if len(x) > pubredact.ExtractMaxBytes {
				t.Errorf("extract is %d bytes", len(x))
			}
		})
	}
	if ev, err := p.RedactLog(context.Background(), logIn(strings.Repeat("y", pubredact.MaxLine))); err != nil ||
		strings.Contains(ev.GetExtract(), pubredact.LineDroppedText) {
		t.Errorf("a line of exactly MaxLine was replaced or dropped: %v", err)
	}
}

// R42: while the rule set is unavailable every item is dropped
// (RULES_UNAVAILABLE) and RulesAvailable reports false.
func TestRedactLogRulesUnavailable(t *testing.T) {
	t.Parallel()
	if p := newPipeline(t); !p.RulesAvailable() {
		t.Fatal("RulesAvailable = false with the built-in rule set")
	}
	t.Skip("public redact exposes no way to build a *Redactor whose Err() != nil " +
		"(newRedactor and the detector hooks are unexported); RULES_UNAVAILABLE needs an exported test hook in redact/")
}

// §4.6a: Drops is HealthReport field 10: absent when zero, sorted by
// class, distinct, E_TEXT = 4, counts match Dropped.
func TestDrops(t *testing.T) {
	t.Parallel()
	p := newPipeline(t)
	if d := p.Drops(); len(d) != 0 {
		t.Fatalf("Drops on a fresh pipeline = %v, want none", d)
	}
	for _, id := range []string{"", "BAD", "x;y"} {
		in := logIn("[error] x")
		in.RuleID = id
		_, _ = p.RedactLog(context.Background(), in)
	}
	in := logIn("[error] x")
	in.UnitID = "../x"
	_, _ = p.RedactLog(context.Background(), in)
	d := p.Drops()
	if len(d) == 0 {
		t.Fatal("Drops empty after four drops")
	}
	var total uint64
	var classes []int32
	for _, c := range d {
		if c.GetDropped() == 0 || c.GetDropped() > 1<<40 {
			t.Errorf("class %v dropped = %d", c.GetClass(), c.GetDropped())
		}
		if c.GetClass() < 1 || c.GetClass() > 7 {
			t.Errorf("class %v out of 1..7", c.GetClass())
		}
		classes = append(classes, int32(c.GetClass()))
		total += c.GetDropped()
	}
	if !slices.IsSorted(classes) || len(slices.Compact(slices.Clone(classes))) != len(classes) {
		t.Errorf("classes %v not sorted and distinct", classes)
	}
	if total != 4 {
		t.Errorf("dropped total = %d, want 4", total)
	}
	if d[0].GetClass() != agentapiv1.RedactClass_REDACT_CLASS_E_TEXT && len(d) == 1 {
		t.Errorf("class = %v, want E_TEXT", d[0].GetClass())
	}
	if agentapiv1.RedactClass_REDACT_CLASS_E_TEXT != 4 {
		t.Error("E_TEXT wire value is not 4")
	}
	d[0].Dropped = 999
	if p.Drops()[0].GetDropped() == 999 {
		t.Error("Drops returns its internal state, not a copy")
	}
}
