package logs_test

// Issue #50: a line the redaction pipeline drops (R35, R36, R37) must not
// vanish silently. The collector counts drops per (rule id, R41 reason)
// and, at the end of a poll, logs at most one WARN a minute
// ("logs: lines dropped by redaction") with dropped, total and reasons,
// and never any line content (R4).
//
// No t.Parallel here: see helpers_test.go.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nofal82/warden-agent/internal/agent/logs"
	"github.com/nofal82/warden-agent/internal/redact"
	pubredact "github.com/nofal82/warden-agent/redact"
)

const dropRecordText = "logs: lines dropped by redaction"

// jumpClock is the public redactor's clock. While jump is set every
// reading moves it a second on, so the pass started for the next item
// passes ItemDeadline at its first check (TIMEOUT, R36).
type jumpClock struct {
	mu   sync.Mutex
	t    time.Time
	jump atomic.Bool
}

func (c *jumpClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jump.Load() {
		c.t = c.t.Add(time.Second)
	}
	return c.t
}

// fakeNow is the collector's cfg.Now.
type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeNow) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeNow) set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}

type dropEnv struct {
	*env
	clk *jumpClock
	now *fakeNow
	// budget is the pipeline's minute-window clock; it moves only in
	// spendBudget.
	budget *fakeNow
	c      *logs.Collector
	seen   int // drop WARN records already returned by newWarns
}

// newDropEnv builds a collector whose pipeline uses a controllable
// redactor clock and a budget clock that moves only in spendBudget, logs JSON, and has already done its first poll over empty
// files so later appends are read.
func newDropEnv(t *testing.T) *dropEnv {
	t.Helper()
	e := newEnv(t)
	d := &dropEnv{env: e, clk: &jumpClock{t: t0}, now: &fakeNow{t: t0}, budget: &fakeNow{t: t0}}
	pub := pubredact.New(pubredact.WithClock(d.clk.now))
	if err := pub.Err(); err != nil {
		t.Fatalf("public redactor unavailable: %v", err)
	}
	e.pipe = redact.New(pub, nil, redact.WithClock(d.budget.now))
	writeFile(t, e.nginxLog, "")
	writeFile(t, e.pgLog, "")
	c, err := logs.NewCollector(logs.Config{
		Rules:     e.rules(t),
		StatePath: e.state,
		Pipeline:  e.pipe,
		Sink:      e.sink.fn,
		Interval:  time.Hour,
		Now:       d.now.now,
		Log:       slog.New(slog.NewJSONHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	d.c = c
	d.poll(t, t0)
	if w := d.newWarns(t); len(w) != 0 {
		t.Fatalf("drop WARN on the first, empty poll: %v", w)
	}
	return d
}

func (d *dropEnv) poll(t *testing.T, at time.Time) {
	t.Helper()
	d.now.set(at)
	d.c.PollOnce(pollCtx(t))
}

// spendBudget starts a new minute window of the pipeline's budget (so
// lines redacted earlier in the test do not count) and leaves exactly
// left bytes of it.
func (d *dropEnv) spendBudget(t *testing.T, left int) {
	t.Helper()
	d.budget.set(d.budget.now().Add(time.Minute))
	in := redact.LogInput{
		RuleID: "nginx-error", UnitID: "nginx.service", ObservedAt: t0,
		Lines: []string{strings.Repeat("x", redact.BytesPerMinute-left)},
	}
	if _, err := d.pipe.RedactLog(context.Background(), in); err != nil {
		t.Fatalf("budget pre-spend dropped: %v", err)
	}
}

// newWarns returns the drop WARN records logged since the previous call.
func (d *dropEnv) newWarns(t *testing.T) []map[string]any {
	t.Helper()
	var all []map[string]any
	sc := bufio.NewScanner(strings.NewReader(d.log.String()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if rec["msg"] == dropRecordText {
			all = append(all, rec)
		}
	}
	out := all[d.seen:]
	d.seen = len(all)
	return out
}

// checkWarn asserts one drop WARN record: level, the three attributes and
// nothing else.
func checkWarn(t *testing.T, rec map[string]any, dropped, total int, reasons string) {
	t.Helper()
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if got, ok := rec["dropped"].(float64); !ok || got != float64(dropped) {
		t.Errorf("dropped = %v, want %d", rec["dropped"], dropped)
	}
	if got, ok := rec["total"].(float64); !ok || got != float64(total) {
		t.Errorf("total = %v, want %d", rec["total"], total)
	}
	if got, ok := rec["reasons"].(string); !ok || got != reasons {
		t.Errorf("reasons = %v, want %q", rec["reasons"], reasons)
	}
	for k := range rec {
		switch k {
		case "time", "level", "msg", "dropped", "total", "reasons":
		default:
			t.Errorf("drop WARN has unexpected attribute %q", k)
		}
	}
}

func oneWarn(t *testing.T, d *dropEnv) map[string]any {
	t.Helper()
	w := d.newWarns(t)
	if len(w) != 1 {
		t.Fatalf("got %d drop WARN records, want 1", len(w))
	}
	return w[0]
}

func noWarn(t *testing.T, d *dropEnv, when string) {
	t.Helper()
	if w := d.newWarns(t); len(w) != 0 {
		t.Errorf("%s: got %d drop WARN records, want 0: %v", when, len(w), w)
	}
}

// (a), (b) One TIMEOUT drop: one WARN, the event is not delivered, and the
// log holds nothing of the line (R4).
func TestDropWarnTimeoutNoContent(t *testing.T) {
	d := newDropEnv(t)
	secret, nonce := akia(), "n"+randFrom(alphaAlnum, 23)
	line := nginxErr("req " + nonce + " key " + secret)
	appendFile(t, d.nginxLog, line)
	d.clk.jump.Store(true)
	d.poll(t, t0.Add(time.Second))

	if evs := d.sink.take(); len(evs) != 0 {
		t.Errorf("dropped line reached the Sink: %d events", len(evs))
	}
	checkWarn(t, oneWarn(t, d), 1, 1, "nginx-error/TIMEOUT=1")
	if got := d.pipe.Dropped(pubredact.EText, "TIMEOUT"); got != 1 {
		t.Errorf("pipeline Dropped(E_TEXT, TIMEOUT) = %d, want 1", got)
	}
	out := d.log.String()
	if strings.Contains(out, strings.TrimSuffix(line, "\n")) {
		t.Error("log output carries the dropped line (R4)")
	}
	for i, s := range []string{secret, nonce} {
		if leakFound(out, s) {
			t.Errorf("log output carries part %d of the dropped line (R4)", i)
		}
	}
}

// (c) Rate limit: one WARN per minute; the rest is reported once the
// minute is up, even by a poll with no new lines. Nothing is lost.
func TestDropWarnRateLimit(t *testing.T) {
	d := newDropEnv(t)
	d.clk.jump.Store(true)
	sum := 0
	for i, n := range []int{2, 3, 1} {
		for j := 0; j < n; j++ {
			appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
		}
		d.poll(t, t0.Add(time.Duration(i)*20*time.Second))
		w := d.newWarns(t)
		switch {
		case i == 0 && len(w) == 1:
			checkWarn(t, w[0], 2, 2, "nginx-error/TIMEOUT=2")
			sum += 2
		case i == 0:
			t.Fatalf("first poll with drops: %d WARN records, want 1", len(w))
		case len(w) != 0:
			t.Errorf("poll %d inside the minute: %d drop WARN records, want 0", i, len(w))
		}
	}
	d.poll(t, t0.Add(time.Minute))
	checkWarn(t, oneWarn(t, d), 4, 6, "nginx-error/TIMEOUT=4")
	sum += 4
	d.poll(t, t0.Add(2*time.Minute))
	noWarn(t, d, "poll with nothing pending")
	if got := d.pipe.Dropped(pubredact.EText, "TIMEOUT"); sum != 6 || got != 6 {
		t.Errorf("sum of dropped = %d, pipeline Dropped = %d, want 6 and 6", sum, got)
	}
}

// (d) The next WARN is allowed at exactly last+1min, not 1ns before.
func TestDropWarnMinuteBoundary(t *testing.T) {
	d := newDropEnv(t)
	d.clk.jump.Store(true)
	last := t0.Add(5 * time.Second)
	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	d.poll(t, last)
	checkWarn(t, oneWarn(t, d), 1, 1, "nginx-error/TIMEOUT=1")

	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	d.poll(t, last.Add(time.Minute-time.Nanosecond))
	noWarn(t, d, "last+1min-1ns")

	d.poll(t, last.Add(time.Minute))
	checkWarn(t, oneWarn(t, d), 1, 2, "nginx-error/TIMEOUT=1")
}

// (e) A clock that goes backwards does not hold pending drops forever.
func TestDropWarnClockBackwards(t *testing.T) {
	d := newDropEnv(t)
	d.clk.jump.Store(true)
	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	d.poll(t, t0.Add(time.Hour))
	checkWarn(t, oneWarn(t, d), 1, 1, "nginx-error/TIMEOUT=1")

	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	d.poll(t, t0)
	checkWarn(t, oneWarn(t, d), 1, 2, "nginx-error/TIMEOUT=1")
}

// (f) Lines that redact fine, secrets included, and lines that do not
// match give no drop WARN.
func TestDropWarnNoDrops(t *testing.T) {
	d := newDropEnv(t)
	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	appendFile(t, d.nginxLog, nginxErr("key "+akia()+" used"))
	appendFile(t, d.nginxLog, "2026/11/12 10:00:01 [notice] 812#812: unrelated\n")
	appendFile(t, d.pgLog, pgErr("relation missing"))
	d.poll(t, t0.Add(time.Second))
	d.poll(t, t0.Add(2*time.Minute))
	if n := len(d.sink.take()); n != 3 {
		t.Errorf("delivered %d events, want 3", n)
	}
	noWarn(t, d, "no drops")
}

// (g) A line over the minute byte budget (R37) is reported as BUDGET.
func TestDropWarnBudget(t *testing.T) {
	d := newDropEnv(t)
	d.spendBudget(t, 0)
	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	d.poll(t, t0.Add(time.Second))
	if n := len(d.sink.take()); n != 0 {
		t.Errorf("line over budget delivered: %d events", n)
	}
	checkWarn(t, oneWarn(t, d), 1, 1, "nginx-error/BUDGET=1")
}

// (h) Drops of several rules and reasons: reasons sorted, counts exact,
// and only the drops since the previous WARN.
func TestDropWarnMixedReasonsSorted(t *testing.T) {
	d := newDropEnv(t)
	d.clk.jump.Store(true)
	appendFile(t, d.pgLog, pgErr("first"))
	d.poll(t, t0)
	checkWarn(t, oneWarn(t, d), 1, 1, "postgresql-error/TIMEOUT=1")

	appendFile(t, d.pgLog, pgErr("a")+pgErr("b"))
	appendFile(t, d.nginxLog, nginxErr("c"))
	d.poll(t, t0.Add(10*time.Second))
	noWarn(t, d, "TIMEOUT drops inside the minute")

	d.clk.jump.Store(false)
	d.spendBudget(t, 0)
	appendFile(t, d.nginxLog, nginxErr("d")+nginxErr("e"))
	appendFile(t, d.pgLog, pgErr("f"))
	d.poll(t, t0.Add(20*time.Second))
	noWarn(t, d, "BUDGET drops inside the minute")

	d.poll(t, t0.Add(time.Minute))
	checkWarn(t, oneWarn(t, d), 6, 7,
		"nginx-error/BUDGET=2,nginx-error/TIMEOUT=1,postgresql-error/BUDGET=1,postgresql-error/TIMEOUT=2")
}

// (i) A drop does not stop the poll: a later line of the same poll is
// still redacted and delivered.
func TestDropWarnPollContinues(t *testing.T) {
	d := newDropEnv(t)
	big := nginxErr("upstream timed out " + strings.Repeat("z", 200))
	small := nginxErr("ok")
	// Room for the small line only: the big one is dropped (BUDGET) and
	// the small one after it still fits.
	d.spendBudget(t, len(small)+10)
	appendFile(t, d.nginxLog, big+small)
	d.poll(t, t0.Add(time.Second))
	evs := d.sink.take()
	if len(evs) != 1 || !strings.Contains(evs[0].GetExtract(), "ok") {
		t.Fatalf("delivered %q, want only the line after the drop", extracts(evs))
	}
	checkWarn(t, oneWarn(t, d), 1, 1, "nginx-error/BUDGET=1")
	if got := d.pipe.Dropped(pubredact.EText, "BUDGET"); got != 1 {
		t.Errorf("pipeline Dropped(E_TEXT, BUDGET) = %d, want 1", got)
	}
}

// (j) Drops still pending inside the minute are logged when Run stops,
// so a burst just before a restart is never silent (security review LOW).
func TestDropWarnFlushedOnStop(t *testing.T) {
	d := newDropEnv(t)
	d.clk.jump.Store(true)
	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	d.poll(t, t0.Add(time.Second))
	checkWarn(t, oneWarn(t, d), 1, 1, "nginx-error/TIMEOUT=1")

	appendFile(t, d.nginxLog, nginxErr("upstream timed out"))
	d.poll(t, t0.Add(2*time.Second))
	noWarn(t, d, "inside the minute")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.c.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	checkWarn(t, oneWarn(t, d), 1, 2, "nginx-error/TIMEOUT=1")
}
