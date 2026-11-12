package logs_test

// Collector tests (issue #44; redaction R1, R2, R4, R9, R9a, §4.7; agent-api
// R43, R44): canaries written into fake Nginx and PostgreSQL error logs
// never reach a LogEvent, an encoded telemetry batch, the offsets file or
// the agent log; the offsets file is saved before a line reaches the
// pipeline; bad state files and unsafe sources never crash the collector
// or replay history.

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/logs"
	"github.com/nofal82/warden-agent/internal/agent/telemetry"
	pubredact "github.com/nofal82/warden-agent/redact"
)

const (
	testServerID   = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	testInstanceID = "0123456789abcdef0123456789abcdef"
)

type leakCanary struct {
	name    string
	line    string // a full log line, newline included
	secrets []string
	marker  string
}

func collectorCanaries() (nginx, pg []leakCanary) {
	c5 := akia()
	nginx = append(nginx, leakCanary{"C5", nginxErr("upstream key " + c5 + " refused"), []string{c5, c5[4:]}, pubredact.Marker("aws-access-key-id")})
	c6 := randFrom(alphaAWSSecret, 40)
	nginx = append(nginx, leakCanary{"C6", nginxErr("aws_secret_access_key = " + c6), []string{c6}, pubredact.Marker("aws-secret-key")})
	bt := randFrom(alphaAlnum, 32)
	nginx = append(nginx, leakCanary{"C11", nginxErr(`client sent header "Authorization: Bearer ` + bt + `"`), []string{bt}, pubredact.Marker("authorization-header")})
	c13 := wdnToken()
	nginx = append(nginx, leakCanary{"C13", nginxErr("enrolling with " + c13), []string{c13, c13[5:]}, pubredact.Marker("warden-enrollment-token")})
	for _, s := range []struct{ name, sep string }{{"ANSI", "\x1b[31m"}, {"U+200B", string(rune(0x200B))}, {"invalid UTF-8", "\xff"}} {
		k := akia()
		nginx = append(nginx, leakCanary{"C22 C5 " + s.name, nginxErr("key " + k[:12] + s.sep + k[12:] + " used"), []string{k}, pubredact.Marker("aws-access-key-id")})
		w := wdnToken()
		pg = append(pg, leakCanary{"C22 C13 " + s.name, pgErr("token " + w[:20] + s.sep + w[20:]), []string{w}, pubredact.Marker("warden-enrollment-token")})
	}
	pw := randFrom(alphaAlnum, 16)
	pg = append(pg, leakCanary{"C9", pgErr("could not connect to postgresql://app:" + pw + "@db:5432/x"), []string{pw}, pubredact.Marker("url-credentials")})
	sv := randFrom(alphaAlnum, 16)
	pg = append(pg, leakCanary{"C12", pgErr("syntax error at DB_PASSWORD=" + sv), []string{sv}, pubredact.Marker("secret-assignment")})
	p2 := randFrom(alphaAlnum, 24)
	pg = append(pg, leakCanary{"C22 C12 U+200B", pgErr("DB_PASSWORD=" + p2[:12] + string(rune(0x200B)) + p2[12:]), []string{p2}, pubredact.Marker("secret-assignment")})
	return nginx, pg
}

// R1, R2, R4, R9, §4.7: the end-to-end canary leak test.
func TestCollectorCanaryLeak(t *testing.T) {
	e := newEnv(t)
	nginx, pg := collectorCanaries()
	all := append(slices.Clone(nginx), pg...)

	// History present before the first start is never shipped.
	hist := akia()
	writeFile(t, e.nginxLog, nginxErr("history key "+hist))
	writeFile(t, e.pgLog, pgErr("history"))
	c := e.collector(t)
	c.PollOnce(pollCtx(t))
	if got := e.sink.take(); len(got) != 0 {
		t.Fatalf("first start shipped %d history events", len(got))
	}

	for _, cn := range nginx {
		appendFile(t, e.nginxLog, cn.line)
		appendFile(t, e.nginxLog, "2026/11/12 10:00:01 [notice] 812#812: unrelated "+cn.secrets[0]+"\n")
	}
	for _, cn := range pg {
		appendFile(t, e.pgLog, cn.line)
		appendFile(t, e.pgLog, "2026-11-12 10:00:01.000 UTC [4711] LOG:  unrelated "+cn.secrets[0]+"\n")
	}
	c.PollOnce(pollCtx(t))
	evs := e.sink.take()
	if len(evs) != len(all) {
		t.Fatalf("delivered %d events, want %d (one per matched canary line, none for unmatched lines)", len(evs), len(all))
	}

	buf, err := telemetry.New(telemetry.Config{
		ServerID: testServerID, InstanceID: testInstanceID,
		RuntimeDir: t.TempDir(), Now: func() time.Time { return t0.Add(time.Second) },
	})
	if err != nil {
		t.Fatalf("telemetry.New: %v", err)
	}
	var hay strings.Builder
	for _, ev := range evs {
		hay.WriteString(ev.GetRuleId() + "\x00" + ev.GetUnitId() + "\x00" + ev.GetExtract() + "\n")
		buf.Add(ev)
	}
	if err := buf.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	var bodies [][]byte
	for {
		seq, body, ok := buf.Next()
		if !ok {
			break
		}
		bodies = append(bodies, body)
		buf.Accepted(seq)
	}
	if len(bodies) == 0 {
		t.Fatal("no batch encoded")
	}
	state, err := os.ReadFile(e.state)
	if err != nil {
		t.Fatalf("offsets file not written: %v", err)
	}
	where := map[string]string{
		"events":       hay.String(),
		"offsets file": string(state),
		"agent log":    e.log.String(),
	}
	for i, b := range bodies {
		where["batch "+string(rune('0'+i))] = string(b)
	}
	for w, h := range where {
		for _, cn := range all {
			for i, s := range cn.secrets {
				if leakFound(h, s) {
					t.Errorf("%s: canary %s part %d leaked", w, cn.name, i)
				}
			}
		}
		if leakFound(h, hist) {
			t.Errorf("%s: history canary leaked", w)
		}
	}

	// Positive control: every canary line is an event with its marker.
	for _, cn := range all {
		found := false
		for _, ev := range evs {
			if strings.Contains(ev.GetExtract(), cn.marker) {
				found = true
			}
		}
		if !found {
			t.Errorf("no event carries %s's marker", cn.name)
		}
	}
	for _, ev := range evs {
		switch ev.GetRuleId() {
		case "nginx-error":
			if ev.GetUnitId() != "nginx.service" {
				t.Errorf("nginx unit = %q", ev.GetUnitId())
			}
		case "postgresql-error":
			if ev.GetUnitId() != "postgresql@14-main.service" {
				t.Errorf("postgresql unit = %q", ev.GetUnitId())
			}
		default:
			t.Errorf("unexpected rule_id %q", ev.GetRuleId())
		}
		if ev.GetCount() != 1 || strings.HasSuffix(ev.GetExtract(), "\n") {
			t.Errorf("event count %d or a trailing newline in the extract", ev.GetCount())
		}
	}
	for _, b := range bodies {
		var batch agentapiv1.TelemetryBatch
		if err := agentapiv1.StrictUnmarshal(b, &batch); err != nil {
			t.Errorf("batch fails the strict decoder: %v", err)
		}
	}
}

// R9a: the read position past a line is on disk before that line reaches
// the pipeline. The Sink runs after redaction, so the offset must already
// be persisted when it is called.
func TestCollectorOffsetsSavedFirst(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.nginxLog, "2026/11/12 09:00:00 [notice] 1#1: start\n")
	c := e.collector(t)
	c.PollOnce(pollCtx(t))
	start := int64(len("2026/11/12 09:00:00 [notice] 1#1: start\n"))
	l1, l2 := nginxErr("first failure"), nginxErr("second failure")
	appendFile(t, e.nginxLog, l1+l2)

	calls := 0
	e.sink.during = func(*agentapiv1.LogEvent) {
		calls++
		m, err := logs.LoadOffsets(e.state)
		if err != nil {
			t.Errorf("offsets file unreadable during the Sink call: %v", err)
			return
		}
		pos, ok := m[e.nginxLog]
		if !ok {
			t.Error("no saved position for the source during the Sink call")
			return
		}
		if want := posOf(t, e.nginxLog, 0); pos.Dev != want.Dev || pos.Ino != want.Ino {
			t.Errorf("saved position names another file")
		}
		min := start + int64(len(l1))
		if calls == 2 {
			min += int64(len(l2))
		}
		if pos.Offset < min {
			t.Errorf("Sink call %d: saved offset %d, want >= %d (R9a)", calls, pos.Offset, min)
		}
	}
	c.PollOnce(pollCtx(t))
	if calls != 2 {
		t.Fatalf("Sink called %d times, want 2", calls)
	}
}

// R9a restart: no duplicate, no loss; a file replaced while the agent was
// down is read from 0.
func TestCollectorRestart(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.nginxLog, "")
	c := e.collector(t)
	c.PollOnce(pollCtx(t))
	appendFile(t, e.nginxLog, nginxErr("A"))
	c.PollOnce(pollCtx(t))
	if got := e.sink.take(); len(got) != 1 {
		t.Fatalf("first run delivered %d events", len(got))
	}

	appendFile(t, e.nginxLog, nginxErr("B"))
	c2 := e.collector(t)
	c2.PollOnce(pollCtx(t))
	got := extracts(e.sink.take())
	if len(got) != 1 || !strings.Contains(got[0], "B") {
		t.Fatalf("after restart = %q, want only B", got)
	}

	must(t, os.Rename(e.nginxLog, e.nginxLog+".1"))
	writeFile(t, e.nginxLog, nginxErr("C"))
	c3 := e.collector(t)
	c3.PollOnce(pollCtx(t))
	got = extracts(e.sink.take())
	if len(got) != 1 || !strings.Contains(got[0], "C") {
		t.Fatalf("file rotated while down = %q, want C from offset 0", got)
	}
}

// A corrupt, oversized, symlinked or non-regular state file: the
// collector starts every source at its end, never replays history, never
// writes through the symlink and never crashes.
func TestCollectorBadStateFile(t *testing.T) {
	for _, kind := range []string{"corrupt", "oversized", "symlink", "directory", "FIFO"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			hist := akia()
			writeFile(t, e.nginxLog, nginxErr("history "+hist))
			replay, err := logs.EncodeOffsets(map[string]logs.Position{e.nginxLog: posOf(t, e.nginxLog, 0)})
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(e.root, "planted")
			writeFile(t, target, string(replay))
			switch kind {
			case "corrupt":
				writeFile(t, e.state, "\xff\xfe\x00corrupt")
			case "oversized":
				writeFile(t, e.state, strings.Repeat("a", logs.MaxOffsetsFile+1))
			case "symlink":
				must(t, os.Symlink(target, e.state))
			case "directory":
				must(t, os.Mkdir(e.state, 0o700))
			case "FIFO":
				must(t, mkfifo(e.state))
			}
			_ = openWithin(t, 5*time.Second, func() error {
				c, err := logs.NewCollector(logs.Config{
					Rules: e.rules(t), StatePath: e.state, Pipeline: e.pipe, Sink: e.sink.fn,
					Interval: time.Hour, Now: func() time.Time { return t0 },
				})
				if err != nil {
					return nil // refusing to start is also safe
				}
				c.PollOnce(pollCtx(t))
				appendFile(t, e.nginxLog, nginxErr("fresh"))
				c.PollOnce(pollCtx(t))
				return nil
			}, unblockFIFO(e.state))
			for _, x := range extracts(e.sink.take()) {
				if strings.Contains(x, "history") || leakFound(x, hist) {
					t.Fatal("history replayed from a bad state file")
				}
			}
			if b, _ := os.ReadFile(target); !bytes.Equal(b, replay) { // #nosec G304 -- test file
				t.Error("collector wrote through a symlinked state file")
			}
		})
	}
}

// Unsafe sources in a rule directory are never read: a symlink to a
// secret, a hard link, a FIFO, a file owned by the agent's uid, an
// unreadable file (listed by Unreadable); the agent log never holds content.
func TestCollectorUnsafeSources(t *testing.T) {
	for _, kind := range []string{"symlink", "hard link", "FIFO", "own uid", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "unreadable" && os.Geteuid() == 0 {
				t.Skip("root reads a 000 file")
			}
			e := newEnv(t)
			k := akia()
			secret := filepath.Join(e.root, "shadow")
			writeFile(t, secret, "")
			switch kind {
			case "symlink":
				must(t, os.Symlink(secret, e.nginxLog))
			case "hard link":
				must(t, os.Link(secret, e.nginxLog))
			case "FIFO":
				must(t, mkfifo(e.nginxLog))
			case "own uid":
				writeFile(t, e.nginxLog, "")
				restore := logs.SetOwnUIDForTest(os.Geteuid())
				defer restore()
			case "unreadable":
				writeFile(t, e.nginxLog, "")
				must(t, os.Chmod(e.nginxLog, 0o000))
			}
			c := e.collector(t)
			_ = openWithin(t, 5*time.Second, func() error {
				c.PollOnce(pollCtx(t))
				appendFile(t, secret, nginxErr("FAKE-SECRET-123 key "+k))
				if kind == "own uid" || kind == "unreadable" {
					must(t, os.Chmod(e.nginxLog, 0o600))
					appendFile(t, e.nginxLog, nginxErr("FAKE-SECRET-123 key "+k))
					if kind == "unreadable" {
						must(t, os.Chmod(e.nginxLog, 0o000))
					}
				}
				c.PollOnce(pollCtx(t))
				return nil
			}, unblockFIFO(e.nginxLog))
			if got := e.sink.take(); len(got) != 0 {
				t.Fatalf("%d events from an unsafe %s source", len(got), kind)
			}
			if leakFound(e.log.String(), k) || strings.Contains(e.log.String(), "FAKE-SECRET-123") {
				t.Error("agent log holds file content")
			}
			if kind == "unreadable" && !slices.Contains(c.Unreadable(), e.nginxLog) {
				t.Errorf("Unreadable() = %v, want it to list the source", c.Unreadable())
			}
		})
	}
}

func TestNewCollectorRefuses(t *testing.T) {
	e := newEnv(t)
	good := func() logs.Config {
		return logs.Config{Rules: e.rules(t), StatePath: e.state, Pipeline: e.pipe, Sink: e.sink.fn,
			Interval: time.Second, Now: time.Now}
	}
	if _, err := logs.NewCollector(good()); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	cases := map[string]func(c *logs.Config){
		"nil pipeline":       func(c *logs.Config) { c.Pipeline = nil },
		"nil sink":           func(c *logs.Config) { c.Sink = nil },
		"empty state path":   func(c *logs.Config) { c.StatePath = "" },
		"relative state":     func(c *logs.Config) { c.StatePath = "state/log-offsets" },
		"zero interval":      func(c *logs.Config) { c.Interval = 0 },
		"negative interval":  func(c *logs.Config) { c.Interval = -time.Second },
		"relative rule dir":  func(c *logs.Config) { c.Rules[0].Dir = "var/log/nginx" },
		"dot-dot rule dir":   func(c *logs.Config) { c.Rules[0].Dir = "/var/log/../../etc" },
		"nil File pattern":   func(c *logs.Config) { c.Rules[0].File = nil },
		"nil Match pattern":  func(c *logs.Config) { c.Rules[0].Match = nil },
		"bad rule id":        func(c *logs.Config) { c.Rules[0].ID = "Nginx;reboot" },
		"duplicate rule ids": func(c *logs.Config) { c.Rules[1].ID = c.Rules[0].ID },
	}
	for name, mutate := range cases {
		cfg := good()
		mutate(&cfg)
		if c, err := logs.NewCollector(cfg); err == nil || c != nil {
			t.Errorf("NewCollector(%s) accepted", name)
		}
	}
}
