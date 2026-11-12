package logs_test

// Shared helpers for the log collection tests (issue #44). Tests in this
// package do not call t.Parallel: OpenFile's own-uid check is switched
// through a package-level test hook.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/logs"
	"github.com/nofal82/warden-agent/internal/redact"
	pubredact "github.com/nofal82/warden-agent/redact"
)

const (
	alphaUpper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphaAlnum     = alphaUpper + "abcdefghijklmnopqrstuvwxyz0123456789"
	alphaUpperB32  = alphaUpper + "234567"
	alphaB64URL    = alphaAlnum + "-_"
	alphaAWSSecret = alphaAlnum + "/+"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

// TestMain gives OpenFile an own uid that is not the test user's, so the
// temp files the tests create are acceptable log sources.
func TestMain(m *testing.M) {
	restore := logs.SetOwnUIDForTest(os.Geteuid() + 1)
	code := m.Run()
	restore()
	os.Exit(code)
}

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

// leakFound is the R61 search (redact/helpers_test.go): whole secret, any
// 12-byte window, case-insensitive, and base64 and hex encodings.
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

// syncBuffer is a goroutine-safe slog destination.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// sink captures the events the collector delivers.
type sink struct {
	mu  sync.Mutex
	evs []*agentapiv1.LogEvent
	// during runs inside the Sink call, before the event is recorded.
	during func(ev *agentapiv1.LogEvent)
}

func (s *sink) fn(ev *agentapiv1.LogEvent) {
	if s.during != nil {
		s.during(ev)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, ev)
}

func (s *sink) take() []*agentapiv1.LogEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.evs
	s.evs = nil
	return out
}

func extracts(evs []*agentapiv1.LogEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.GetExtract())
	}
	return out
}

// ruleIn returns the production rule id with its directory moved to dir.
func ruleIn(t *testing.T, id, dir string) logs.Rule {
	t.Helper()
	for _, r := range logs.Rules() {
		if r.ID == id {
			r.Dir = dir
			return r
		}
	}
	t.Fatalf("no production rule %q", id)
	return logs.Rule{}
}

func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	d := filepath.Join(parts...)
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	return d
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// posOf returns the saved position of the file now at path.
func posOf(t testing.TB, path string, off int64) logs.Position {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return logs.Position{Dev: uint64(st.Dev), Ino: st.Ino, Offset: off} // #nosec G115 -- Dev is a device number
}

func newPipeline(t testing.TB) *redact.Pipeline {
	t.Helper()
	pub := pubredact.New()
	if err := pub.Err(); err != nil {
		t.Fatalf("public redactor unavailable: %v", err)
	}
	return redact.New(pub, nil)
}

// env is a collector over temp copies of the nginx and postgresql rules.
type env struct {
	root, nginx, pg, state string
	nginxLog, pgLog        string
	sink                   *sink
	log                    *syncBuffer
	pipe                   *redact.Pipeline
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		root:  root,
		nginx: mkdir(t, root, "var", "log", "nginx"),
		pg:    mkdir(t, root, "var", "log", "postgresql"),
		state: filepath.Join(mkdir(t, root, "state"), "log-offsets"),
		sink:  &sink{},
		log:   &syncBuffer{},
		pipe:  newPipeline(t),
	}
	e.nginxLog = filepath.Join(e.nginx, "error.log")
	e.pgLog = filepath.Join(e.pg, "postgresql-14-main.log")
	return e
}

func (e *env) rules(t *testing.T) []logs.Rule {
	return []logs.Rule{ruleIn(t, "nginx-error", e.nginx), ruleIn(t, "postgresql-error", e.pg)}
}

func (e *env) collector(t *testing.T) *logs.Collector {
	t.Helper()
	c, err := logs.NewCollector(logs.Config{
		Rules:     e.rules(t),
		StatePath: e.state,
		Pipeline:  e.pipe,
		Sink:      e.sink.fn,
		Interval:  time.Hour,
		Now:       func() time.Time { return t0 },
		Log:       slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	return c
}

func pollCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func nginxErr(msg string) string {
	return "2026/11/12 10:00:00 [error] 812#812: *41 " + msg + "\n"
}

func pgErr(msg string) string {
	return "2026-11-12 10:00:00.000 UTC [4711] app@shop ERROR:  " + msg + "\n"
}

// openWithin runs fn and fails if it blocks (a FIFO opened for reading
// without a writer blocks forever). unblock is called on timeout so the
// goroutine can finish.
func openWithin(t *testing.T, d time.Duration, fn func() error, unblock func()) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		unblock()
		t.Fatalf("call blocked for over %v", d)
		return nil
	}
}

func unblockFIFO(path string) func() {
	return func() {
		f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- test FIFO
		if err == nil {
			_ = f.Close()
		}
	}
}

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o600) }
