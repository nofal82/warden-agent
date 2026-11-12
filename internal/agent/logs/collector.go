package logs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/redact"
)

const (
	// DefaultInterval is the production poll interval.
	DefaultInterval = 2 * time.Second
	// pollBytes bounds the input read from one source in one poll.
	pollBytes = 256 << 10
	// discoverEvery: sources are looked up again every this many polls.
	discoverEvery = 15
	// maxDirEntries bounds one directory listing.
	maxDirEntries = 1024
)

var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

// ErrConfig: a Config field is missing or invalid.
var ErrConfig = errors.New("logs: invalid collector configuration")

// Sink receives redacted events only.
type Sink func(*agentapiv1.LogEvent)

// Config is a collector's configuration.
type Config struct {
	Rules     []Rule
	StatePath string
	Pipeline  *redact.Pipeline
	Sink      Sink
	Interval  time.Duration
	Now       func() time.Time
	// Log receives local reports: paths, counts and error kinds, never
	// file content (redaction R4).
	Log *slog.Logger
}

type source struct {
	rule Rule
	unit string
	t    *Tailer
}

// Collector tails every source of its rules.
type Collector struct {
	cfg   Config
	log   *slog.Logger
	polls int
	// unreadableDirs are rule directories the agent may not list.
	unreadableDirs []string
	sources        map[string]*source
	pos            map[string]Position
	saved          bool // pos is what the state file holds

	mu         sync.Mutex
	unreadable []string
	reported   map[string]string
}

// NewCollector checks cfg and loads the persisted positions. A bad state
// file is reported and ignored: every source then starts at its end.
func NewCollector(cfg Config) (*Collector, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	pos, err := LoadOffsets(cfg.StatePath)
	if err != nil {
		log.Warn("logs: offsets state unusable; every source starts at its end", "error", err.Error())
		pos = map[string]Position{}
	}
	return &Collector{cfg: cfg, log: log, sources: map[string]*source{}, pos: pos, reported: map[string]string{}}, nil
}

func checkConfig(cfg Config) error {
	switch {
	case cfg.Pipeline == nil, cfg.Sink == nil, cfg.Interval <= 0:
		return ErrConfig
	case !filepath.IsAbs(cfg.StatePath) || filepath.Clean(cfg.StatePath) != cfg.StatePath:
		return fmt.Errorf("%w: state path", ErrConfig)
	}
	seen := map[string]bool{}
	for _, r := range cfg.Rules {
		if !ruleIDPattern.MatchString(r.ID) || seen[r.ID] || r.File == nil || r.Match == nil ||
			!filepath.IsAbs(r.Dir) || filepath.Clean(r.Dir) != r.Dir {
			return fmt.Errorf("%w: rule", ErrConfig)
		}
		seen[r.ID] = true
	}
	return nil
}

// Run polls every Interval until ctx is done.
func (c *Collector) Run(ctx context.Context) error {
	tick := time.NewTicker(c.cfg.Interval)
	defer tick.Stop()
	defer c.close()
	for {
		c.PollOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (c *Collector) close() {
	for _, s := range c.sources {
		_ = s.t.Close()
	}
}

type pending struct {
	src   *source
	lines []string
}

// PollOnce reads every source once. The new positions are saved before
// any line read in this poll is passed to the redactor (redaction R9a);
// when they cannot be saved, the lines are not passed on at all.
func (c *Collector) PollOnce(ctx context.Context) {
	if c.polls%discoverEvery == 0 {
		c.discover()
	}
	c.polls++
	var work []pending
	unreadable := slices.Clone(c.unreadableDirs)
	for _, path := range sortedKeys(c.sources) {
		s := c.sources[path]
		lines, pos, err := s.t.Poll(pollBytes)
		c.report(path, err, s.t.Problem())
		if errors.Is(s.t.Problem(), ErrUnreadable) {
			unreadable = append(unreadable, path)
		}
		if pos.Ino != 0 && pos != c.pos[path] {
			c.pos[path], c.saved = pos, false
		}
		if len(lines) > 0 {
			work = append(work, pending{s, lines})
		}
	}
	c.mu.Lock()
	c.unreadable = unreadable
	c.mu.Unlock()
	if !c.saved {
		if err := SaveOffsets(c.cfg.StatePath, c.pos); err != nil {
			c.log.Warn("logs: offsets not saved; lines of this poll are skipped (R9a)", "error", err.Error(), "sources", len(work))
			return
		}
		c.saved = true
	}
	for _, w := range work {
		for _, line := range w.lines {
			if ctx.Err() != nil {
				return
			}
			c.handle(ctx, w.src, strings.TrimSuffix(line, "\r"))
		}
	}
}

func (c *Collector) handle(ctx context.Context, s *source, line string) {
	if !s.rule.Matches(line) {
		return
	}
	ev, err := c.cfg.Pipeline.RedactLog(ctx, redact.LogInput{
		RuleID: s.rule.ID, UnitID: s.unit, Lines: []string{line}, ObservedAt: c.cfg.Now(),
	})
	if err != nil {
		return // dropped and counted by the pipeline (redaction R35, R41)
	}
	c.cfg.Sink(ev)
}

// discover finds the files of every rule. A file seen for the first time
// on the first discovery starts at its saved position or its end; one
// that appears later is new and is read from its start.
func (c *Collector) discover() {
	first := c.polls == 0
	found := map[string]bool{}
	c.unreadableDirs = nil
	for _, r := range c.cfg.Rules {
		for _, d := range c.ruleDirs(r) {
			names, err := listDir(d.dir, maxDirEntries)
			if err != nil {
				c.dirError(d.dir, err) // missing or unreadable: nothing to tail
				continue
			}
			slices.Sort(names)
			for _, name := range names {
				unit, ok := r.unitFor(d.sub, name)
				if !ok {
					continue
				}
				path := filepath.Join(d.dir, name)
				if found[path] || len(found) >= maxEntries {
					continue
				}
				found[path] = true
				if _, ok := c.sources[path]; ok {
					continue
				}
				var saved *Position
				if p, ok := c.pos[path]; ok {
					saved = &p
				} else if !first {
					saved = &Position{}
				}
				c.sources[path] = &source{rule: r, unit: unit, t: NewTailer(path, saved)}
			}
		}
	}
	for path, s := range c.sources {
		if !found[path] {
			_ = s.t.Close()
			delete(c.sources, path)
		}
	}
	for path := range c.pos {
		if !found[path] {
			delete(c.pos, path)
			c.saved = false
		}
	}
}

type ruleDir struct{ dir, sub string }

func (c *Collector) ruleDirs(r Rule) []ruleDir {
	if r.SubDir == nil {
		return []ruleDir{{dir: r.Dir}}
	}
	names, err := listDir(r.Dir, maxDirEntries)
	if err != nil {
		c.dirError(r.Dir, err)
		return nil
	}
	slices.Sort(names)
	var out []ruleDir
	for _, n := range names {
		if r.SubDir.MatchString(n) {
			out = append(out, ruleDir{dir: filepath.Join(r.Dir, n, r.SubPath), sub: n})
		}
	}
	return out
}

// dirError records a rule directory the agent may not list; a missing
// directory (the software is not installed) is not reported.
func (c *Collector) dirError(dir string, err error) {
	if errors.Is(err, ErrUnreadable) || errors.Is(err, ErrUnsafeFile) {
		if errors.Is(err, ErrUnreadable) {
			c.unreadableDirs = append(c.unreadableDirs, dir)
		}
		c.report(dir, nil, err)
	}
}

// report logs a source's state when it changes. Only the path and the
// error kind are logged, never content.
func (c *Collector) report(path string, err, problem error) {
	state := ""
	switch {
	case problem != nil:
		state = problem.Error()
	case err != nil && !errors.Is(err, os.ErrNotExist):
		state = err.Error()
	}
	if c.reported[path] == state {
		return
	}
	c.reported[path] = state
	if state == "" {
		c.log.Info("logs: source readable", "path", path)
		return
	}
	c.log.Warn("logs: source not read", "path", path, "error", state)
}

// Unreadable lists the source paths the agent's user may not read (local
// health only; the agent never changes a permission to read more).
func (c *Collector) Unreadable() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.unreadable)
}

func sortedKeys(m map[string]*source) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
