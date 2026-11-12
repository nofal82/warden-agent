package logs_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Security review HIGH (issue #44): a service user that owns its log
// directory creates many matching files and fills them. The collector
// tails at most 8 files per rule and reads at most 1 MiB per poll across
// all sources, so raw lines held before redaction stay bounded.
func TestCollectorBoundsManySources(t *testing.T) {
	e := newEnv(t)
	for i := 10; i < 30; i++ {
		writeFile(t, filepath.Join(e.pg, fmt.Sprintf("postgresql-%d-main.log", i)), "")
	}
	c := e.collector(t)
	c.PollOnce(pollCtx(t))                                      // first start: positions at the end
	big := strings.Repeat(pgErr(strings.Repeat("x", 900)), 400) // about 380 KiB per file
	units := map[string]bool{}
	for i := 10; i < 30; i++ {
		appendFile(t, filepath.Join(e.pg, fmt.Sprintf("postgresql-%d-main.log", i)), big)
	}
	c.PollOnce(pollCtx(t))
	evs := e.sink.take()
	read := 0
	for _, ev := range evs {
		units[ev.GetUnitId()] = true
		read += 1000
	}
	if len(units) > 8 {
		t.Errorf("events from %d files of one rule, want at most 8", len(units))
	}
	if read > (1<<20)+64<<10 {
		t.Errorf("about %d bytes of lines handled in one poll, want at most 1 MiB", read)
	}
	if len(evs) == 0 {
		t.Error("no events at all")
	}
}
