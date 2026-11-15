package logs_test

import (
	"os"
	"testing"
)

// R9a: a start that finds the busy marker of a process that stopped while
// redacting counts the restart once and removes the marker; a clean poll
// leaves no marker behind.
func TestCollectorCountsCrashRestart(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.nginxLog, "")
	c := e.collector(t)
	if c.RestartsSkipped() != 0 {
		t.Fatal("restart counted without a marker")
	}
	c.PollOnce(pollCtx(t))
	appendFile(t, e.nginxLog, nginxErr("one"))
	c.PollOnce(pollCtx(t))
	if _, err := os.Lstat(e.state + ".busy"); !os.IsNotExist(err) {
		t.Fatalf("busy marker left after a clean poll: %v", err)
	}
	writeFile(t, e.state+".busy", "")
	c2 := e.collector(t)
	if c2.RestartsSkipped() != 1 {
		t.Errorf("RestartsSkipped = %d, want 1", c2.RestartsSkipped())
	}
	if _, err := os.Lstat(e.state + ".busy"); !os.IsNotExist(err) {
		t.Error("marker not removed at start")
	}
}
