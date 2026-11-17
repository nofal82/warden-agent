package redact_test

// Issue #52 (R36, R49, §7 REDACT_ITEM_DEADLINE, Go reviewer ruling
// 17 Nov 2026): agent log events get AgentItemDeadline (250 ms) per item
// so a scheduling stall on a loaded server does not drop them; intake
// keeps ItemDeadline (50 ms). Exactly at the deadline is kept.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nofal82/warden-agent/internal/redact"
	pubredact "github.com/nofal82/warden-agent/redact"
)

// jumpClock returns t0 on its first call (the item start) and t0+jump on
// every later call, so the whole item appears to take exactly jump.
type jumpClock struct {
	mu    sync.Mutex
	calls int
	jump  time.Duration
}

func (c *jumpClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls == 1 {
		return t0
	}
	return t0.Add(c.jump)
}

func TestRedactLogAgentDeadline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		jump time.Duration
		drop bool
	}{
		{"200ms kept (over intake 50ms)", 200 * time.Millisecond, false},
		{"exactly 250ms kept", pubredact.AgentItemDeadline, false},
		{"250ms+1ns dropped", pubredact.AgentItemDeadline + 1, true},
		{"300ms dropped", 300 * time.Millisecond, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clk := &jumpClock{jump: tc.jump}
			p := redact.New(redact.NewRedactor(pubredact.WithClock(clk.now)), nil)
			before := p.Dropped(pubredact.EText, "TIMEOUT")
			ev, err := p.RedactLog(context.Background(), logIn("[error] upstream timed out"))
			if !tc.drop {
				if err != nil || ev == nil {
					t.Fatalf("RedactLog = (%v, %v), want the event kept", ev != nil, err)
				}
				return
			}
			if err == nil || ev != nil {
				t.Fatalf("RedactLog = (%v, %v), want a drop", ev != nil, err)
			}
			var de *redact.DropError
			if !errors.As(err, &de) || de.Reason != "TIMEOUT" || de.Class != pubredact.EText {
				t.Errorf("err = %v, want DropError{EText, TIMEOUT}", err)
			}
			if got := p.Dropped(pubredact.EText, "TIMEOUT"); got != before+1 {
				t.Errorf("Dropped(EText, TIMEOUT) = %d, want %d", got, before+1)
			}
		})
	}
}

func TestNewRedactorDeadline(t *testing.T) {
	t.Parallel()
	if d := redact.NewRedactor().Deadline(); d != pubredact.AgentItemDeadline {
		t.Errorf("NewRedactor().Deadline() = %v, want AgentItemDeadline", d)
	}
	// The agent deadline is appended last: a caller option cannot lower it.
	r := redact.NewRedactor(pubredact.WithDeadline(pubredact.ItemDeadline))
	if err := r.Err(); err != nil {
		t.Fatalf("Err() = %v", err)
	}
	if d := r.Deadline(); d != pubredact.AgentItemDeadline {
		t.Errorf("NewRedactor(WithDeadline(ItemDeadline)).Deadline() = %v, want AgentItemDeadline", d)
	}
	if d := pubredact.New().Deadline(); d != pubredact.ItemDeadline {
		t.Errorf("pubredact.New().Deadline() = %v, want ItemDeadline (intake)", d)
	}
}

// A bad caller option still fails closed even though the agent deadline is
// appended after it: a later valid option never clears an invalid one (R42).
func TestNewRedactorBadOptionFailsClosed(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{0, pubredact.MaxItemDeadline + 1} {
		if err := redact.NewRedactor(pubredact.WithDeadline(d)).Err(); !errors.Is(err, pubredact.ErrRulesUnavailable) {
			t.Errorf("NewRedactor(WithDeadline(%v)).Err() = %v, want ErrRulesUnavailable", d, err)
		}
	}
}
