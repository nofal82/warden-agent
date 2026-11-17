package redact

// Issue #52 (R36, R49, §7 REDACT_ITEM_DEADLINE, Go reviewer ruling
// 17 Nov 2026): agent log events get 250 ms per item, intake keeps 50 ms.
// The deadline is a bounded option; out of range fails closed.

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestDeadlineConstants(t *testing.T) {
	t.Parallel()
	if ItemDeadline != 50*time.Millisecond {
		t.Errorf("ItemDeadline = %v, want 50ms (intake)", ItemDeadline)
	}
	if AgentItemDeadline != 250*time.Millisecond {
		t.Errorf("AgentItemDeadline = %v, want 250ms", AgentItemDeadline)
	}
	if MinItemDeadline != ItemDeadline || MaxItemDeadline != AgentItemDeadline {
		t.Errorf("bounds = [%v, %v], want [50ms, 250ms]", MinItemDeadline, MaxItemDeadline)
	}
	// The plain-build timing gates must keep proving the 50 ms cost bound,
	// not the larger agent scheduling budget.
	if timingGateBound != 50*time.Millisecond {
		t.Errorf("timingGateBound = %v, want 50ms", timingGateBound)
	}
	if timingGateBound != ItemDeadline {
		t.Errorf("timingGateBound = %v, want ItemDeadline %v", timingGateBound, ItemDeadline)
	}
	if timingGateBound == AgentItemDeadline {
		t.Errorf("timingGateBound equals AgentItemDeadline: the timing gates were loosened")
	}
	if d := New().Deadline(); d != ItemDeadline {
		t.Errorf("New().Deadline() = %v, want ItemDeadline (intake default)", d)
	}
}

func TestWithDeadlineBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		d    time.Duration
		ok   bool
	}{
		{"min", MinItemDeadline, true},
		{"agent", AgentItemDeadline, true},
		{"max", MaxItemDeadline, true},
		{"min-1ns", MinItemDeadline - 1, false},
		{"max+1ns", MaxItemDeadline + 1, false},
		{"zero", 0, false},
		{"negative", -1, false},
		{"MinInt64", math.MinInt64, false},
		{"MaxInt64", math.MaxInt64, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := checkDeadline(tc.d); (err == nil) != tc.ok {
				t.Errorf("checkDeadline(%v) = %v, want ok %v", tc.d, err, tc.ok)
			}
			r := New(WithClock(frozenClock), WithDeadline(tc.d))
			if tc.ok {
				if err := r.Err(); err != nil {
					t.Fatalf("Err() = %v, want nil", err)
				}
				if r.Deadline() != tc.d {
					t.Errorf("Deadline() = %v, want %v", r.Deadline(), tc.d)
				}
				return
			}
			if err := r.Err(); !errors.Is(err, ErrRulesUnavailable) {
				t.Errorf("Err() = %v, want ErrRulesUnavailable", err)
			}
			out, _, err := r.Redact(bg, fieldFor(EText), "[error] plain text", nil)
			if !errors.Is(err, ErrRulesUnavailable) || out != "" {
				t.Errorf("Redact = (%q, %v), want (\"\", ErrRulesUnavailable)", out, err)
			}
		})
	}
}

// TestDigestExcludesDeadline: the per-item deadline is a scheduling bound,
// not a rule, so the agent and intake share one rules digest (§4.5 digest
// row as amended).
func TestDigestExcludesDeadline(t *testing.T) {
	t.Parallel()
	table := canonicalRuleTable(ruleTable())
	v := fmt.Sprint(MaxEventInput, MaxLine)
	want := fmt.Sprintf("\nlimits=%d:%s\n", len(v), v)
	if !strings.Contains(table, want) {
		t.Errorf("canonical table has no %q field", strings.TrimSpace(want))
	}
	for _, d := range []time.Duration{ItemDeadline, AgentItemDeadline} {
		for _, s := range []string{d.String(), fmt.Sprint(int64(d))} {
			if strings.Contains(table, s) {
				t.Errorf("canonical table contains the deadline rendering %q", s)
			}
		}
	}
}
