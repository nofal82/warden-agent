package redact_test

// Issue #50: every drop returns a typed *DropError (class and R41 reason)
// that wraps ErrDropped, so a caller can count and report drops without
// parsing error text. The error never carries item content (R4).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nofal82/warden-agent/internal/redact"
	pubredact "github.com/nofal82/warden-agent/redact"
)

func TestRedactLogDropError(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	fixed := func() time.Time { return t0 }

	cases := []struct {
		name   string
		pipe   func(t *testing.T) *redact.Pipeline
		ctx    context.Context
		in     func(secret, nonce string) redact.LogInput
		class  pubredact.Class
		reason string
	}{
		{
			name:   "RULES_UNAVAILABLE nil redactor",
			pipe:   func(*testing.T) *redact.Pipeline { return redact.New(nil, nil) },
			in:     func(s, n string) redact.LogInput { return logIn("[error] " + n + " key " + s) },
			class:  pubredact.EText,
			reason: "RULES_UNAVAILABLE",
		},
		{
			name: "ERROR bad rule id",
			pipe: func(t *testing.T) *redact.Pipeline { return newPipeline(t) },
			in: func(s, n string) redact.LogInput {
				in := logIn("[error] " + n + " key " + s)
				in.RuleID = "BAD;" + n
				return in
			},
			class:  pubredact.EText,
			reason: "ERROR",
		},
		{
			name: "ERROR invalid unit id",
			pipe: func(t *testing.T) *redact.Pipeline { return newPipeline(t) },
			in: func(s, n string) redact.LogInput {
				in := logIn("[error] " + n + " key " + s)
				in.UnitID = "../" + n + ";" + s + ".service"
				return in
			},
			class:  pubredact.NPatterned,
			reason: "ERROR",
		},
		{
			name:   "TIMEOUT cancelled context",
			pipe:   func(t *testing.T) *redact.Pipeline { return newPipeline(t) },
			ctx:    cancelled,
			in:     func(s, n string) redact.LogInput { return logIn("[error] " + n + " key " + s) },
			class:  pubredact.EText,
			reason: "TIMEOUT",
		},
		{
			name: "TIMEOUT clock jumps past ItemDeadline mid-pass",
			pipe: func(*testing.T) *redact.Pipeline {
				clk := &stepClock{t: t0, step: 2 * pubredact.ItemDeadline}
				return redact.New(pubredact.New(pubredact.WithClock(clk.now)), nil)
			},
			in:     func(s, n string) redact.LogInput { return logIn("[error] " + n + " key " + s) },
			class:  pubredact.EText,
			reason: "TIMEOUT",
		},
		{
			name: "BUDGET minute budget used up",
			pipe: func(t *testing.T) *redact.Pipeline {
				p := redact.New(pubredact.New(pubredact.WithClock(fixed)), nil, redact.WithClock(fixed))
				// One oversized line spends the whole minute (it is replaced
				// by the fixed LINE DROPPED text, not dropped).
				if _, err := p.RedactLog(context.Background(), logIn(strings.Repeat("x", redact.BytesPerMinute))); err != nil {
					t.Fatalf("budget pre-spend dropped: %v", err)
				}
				return p
			},
			in:     func(s, n string) redact.LogInput { return logIn("[error] " + n + " key " + s) },
			class:  pubredact.EText,
			reason: "BUDGET",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := tc.pipe(t)
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			secret, nonce := akia(), "n"+randFrom(alphaAlnum, 23)
			before := p.Dropped(tc.class, tc.reason)
			ev, err := p.RedactLog(ctx, tc.in(secret, nonce))
			if err == nil || ev != nil {
				t.Fatalf("RedactLog = (%v, %v), want a drop", ev != nil, err)
			}
			if !errors.Is(err, redact.ErrDropped) {
				t.Errorf("errors.Is(err, ErrDropped) = false")
			}
			var de *redact.DropError
			if !errors.As(err, &de) {
				t.Fatalf("errors.As(err, *DropError) = false; err type %T", err)
			}
			if de.Class != tc.class || de.Reason != tc.reason {
				t.Errorf("DropError = {%d, %q}, want {%d, %q}", de.Class, de.Reason, tc.class, tc.reason)
			}
			want := fmt.Sprintf("redact: item dropped: class %d, %s", tc.class, tc.reason)
			if got := err.Error(); got != want {
				t.Errorf("Error() = %q, want %q", got, want)
			}
			if de.Unwrap() != redact.ErrDropped { //nolint:errorlint // Unwrap must return the sentinel itself
				t.Error("Unwrap() is not ErrDropped")
			}
			for i, s := range []string{secret, nonce} {
				if leakFound(err.Error(), s) || strings.Contains(err.Error(), s) {
					t.Errorf("error text carries input part %d (R4)", i)
				}
			}
			if got := p.Dropped(tc.class, tc.reason) - before; got != 1 {
				t.Errorf("Dropped(%d, %s) rose by %d, want 1", tc.class, tc.reason, got)
			}
		})
	}
}

// A redacted item returns a nil error, not a typed nil *DropError.
func TestRedactLogSuccessNilError(t *testing.T) {
	t.Parallel()
	ev, err := newPipeline(t).RedactLog(context.Background(), logIn("[error] upstream timed out"))
	if err != nil || ev == nil {
		t.Fatalf("RedactLog = (%v, %v), want an event and nil error", ev, err)
	}
	var de *redact.DropError
	if errors.As(err, &de) {
		t.Error("errors.As found a *DropError on success")
	}
}
