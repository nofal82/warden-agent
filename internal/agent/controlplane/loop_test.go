package controlplane_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

func TestEnrollDelay(t *testing.T) {
	t.Parallel()
	cases := []struct {
		n    int
		want time.Duration
	}{
		{math.MinInt, time.Minute},
		{-1, time.Minute},
		{0, time.Minute},
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 16 * time.Minute},
		{6, 32 * time.Minute},
		{7, time.Hour},
		{8, time.Hour},
		{31, time.Hour},
		{32, time.Hour},
		{63, time.Hour},
		{64, time.Hour},
		{65, time.Hour},
		{1 << 40, time.Hour},
		{math.MaxInt, time.Hour},
	}
	for _, tc := range cases {
		if got := controlplane.EnrollDelay(tc.n); got != tc.want {
			t.Errorf("EnrollDelay(%d) = %v, want %v", tc.n, got, tc.want)
		}
	}
	if controlplane.EnrollBackoffFirst != time.Minute || controlplane.EnrollBackoffCap != time.Hour {
		t.Error("§4.9 Enroll backoff constants changed")
	}
	if controlplane.EnrollDeadline != 30*time.Second || controlplane.DialDeadline != 10*time.Second {
		t.Error("R47 deadlines changed")
	}
}

// fakeClock records sleeps and advances Now by them. jitter defaults to
// identity.
type fakeClock struct {
	mu       sync.Mutex
	now      time.Time
	sleeps   []time.Duration
	jitters  []time.Duration
	jitter   func(time.Duration) time.Duration
	onSleep  func(ctx context.Context) error
	sleepErr error
}

var _ controlplane.Clock = (*fakeClock)(nil)

func newFakeClock() *fakeClock { return &fakeClock{now: testNow} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	hook, serr := c.onSleep, c.sleepErr
	c.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	if serr != nil {
		return serr
	}
	return ctx.Err()
}

func (c *fakeClock) Jitter(d time.Duration) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.jitters = append(c.jitters, d)
	if c.jitter != nil {
		return c.jitter(d)
	}
	return d
}

// script returns an attempt that yields errs in order, then success. It
// records the now of every attempt.
type script struct {
	errs  []error
	nows  []time.Time
	calls int
}

func (s *script) attempt(_ context.Context, now time.Time) (identity.Identity, error) {
	s.calls++
	s.nows = append(s.nows, now)
	if s.calls <= len(s.errs) {
		return identity.Identity{}, s.errs[s.calls-1]
	}
	return identity.Identity{}, nil
}

func retryErr() error {
	return fmt.Errorf("identity: enroll: %w", &controlplane.StatusError{
		Code: codes.PermissionDenied, Reason: agentapiv1.EndReason_END_REASON_ENROLLMENT_REFUSED, HasDetail: true,
	})
}

func TestRunLoopSuccessFirstTry(t *testing.T) {
	t.Parallel()
	c, s := newFakeClock(), &script{}
	if _, err := controlplane.RunLoop(context.Background(), s.attempt, c); err != nil {
		t.Fatal(err)
	}
	if s.calls != 1 || len(c.sleeps) != 0 {
		t.Fatalf("calls %d sleeps %v", s.calls, c.sleeps)
	}
	if !s.nows[0].Equal(testNow) {
		t.Errorf("attempt got now %v, want the clock's %v", s.nows[0], testNow)
	}
}

func TestRunLoopTokenExpired(t *testing.T) {
	t.Parallel()
	for _, e := range []error{identity.ErrTokenExpired, fmt.Errorf("wrapped: %w", identity.ErrTokenExpired)} {
		c, s := newFakeClock(), &script{errs: []error{e, e, e}}
		_, err := controlplane.RunLoop(context.Background(), s.attempt, c)
		if !errors.Is(err, identity.ErrTokenExpired) {
			t.Fatalf("err = %v, want ErrTokenExpired", err)
		}
		if s.calls != 1 || len(c.sleeps) != 0 {
			t.Fatalf("calls %d sleeps %v", s.calls, c.sleeps)
		}
	}
}

// TestRunLoopTokenExpiresAfterRetries: retries until the attempt reports
// the token expired, then stops at once.
func TestRunLoopTokenExpiresAfterRetries(t *testing.T) {
	t.Parallel()
	c := newFakeClock()
	s := &script{errs: []error{retryErr(), retryErr(), identity.ErrTokenExpired, retryErr()}}
	_, err := controlplane.RunLoop(context.Background(), s.attempt, c)
	if !errors.Is(err, identity.ErrTokenExpired) || s.calls != 3 || len(c.sleeps) != 2 {
		t.Fatalf("err %v calls %d sleeps %v", err, s.calls, c.sleeps)
	}
}

func TestRunLoopBackoffSequence(t *testing.T) {
	t.Parallel()
	errs := []error{
		retryErr(),
		controlplane.ErrNotConnected,
		fmt.Errorf("identity: enroll: %w", controlplane.ErrResponseRefused),
		retryErr(), retryErr(), retryErr(), retryErr(), retryErr(), retryErr(),
	}
	c, s := newFakeClock(), &script{errs: errs}
	if _, err := controlplane.RunLoop(context.Background(), s.attempt, c); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{
		time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, time.Hour, time.Hour, time.Hour,
	}
	if fmt.Sprint(c.sleeps) != fmt.Sprint(want) {
		t.Fatalf("sleeps %v, want %v", c.sleeps, want)
	}
	if fmt.Sprint(c.jitters) != fmt.Sprint(want) {
		t.Fatalf("jitter inputs %v, want %v", c.jitters, want)
	}
	if s.calls != len(errs)+1 {
		t.Fatalf("calls %d", s.calls)
	}
	// Each attempt's now comes from the clock, after the previous sleeps.
	at := testNow
	for i, now := range s.nows {
		if !now.Equal(at) {
			t.Fatalf("attempt %d now %v, want %v", i, now, at)
		}
		if i < len(want) {
			at = at.Add(want[i])
		}
	}
}

// TestRunLoopSleepsJittered: the loop sleeps the jittered delay, not the
// raw one.
func TestRunLoopSleepsJittered(t *testing.T) {
	t.Parallel()
	c := newFakeClock()
	c.jitter = func(d time.Duration) time.Duration { return d*8/10 + 7 }
	s := &script{errs: []error{retryErr(), retryErr()}}
	if _, err := controlplane.RunLoop(context.Background(), s.attempt, c); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Minute*8/10 + 7, 2*time.Minute*8/10 + 7}
	if fmt.Sprint(c.sleeps) != fmt.Sprint(want) {
		t.Fatalf("sleeps %v, want %v", c.sleeps, want)
	}
}

func TestRunLoopRetryLongest(t *testing.T) {
	t.Parallel()
	for _, e := range []error{
		&controlplane.StatusError{Code: codes.Internal},
		&controlplane.StatusError{Code: codes.Unknown},
		&controlplane.StatusError{Code: codes.ResourceExhausted, HasDetail: true},
		fmt.Errorf("identity: enroll: %w", &controlplane.StatusError{Code: codes.Code(99)}),
	} {
		c, s := newFakeClock(), &script{errs: []error{e}}
		if _, err := controlplane.RunLoop(context.Background(), s.attempt, c); err != nil {
			t.Fatal(err)
		}
		if len(c.sleeps) != 1 || c.sleeps[0] != controlplane.EnrollBackoffCap {
			t.Fatalf("%v: sleeps %v, want [1h]", e, c.sleeps)
		}
		if len(c.jitters) != 1 || c.jitters[0] != controlplane.EnrollBackoffCap {
			t.Fatalf("%v: jitter inputs %v", e, c.jitters)
		}
	}
}

func TestRunLoopStop(t *testing.T) {
	t.Parallel()
	for _, e := range []error{
		errors.New("local failure"),
		identity.ErrCertificateRejected,
		fmt.Errorf("identity: enroll: %w", &controlplane.StatusError{Code: codes.Unimplemented}),
		fmt.Errorf("identity: enroll: %w", &controlplane.StatusError{Code: codes.InvalidArgument}),
		&controlplane.StatusError{Code: codes.ResourceExhausted},
	} {
		c, s := newFakeClock(), &script{errs: []error{e, e}}
		_, err := controlplane.RunLoop(context.Background(), s.attempt, c)
		if !errors.Is(err, e) {
			t.Fatalf("err = %v, want %v", err, e)
		}
		if s.calls != 1 || len(c.sleeps) != 0 {
			t.Fatalf("%v: calls %d sleeps %v", e, s.calls, c.sleeps)
		}
	}
}

func TestRunLoopCancelDuringSleep(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeClock()
	c.onSleep = func(ctx context.Context) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	s := &script{errs: []error{retryErr(), retryErr()}}
	_, err := controlplane.RunLoop(ctx, s.attempt, c)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if s.calls != 1 {
		t.Fatalf("%d attempts after cancel", s.calls)
	}
}

func TestRunLoopCancelledBefore(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newFakeClock()
	s := &script{errs: []error{retryErr(), retryErr(), retryErr()}}
	_, err := controlplane.RunLoop(ctx, s.attempt, c)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if s.calls > 1 || len(c.sleeps) > 1 {
		t.Fatalf("calls %d sleeps %v with a cancelled context", s.calls, c.sleeps)
	}
}

// TestRunLoopCancelledAttempt: the attempt itself sees the cancellation;
// the loop returns without sleeping again.
func TestRunLoopCancelledAttempt(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	c := newFakeClock()
	calls := 0
	attempt := func(context.Context, time.Time) (identity.Identity, error) {
		calls++
		cancel()
		return identity.Identity{}, retryErr()
	}
	_, err := controlplane.RunLoop(ctx, attempt, c)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Fatalf("%d attempts", calls)
	}
}

func TestRunLoopSleepError(t *testing.T) {
	t.Parallel()
	boom := errors.New("sleep failed")
	c := newFakeClock()
	c.sleepErr = boom
	s := &script{errs: []error{retryErr(), retryErr()}}
	_, err := controlplane.RunLoop(context.Background(), s.attempt, c)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the sleep error", err)
	}
	if s.calls != 1 {
		t.Fatalf("%d attempts", s.calls)
	}
}

func TestRealJitter(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{time.Minute, time.Hour, controlplane.EnrollBackoffCap} {
		lo := time.Duration(float64(d) * (1 - controlplane.JitterFraction))
		hi := time.Duration(float64(d) * (1 + controlplane.JitterFraction))
		seen := map[time.Duration]bool{}
		var below, above int
		for range 10000 {
			j := controlplane.RealJitter(d)
			if j < lo || j > hi {
				t.Fatalf("Jitter(%v) = %v outside [%v, %v]", d, j, lo, hi)
			}
			seen[j] = true
			if j < d {
				below++
			} else if j > d {
				above++
			}
		}
		if len(seen) < 1000 {
			t.Errorf("Jitter(%v): only %d distinct values in 10000", d, len(seen))
		}
		// Uniform on both sides: each side well above a third.
		if below < 3000 || above < 3000 {
			t.Errorf("Jitter(%v): %d below, %d above", d, below, above)
		}
	}
	if j := controlplane.RealJitter(0); j != 0 {
		t.Errorf("Jitter(0) = %v", j)
	}
}
