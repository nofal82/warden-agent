package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/nofal82/warden-agent/internal/identity"
)

// Enrollment backoff of §4.9 and agent-identity §5.2.
const (
	EnrollBackoffFirst = time.Minute
	EnrollBackoffCap   = time.Hour
	// JitterFraction is the ±20 % jitter.
	JitterFraction = 0.2
)

// clock is the loop's time source; tests replace it (export_test.go).
type clock interface {
	Now() time.Time
	// Sleep waits d or until ctx is done, returning ctx.Err() then.
	Sleep(ctx context.Context, d time.Duration) error
	// Jitter returns d scaled by a uniform factor in [1-JitterFraction,
	// 1+JitterFraction].
	Jitter(d time.Duration) time.Duration
}

// attemptFunc is one enrollment attempt at now.
type attemptFunc func(ctx context.Context, now time.Time) (identity.Identity, error)

// EnrollDelay is the un-jittered delay before retry number n (n ≥ 1):
// EnrollBackoffFirst doubled n-1 times, at most EnrollBackoffCap. n below
// 1 is treated as 1.
func EnrollDelay(n int) time.Duration {
	d := EnrollBackoffFirst
	for i := 1; i < n && d < EnrollBackoffCap; i++ {
		d *= 2
	}
	return min(d, EnrollBackoffCap)
}

// RunEnroll runs enrollment for R18a case 3 (identity.StartEnroll): it
// calls identity.Enroll with send until it succeeds, and retries with the
// same pending key under the §4.9 backoff after every error ActionOf does
// not map to ActionStop. Every wait is jittered, then capped at
// EnrollBackoffCap (Nofal, PR #33). It returns identity.ErrTokenExpired once
// the token has expired (no request is sent then), ErrEnrollStopped wrapping
// the cause of an ActionStop failure, or ctx's error.
func RunEnroll(ctx context.Context, d *identity.StateDir, in identity.EnrollInput, send identity.EnrollFunc) (identity.Identity, error) {
	return runEnroll(ctx, d, in, send, realClock{})
}

func runEnroll(ctx context.Context, d *identity.StateDir, in identity.EnrollInput, send identity.EnrollFunc, c clock) (identity.Identity, error) {
	attempt := func(ctx context.Context, now time.Time) (identity.Identity, error) {
		return identity.Enroll(ctx, d, in, send, now)
	}
	return runLoop(ctx, attempt, c)
}

func runLoop(ctx context.Context, attempt attemptFunc, c clock) (identity.Identity, error) {
	for retry := 1; ; retry++ {
		if err := ctx.Err(); err != nil {
			return identity.Identity{}, err
		}
		id, err := attempt(ctx, c.Now())
		if err == nil {
			return id, nil
		}
		if errors.Is(err, identity.ErrTokenExpired) {
			return identity.Identity{}, err
		}
		if cerr := ctx.Err(); cerr != nil {
			return identity.Identity{}, cerr
		}
		var wait time.Duration
		switch ActionOf(err) {
		case ActionRetry:
			wait = EnrollDelay(retry)
		case ActionRetryLongest:
			wait = EnrollBackoffCap
		default:
			return identity.Identity{}, fmt.Errorf("%w: %w", ErrEnrollStopped, err)
		}
		if err := c.Sleep(ctx, min(c.Jitter(wait), EnrollBackoffCap)); err != nil {
			return identity.Identity{}, err
		}
	}
}

// realClock is the production clock: the system time and crypto/rand
// jitter, so a fleet started together does not retry together.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (realClock) Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	span := uint64(float64(d) * 2 * JitterFraction) // width of [d-20 %, d+20 %]
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	off := binary.LittleEndian.Uint64(b[:]) % (span + 1)
	return d - time.Duration(span/2) + time.Duration(off) // #nosec G115 -- off ≤ span ≤ 0.4·d, within int64
}
