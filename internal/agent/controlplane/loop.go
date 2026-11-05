package controlplane

import (
	"context"
	"errors"
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
// EnrollBackoffFirst doubled n-1 times, at most EnrollBackoffCap.
func EnrollDelay(n int) time.Duration {
	return 0
}

// RunEnroll runs enrollment for R18a case 3 (identity.StartEnroll): it
// calls identity.Enroll with send until it succeeds, and retries with the
// same pending key under the §4.9 backoff after every error ActionOf does
// not map to ActionStop. It returns identity.ErrTokenExpired once the
// token has expired (no request is sent then), the error of an ActionStop
// failure, or ctx's error.
func RunEnroll(ctx context.Context, d *identity.StateDir, in identity.EnrollInput, send identity.EnrollFunc) (identity.Identity, error) {
	return identity.Identity{}, errors.ErrUnsupported
}

func runLoop(ctx context.Context, attempt attemptFunc, c clock) (identity.Identity, error) {
	return identity.Identity{}, errors.ErrUnsupported
}
