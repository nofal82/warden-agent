package controlplane

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc/resolver"

	"github.com/nofal82/warden-agent/internal/identity"
)

// SetDialer replaces gRPC's TCP dialer, so tests reach an in-process
// bufconn server and never open a socket.
func SetDialer(c *EnrollClient, d func(context.Context, string) (net.Conn, error)) {
	c.dialer = d
}

// Clock is the loop's time source, exported for the fake in loop_test.go.
type Clock = clock

// AttemptFunc is one enrollment attempt.
type AttemptFunc = attemptFunc

// RunLoop is runLoop.
func RunLoop(ctx context.Context, attempt AttemptFunc, c Clock) (identity.Identity, error) {
	return runLoop(ctx, attempt, c)
}

// RealJitter is the production clock's Jitter (crypto/rand).
func RealJitter(d time.Duration) time.Duration {
	return realClock{}.Jitter(d)
}

// DecodeEnrollResponse is the response path after gRPC has delivered the
// raw bytes: size limit, strict decode, field limits, copy.
func DecodeEnrollResponse(b []byte) ([]byte, error) {
	return decodeEnrollResponse(b)
}

// RunEnrollWithClock is RunEnroll with the loop's clock replaced.
func RunEnrollWithClock(ctx context.Context, d *identity.StateDir, in identity.EnrollInput, send identity.EnrollFunc, c Clock) (identity.Identity, error) {
	return runEnroll(ctx, d, in, send, c)
}

// Timings are the stream's durations (stream.go); tests shorten them.
type Timings = timings

// DefaultTimings are the production durations.
var DefaultTimings = defaultTimings

// SetConnectDialer replaces gRPC's TCP dialer of a ConnectClient, so tests
// reach an in-process bufconn server and never open a socket.
func SetConnectDialer(c *ConnectClient, d func(context.Context, string) (net.Conn, error)) {
	c.dialer = d
}

// SetStreamTimings replaces the stream's durations.
func SetStreamTimings(c *ConnectClient, t Timings) { c.t = t }

// SetConnectClock replaces the reconnect loop's clock (Now, Sleep, Jitter).
func SetConnectClock(c *ConnectClient, k Clock) { c.clock = k }

// SetConnectUniform replaces the first reconnect's uniform random delay.
func SetConnectUniform(c *ConnectClient, u func(max time.Duration) time.Duration) { c.uniform = u }

// SetResolver replaces the name resolver of an EnrollClient (passed to
// gRPC as grpc.WithResolvers), so tests control name resolution and never
// query DNS (issue #46).
func SetResolver(c *EnrollClient, b resolver.Builder) { c.resolver = b }

// SetConnectResolver is SetResolver for a ConnectClient.
func SetConnectResolver(c *ConnectClient, b resolver.Builder) { c.resolver = b }

// BaseDialer is the production TCP dialer used when no test dialer is set.
var BaseDialer = baseDialer
