package controlplane

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"

	"google.golang.org/grpc/credentials"
)

// DialClass is the coarse reason a connection never became READY. It is
// what the agent logs for a failed attempt (issue #46), so an operator
// can tell a wrong name from a firewall from a wrong CA without the
// underlying error text, which may carry peer-chosen bytes.
type DialClass string

// Dial classes.
const (
	DialDNS     DialClass = "dns"     // name resolution produced no address
	DialRefused DialClass = "refused" // TCP connection refused
	DialTimeout DialClass = "timeout" // dial deadline (R47) or a network timeout
	DialTLS     DialClass = "tls"     // TLS handshake failed
	DialOther   DialClass = "other"   // any other network error
)

// DialError is returned when no ready connection was made. It unwraps to
// ErrNotConnected, so retry decisions (ActionOf, EndActionOf) are
// unchanged.
type DialError struct {
	// Endpoint is the host:port of endpoints.json, already checked by
	// Target, so it is safe to log.
	Endpoint string
	Class    DialClass
}

// Error never includes the underlying error: a resolver, dialer or TLS
// message can hold a certificate subject or other peer-chosen text.
func (e *DialError) Error() string {
	return ErrNotConnected.Error() + ": " + e.Endpoint + ": " + string(e.Class)
}

// Unwrap returns ErrNotConnected.
func (e *DialError) Unwrap() error { return ErrNotConnected }

// dialProbe records the class of the first failure inside one connection
// attempt. gRPC reports only a connectivity state, so the dialer and the
// TLS handshake are wrapped to see the cause. It is written from gRPC's
// goroutines, hence the mutex.
type dialProbe struct {
	mu     sync.Mutex
	class  DialClass
	dialed bool
}

func (p *dialProbe) record(c DialClass) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.class == "" {
		p.class = c
	}
}

func (p *dialProbe) markDialed() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialed = true
}

// result is the class for an attempt that failed: deadline reports
// whether the dial deadline expired rather than gRPC giving up. When the
// dialer was never called, the resolver produced no address.
func (p *dialProbe) result(endpoint string, deadline bool) *DialError {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.class
	switch {
	case c != "":
	case deadline:
		c = DialTimeout
	case !p.dialed:
		c = DialDNS
	default:
		c = DialOther
	}
	return &DialError{Endpoint: endpoint, Class: c}
}

// dialer wraps base (gRPC's plain TCP dial when nil) to record failures.
func (p *dialProbe) dialer(base func(context.Context, string) (net.Conn, error)) func(context.Context, string) (net.Conn, error) {
	if base == nil {
		var d net.Dialer
		base = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		p.markDialed()
		conn, err := base(ctx, addr)
		if err != nil {
			p.record(netClass(err))
		}
		return conn, err
	}
}

// netClass classifies a dial error.
func netClass(err error) DialClass {
	var dnsErr *net.DNSError
	var ne net.Error
	switch {
	case errors.As(err, &dnsErr):
		return DialDNS
	case errors.Is(err, syscall.ECONNREFUSED):
		return DialRefused
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return DialTimeout
	}
	return DialOther
}

// probeCreds records a failed client handshake as DialTLS (a timeout
// inside the handshake as DialTimeout). Everything else is the wrapped
// credentials' own behaviour.
type probeCreds struct {
	credentials.TransportCredentials
	p *dialProbe
}

func (c probeCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
			c.p.record(DialTimeout)
		} else {
			c.p.record(DialTLS)
		}
	}
	return conn, info, err
}

func (c probeCreds) Clone() credentials.TransportCredentials {
	return probeCreds{TransportCredentials: c.TransportCredentials.Clone(), p: c.p}
}
