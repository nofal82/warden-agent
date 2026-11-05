package controlplane

import (
	"net"
	"net/netip"
	"regexp"

	"github.com/nofal82/warden-agent/internal/identity"
)

// maxEndpointBytes bounds an endpoint before it is parsed: a 253-byte
// name, the brackets of an IPv6 literal, a colon and five port digits.
const maxEndpointBytes = 253 + 2 + 1 + 5

var portRE = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

// Target returns the explicit gRPC target of R2 for an endpoint host:port
// from endpoints.json: passthrough:///<ip>:<port> for an IP literal,
// dns:///<host>:<port> otherwise. Any scheme, path, user part, zone or
// character outside a host name is refused, so the target can never select
// another resolver (unix:, xds:). Errors never echo the input.
func Target(endpoint string) (string, error) {
	if len(endpoint) == 0 || len(endpoint) > maxEndpointBytes {
		return "", endpointErr("length")
	}
	for i := 0; i < len(endpoint); i++ {
		if !endpointByte(endpoint[i]) {
			return "", endpointErr("character not allowed")
		}
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", endpointErr("not host:port")
	}
	if !validPort(port) {
		return "", endpointErr("port")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		bracketed := endpoint[0] == '['
		if addr.Zone() != "" || bracketed != addr.Is6() {
			return "", endpointErr("IP literal")
		}
		return "passthrough:///" + net.JoinHostPort(addr.String(), port), nil
	}
	if endpoint[0] == '[' {
		return "", endpointErr("brackets around a name")
	}
	if err := identity.ValidateServerName(host); err != nil {
		return "", endpointErr("host")
	}
	return "dns:///" + host + ":" + port, nil
}

// endpointByte allows the bytes of a DNS name, an IP literal and a port.
func endpointByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '.' || c == '-' || c == ':' || c == '[' || c == ']'
}

func validPort(p string) bool {
	if !portRE.MatchString(p) {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		n = n*10 + int(p[i]-'0')
	}
	return n <= 65535
}

func endpointErr(what string) error {
	return &endpointError{what: what}
}

type endpointError struct{ what string }

func (e *endpointError) Error() string { return ErrInvalidEndpoint.Error() + ": " + e.what }
func (e *endpointError) Unwrap() error { return ErrInvalidEndpoint }
