package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// MaxTrustedControlPlaneCAs is the R10d bound.
const MaxTrustedControlPlaneCAs = 2

// ClientTLSConfig returns the agent's TLS client configuration of R24 for
// one connection to the control plane.
//
// trustedCAs is the trusted control-plane CA set of R10d (1 or 2 CA
// certificates, already filtered by the keyset; computing it is not done
// here). serverName is `server_name` from endpoints.json, checked with
// ValidateServerName. client is nil on the enrollment endpoint and the
// identity's certificate on the agent endpoint. now supplies the time for
// the VerifyConnection re-verification; nil means time.Now.
//
// The configuration: TLS 1.3 only; RootCAs holds only trustedCAs, never
// the system roots; ServerName is serverName; ClientSessionCache is nil;
// certificate verification is never switched off. Its VerifyConnection (which runs after Go's
// own verification) checks: exactly one presented peer certificate;
// VerifiedChains not empty; every verified chain has length exactly 2, its
// first element is the presented leaf and its second element is byte for
// byte one of trustedCAs; a re-verification
// of the leaf with the key usage set explicitly to serverAuth; the leaf has
// EKU serverAuth only, is not a CA and carries a DNS or IP SAN equal to
// serverName. A failure returns ErrPeerRejected and the handshake fails.
func ClientTLSConfig(trustedCAs []*x509.Certificate, serverName string, client *tls.Certificate, now func() time.Time) (*tls.Config, error) {
	if len(trustedCAs) == 0 || len(trustedCAs) > MaxTrustedControlPlaneCAs {
		return nil, fmt.Errorf("%w: %d control-plane CAs, want 1 to %d", ErrInvalidTrust, len(trustedCAs), MaxTrustedControlPlaneCAs)
	}
	pool := x509.NewCertPool()
	cas := make([]*x509.Certificate, 0, len(trustedCAs))
	for i, ca := range trustedCAs {
		if !isCA(ca) {
			return nil, fmt.Errorf("%w: control-plane CA %d is not a CA certificate", ErrInvalidTrust, i)
		}
		pool.AddCert(ca)
		cas = append(cas, ca)
	}
	if err := ValidateServerName(serverName); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	v := peerVerifier{roots: pool, cas: cas, serverName: serverName, now: now}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		RootCAs:            pool,
		ServerName:         serverName,
		ClientSessionCache: nil, // R24: every connection is a full handshake
		VerifyConnection:   v.verify,
	}
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
	}
	return cfg, nil
}

type peerVerifier struct {
	roots      *x509.CertPool
	cas        []*x509.Certificate
	serverName string
	now        func() time.Time
}

func (v peerVerifier) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) != 1 {
		return peerReject("%d peer certificates presented, want 1", len(cs.PeerCertificates))
	}
	if len(cs.VerifiedChains) == 0 {
		return peerReject("no verified chain")
	}
	leaf := cs.PeerCertificates[0]
	for _, chain := range cs.VerifiedChains {
		if len(chain) != 2 || !bytes.Equal(chain[0].Raw, leaf.Raw) || !v.trusted(chain[1]) {
			return peerReject("chain is not the leaf plus a trusted control-plane CA")
		}
	}
	// Go has already verified for serverAuth; this verifies again with the
	// key usage stated here rather than relied on as a library default.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       v.roots,
		CurrentTime: v.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return peerReject("does not verify for serverAuth")
	}
	if leaf.IsCA || !ekuOnly(leaf, x509.ExtKeyUsageServerAuth) {
		return peerReject("not a serverAuth-only end-entity certificate")
	}
	if !hasExactSAN(leaf, v.serverName) {
		return peerReject("no SAN equal to the server name")
	}
	return nil
}

func (v peerVerifier) trusted(c *x509.Certificate) bool {
	for _, ca := range v.cas {
		if bytes.Equal(c.Raw, ca.Raw) {
			return true
		}
	}
	return false
}

// hasExactSAN reports whether the leaf names serverName exactly: an IP SAN
// equal to an IP literal, or a DNS SAN equal (ignoring ASCII case) to a DNS
// name. Unlike Go's hostname check it accepts no wildcard.
func hasExactSAN(leaf *x509.Certificate, serverName string) bool {
	if addr, err := netip.ParseAddr(serverName); err == nil {
		for _, ip := range leaf.IPAddresses {
			if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap() == addr.Unmap() {
				return true
			}
		}
		return false
	}
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, serverName) {
			return true
		}
	}
	return false
}

func peerReject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrPeerRejected, fmt.Sprintf(format, args...))
}
