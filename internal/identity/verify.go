package identity

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// MaxCertificateBytes is the DER limit of an issued leaf (§4.5).
const MaxCertificateBytes = 4096

// MaxSkew is the spec's MAX_SKEW (action-envelope R16, OQ2): the clock
// difference R15 tolerates on each end of the issued certificate's
// validity, so small drift between server and control plane never blocks
// enrollment. Added to R15 by Nofal on 2026-10-30 (PR #29).
const MaxSkew = 60 * time.Second

var (
	oidCN             = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// uriSANTag is the context-specific tag of uniformResourceIdentifier in
// GeneralName (RFC 5280 §4.2.1.6).
const uriSANTag = 6

// VerifiedIdentity is a private key and a certificate that passed R15.
// It can only be produced by VerifyIssued, so StateDir.WriteIdentity can
// never store an unchecked pair.
type VerifiedIdentity struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// Certificate returns the verified leaf.
func (v VerifiedIdentity) Certificate() *x509.Certificate { return v.cert }

// TLSCertificate returns the pair as a client certificate for the agent
// endpoint.
func (v VerifiedIdentity) TLSCertificate() tls.Certificate {
	if v.key == nil || v.cert == nil {
		return tls.Certificate{} // zero value: not a usable identity
	}
	return tls.Certificate{
		Certificate: [][]byte{v.cert.Raw},
		PrivateKey:  v.key,
		Leaf:        v.cert,
	}
}

// VerifyIssued applies R15 to the certificate an enrollment returned. It
// accepts certDER only when all of these hold:
//   - it is one DER certificate of at most 4 KiB with no trailing data;
//   - its subject is exactly CN=<serverID>, and its only SAN is exactly one
//     URI, urn:uuid:<serverID> (no DNS, IP or e-mail SAN) (§4.1, §4.4);
//   - its public key equals key's public key;
//   - it is signed directly by agentCA (chain of length 2, no
//     intermediate), agentCA is a CA certificate, the leaf is not a CA, its
//     extended key usage is clientAuth only;
//   - now is within its validity widened by MaxSkew on both sides; outside
//     that the error is also ErrClockSkew.
//
// On any failure it returns ErrCertificateRejected; the caller discards
// the certificate and never adopts a UUID from it.
func VerifyIssued(certDER []byte, serverID string, key *ecdsa.PrivateKey, agentCA *x509.Certificate, now time.Time) (VerifiedIdentity, error) {
	if err := ValidateServerID(serverID); err != nil {
		return VerifiedIdentity{}, fmt.Errorf("%w: %w", ErrCertificateRejected, err)
	}
	if !isP256(key) {
		return VerifiedIdentity{}, fmt.Errorf("%w: %w", ErrCertificateRejected, ErrInvalidKey)
	}
	if !isCA(agentCA) {
		return VerifiedIdentity{}, fmt.Errorf("%w: %w: agent CA is not a CA certificate", ErrCertificateRejected, ErrInvalidTrust)
	}
	if len(certDER) == 0 || len(certDER) > MaxCertificateBytes {
		return VerifiedIdentity{}, reject("size %d bytes", len(certDER))
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return VerifiedIdentity{}, reject("does not parse")
	}
	if err := checkSubject(cert, serverID); err != nil {
		return VerifiedIdentity{}, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return VerifiedIdentity{}, reject("public key is not the pending key")
	}
	if cert.IsCA || !ekuOnly(cert, x509.ExtKeyUsageClientAuth) {
		return VerifiedIdentity{}, reject("not a clientAuth-only end-entity certificate")
	}
	at, err := withinSkew(cert, now)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(agentCA)
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return VerifiedIdentity{}, reject("does not verify against the agent CA")
	}
	for _, c := range chains {
		if len(c) != 2 || !c[1].Equal(agentCA) {
			return VerifiedIdentity{}, reject("not signed directly by the agent CA")
		}
	}
	return VerifiedIdentity{key: key, cert: cert}, nil
}

// withinSkew refuses with ErrClockSkew when now is more than MaxSkew
// outside the leaf's validity. Otherwise it returns now moved into the
// validity window, the time the chain is then verified at, so a drift the
// tolerance allows never fails the chain check.
func withinSkew(cert *x509.Certificate, now time.Time) (time.Time, error) {
	if now.Before(cert.NotBefore.Add(-MaxSkew)) || now.After(cert.NotAfter.Add(MaxSkew)) {
		return time.Time{}, fmt.Errorf("%w: %w (valid %s to %s, server clock %s, tolerance %s)",
			ErrCertificateRejected, ErrClockSkew,
			cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339),
			now.UTC().Format(time.RFC3339), MaxSkew)
	}
	switch {
	case now.Before(cert.NotBefore):
		return cert.NotBefore, nil
	case now.After(cert.NotAfter):
		return cert.NotAfter, nil
	}
	return now, nil
}

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCertificateRejected, fmt.Sprintf(format, args...))
}

// checkSubject requires the §4.1 certificate link: subject exactly
// CN=<uuid> and exactly one SAN, the URI urn:uuid:<uuid>. It reads the raw
// encodings, because the parsed fields drop attributes and SAN types the
// Go library does not model.
func checkSubject(cert *x509.Certificate, serverID string) error {
	var subject pkix.RDNSequence
	rest, err := asn1.Unmarshal(cert.RawSubject, &subject)
	if err != nil || len(rest) != 0 || len(subject) != 1 || len(subject[0]) != 1 {
		return reject("subject is not exactly one CN")
	}
	cn := subject[0][0]
	if !cn.Type.Equal(oidCN) {
		return reject("subject is not exactly one CN")
	}
	if s, ok := cn.Value.(string); !ok || s != serverID {
		return reject("CN does not name this server")
	}
	uri, err := onlyURISAN(cert)
	if err != nil {
		return err
	}
	if uri != "urn:uuid:"+serverID {
		return reject("SAN does not name this server")
	}
	return nil
}

// onlyURISAN returns the single URI SAN, refusing a certificate with no SAN
// extension, more than one, or any GeneralName other than one URI.
func onlyURISAN(cert *x509.Certificate) (string, error) {
	var found []byte
	n := 0
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			found = ext.Value
			n++
		}
	}
	if n != 1 {
		return "", reject("want exactly one SAN extension, have %d", n)
	}
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(found, &seq)
	if err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return "", reject("SAN extension does not parse")
	}
	var name asn1.RawValue
	rest, err = asn1.Unmarshal(seq.Bytes, &name)
	if err != nil || len(rest) != 0 {
		return "", reject("want exactly one SAN")
	}
	if name.Class != asn1.ClassContextSpecific || name.Tag != uriSANTag || name.IsCompound {
		return "", reject("SAN is not a URI")
	}
	return string(name.Bytes), nil
}

func isCA(c *x509.Certificate) bool {
	return c != nil && c.BasicConstraintsValid && c.IsCA
}

// ekuOnly reports whether the certificate's extended key usage is exactly
// want, with no unknown usage alongside it.
func ekuOnly(c *x509.Certificate, want x509.ExtKeyUsage) bool {
	return len(c.ExtKeyUsage) == 1 && c.ExtKeyUsage[0] == want && len(c.UnknownExtKeyUsage) == 0
}
