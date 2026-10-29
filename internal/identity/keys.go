package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

// MaxCSRBytes is the CSR limit of §4.4.
const MaxCSRBytes = 4096

// GenerateKey creates a new ECDSA P-256 agent key from crypto/rand (§4.4).
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate P-256 key: %w", err)
	}
	return key, nil
}

// CreateCSR returns the PKCS #10 request (DER) for key's public key. The
// control plane ignores the subject and extensions (R14), so the request
// carries none. It refuses any key that is not P-256.
func CreateCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	if !isP256(key) {
		return nil, ErrInvalidKey
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		// The key is the only input, so a signing failure means a bad key
		// (for example a public point that does not match the scalar).
		return nil, fmt.Errorf("%w: cannot sign a CSR with it", ErrInvalidKey)
	}
	if len(der) > MaxCSRBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrInvalidCSR, len(der))
	}
	return der, nil
}

func isP256(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve == elliptic.P256()
}

// checkCSR applies the §4.4 checks the control plane will apply (size,
// PKCS #10 with nothing after it, P-256 key, valid signature), so the agent
// never sends a request it knows is invalid.
func checkCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > MaxCSRBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrInvalidCSR, len(der))
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrInvalidCSR)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key is not ECDSA P-256", ErrInvalidCSR)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature does not verify", ErrInvalidCSR)
	}
	return csr, nil
}
