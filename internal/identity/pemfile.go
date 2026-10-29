package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PEM block types of the state files (§4.7).
const (
	pemTypePrivateKey  = "PRIVATE KEY"
	pemTypeCertificate = "CERTIFICATE"
	pemTypeTokenHash   = "WARDEN ENROLL TOKEN SHA256"
)

// EncodePendingEnrollKey encodes enroll.pending-key.pem (§4.7, R12a): a
// PKCS #8 "PRIVATE KEY" PEM block followed by a "WARDEN ENROLL TOKEN
// SHA256" PEM block holding the 32-byte SHA-256 of the token the key was
// generated for, and nothing else.
func EncodePendingEnrollKey(key *ecdsa.PrivateKey, tokenHash [sha256.Size]byte) ([]byte, error) {
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	return append(keyPEM, pem.EncodeToMemory(&pem.Block{Type: pemTypeTokenHash, Bytes: tokenHash[:]})...), nil
}

// DecodePendingEnrollKey parses what EncodePendingEnrollKey wrote, strictly:
// exactly those two blocks in that order, no PEM headers, no other data, a
// P-256 key and a 32-byte hash. Anything else is ErrMalformedFile.
func DecodePendingEnrollKey(data []byte) (*ecdsa.PrivateKey, [sha256.Size]byte, error) {
	var hash [sha256.Size]byte
	blocks, err := decodeExact(data, pemTypePrivateKey, pemTypeTokenHash)
	if err != nil {
		return nil, hash, err
	}
	key, err := parseKey(blocks[0].Bytes)
	if err != nil {
		return nil, hash, err
	}
	if len(blocks[1].Bytes) != sha256.Size {
		return nil, hash, fmt.Errorf("%w: token hash is %d bytes", ErrMalformedFile, len(blocks[1].Bytes))
	}
	copy(hash[:], blocks[1].Bytes)
	return key, hash, nil
}

// DecodeIdentity parses identity.pem (§4.7) strictly: exactly one PKCS #8
// "PRIVATE KEY" block followed by one "CERTIFICATE" block, no PEM headers,
// no other data, a P-256 key whose public key is the certificate's. It does
// not check the certificate's validity or names; the caller decides what a
// loaded identity must satisfy (R18a).
func DecodeIdentity(data []byte) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	blocks, err := decodeExact(data, pemTypePrivateKey, pemTypeCertificate)
	if err != nil {
		return nil, nil, err
	}
	key, err := parseKey(blocks[0].Bytes)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: certificate does not parse", ErrMalformedFile)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, fmt.Errorf("%w: key does not match the certificate", ErrMalformedFile)
	}
	return key, cert, nil
}

func encodeIdentity(key *ecdsa.PrivateKey, certDER []byte) ([]byte, error) {
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	return append(keyPEM, pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: certDER})...), nil
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	if !isP256(key) {
		return nil, ErrInvalidKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("identity: encode key: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der})
	clear(der) // best effort: the key stays in memory elsewhere anyway
	return out, nil
}

func parseKey(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: key is not PKCS #8", ErrMalformedFile)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !isP256(key) {
		return nil, fmt.Errorf("%w: key is not ECDSA P-256", ErrMalformedFile)
	}
	// ParsePKCS8PrivateKey accepts bytes after the key; only the exact
	// encoding this package writes is accepted.
	again, err := x509.MarshalPKCS8PrivateKey(key)
	same := err == nil && bytes.Equal(again, der)
	clear(again)
	if !same {
		return nil, fmt.Errorf("%w: key is not in canonical PKCS #8 form", ErrMalformedFile)
	}
	return key, nil
}

// decodeExact decodes exactly the PEM blocks of the given types, in order,
// and accepts data only when it is byte for byte the canonical encoding of
// those blocks. pem.Decode alone would skip text before a block and
// tolerate headers and odd line lengths; comparing with the re-encoding
// refuses all of that, so the file is either exactly what this package
// writes or it is refused.
func decodeExact(data []byte, types ...string) ([]*pem.Block, error) {
	blocks := make([]*pem.Block, 0, len(types))
	var canonical []byte
	rest := data
	for _, typ := range types {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil || b.Type != typ || len(b.Headers) != 0 {
			return nil, fmt.Errorf("%w: want a %s block", ErrMalformedFile, typ)
		}
		blocks = append(blocks, b)
		canonical = append(canonical, pem.EncodeToMemory(b)...)
	}
	if len(rest) != 0 || !bytes.Equal(canonical, data) {
		clear(canonical)
		return nil, fmt.Errorf("%w: not in canonical form", ErrMalformedFile)
	}
	clear(canonical)
	return blocks, nil
}
