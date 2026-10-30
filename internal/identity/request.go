package identity

import (
	"fmt"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

// Executor binding sizes (agent-identity §4.5; executor-ipc R52).
const (
	ExecutorPublicKeySize = 32
	BindingMACSize        = 32
)

// enrollFormatVersion is the only EnrollRequest format (§4.5).
const enrollFormatVersion = 1

// ExecutorBinding is the executor's raw Ed25519 result public key and the
// binding MAC the installer computed over it (R12b). The agent cannot check
// the MAC (it never sees the secret); it only forwards both values.
//
// How the values are read from the executor binding file is defined by
// agent-packaging.md, not yet written; callers pass them in.
type ExecutorBinding struct {
	PublicKey [ExecutorPublicKeySize]byte
	MAC       [BindingMACSize]byte
}

// NewExecutorBinding copies pub and mac into an ExecutorBinding, refusing
// any length other than exactly 32 bytes each (agent-api R17).
func NewExecutorBinding(pub, mac []byte) (ExecutorBinding, error) {
	var b ExecutorBinding
	if len(pub) != ExecutorPublicKeySize {
		return b, fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidBinding, len(pub), ExecutorPublicKeySize)
	}
	if len(mac) != BindingMACSize {
		return b, fmt.Errorf("%w: MAC is %d bytes, want %d", ErrInvalidBinding, len(mac), BindingMACSize)
	}
	copy(b.PublicKey[:], pub)
	copy(b.MAC[:], mac)
	return b, nil
}

// BuildEnrollRequest builds the EnrollRequest of agent-api §4.3 with
// format_version 1. It validates every field so a request the control plane
// would refuse MALFORMED is never sent: token (§4.2), serverID (§4.1) and
// csr (a P-256 PKCS #10 request of at most 4 KiB whose signature verifies).
func BuildEnrollRequest(token, serverID string, csr []byte, b ExecutorBinding) (*agentapiv1.EnrollRequest, error) {
	if err := ValidateToken(token); err != nil {
		return nil, err
	}
	if err := ValidateServerID(serverID); err != nil {
		return nil, err
	}
	if _, err := checkCSR(csr); err != nil {
		return nil, err
	}
	return &agentapiv1.EnrollRequest{
		FormatVersion:      enrollFormatVersion,
		Token:              token,
		ServerId:           serverID,
		Csr:                append([]byte(nil), csr...),
		ExecutorPublicKey:  append([]byte(nil), b.PublicKey[:]...),
		ExecutorBindingMac: append([]byte(nil), b.MAC[:]...),
	}, nil
}
