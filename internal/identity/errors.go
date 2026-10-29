package identity

import "errors"

// Error classes. Callers test with errors.Is; the wrapped message adds the
// check or file that failed, never a secret (R20).
var (
	// ErrInvalidServerID: not a lowercase canonical UUID v4 (§4.1).
	ErrInvalidServerID = errors.New("identity: invalid server ID")
	// ErrInvalidToken: not an enrollment token in its text form (§4.2).
	ErrInvalidToken = errors.New("identity: invalid enrollment token")
	// ErrInvalidKey: not an ECDSA P-256 private key (§4.4).
	ErrInvalidKey = errors.New("identity: invalid agent key")
	// ErrInvalidCSR: not a P-256 PKCS #10 request of at most 4 KiB with a
	// valid signature (§4.4).
	ErrInvalidCSR = errors.New("identity: invalid certificate signing request")
	// ErrInvalidBinding: executor public key or binding MAC not exactly
	// 32 bytes (§4.5, agent-api R17).
	ErrInvalidBinding = errors.New("identity: invalid executor binding")
	// ErrInvalidServerName: not a DNS name or IP literal of at most
	// 253 characters (§4.3).
	ErrInvalidServerName = errors.New("identity: invalid server name")
	// ErrInvalidTrust: the trusted control-plane CAs or the agent CA are
	// not usable trust anchors.
	ErrInvalidTrust = errors.New("identity: invalid trust anchor")
	// ErrCertificateRejected: an issued certificate failed R15.
	ErrCertificateRejected = errors.New("identity: issued certificate rejected")
	// ErrMalformedFile: a state file does not have its exact encoding.
	ErrMalformedFile = errors.New("identity: malformed state file")
	// ErrUnsafeFile: a file or one of its directories breaks R10e or the
	// §4.7 state-directory rules (symlink, owner, mode, not a regular file).
	ErrUnsafeFile = errors.New("identity: unsafe file")
	// ErrFileTooLarge: a file is larger than the limit for its kind.
	ErrFileTooLarge = errors.New("identity: file too large")
	// ErrPeerRejected: the control plane's TLS certificate failed an R24
	// check in VerifyConnection.
	ErrPeerRejected = errors.New("identity: control-plane certificate rejected")
)
