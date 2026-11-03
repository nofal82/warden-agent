package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

var tokenExpiresRE = regexp.MustCompile(`^[1-9][0-9]{0,11}$`)

// StartState is the R18a case the agent is in at start.
type StartState int

// The R18a cases.
const (
	// StartUseIdentity: identity.pem is valid (case 1).
	StartUseIdentity StartState = iota + 1
	// StartUsePrevious: identity.pem is not valid, identity.prev.pem is (case 2).
	StartUsePrevious
	// StartEnroll: no valid pair and a token file (case 3): call Enroll.
	StartEnroll
	// StartTokenExpired: case 3 with token-expires in the past: send no
	// request; health reports HealthTokenExpired.
	StartTokenExpired
	// StartNoIdentity: no valid pair and no token file (case 4): make no
	// connection; health reports HealthNoIdentity.
	StartNoIdentity
)

// Identity is a key and certificate loaded from identity.pem or
// identity.prev.pem, or written by Enroll.
type Identity struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// Certificate returns the identity's certificate.
func (i Identity) Certificate() *x509.Certificate { return i.cert }

// TLSCertificate returns the pair as a client certificate for the agent
// endpoint; the zero value when the identity is empty.
func (i Identity) TLSCertificate() tls.Certificate {
	if i.key == nil || i.cert == nil {
		return tls.Certificate{}
	}
	return tls.Certificate{Certificate: [][]byte{i.cert.Raw}, PrivateKey: i.key, Leaf: i.cert}
}

// Start is the outcome of Decide.
type Start struct {
	State StartState
	// Identity is set for StartUseIdentity and StartUsePrevious.
	Identity Identity
	// TokenPresent: in case 1, a token file left by a crash after
	// identity.pem was written. It stays until AfterHandshake; if the
	// control plane refuses identity.pem while it exists, the caller
	// enrolls (case 3).
	TokenPresent bool
}

// Decide applies the start-up states of R18a. Call it after the trust
// files passed R10e and the R10d set is not empty. serverID is the agent
// copy of server-id (R5). Decide only reads, except that it removes a
// renewal pending key it will never use (case 1: the key is already in
// identity.pem; case 3: it is never used for enrollment).
func Decide(d *StateDir, serverID string, now time.Time) (Start, error) {
	if id, ok := loadValid(d, FileIdentity, serverID, now); ok {
		if err := dropRenewalKeyIfIn(d, id.key); err != nil {
			return Start{}, err
		}
		present, err := exists(d, FileToken)
		if err != nil {
			return Start{}, err
		}
		return Start{State: StartUseIdentity, Identity: id, TokenPresent: present}, nil
	}
	if id, ok := loadValid(d, FileIdentityPrev, serverID, now); ok {
		return Start{State: StartUsePrevious, Identity: id}, nil
	}
	present, err := exists(d, FileToken)
	if err != nil {
		return Start{}, err
	}
	if !present {
		return Start{State: StartNoIdentity}, nil
	}
	if err := d.Remove(FileIdentityPendingKey); err != nil {
		return Start{}, err
	}
	if tokenExpired(d, now) {
		return Start{State: StartTokenExpired}, nil
	}
	return Start{State: StartEnroll}, nil
}

// loadValid reports whether name holds a valid pair (R18a case 1): it
// loads under the §4.7 rules, is not expired and names exactly serverID.
// The chain is not checked: a renewed certificate may come from a newer
// agent CA during an overlap (R15a).
func loadValid(d *StateDir, name, serverID string, now time.Time) (Identity, bool) {
	data, err := d.ReadFile(name)
	if err != nil {
		return Identity{}, false
	}
	defer clear(data)
	key, cert, err := DecodeIdentity(data)
	if err != nil || now.After(cert.NotAfter) || checkSubject(cert, serverID) != nil {
		return Identity{}, false
	}
	return Identity{key: key, cert: cert}, true
}

// dropRenewalKeyIfIn removes identity.pending-key.pem when it holds key: a
// crash after the renewed pair was written (R18a case 1). Any other content
// is kept for the renewal retry (R22).
func dropRenewalKeyIfIn(d *StateDir, key *ecdsa.PrivateKey) error {
	data, err := d.ReadFile(FileIdentityPendingKey)
	if err != nil {
		return nil // missing or unreadable: nothing this step may remove
	}
	defer clear(data)
	blocks, err := decodeExact(data, pemTypePrivateKey)
	if err != nil {
		return nil
	}
	pending, err := parseKey(blocks[0].Bytes)
	if err != nil || !pending.Equal(key) {
		return nil
	}
	return d.Remove(FileIdentityPendingKey)
}

func exists(d *StateDir, name string) (bool, error) {
	data, err := d.ReadFile(name)
	clear(data)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case errors.Is(err, ErrUnsafeFile), errors.Is(err, ErrFileTooLarge):
		// The file is there; Enroll refuses it.
		return true, nil
	}
	return false, err
}

// tokenExpired reports whether token-expires holds a time before now. A
// missing or malformed file is ignored (R18a case 3).
func tokenExpired(d *StateDir, now time.Time) bool {
	data, err := d.ReadFile(FileTokenExpires)
	if err != nil {
		return false
	}
	at, ok := parseTokenExpires(data)
	return ok && at < now.Unix()
}

// parseTokenExpires decodes token-expires (§4.7): ASCII decimal Unix
// seconds, ^[1-9][0-9]{0,11}$, no newline.
func parseTokenExpires(data []byte) (int64, bool) {
	if !tokenExpiresRE.Match(data) {
		return 0, false
	}
	n, err := strconv.ParseInt(string(data), 10, 64)
	return n, err == nil
}

// parseTokenFile decodes the token file: exactly the 48-byte §4.2 text
// form, with no newline or anything else.
func parseTokenFile(data []byte) (string, error) {
	s := string(data)
	if err := ValidateToken(s); err != nil {
		return "", err
	}
	return s, nil
}

// EnrollFunc sends one EnrollRequest to the enrollment endpoint and returns
// the issued leaf certificate (DER). Dialling, deadlines and retries are
// the caller's.
type EnrollFunc func(ctx context.Context, req *agentapiv1.EnrollRequest) ([]byte, error)

// EnrollInput is what one enrollment attempt needs besides the state
// directory: the agent copy of server-id (R5), agent-ca.pem (R15) and the
// executor binding (R12b).
type EnrollInput struct {
	ServerID string
	AgentCA  *x509.Certificate
	Binding  ExecutorBinding
}

// Enroll runs one enrollment attempt (R12, R12a, R15, R18a case 3):
//  0. in.AgentCA must be a CA certificate, checked before the token is used;
//  1. token-expires in the past: ErrTokenExpired, no request;
//  2. the token file must hold exactly a §4.2 token;
//  3. a pending key bound to this token is reused; any other pending key
//     is replaced by a new key, written durably before the request;
//  4. send the request built from the token, serverID, the key's CSR and
//     the binding;
//  5. the returned certificate must pass VerifyIssued (R15);
//  6. write identity.pem, then remove the token file, token-expires and the
//     pending key, in that order (R12a).
//
// On any failure nothing is written after the pending key, and the token
// and pending key stay, so the caller's retry reuses the same key.
func Enroll(ctx context.Context, d *StateDir, in EnrollInput, send EnrollFunc, now time.Time) (Identity, error) {
	// A bad local agent-ca.pem would only be caught by R15 after the send,
	// when the control plane has already consumed the token.
	if !isCA(in.AgentCA) {
		return Identity{}, fmt.Errorf("%w: agent CA is not a CA certificate", ErrInvalidTrust)
	}
	if tokenExpired(d, now) {
		return Identity{}, ErrTokenExpired
	}
	data, err := d.ReadFile(FileToken)
	if err != nil {
		return Identity{}, err
	}
	token, err := parseTokenFile(data)
	clear(data)
	if err != nil {
		return Identity{}, fmt.Errorf("%s: %w", FileToken, err)
	}
	key, err := pendingKeyFor(d, token)
	if err != nil {
		return Identity{}, err
	}
	csr, err := CreateCSR(key)
	if err != nil {
		return Identity{}, err
	}
	req, err := BuildEnrollRequest(token, in.ServerID, csr, in.Binding)
	if err != nil {
		return Identity{}, err
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, fmt.Errorf("identity: enroll: %w", err)
	}
	certDER, err := send(ctx, req)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: enroll: %w", err)
	}
	v, err := VerifyIssued(certDER, in.ServerID, key, in.AgentCA, now)
	if err != nil {
		return Identity{}, err
	}
	if err := d.WriteIdentity(v); err != nil {
		return Identity{}, err
	}
	// Token first, pending key last: a crash in between never leaves a
	// token without its key (R12a).
	for _, name := range []string{FileToken, FileTokenExpires, FileEnrollPendingKey} {
		if err := d.Remove(name); err != nil {
			return Identity{}, err
		}
	}
	return Identity(v), nil
}

// pendingKeyFor returns the key of enroll.pending-key.pem when it is bound
// to token, and otherwise generates a new key and writes it, bound to
// token, before anything is sent (R12a).
func pendingKeyFor(d *StateDir, token string) (*ecdsa.PrivateKey, error) {
	hash := TokenHash(token)
	if data, err := d.ReadFile(FileEnrollPendingKey); err == nil {
		key, bound, derr := DecodePendingEnrollKey(data)
		clear(data)
		if derr == nil && bound == hash {
			return key, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrUnsafeFile) && !errors.Is(err, ErrFileTooLarge) {
		return nil, err
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	data, err := EncodePendingEnrollKey(key, hash)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if err := d.WriteFile(FileEnrollPendingKey, data); err != nil {
		return nil, err
	}
	return key, nil
}

// AfterHandshake runs after the first successful mTLS handshake. used is
// the pair that completed it. Only when used is the pair now in
// identity.pem does it remove what that handshake made obsolete, in this
// order: a leftover token, token-expires, enroll.pending-key.pem (R18a
// case 1, R12a), then identity.prev.pem (R22). Otherwise it removes nothing
// and returns ErrNotCurrentIdentity, so a handshake with identity.prev.pem
// (case 2) never deletes that pair. It returns the names it removed, for
// the local report.
func (d *StateDir) AfterHandshake(used Identity) ([]string, error) {
	if err := d.isCurrent(used); err != nil {
		return nil, err
	}
	var removed []string
	for _, name := range []string{FileToken, FileTokenExpires, FileEnrollPendingKey, FileIdentityPrev} {
		present, err := exists(d, name)
		if err != nil {
			return removed, err
		}
		if !present {
			continue
		}
		if err := d.Remove(name); err != nil {
			return removed, err
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// isCurrent reports whether used is the pair in identity.pem. Validity is
// not rechecked: the handshake already succeeded with it.
func (d *StateDir) isCurrent(used Identity) error {
	if used.key == nil || used.cert == nil {
		return fmt.Errorf("%w: no pair", ErrNotCurrentIdentity)
	}
	data, err := d.ReadFile(FileIdentity)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotCurrentIdentity, err)
	}
	defer clear(data)
	key, cert, err := DecodeIdentity(data)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotCurrentIdentity, err)
	}
	if !bytes.Equal(cert.Raw, used.cert.Raw) || !key.Equal(used.key) {
		return ErrNotCurrentIdentity
	}
	return nil
}
