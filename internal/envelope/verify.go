package envelope

import (
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"time"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// Limits and constants from action-envelope §3 and §4.3.
const (
	MaxEnvelopeBytes = 16384 // R11
	MaxLifetime      = 600   // seconds, R15
	MaxSkew          = 60    // seconds, R16
	FormatVersion    = 1     // R14

	// Domain is prefixed to the body before signing (R2): 25 ASCII bytes
	// and one 0x00 byte, so a signature made by the same key for any other
	// purpose is never accepted as an envelope.
	Domain = "warden/v1/action-envelope\x00"
)

// §4.5 check numbers.
const (
	checkSize = iota + 1
	checkOuter
	checkKey
	checkSignature
	checkBody
	checkFormatVersion
	checkKeyAtCreation
	checkLifetime
	checkNotYetValid
	checkExpired
	checkHost
)

// Test-only observability (AC4, AC7, AC8): the body is never decoded, and
// ed25519.Verify is never reached for a non-canonical S, before the earlier
// checks pass.
var (
	bodyDecodes       atomic.Uint64
	signatureVerifies atomic.Uint64
)

// Config is what a verifier needs. Every value comes from the verifier's
// own trusted configuration, never from the sender of the envelope (R7).
type Config struct {
	// Keys is the set of trusted envelope-role keys. Nil or empty means no
	// keyset is installed: every envelope is rejected UNKNOWN_KEY.
	Keys *KeySet
	// ServerID is this server's identity from its own root-owned file
	// (R17), a lowercase canonical UUID.
	ServerID string
	// Now is the verifier's wall clock.
	Now func() time.Time
}

// Verifier runs the stateless checks 1–11 of action-envelope §4.5. It is
// safe for concurrent use.
type Verifier struct {
	keys     *KeySet
	serverID string
	now      func() time.Time
}

// Verified is an envelope that passed checks 1–11.
type Verified struct {
	Body  *wardenv1.EnvelopeBody
	KeyID KeyID
}

// NewVerifier returns a verifier for cfg. It refuses a missing clock or a
// malformed server identity rather than run with a default.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Now == nil {
		return nil, errors.New("envelope: Config.Now is nil")
	}
	if !uuidAnyRE.MatchString(cfg.ServerID) {
		return nil, errors.New("envelope: Config.ServerID is not a lowercase canonical UUID")
	}
	return &Verifier{keys: cfg.Keys, serverID: cfg.ServerID, now: cfg.Now}, nil
}

// Verify runs checks 1–11 in §4.5 order and returns the first failure as a
// *Rejection. Before the signature check it parses only the outer
// SignedEnvelope (R5); it verifies the received body bytes and never
// re-marshals them (R4).
func (v *Verifier) Verify(raw []byte) (*Verified, error) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, reject(CodeOversized, checkSize)
	}
	var outer wardenv1.SignedEnvelope
	if wirescan.Unmarshal(raw, &outer) != nil ||
		len(outer.GetKeyId()) != len(KeyID{}) ||
		len(outer.GetSignature()) != ed25519.SignatureSize ||
		len(outer.GetBody()) == 0 {
		return nil, reject(CodeMalformed, checkOuter)
	}

	now := v.now().Unix()
	keyID := KeyID(outer.GetKeyId())
	key, ok := v.keys.lookup(keyID)
	if !ok || !key.validAt(now) {
		return nil, reject(CodeUnknownKey, checkKey)
	}

	if !verifySignature(key.PublicKey, outer.GetBody(), outer.GetSignature()) {
		return nil, reject(CodeBadSignature, checkSignature)
	}

	bodyDecodes.Add(1)
	body := new(wardenv1.EnvelopeBody)
	if wirescan.Unmarshal(outer.GetBody(), body) != nil || !bodyWithinLimits(body) {
		return nil, reject(CodeBodyInvalid, checkBody)
	}
	if body.GetFormatVersion() != FormatVersion {
		return nil, reject(CodeUnsupportedFormatVersion, checkFormatVersion)
	}
	if rej := checkTimes(key, body.GetCreatedAt(), body.GetExpiresAt(), now); rej != nil {
		return nil, rej
	}
	if body.GetTargetServerId() != v.serverID {
		return nil, reject(CodeWrongHost, checkHost)
	}
	return &Verified{Body: body, KeyID: keyID}, nil
}

// verifySignature checks the canonical-S rule (R4a) itself before calling
// pure Ed25519 over Domain || body (R1, R2).
func verifySignature(pub ed25519.PublicKey, body, sig []byte) bool {
	if !canonicalS(sig[32:]) {
		return false
	}
	msg := make([]byte, 0, len(Domain)+len(body))
	msg = append(msg, Domain...)
	msg = append(msg, body...)
	signatureVerifies.Add(1)
	return ed25519.Verify(pub, msg, sig)
}

// checkTimes runs checks 7–10. created and expires are already within
// 1 … 2^40 − 1 (check 5), so none of the sums below can overflow int64,
// whatever now is.
func checkTimes(key TrustedKey, created, expires, now int64) *Rejection {
	if !key.validAt(created) {
		return reject(CodeUnknownKey, checkKeyAtCreation)
	}
	if expires <= created || expires-created > MaxLifetime {
		return reject(CodeLifetimeInvalid, checkLifetime)
	}
	if created-MaxSkew > now {
		return reject(CodeNotYetValid, checkNotYetValid)
	}
	if now > expires+MaxSkew {
		return reject(CodeExpired, checkExpired)
	}
	return nil
}

// orderL is the Ed25519 group order
// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
var orderL = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// canonicalS reports whether the 32-byte little-endian scalar s is below L.
// A signature with S >= L is malleable (S + L verifies like S) and is
// rejected here, not left to the library (R4a). S is public, so the
// comparison need not be constant time.
func canonicalS(s []byte) bool {
	for i := len(orderL) - 1; i >= 0; i-- {
		if s[i] != orderL[i] {
			return s[i] < orderL[i]
		}
	}
	return false // s == L
}
