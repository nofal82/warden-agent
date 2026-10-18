package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
)

// KeyID identifies a signing key: the SHA-256 of its raw 32-byte Ed25519
// public key (R9). It is always computed from the key bytes, never taken
// from a file name or a field (R10).
type KeyID [sha256.Size]byte

// KeyIDOf returns the key ID of pub.
func KeyIDOf(pub ed25519.PublicKey) KeyID {
	return sha256.Sum256(pub)
}

// TrustedKey is one envelope-role key of the installed keyset. Loading and
// verifying the keyset itself (roles, root signature, sequence number) is
// not done here; only envelope-role keys may be passed in.
type TrustedKey struct {
	PublicKey ed25519.PublicKey
	// Validity period in Unix seconds, both bounds inclusive.
	NotBefore int64
	NotAfter  int64
}

func (k TrustedKey) validAt(t int64) bool {
	return k.NotBefore <= t && t <= k.NotAfter
}

// KeySet is an immutable set of trusted envelope keys, indexed by key ID.
type KeySet struct {
	keys map[KeyID]TrustedKey
}

// NewKeySet builds a key set. It refuses a key that is not exactly 32 bytes,
// an empty or inverted validity period and a duplicate key. An empty set is
// allowed: it trusts nothing.
func NewKeySet(keys ...TrustedKey) (*KeySet, error) {
	set := &KeySet{keys: make(map[KeyID]TrustedKey, len(keys))}
	for i, k := range keys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("envelope: key %d: public key is %d bytes, want %d", i, len(k.PublicKey), ed25519.PublicKeySize)
		}
		if k.NotBefore < 1 || k.NotBefore > k.NotAfter {
			return nil, fmt.Errorf("envelope: key %d: invalid validity period %d … %d", i, k.NotBefore, k.NotAfter)
		}
		id := KeyIDOf(k.PublicKey)
		if _, dup := set.keys[id]; dup {
			return nil, fmt.Errorf("envelope: key %d: %w", i, errDuplicateKey)
		}
		// Copy the key so a caller cannot change a trusted key afterwards.
		k.PublicKey = ed25519.PublicKey(bytes.Clone(k.PublicKey))
		set.keys[id] = k
	}
	return set, nil
}

var errDuplicateKey = errors.New("duplicate key")

// lookup is nil-safe: a nil set trusts nothing.
func (s *KeySet) lookup(id KeyID) (TrustedKey, bool) {
	if s == nil {
		return TrustedKey{}, false
	}
	k, ok := s.keys[id]
	return k, ok
}
