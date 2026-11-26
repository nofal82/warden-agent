package trustdoc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// Domains of signing-and-updates §4.2, without the 0x00 that R2 appends.
// The verifier picks the domain from the kind it expects, never from the
// document.
const (
	DomainKeyset   = "warden/v1/envelope-keyset"
	DomainManifest = "warden/v1/server-manifest"
)

// Raw size limits of §4.2, checked before any parsing (R3).
const (
	MaxKeysetBytes   = 4096
	MaxManifestBytes = 32768
)

// Validity limits of R11 and R13, in seconds.
const (
	MaxKeyValidity     = 31536000  // 365 days
	MaxCAEntryValidity = 158112000 // 1,830 days
	maxTime            = 1<<40 - 1
)

// Code is the refusal code of a document kind (action-envelope §4.6).
type Code string

// Refusal codes. Oversized and malformed documents use the kind's code too:
// trust documents have no separate code for them (§4.1).
const (
	CodeKeysetInvalid   Code = "KEYSET_INVALID"
	CodeManifestInvalid Code = "MANIFEST_INVALID"
)

// Rejection is the error every refusal returns. Reason is a short fixed
// text for logs; it never contains document bytes.
type Rejection struct {
	Code   Code
	Reason string
}

func (r *Rejection) Error() string { return string(r.Code) + ": " + r.Reason }

func reject(c Code, reason string) *Rejection { return &Rejection{Code: c, Reason: reason} }

// Test-only observability (AC1, AC3): proves the body is decoded only after
// the signature verified, and that ed25519.Verify is never reached for a
// non-canonical S. Tests that read them must not run in parallel.
var (
	bodyDecodes       atomic.Uint64
	signatureVerifies atomic.Uint64
)

// openOuter checks the raw size limit, then strictly decodes the outer
// container: key_id exactly 32 bytes, a non-empty body, and an Ed25519
// signature of exactly 64 bytes (§4.1; both kinds here are Ed25519, so the
// ECDSA range of the contract option is refused).
func openOuter(raw []byte, limit int) (*wardenv1.SignedDocument, string) {
	if len(raw) > limit {
		return nil, "document larger than the kind's limit"
	}
	doc := new(wardenv1.SignedDocument)
	if wirescan.Unmarshal(raw, doc) != nil {
		return nil, "malformed container"
	}
	switch {
	case len(doc.GetKeyId()) != sha256.Size:
		return nil, "key_id is not 32 bytes"
	case len(doc.GetBody()) == 0:
		return nil, "empty body"
	case len(doc.GetSignature()) != ed25519.SignatureSize:
		return nil, "signature is not 64 bytes"
	}
	return doc, ""
}

// signedMessage is DOMAIN || 0x00 || body (R2).
func signedMessage(domain string, body []byte) []byte {
	msg := make([]byte, 0, len(domain)+1+len(body))
	msg = append(msg, domain...)
	msg = append(msg, 0)
	return append(msg, body...)
}

// verifyEd25519 applies the canonical-S check itself (action-envelope R4a)
// before pure Ed25519 over the signed message (R6).
func verifyEd25519(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || !canonicalS(sig[32:]) {
		return false
	}
	signatureVerifies.Add(1)
	return ed25519.Verify(pub, msg, sig)
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
// S >= L is malleable (S + L verifies like S). S is public, so the
// comparison need not be constant time.
func canonicalS(s []byte) bool {
	for i := len(orderL) - 1; i >= 0; i-- {
		if s[i] != orderL[i] {
			return s[i] < orderL[i]
		}
	}
	return false // s == L
}

// verifyAndDecode verifies sig over the kind's signed message and only then
// strictly decodes body into m (R3, R4). It works on a private copy, so a
// caller that reuses raw cannot make the decoded bytes differ from the
// signed ones. It returns the R7 document hash.
func verifyAndDecode(pub ed25519.PublicKey, domain string, doc *wardenv1.SignedDocument, m proto.Message) ([sha256.Size]byte, string) {
	body := bytes.Clone(doc.GetBody())
	msg := signedMessage(domain, body)
	if !verifyEd25519(pub, msg, doc.GetSignature()) {
		return [sha256.Size]byte{}, "bad signature"
	}
	bodyDecodes.Add(1)
	if wirescan.Unmarshal(body, m) != nil {
		return [sha256.Size]byte{}, "malformed body"
	}
	return sha256.Sum256(msg), ""
}

// validity is R13 plus the kind's maximum length: inclusive bounds,
// not_before < not_after, both in 1 … 2^40 − 1. The subtraction cannot
// overflow once both bounds are in that range.
func validity(notBefore, notAfter, maxLen int64) bool {
	return notBefore >= 1 && notAfter <= maxTime && notBefore < notAfter &&
		notAfter-notBefore <= maxLen
}

// sortedBy reports whether the keys are strictly increasing in byte order,
// which also forbids duplicates (§4 "sorted").
func sortedBy(n int, key func(int) []byte) bool {
	for i := 1; i < n; i++ {
		if bytes.Compare(key(i-1), key(i)) >= 0 {
			return false
		}
	}
	return true
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}
