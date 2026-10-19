package envelope

// Test helpers shared by the envelope verifier tests. Nothing here is a real
// secret: every private key is derived at runtime from a public label with
// SHA-256, and the only fixed key is the public RFC 8032 §7.1 TEST 1 vector.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// fakeNow is the fixed verifier clock used by every test (2027-01-15).
const fakeNow int64 = 1_800_000_000

const (
	maxTime int64 = 1<<40 - 1

	serverA = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	serverB = "7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d"

	validActionID   = "01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f" // UUID v7
	validDecisionID = "3c4d5e6f-7a8b-4c9d-ae0f-1a2b3c4d5e6f" // UUID v4
	validApprovalID = "9e8d7c6b-5a49-4382-b716-05f4e3d2c1b0" // UUID v4
	validIdemKey    = "wf-0001:step-restart:1"
)

func clockAt(sec int64) func() time.Time {
	return func() time.Time { return time.Unix(sec, 0) }
}

// testKey derives a deterministic Ed25519 key from a label. Test-only.
func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("warden-envelope-test-only/" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

var (
	keyA     = testKey("a")
	keyB     = testKey("b")
	keyOther = testKey("untrusted")
)

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey {
	return k.Public().(ed25519.PublicKey)
}

func keyIDBytes(k ed25519.PrivateKey) []byte {
	sum := sha256.Sum256(pubOf(k))
	return sum[:]
}

func digest(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

// validBody returns a body that passes checks 5–11 for a verifier at fakeNow
// whose ServerID is serverA.
func validBody() *wardenv1.EnvelopeBody {
	return &wardenv1.EnvelopeBody{
		FormatVersion:   1,
		ActionId:        validActionID,
		TargetServerId:  serverA,
		PlaybookId:      "service-recover",
		PlaybookVersion: "1.2.3",
		PlaybookDigest:  digest("playbook-package"),
		StepId:          "restart",
		Params: &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_ServiceRestart{
			ServiceRestart: &wardenv1.ServiceRestartRequest{Unit: "nginx.service"},
		}},
		PolicyDecision: &wardenv1.PolicyDecision{
			DecisionId:         validDecisionID,
			AutonomyLevel:      wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L2,
			PolicyBundleDigest: digest("policy-bundle"),
			ApprovalId:         "",
		},
		CreatedAt:      fakeNow - 10,
		ExpiresAt:      fakeNow + 290,
		IdempotencyKey: validIdemKey,
	}
}

func bodyWith(mut func(b *wardenv1.EnvelopeBody)) *wardenv1.EnvelopeBody {
	b := validBody()
	mut(b)
	return b
}

func marshalDet(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// domainLiteral is written out independently of the package constant so a
// wrong constant cannot make the tests agree with a wrong implementation.
const domainLiteral = "warden/v1/action-envelope\x00"

func signedMessage(body []byte) []byte {
	msg := make([]byte, 0, len(domainLiteral)+len(body))
	msg = append(msg, domainLiteral...)
	return append(msg, body...)
}

func signRaw(k ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(k, msg)
}

func signBody(k ed25519.PrivateKey, body []byte) []byte {
	return ed25519.Sign(k, signedMessage(body))
}

// wrap encodes a SignedEnvelope by hand so that zero-length fields are still
// present on the wire (deterministic Marshal would drop them).
func wrap(keyID, body, sig []byte) []byte {
	var b []byte
	if keyID != nil {
		b = fBytes(b, 1, keyID)
	}
	if body != nil {
		b = fBytes(b, 2, body)
	}
	if sig != nil {
		b = fBytes(b, 3, sig)
	}
	return b
}

func sealBytes(k ed25519.PrivateKey, body []byte) []byte {
	return wrap(keyIDBytes(k), body, signBody(k, body))
}

func seal(t testing.TB, k ed25519.PrivateKey, b *wardenv1.EnvelopeBody) []byte {
	t.Helper()
	return sealBytes(k, marshalDet(t, b))
}

// protowire helpers --------------------------------------------------------

func fVarint(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func fBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func fFixed32(b []byte, num protowire.Number, v uint32) []byte {
	b = protowire.AppendTag(b, num, protowire.Fixed32Type)
	return protowire.AppendFixed32(b, v)
}

func fFixed64(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.Fixed64Type)
	return protowire.AppendFixed64(b, v)
}

func fGroup(b []byte, num protowire.Number, inner []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.StartGroupType)
	b = append(b, inner...)
	return protowire.AppendTag(b, num, protowire.EndGroupType)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// withField returns b with recs (records of one field number, or of
// ascending numbers that all fit before the next field of b) inserted at
// their ascending position, replacing any record of b with recs' first
// field number. Tests use it so an input breaks only the rule under test,
// not R13 (k).
func withField(tb testing.TB, b, recs []byte) []byte {
	tb.Helper()
	num, _, n := protowire.ConsumeTag(recs)
	if n < 0 {
		tb.Fatalf("withField: bad record tag")
	}
	var out []byte
	placed := false
	for len(b) > 0 {
		rnum, _, rn := protowire.ConsumeField(b)
		if rn < 0 {
			tb.Fatalf("withField: bad base record")
		}
		if rnum != num {
			if !placed && rnum > num {
				out, placed = append(out, recs...), true
			}
			out = append(out, b[:rn]...)
		}
		b = b[rn:]
	}
	if !placed {
		out = append(out, recs...)
	}
	return out
}

// Keys and verifiers -------------------------------------------------------

func trusted(k ed25519.PrivateKey, notBefore, notAfter int64) TrustedKey {
	return TrustedKey{PublicKey: pubOf(k), NotBefore: notBefore, NotAfter: notAfter}
}

// wideKey is valid for the whole allowed timestamp range.
func wideKey(k ed25519.PrivateKey) TrustedKey { return trusted(k, 1, maxTime) }

func mustKeySet(t testing.TB, keys ...TrustedKey) *KeySet {
	t.Helper()
	ks, err := NewKeySet(keys...)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return ks
}

func mustVerifier(t testing.TB, ks *KeySet, serverID string, now int64) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{Keys: ks, ServerID: serverID, Now: clockAt(now)})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// defaultVerifier trusts keyA for the whole range, is serverA, and runs at
// fakeNow.
func defaultVerifier(t testing.TB) *Verifier {
	t.Helper()
	return mustVerifier(t, mustKeySet(t, wideKey(keyA)), serverA, fakeNow)
}

func counters() (decodes, verifies uint64) {
	return bodyDecodes.Load(), signatureVerifies.Load()
}

// checkOf maps each code to the check numbers it may carry.
var checkOf = map[Code][]int{
	CodeOversized:                {1},
	CodeMalformed:                {2},
	CodeUnknownKey:               {3, 7},
	CodeBadSignature:             {4},
	CodeBodyInvalid:              {5},
	CodeUnsupportedFormatVersion: {6},
	CodeLifetimeInvalid:          {8},
	CodeNotYetValid:              {9},
	CodeExpired:                  {10},
	CodeWrongHost:                {11},
}

func asRejection(t testing.TB, res *Verified, err error) *Rejection {
	t.Helper()
	if err == nil {
		t.Fatalf("Verify accepted; want a rejection")
	}
	if res != nil {
		t.Errorf("Verify returned a non-nil result together with error %v", err)
	}
	var rej *Rejection
	if !errors.As(err, &rej) {
		t.Fatalf("Verify error %T (%v) is not *Rejection", err, err)
	}
	if rej.Error() == "" {
		t.Errorf("Rejection.Error() is empty")
	}
	return rej
}

// expectReject asserts the code and check number of a rejection.
func expectReject(t testing.TB, v *Verifier, raw []byte, code Code, check int) {
	t.Helper()
	res, err := v.Verify(raw)
	rej := asRejection(t, res, err)
	if rej.Code != code || rej.Check != check {
		t.Fatalf("got %s at check %d, want %s at check %d", rej.Code, rej.Check, code, check)
	}
}

// expectAccept asserts success and that the returned body equals want.
func expectAccept(t testing.TB, v *Verifier, raw []byte, want *wardenv1.EnvelopeBody, signer ed25519.PrivateKey) *Verified {
	t.Helper()
	res, err := v.Verify(raw)
	if err != nil {
		t.Fatalf("Verify rejected a valid envelope: %v", err)
	}
	if res == nil || res.Body == nil {
		t.Fatalf("Verify returned nil result without error")
	}
	if want != nil && !proto.Equal(res.Body, want) {
		t.Fatalf("returned body differs from the signed body:\n got %v\nwant %v", res.Body, want)
	}
	if signer != nil && !bytes.Equal(res.KeyID[:], keyIDBytes(signer)) {
		t.Fatalf("KeyID = %x, want %x", res.KeyID, keyIDBytes(signer))
	}
	return res
}

// Ed25519 group order and S manipulation (R4a) ------------------------------

var groupOrderL = func() *big.Int {
	l, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		panic("bad L constant")
	}
	return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
}()

func leToInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// intToLE32 encodes n little-endian into 32 bytes; n must fit.
func intToLE32(n *big.Int) []byte {
	be := n.Bytes()
	if len(be) > 32 {
		panic("value does not fit in 32 bytes")
	}
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[len(be)-1-i]
	}
	return out
}

// withS replaces S (bytes 32..63) of sig.
func withS(sig []byte, s *big.Int) []byte {
	out := append([]byte(nil), sig[:32]...)
	return append(out, intToLE32(s)...)
}

func flipBit(b []byte, bit int) []byte {
	out := append([]byte(nil), b...)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// consumeFieldLen returns the length of the first field (tag and value) in
// b, or a negative value on a bad encoding.
func consumeFieldLen(b []byte) int {
	num, typ, n := protowire.ConsumeTag(b)
	if n < 0 {
		return n
	}
	m := protowire.ConsumeFieldValue(num, typ, b[n:])
	if m < 0 {
		return m
	}
	return n + m
}

// Non-canonical encodings (R13 canonical-encoding rule) --------------------

// overlongN returns a non-minimal varint encoding of v that is exactly total
// bytes long; it still decodes to v with protowire.ConsumeVarint.
func overlongN(v uint64, total int) []byte {
	b := protowire.AppendVarint(nil, v)
	if total <= len(b) || total > 10 {
		panic("overlongN: impossible length")
	}
	b[len(b)-1] |= 0x80
	for len(b) < total-1 {
		b = append(b, 0x80)
	}
	return append(b, 0x00)
}

// overlong is v encoded one byte longer than necessary.
func overlong(v uint64) []byte { return overlongN(v, protowire.SizeVarint(v)+1) }

// rawTag is the varint value of a field tag.
func rawTag(num protowire.Number, typ protowire.Type) uint64 {
	return protowire.EncodeTag(num, typ)
}

// i64 is the two's-complement wire value of a signed integer.
// i64 is the two's complement uint64 that a varint carries for v.
func i64(v int64) uint64 {
	if v >= 0 {
		return uint64(v)
	}
	// For v < 0, m = -(v+1) is in 0 … MaxInt64 (no overflow, even for
	// MinInt64), and ^m = 2^64 - 1 - m = 2^64 + v.
	if m := -(v + 1); m >= 0 {
		return ^uint64(m)
	}
	panic("unreachable")
}

// encMut says how mutateAt re-encodes the field it finds.
type encMut int

const (
	mutTag   encMut = iota // overlong tag, value unchanged
	mutValue               // overlong varint value, or overlong length prefix
)

// mutateAt re-encodes the first field found at path (field numbers, outer
// first) of the message encoding b non-minimally, re-encoding the enclosing
// length prefixes minimally. Everything else is copied byte for byte, so
// exactly one varint becomes non-canonical.
func mutateAt(tb testing.TB, b []byte, path []protowire.Number, how encMut) []byte {
	tb.Helper()
	out, ok := mutateFields(b, path, how)
	if !ok {
		tb.Fatalf("mutateAt: field path %v not found", path)
	}
	return out
}

func mutateFields(b []byte, path []protowire.Number, how encMut) ([]byte, bool) {
	var out []byte
	done := false
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, false
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return nil, false
		}
		tag, val := b[:n], b[n:n+m]
		b = b[n+m:]
		if done || num != path[0] {
			out = append(append(out, tag...), val...)
			continue
		}
		done = true
		switch {
		case len(path) > 1:
			payload, _ := protowire.ConsumeBytes(val)
			inner, ok := mutateFields(payload, path[1:], how)
			if !ok {
				return nil, false
			}
			out = protowire.AppendBytes(append(out, tag...), inner)
		case how == mutTag:
			out = append(append(out, overlong(rawTag(num, typ))...), val...)
		case typ == protowire.VarintType:
			v, _ := protowire.ConsumeVarint(val)
			out = append(append(out, tag...), overlong(v)...)
		case typ == protowire.BytesType:
			payload, _ := protowire.ConsumeBytes(val)
			out = append(append(out, tag...), overlong(uint64(len(payload)))...)
			out = append(out, payload...)
		default:
			return nil, false
		}
	}
	return out, done
}
