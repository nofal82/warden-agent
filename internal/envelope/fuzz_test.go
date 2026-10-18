package envelope

// Native Go fuzz targets for the verifier (AC4, AC8).

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	"math/big"
	"math/bits"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// fuzzVerifier trusts keyA for the whole range, is serverA and runs at fakeNow.
func fuzzVerifier(f *testing.F) *Verifier {
	f.Helper()
	ks, err := NewKeySet(wideKey(keyA))
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewVerifier(Config{Keys: ks, ServerID: serverA, Now: clockAt(fakeNow)})
	if err != nil {
		f.Fatal(err)
	}
	return v
}

// attackBodies are the signed-body seeds shared by both fuzz targets.
func attackBodies(tb testing.TB) [][]byte {
	base := marshalDet(tb, validBody())
	noParams := marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	restart := marshalDet(tb, &wardenv1.ServiceRestartRequest{Unit: "nginx.service"})
	out := [][]byte{
		base,
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_MemStatus{MemStatus: &wardenv1.MemStatusRequest{}}}
		})),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 2 })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = b.CreatedAt + 601 })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = fakeNow + 61; b.ExpiresAt = fakeNow + 100 })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = fakeNow - 400; b.ExpiresAt = fakeNow - 61 })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.TargetServerId = serverB })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a..b" })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3+build" })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 99 })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 1 << 40 })),
		marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = &wardenv1.TypedRequest{} })),
		fVarint(append([]byte(nil), base...), 99, 1),
		fBytes(append([]byte(nil), base...), 2, []byte(validActionID)),
		fBytes(append([]byte(nil), base...), 9, marshalDet(tb, validBody().PolicyDecision)),
		fBytes(append([]byte(nil), noParams...), 8, cat(fBytes(nil, 11, restart), fBytes(nil, 7, nil))),
		fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 11, fVarint(append([]byte(nil), restart...), 99, 1))),
		fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 11, fGroup(nil, 1, nil))),
		fGroup(append([]byte(nil), base...), 99, nil),
		append(append([]byte(nil), base...), 0x0c),
		base[:len(base)-1],
		{0x00},
		{0xff, 0xff, 0xff},
	}
	return append(out, nonCanonicalBodies(tb)...)
}

// nonCanonicalBodies is one signed-body seed for each non-canonical form
// (R13): overlong tag, value and length at depths 0-2, and out-of-range
// uint32, enum and bool values that a lax decoder would truncate.
func nonCanonicalBodies(tb testing.TB) [][]byte {
	base := marshalDet(tb, validBody())
	noFV := marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 }))
	noPD := marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil }))
	noParams := marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	pdNoLevel := marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 0 }).PolicyDecision)
	withLevel := func(v uint64) []byte {
		return fBytes(append([]byte(nil), noPD...), 9, cat(pdNoLevel, []byte{0x10}, protowire.AppendVarint(nil, v)))
	}
	withReq := func(member protowire.Number, req []byte) []byte {
		return fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, member, req))
	}
	return [][]byte{
		fVarint(append([]byte(nil), noFV...), 1, 1<<32+1),
		fVarint(append([]byte(nil), noFV...), 1, math.MaxUint64),
		cat(noFV, []byte{0x08, 0x81, 0x00}),
		cat(noFV, []byte{0x88, 0x00, 0x01}),
		withLevel(1<<32 + 4),
		withLevel(1 << 31),
		withLevel(i64(math.MinInt32 - 1)),
		fBytes(append([]byte(nil), noPD...), 9, cat(pdNoLevel, []byte{0x10, 0xff, 0xff, 0xff, 0xff, 0x0f})),
		mutateAt(tb, base, []protowire.Number{10}, mutValue),
		mutateAt(tb, base, []protowire.Number{2}, mutValue),
		mutateAt(tb, base, []protowire.Number{9}, mutTag),
		mutateAt(tb, base, []protowire.Number{9, 2}, mutValue),
		mutateAt(tb, base, []protowire.Number{8, 11, 1}, mutValue),
		withReq(17, fVarint(nil, 5, 2)),
		withReq(17, fVarint(nil, 2, 1<<32+7)),
		withReq(22, fBytes(nil, 3, cat(protowire.AppendVarint(nil, 1), overlong(2)))),
		withReq(22, fBytes(nil, 4, cat(protowire.AppendVarint(nil, math.MaxUint64), protowire.AppendVarint(nil, 1<<63)))),
		// R13 (i): repeated numeric fields written unpacked.
		withReq(22, fVarint(nil, 3, 101)),
		withReq(22, cat(fVarint(nil, 3, 101), fVarint(nil, 3, 202))),
		withReq(22, cat(fBytes(nil, 3, protowire.AppendVarint(nil, 101)), fVarint(nil, 3, 202))),
		withReq(22, fVarint(nil, 4, math.MaxUint64)),
		withReq(22, cat(fBytes(nil, 3, protowire.AppendVarint(nil, 101)), fVarint(nil, 4, 0))),
		withReq(22, fFixed64(nil, 3, 101)),
		// R13 (i), 2026-10-18: split and empty packed records.
		withReq(22, cat(fBytes(nil, 3, protowire.AppendVarint(nil, 101)), fBytes(nil, 3, protowire.AppendVarint(nil, 202)))),
		withReq(22, fBytes(nil, 3, nil)),
		withReq(22, cat(fBytes(nil, 4, nil), fBytes(nil, 4, protowire.AppendVarint(nil, 0)))),
		withReq(22, cat(fBytes(nil, 4, protowire.AppendVarint(nil, 0)), fBytes(nil, 4, nil))),
		// R13 (j), R14: explicit proto3 defaults at depths 0-2.
		fVarint(append([]byte(nil), noFV...), 1, 0),
		cat([]byte{0x08, 0x00}, noFV),
		fVarint(marshalDet(tb, bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 })), 10, 0),
		fBytes(append([]byte(nil), noPD...), 9, fBytes(marshalDet(tb, validBody().PolicyDecision), 4, nil)),
		fBytes(append([]byte(nil), noPD...), 9, cat(pdNoLevel, fVarint(nil, 2, 0))),
		withReq(17, fVarint(nil, 5, 0)),
		withReq(22, fVarint(nil, 5, 0)),
		withReq(11, fBytes(nil, 1, nil)),
	}
}

var (
	bodyDescriptor  = (&wardenv1.EnvelopeBody{}).ProtoReflect().Descriptor()
	outerDescriptor = (&wardenv1.SignedEnvelope{}).ProtoReflect().Descriptor()
)

// readVarint decodes a base-128 varint without protowire: at most 10 bytes,
// and the 10th byte may only carry bit 63.
func readVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if i == 9 && c > 1 {
			return 0, -1
		}
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, -1
}

// minimalLen is the length of the shortest varint encoding of v.
func minimalLen(v uint64) int { return (bits.Len64(v|1) + 6) / 7 }

func inRange(k protoreflect.Kind, v uint64) bool {
	switch k {
	case protoreflect.Int32Kind, protoreflect.EnumKind:
		// In int32 range exactly when the top 33 bits are all 0 (0 … MaxInt32)
		// or all 1 (sign-extended MinInt32 … -1).
		top := v >> 31
		return top == 0 || top == 1<<33-1
	case protoreflect.Uint32Kind, protoreflect.Sint32Kind:
		return v <= math.MaxUint32
	case protoreflect.BoolKind:
		return v <= 1
	}
	return true
}

// canonicalOK is an independent oracle for the canonical-encoding rule: every
// tag, length prefix, varint value and packed element in b (recursively, by
// md) is minimal, every int32/enum, uint32/sint32 and bool value is in
// range, every repeated numeric or enum field is exactly one non-empty
// packed record per message (R13 (i)), and no non-repeated, non-message
// field with implicit presence holds its explicitly encoded default (R13
// (j)). Anything it cannot parse is "not OK".
func canonicalOK(b []byte, md protoreflect.MessageDescriptor) bool {
	packedSeen := map[protowire.Number]bool{}
	for len(b) > 0 {
		tag, n := readVarint(b)
		if n < 0 || n != minimalLen(tag) {
			return false
		}
		b = b[n:]
		num, _ := protowire.DecodeTag(tag)
		fd := md.Fields().ByNumber(num)
		if fd == nil {
			return false
		}
		// R13 (j): a zero value here would be the proto3 default written out.
		implicit := !fd.IsList() && fd.Kind() != protoreflect.MessageKind && !fd.HasPresence()
		switch protowire.Type(tag & 7) {
		case protowire.VarintType:
			if fd.IsList() {
				// An unpacked element of a repeated numeric or enum field.
				return false
			}
			v, k := readVarint(b)
			if k < 0 || k != minimalLen(v) || !inRange(fd.Kind(), v) || (implicit && v == 0) {
				return false
			}
			b = b[k:]
		case protowire.BytesType:
			l, k := readVarint(b)
			// int(l) cannot overflow once l <= MaxInt32, and comparing with
			// the remaining length first keeps k+int(l) from overflowing on
			// 32-bit platforms.
			if k < 0 || k != minimalLen(l) || l > math.MaxInt32 || int(l) > len(b)-k {
				return false
			}
			end := k + int(l)
			payload := b[k:end]
			b = b[end:]
			if implicit && l == 0 {
				return false
			}
			if fd.Kind() == protoreflect.MessageKind {
				if !canonicalOK(payload, fd.Message()) {
					return false
				}
				continue
			}
			if fd.IsList() && fd.Kind() != protoreflect.BytesKind && fd.Kind() != protoreflect.StringKind {
				// R13 (i): one non-empty packed record per field per message.
				if packedSeen[num] || l == 0 {
					return false
				}
				packedSeen[num] = true
				for len(payload) > 0 {
					v, k := readVarint(payload)
					if k < 0 || k != minimalLen(v) || !inRange(fd.Kind(), v) {
						return false
					}
					payload = payload[k:]
				}
			}
		default: // the contract has no fixed-width or group fields
			return false
		}
	}
	return true
}

var allowedChecks = func() map[Code]map[int]bool {
	m := map[Code]map[int]bool{}
	for c, checks := range checkOf {
		m[c] = map[int]bool{}
		for _, n := range checks {
			m[c][n] = true
		}
	}
	return m
}()

// FuzzVerify: arbitrary raw input never panics, every rejection is
// well-formed, and the body is never decoded unless the signature verifies.
func FuzzVerify(f *testing.F) {
	v := fuzzVerifier(f)
	body := marshalDet(f, validBody())
	kid := keyIDBytes(keyA)
	sig := signBody(keyA, body)
	good := wrap(kid, body, sig)

	f.Add(good)
	f.Add([]byte{})
	f.Add(good[:len(good)-1])
	f.Add(bytes.Repeat([]byte{0xff}, MaxEnvelopeBytes+1))
	f.Add(wrap(kid, body, sig[:63]))
	f.Add(wrap(kid[:31], body, sig))
	f.Add(wrap(kid, []byte{}, sig))
	f.Add(wrap(kid, body, make([]byte, 64)))
	f.Add(wrap(kid, body, withS(sig, groupOrderL)))
	f.Add(wrap(kid, body, withS(sig, new(big.Int).Add(leToInt(sig[32:]), groupOrderL))))
	f.Add(wrap(kid, flipBit(body, 5), sig))
	f.Add(wrap(keyIDBytes(keyOther), body, signBody(keyOther, body)))
	f.Add(wrap(kid, body, signRaw(keyA, body)))
	f.Add(fBytes(append([]byte(nil), good...), 1, kid))
	f.Add(fVarint(append([]byte(nil), good...), 4, 1))
	f.Add(fGroup(append([]byte(nil), good...), 2, nil))
	// R13 (j): explicit empty outer fields.
	f.Add(cat(fBytes(nil, 1, nil), fBytes(nil, 2, body), fBytes(nil, 3, sig)))
	f.Add(cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, nil)))
	for _, b := range attackBodies(f) {
		f.Add(sealBytes(keyA, b))
	}

	pub := pubOf(keyA)
	f.Fuzz(func(t *testing.T, raw []byte) {
		d0, s0 := counters()
		res, err := v.Verify(raw)
		d1, s1 := counters()

		if d1 != d0 {
			// AC4: decoding implies a valid signature over Domain||body.
			var env wardenv1.SignedEnvelope
			if uerr := proto.Unmarshal(raw, &env); uerr != nil {
				t.Fatalf("body decoded but outer does not parse: %v", uerr)
			}
			if !ed25519.Verify(pub, signedMessage(env.GetBody()), env.GetSignature()) {
				t.Fatalf("body decoded without a valid signature")
			}
			if s1 == s0 {
				t.Fatalf("body decoded but ed25519.Verify was not called")
			}
		}
		if err == nil {
			if res == nil || res.Body == nil {
				t.Fatalf("nil result without error")
			}
			var env wardenv1.SignedEnvelope
			if uerr := proto.Unmarshal(raw, &env); uerr != nil {
				t.Fatalf("accepted but outer does not parse: %v", uerr)
			}
			if !ed25519.Verify(pub, signedMessage(env.GetBody()), env.GetSignature()) {
				t.Fatalf("accepted without a valid signature")
			}
			if len(raw) > MaxEnvelopeBytes {
				t.Fatalf("accepted an oversized envelope")
			}
			if res.KeyID != KeyIDOf(pub) {
				t.Fatalf("accepted with unexpected key id")
			}
			if !canonicalOK(raw, outerDescriptor) || !canonicalOK(env.GetBody(), bodyDescriptor) {
				t.Fatalf("accepted a non-canonical encoding: %x", raw)
			}
			return
		}
		if res != nil {
			t.Fatalf("non-nil result with error")
		}
		var rej *Rejection
		if !errors.As(err, &rej) {
			t.Fatalf("error %T is not *Rejection", err)
		}
		if !allowedChecks[rej.Code][rej.Check] {
			t.Fatalf("inconsistent rejection %s at check %d", rej.Code, rej.Check)
		}
		if rej.Check <= 4 && d1 != d0 {
			t.Fatalf("body decoded before rejection at check %d", rej.Check)
		}
		// A rejection after check 2 means the outer strict scan passed.
		if rej.Check >= 3 && !canonicalOK(raw, outerDescriptor) {
			t.Fatalf("non-canonical outer envelope passed check 2 (rejected at %d): %x", rej.Check, raw)
		}
		if len(raw) > MaxEnvelopeBytes && rej.Code != CodeOversized {
			t.Fatalf("oversized input gave %s", rej.Code)
		}
	})
}

// Independent oracles for §4.2, written separately from the implementation.
var (
	reUUIDv7   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	reUUIDv4   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	reUUIDAny  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	rePlaybook = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	reStep     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	reIdem     = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	// semver.org regular expression with the build-metadata part removed.
	reSemVer = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$`)
)

func assertNoUnknown(t *testing.T, m protoreflect.Message) {
	t.Helper()
	if len(m.GetUnknown()) != 0 {
		t.Fatalf("%s carries unknown fields", m.Descriptor().FullName())
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() {
			assertNoUnknown(t, v.Message())
		}
		return true
	})
}

func assertBodyInvariants(t *testing.T, b *wardenv1.EnvelopeBody) {
	t.Helper()
	fail := func(what string) { t.Fatalf("accepted body breaks §4.2: %s (%v)", what, b) }
	if b.GetFormatVersion() != 1 {
		fail("format_version")
	}
	if !reUUIDv7.MatchString(b.GetActionId()) {
		fail("action_id")
	}
	if !reUUIDAny.MatchString(b.GetTargetServerId()) || b.GetTargetServerId() != serverA {
		fail("target_server_id")
	}
	if !rePlaybook.MatchString(b.GetPlaybookId()) {
		fail("playbook_id")
	}
	if len(b.GetPlaybookVersion()) > 32 || !reSemVer.MatchString(b.GetPlaybookVersion()) {
		fail("playbook_version")
	}
	if len(b.GetPlaybookDigest()) != 32 {
		fail("playbook_digest")
	}
	if !reStep.MatchString(b.GetStepId()) {
		fail("step_id")
	}
	if b.GetParams() == nil || b.GetParams().GetRequest() == nil {
		fail("params")
	}
	pd := b.GetPolicyDecision()
	if pd == nil || !reUUIDv4.MatchString(pd.GetDecisionId()) || len(pd.GetPolicyBundleDigest()) != 32 {
		fail("policy_decision")
	}
	if lvl := pd.GetAutonomyLevel(); lvl < wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L0 || lvl > wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L3 {
		fail("autonomy_level")
	}
	if a := pd.GetApprovalId(); a != "" && !reUUIDv4.MatchString(a) {
		fail("approval_id")
	}
	c, e := b.GetCreatedAt(), b.GetExpiresAt()
	if c < 1 || c > maxTime || e < 1 || e > maxTime {
		fail("timestamp range")
	}
	if e <= c || e-c > 600 {
		fail("lifetime")
	}
	if c > fakeNow+60 {
		fail("not yet valid")
	}
	if fakeNow > e+60 {
		fail("expired")
	}
	k := b.GetIdempotencyKey()
	if !reIdem.MatchString(k) || strings.Contains(k, "..") {
		fail("idempotency_key")
	}
	assertNoUnknown(t, b.ProtoReflect())
}

// FuzzVerifyBody signs arbitrary body bytes with the trusted key so fuzzing
// reaches the body decoder and the §4.2 validator.
func FuzzVerifyBody(f *testing.F) {
	v := fuzzVerifier(f)
	for _, b := range attackBodies(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		raw := sealBytes(keyA, body)
		res, err := v.Verify(raw)
		if len(raw) > MaxEnvelopeBytes || len(body) == 0 {
			var rej *Rejection
			if err == nil || !errors.As(err, &rej) || (rej.Code != CodeOversized && rej.Code != CodeMalformed) {
				t.Fatalf("oversized or empty body: got %v", err)
			}
			return
		}
		if err != nil {
			var rej *Rejection
			if !errors.As(err, &rej) {
				t.Fatalf("error %T is not *Rejection", err)
			}
			if rej.Check < 5 || rej.Check > 11 || !allowedChecks[rej.Code][rej.Check] {
				t.Fatalf("correctly signed body rejected with %s at check %d", rej.Code, rej.Check)
			}
			// A rejection after check 5 means the body passed the strict
			// scan, so it must be canonical: in particular a format_version
			// written as 0 must never reach check 6 (R14, R13 (j)).
			if rej.Check >= 6 && !canonicalOK(body, bodyDescriptor) {
				t.Fatalf("non-canonical body passed check 5 (rejected with %s at check %d): %x", rej.Code, rej.Check, body)
			}
			return
		}
		if res == nil || res.Body == nil {
			t.Fatalf("nil result without error")
		}
		assertBodyInvariants(t, res.Body)
		if !canonicalOK(body, bodyDescriptor) {
			t.Fatalf("accepted a non-canonical body: %x", body)
		}
		var fresh wardenv1.EnvelopeBody
		if uerr := proto.Unmarshal(body, &fresh); uerr != nil || !proto.Equal(&fresh, res.Body) {
			t.Fatalf("returned body differs from the signed bytes: %v", uerr)
		}
	})
}
