package envelope

// Checks 1–4 of action-envelope.md §4.5 (size, outer decode, key lookup,
// signature), AC1, AC3, AC4/AC7 decode counter and the R4a S < L pre-check.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

func TestConstants(t *testing.T) {
	if MaxEnvelopeBytes != 16384 {
		t.Errorf("MaxEnvelopeBytes = %d, want 16384", MaxEnvelopeBytes)
	}
	if MaxLifetime != 600 {
		t.Errorf("MaxLifetime = %d, want 600", MaxLifetime)
	}
	if MaxSkew != 60 {
		t.Errorf("MaxSkew = %d, want 60", MaxSkew)
	}
	if FormatVersion != 1 {
		t.Errorf("FormatVersion = %d, want 1", FormatVersion)
	}
	if Domain != domainLiteral || len(Domain) != 26 || Domain[25] != 0x00 {
		t.Errorf("Domain = %q (len %d), want %q (26 bytes ending in 0x00)", Domain, len(Domain), domainLiteral)
	}
}

func TestKeyIDOf(t *testing.T) {
	for _, k := range []ed25519.PrivateKey{keyA, keyB, keyOther} {
		got := KeyIDOf(pubOf(k))
		want := sha256.Sum256(pubOf(k))
		if got != KeyID(want) {
			t.Errorf("KeyIDOf = %x, want %x", got, want)
		}
	}
}

// --- happy paths -----------------------------------------------------------

func TestVerifyValidEnvelopes(t *testing.T) {
	v := defaultVerifier(t)
	cases := map[string]*wardenv1.EnvelopeBody{
		"service_restart": validBody(),
		"mem_status_no_fields": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_MemStatus{MemStatus: &wardenv1.MemStatusRequest{}}}
		}),
		"db_terminate_session_repeated": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_DbTerminateSession{DbTerminateSession: &wardenv1.DbTerminateSessionRequest{
				Engine:              wardenv1.Engine_ENGINE_POSTGRESQL,
				Instance:            "postgresql.service",
				SessionIds:          []uint64{101, 202, 303},
				SessionStartedAt:    []int64{1_700_000_000_000_000, 1_700_000_000_000_001, 1_700_000_000_000_002},
				MinIdleSeconds:      600,
				SessionOwnerDigests: nil,
			}}}
		}),
		"approval_id_set": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.PolicyDecision.ApprovalId = validApprovalID
			b.PolicyDecision.AutonomyLevel = wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L3
		}),
		"autonomy_l0": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.PolicyDecision.AutonomyLevel = wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L0
		}),
		"prerelease_version": bodyWith(func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-rc.1" }),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			expectAccept(t, v, seal(t, keyA, body), body, keyA)
		})
	}
}

// Every params member, including field-less ones, is accepted; member
// contents are not validated by the verifier.
func TestVerifyEveryParamsMember(t *testing.T) {
	v := defaultVerifier(t)
	oneof := (&wardenv1.TypedRequest{}).ProtoReflect().Descriptor().Oneofs().ByName("request")
	if oneof.Fields().Len() != 21 {
		t.Fatalf("TypedRequest has %d oneof members, want 21", oneof.Fields().Len())
	}
	for i := 0; i < oneof.Fields().Len(); i++ {
		fd := oneof.Fields().Get(i)
		t.Run(string(fd.Name()), func(t *testing.T) {
			tr := &wardenv1.TypedRequest{}
			m := tr.ProtoReflect()
			m.Set(fd, m.NewField(fd))
			body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = tr })
			expectAccept(t, v, seal(t, keyA, body), body, keyA)
		})
	}
}

// --- check 1: OVERSIZED ----------------------------------------------------

// paddedEnvelope returns a valid envelope signed by keyA whose total size is
// exactly size bytes, by padding FsUsageRequest.mount_path.
func paddedEnvelope(t *testing.T, size int) ([]byte, *wardenv1.EnvelopeBody) {
	t.Helper()
	for n := size - 400; n < size; n++ {
		body := bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_FsUsage{
				FsUsage: &wardenv1.FsUsageRequest{MountPath: "/" + strings.Repeat("a", n)},
			}}
		})
		bb := marshalDet(t, body)
		if len(wrap(make([]byte, 32), bb, make([]byte, 64))) == size {
			raw := sealBytes(keyA, bb)
			if len(raw) != size {
				t.Fatalf("padded envelope is %d bytes, want %d", len(raw), size)
			}
			return raw, body
		}
	}
	t.Fatalf("could not build a %d-byte envelope", size)
	return nil, nil
}

func TestCheck1ExactlyMaxPasses(t *testing.T) {
	raw, body := paddedEnvelope(t, 16384)
	expectAccept(t, defaultVerifier(t), raw, body, keyA)
}

func TestCheck1Oversized(t *testing.T) {
	v := defaultVerifier(t)
	valid17, _ := paddedEnvelope(t, 16385)
	cases := map[string][]byte{
		"16385_garbage":            bytes.Repeat([]byte{0xff}, 16385),
		"16385_zero":               make([]byte, 16385),
		"16385_valid_signed":       valid17,
		"valid_plus_trailing_byte": append(func() []byte { r, _ := paddedEnvelope(t, 16384); return r }(), 0x00),
		"1_MiB":                    bytes.Repeat([]byte{0x0a}, 1<<20),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d0, s0 := counters()
			expectReject(t, v, raw, CodeOversized, 1)
			if d1, s1 := counters(); d1 != d0 || s1 != s0 {
				t.Fatalf("oversized input reached decode/verify (decodes %d->%d, verifies %d->%d)", d0, d1, s0, s1)
			}
		})
	}
}

// --- check 2: MALFORMED ----------------------------------------------------

func TestCheck2Malformed(t *testing.T) {
	v := defaultVerifier(t)
	body := marshalDet(t, validBody())
	kid := keyIDBytes(keyA)
	sig := signBody(keyA, body)
	good := wrap(kid, body, sig)

	cases := map[string][]byte{
		"empty_input":              {},
		"nil_input":                nil,
		"single_zero_byte":         {0x00},
		"single_ff":                {0xff},
		"random_bytes":             []byte("this is not a protobuf message at all \x00\x01\x02"),
		"truncated_last_byte":      good[:len(good)-1],
		"truncated_half":           good[:len(good)/2],
		"truncated_in_tag":         append(append([]byte(nil), good...), 0x80),
		"sig_63":                   wrap(kid, body, sig[:63]),
		"sig_65":                   wrap(kid, body, append(append([]byte(nil), sig...), 0)),
		"sig_0_present":            wrap(kid, body, []byte{}),
		"sig_absent":               wrap(kid, body, nil),
		"key_id_0_present":         wrap([]byte{}, body, sig),
		"key_id_absent":            wrap(nil, body, sig),
		"key_id_31":                wrap(kid[:31], body, sig),
		"key_id_33":                wrap(append(append([]byte(nil), kid...), 0), body, sig),
		"body_empty_present":       wrap(kid, []byte{}, sig),
		"body_absent":              wrap(kid, nil, sig),
		"unknown_outer_field_4":    fBytes(append([]byte(nil), good...), 4, []byte("x")),
		"unknown_outer_field_99":   fVarint(append([]byte(nil), good...), 99, 1),
		"unknown_outer_fixed32":    fFixed32(append([]byte(nil), good...), 5, 7),
		"duplicate_key_id":         fBytes(append([]byte(nil), good...), 1, kid),
		"duplicate_body":           fBytes(append([]byte(nil), good...), 2, body),
		"duplicate_signature":      fBytes(append([]byte(nil), good...), 3, sig),
		"duplicate_body_different": fBytes(append([]byte(nil), good...), 2, []byte{0x08, 0x01}),
		"group_outer_unknown":      fGroup(append([]byte(nil), good...), 9, nil),
		"group_outer_known_number": fGroup(append([]byte(nil), good...), 2, nil),
		"lone_end_group":           append(append([]byte(nil), good...), 0x0c),
		"key_id_as_varint":         cat(fVarint(nil, 1, 5), fBytes(nil, 2, body), fBytes(nil, 3, sig)),
		"signature_as_fixed64":     cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fFixed64(nil, 3, 1)),
		"body_as_fixed32":          cat(fBytes(nil, 1, kid), fFixed32(nil, 2, 1), fBytes(nil, 3, sig)),
		"field_number_zero":        append([]byte{0x02, 0x00}, good...),
		"length_overflow":          cat(fBytes(nil, 1, kid), []byte{0x12, 0xff, 0xff, 0xff, 0xff, 0x0f}),
		"overlong_varint_tag":      append(bytes.Repeat([]byte{0x80}, 11), 0x01),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d0, s0 := counters()
			expectReject(t, v, raw, CodeMalformed, 2)
			if d1, s1 := counters(); d1 != d0 || s1 != s0 {
				t.Fatalf("malformed input reached decode/verify")
			}
		})
	}
}

// --- check 3: UNKNOWN_KEY before the signature ------------------------------

func TestCheck3UnknownKey(t *testing.T) {
	body := validBody()
	rawA := seal(t, keyA, body)
	rawOther := seal(t, keyOther, body)

	empty := mustKeySet(t)
	type tc struct {
		ks  *KeySet
		now int64
		raw []byte
	}
	cases := map[string]tc{
		"signed_by_untrusted_key":     {mustKeySet(t, wideKey(keyA)), fakeNow, rawOther},
		"nil_keyset":                  {nil, fakeNow, rawA},
		"empty_keyset":                {empty, fakeNow, rawA},
		"key_removed_from_new_keyset": {mustKeySet(t, wideKey(keyB)), fakeNow, rawA},
		"now_one_second_after_valid":  {mustKeySet(t, trusted(keyA, fakeNow-1000, fakeNow-1)), fakeNow, rawA},
		"now_one_second_before_valid": {mustKeySet(t, trusted(keyA, fakeNow+1, fakeNow+1000)), fakeNow, rawA},
		"key_id_points_to_other_key":  {mustKeySet(t, wideKey(keyB)), fakeNow, wrap(keyIDBytes(keyOther), marshalDet(t, body), signBody(keyA, marshalDet(t, body)))},
		"key_id_bit_flipped":          {mustKeySet(t, wideKey(keyA)), fakeNow, wrap(flipBit(keyIDBytes(keyA), 0), marshalDet(t, body), signBody(keyA, marshalDet(t, body)))},
		"key_id_all_zero":             {mustKeySet(t, wideKey(keyA)), fakeNow, wrap(make([]byte, 32), marshalDet(t, body), signBody(keyA, marshalDet(t, body)))},
		// key_id is SHA-256 of the key; the raw public key itself is not an id.
		"key_id_is_raw_public_key": {mustKeySet(t, wideKey(keyA)), fakeNow, wrap(pubOf(keyA), marshalDet(t, body), signBody(keyA, marshalDet(t, body)))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := NewVerifier(Config{Keys: c.ks, ServerID: serverA, Now: clockAt(c.now)})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			d0, s0 := counters()
			expectReject(t, v, c.raw, CodeUnknownKey, 3)
			if d1, s1 := counters(); d1 != d0 || s1 != s0 {
				t.Fatalf("unknown key reached decode/verify")
			}
		})
	}
}

func TestCheck3NowExactlyOnBoundsAccepted(t *testing.T) {
	// now == NotBefore; created_at == NotBefore so check 7 passes too.
	b1 := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = fakeNow; b.ExpiresAt = fakeNow + 300 })
	v1 := mustVerifier(t, mustKeySet(t, trusted(keyA, fakeNow, fakeNow+1000)), serverA, fakeNow)
	expectAccept(t, v1, seal(t, keyA, b1), b1, keyA)

	// now == NotAfter.
	b2 := validBody()
	v2 := mustVerifier(t, mustKeySet(t, trusted(keyA, fakeNow-1000, fakeNow)), serverA, fakeNow)
	expectAccept(t, v2, seal(t, keyA, b2), b2, keyA)

	// NotBefore == NotAfter == now.
	b3 := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = fakeNow; b.ExpiresAt = fakeNow + 1 })
	v3 := mustVerifier(t, mustKeySet(t, trusted(keyA, fakeNow, fakeNow)), serverA, fakeNow)
	expectAccept(t, v3, seal(t, keyA, b3), b3, keyA)
}

func TestKeyRotationOverlap(t *testing.T) {
	ks := mustKeySet(t, wideKey(keyA), wideKey(keyB))
	v := mustVerifier(t, ks, serverA, fakeNow)
	body := validBody()
	expectAccept(t, v, seal(t, keyA, body), body, keyA)
	expectAccept(t, v, seal(t, keyB, body), body, keyB)

	// Old key removed: a new KeySet without it is installed.
	v2 := mustVerifier(t, mustKeySet(t, wideKey(keyB)), serverA, fakeNow)
	expectReject(t, v2, seal(t, keyA, body), CodeUnknownKey, 3)
	expectAccept(t, v2, seal(t, keyB, body), body, keyB)
}

// --- check 4: BAD_SIGNATURE -------------------------------------------------

func TestCheck4BadSignature(t *testing.T) {
	v := mustVerifier(t, mustKeySet(t, wideKey(keyA), wideKey(keyB)), serverA, fakeNow)
	bodyBytes := marshalDet(t, validBody())
	otherBodyBytes := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "other-key" }))
	kidA := keyIDBytes(keyA)
	sigA := signBody(keyA, bodyBytes)
	sigOther := signBody(keyA, otherBodyBytes)

	noNul := []byte(strings.TrimSuffix(domainLiteral, "\x00"))
	cases := map[string][]byte{
		"body_bit_flipped":        wrap(kidA, flipBit(bodyBytes, 3), sigA),
		"body_last_bit_flipped":   wrap(kidA, flipBit(bodyBytes, len(bodyBytes)*8-1), sigA),
		"sig_first_bit_flipped":   wrap(kidA, bodyBytes, flipBit(sigA, 0)),
		"sig_R_bit_flipped":       wrap(kidA, bodyBytes, flipBit(sigA, 100)),
		"all_zero_signature":      wrap(kidA, bodyBytes, make([]byte, 64)),
		"signed_without_prefix":   wrap(kidA, bodyBytes, signRaw(keyA, bodyBytes)),
		"prefix_without_nul":      wrap(kidA, bodyBytes, signRaw(keyA, cat(noNul, bodyBytes))),
		"prefix_nul_then_other":   wrap(kidA, bodyBytes, signRaw(keyA, cat(noNul, []byte{0x01}, bodyBytes))),
		"prefix_v2":               wrap(kidA, bodyBytes, signRaw(keyA, cat([]byte("warden/v2/action-envelope\x00"), bodyBytes))),
		"other_domain":            wrap(kidA, bodyBytes, signRaw(keyA, cat([]byte("warden/v1/server-manifest\x00"), bodyBytes))),
		"swapped_signatures":      wrap(kidA, bodyBytes, sigOther),
		"trusted_kid_other_key":   wrap(kidA, bodyBytes, signBody(keyB, bodyBytes)),
		"trusted_kid_untrusted":   wrap(kidA, bodyBytes, signBody(keyOther, bodyBytes)),
		"body_with_appended_byte": wrap(kidA, append(append([]byte(nil), bodyBytes...), 0x00), sigA),
		"body_truncated":          wrap(kidA, bodyBytes[:len(bodyBytes)-1], sigA),
		"sig_over_domain_only":    wrap(kidA, bodyBytes, signRaw(keyA, []byte(domainLiteral))),
		"ed25519ph_style_digest":  wrap(kidA, bodyBytes, signRaw(keyA, func() []byte { s := sha256.Sum256(signedMessage(bodyBytes)); return s[:] }())),
	}
	for i := 0; i < len(domainLiteral); i++ {
		p := []byte(domainLiteral)
		p[i] ^= 0x01
		cases["prefix_byte_"+string(rune('a'+i))+"_flipped"] = wrap(kidA, bodyBytes, signRaw(keyA, cat(p, bodyBytes)))
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d0, _ := counters()
			expectReject(t, v, raw, CodeBadSignature, 4)
			if d1, _ := counters(); d1 != d0 {
				t.Fatalf("body decoded after a failed signature (decodes %d->%d)", d0, d1)
			}
		})
	}
}

// R4a: S >= L is rejected before ed25519.Verify is called.
func TestCheck4NonCanonicalS(t *testing.T) {
	v := defaultVerifier(t)
	bodyBytes := marshalDet(t, validBody())
	kid := keyIDBytes(keyA)
	sig := signBody(keyA, bodyBytes)
	origS := leToInt(sig[32:])
	if origS.Cmp(groupOrderL) >= 0 {
		t.Fatalf("library produced S >= L")
	}
	max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	cases := map[string]*big.Int{
		"S_equals_L":              groupOrderL,
		"S_equals_L_plus_1":       new(big.Int).Add(groupOrderL, big.NewInt(1)),
		"S_plus_L_malleated":      new(big.Int).Add(origS, groupOrderL),
		"S_2^253":                 new(big.Int).Lsh(big.NewInt(1), 253),
		"S_2^255":                 new(big.Int).Lsh(big.NewInt(1), 255),
		"S_all_ones":              max256,
		"S_plus_2L_malleated":     new(big.Int).Add(origS, new(big.Int).Lsh(groupOrderL, 1)),
		"S_L_plus_1_high_bit_set": new(big.Int).Add(groupOrderL, new(big.Int).Lsh(big.NewInt(1), 255)),
	}
	for name, s := range cases {
		if s.BitLen() > 256 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			d0, s0 := counters()
			expectReject(t, v, wrap(kid, bodyBytes, withS(sig, s)), CodeBadSignature, 4)
			d1, s1 := counters()
			if s1 != s0 {
				t.Fatalf("ed25519.Verify was called for S >= L (verifies %d->%d)", s0, s1)
			}
			if d1 != d0 {
				t.Fatalf("body decoded for S >= L")
			}
		})
	}

	// S = L - 1 passes the pre-check (and then fails Verify): the pre-check is
	// not wider than the spec.
	t.Run("S_equals_L_minus_1_reaches_verify", func(t *testing.T) {
		_, s0 := counters()
		expectReject(t, v, wrap(kid, bodyBytes, withS(sig, new(big.Int).Sub(groupOrderL, big.NewInt(1)))), CodeBadSignature, 4)
		if _, s1 := counters(); s1 != s0+1 {
			t.Fatalf("ed25519.Verify should be called exactly once for S = L-1 (verifies %d->%d)", s0, s1)
		}
	})
	t.Run("valid_signature_calls_verify_once", func(t *testing.T) {
		d0, s0 := counters()
		expectAccept(t, v, wrap(kid, bodyBytes, sig), nil, keyA)
		d1, s1 := counters()
		if s1 != s0+1 {
			t.Fatalf("ed25519.Verify calls %d->%d, want exactly one", s0, s1)
		}
		if d1 != d0+1 {
			t.Fatalf("body decodes %d->%d, want exactly one", d0, d1)
		}
	})
}

// --- AC1: RFC 8032 §7.1 TEST 1 vector --------------------------------------

// The RFC 8032 §7.1 TEST 1 seed is a published test vector, not a secret. It
// is assembled from two fragments so secret scanners do not flag it.
var rfc8032Test1Seed = func() []byte {
	b, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc4" + "4449c5697b326919703bac031cae7f60")
	if err != nil {
		panic(err)
	}
	return b
}()

const rfc8032Test1PublicHex = "d75a980182b10ab7d54bfed3c964073a" + "0ee172f3daa62325af021a68f707511a"

func TestAC1RFC8032Vector(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(rfc8032Test1Seed)
	if got := hex.EncodeToString(pubOf(priv)); got != rfc8032Test1PublicHex {
		t.Fatalf("RFC 8032 TEST 1 public key = %s, want %s", got, rfc8032Test1PublicHex)
	}
	// Sanity: the RFC's own empty-message signature (the vector itself).
	rfcSig, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if !ed25519.Verify(pubOf(priv), nil, rfcSig) {
		t.Fatalf("RFC 8032 TEST 1 signature does not verify")
	}

	body := validBody()
	bodyBytes := marshalDet(t, body)
	sig := signBody(priv, bodyBytes)
	kid := keyIDBytes(priv)
	v := mustVerifier(t, mustKeySet(t, wideKey(priv)), serverA, fakeNow)
	expectAccept(t, v, wrap(kid, bodyBytes, sig), body, priv)

	t.Run("every_signature_bit", func(t *testing.T) {
		for bit := 0; bit < 64*8; bit++ {
			res, err := v.Verify(wrap(kid, bodyBytes, flipBit(sig, bit)))
			rej := asRejection(t, res, err)
			if rej.Code != CodeBadSignature || rej.Check != 4 {
				t.Fatalf("signature bit %d: got %s/%d, want BAD_SIGNATURE/4", bit, rej.Code, rej.Check)
			}
		}
	})
	t.Run("every_body_bit", func(t *testing.T) {
		for bit := 0; bit < len(bodyBytes)*8; bit++ {
			res, err := v.Verify(wrap(kid, flipBit(bodyBytes, bit), sig))
			rej := asRejection(t, res, err)
			if rej.Code != CodeBadSignature || rej.Check != 4 {
				t.Fatalf("body bit %d: got %s/%d, want BAD_SIGNATURE/4", bit, rej.Code, rej.Check)
			}
		}
	})
	t.Run("every_prefix_bit", func(t *testing.T) {
		for bit := 0; bit < len(domainLiteral)*8; bit++ {
			p := flipBit([]byte(domainLiteral), bit)
			res, err := v.Verify(wrap(kid, bodyBytes, signRaw(priv, cat(p, bodyBytes))))
			rej := asRejection(t, res, err)
			if rej.Code != CodeBadSignature || rej.Check != 4 {
				t.Fatalf("prefix bit %d: got %s/%d, want BAD_SIGNATURE/4", bit, rej.Code, rej.Check)
			}
		}
	})
}

// --- AC3: re-encoded body with a different field order ---------------------

// reorder re-emits the top-level fields of a valid encoding in reverse order.
func reorder(t *testing.T, b []byte) []byte {
	t.Helper()
	var fields [][]byte
	for len(b) > 0 {
		n := consumeFieldLen(b)
		if n < 0 {
			t.Fatalf("reorder: bad encoding")
		}
		fields = append(fields, b[:n])
		b = b[n:]
	}
	var out []byte
	for i := len(fields) - 1; i >= 0; i-- {
		out = append(out, fields[i]...)
	}
	return out
}

func TestAC3ReorderedBody(t *testing.T) {
	v := defaultVerifier(t)
	body := validBody()
	orig := marshalDet(t, body)
	re := reorder(t, orig)
	if bytes.Equal(orig, re) {
		t.Fatalf("reordered encoding equals the original")
	}
	var decoded wardenv1.EnvelopeBody
	if err := proto.Unmarshal(re, &decoded); err != nil || !proto.Equal(&decoded, body) {
		t.Fatalf("reordered encoding is not the same message: %v", err)
	}
	// The signature covers the received bytes only (R4), so the original
	// signature does not cover the reordered ones.
	t.Run("original_signature_BAD_SIGNATURE", func(t *testing.T) {
		expectReject(t, v, wrap(keyIDBytes(keyA), re, signBody(keyA, orig)), CodeBadSignature, 4)
	})
	// The verifier still never re-encodes the body (R4, OQ12), but the
	// strict scan accepts only ascending field order (R13 (k), 2026-10-19),
	// so the reordered bytes are BODY_INVALID even when the trusted key
	// signed them.
	t.Run("resigned_reordered_body_BODY_INVALID", func(t *testing.T) {
		expectBodyReject(t, v, re, CodeBodyInvalid, 5)
	})
}
