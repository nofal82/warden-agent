package envelope

// AC24 ordering pairs among checks 1–11, the AC4/AC7 decode counter across
// every check, keyset and verifier construction, and concurrent use.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

func TestAC24OrderingPairs(t *testing.T) {
	nb, na := fakeNow-100, fakeNow+30
	vNarrow := mustVerifier(t, mustKeySet(t, trusted(keyA, nb, na)), serverA, fakeNow)
	vA := defaultVerifier(t)
	vB := mustVerifier(t, mustKeySet(t, wideKey(keyA)), serverB, fakeNow)

	oversizedBadSig := func() []byte {
		body := bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_FsUsage{
				FsUsage: &wardenv1.FsUsageRequest{MountPath: "/" + strings.Repeat("a", 17000)}}}
		})
		return wrap(keyIDBytes(keyA), marshalDet(t, body), make([]byte, 64))
	}()
	bodyBytes := marshalDet(t, validBody())
	invalidBody := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.ActionId = "x" }))

	type tc struct {
		v     *Verifier
		raw   []byte
		code  Code
		check int
	}
	cases := map[string]tc{
		"oversized+bad_signature": {vA, oversizedBadSig, CodeOversized, 1},
		"oversized+malformed":     {vA, bytes.Repeat([]byte{0xff}, MaxEnvelopeBytes+1), CodeOversized, 1},
		"malformed+unknown_key": {vA, wrap(keyIDBytes(keyOther), bodyBytes,
			append(signBody(keyOther, bodyBytes), 0)), CodeMalformed, 2},
		"malformed_kid_len+bad_sig": {vA, wrap(keyIDBytes(keyA)[:31], bodyBytes, make([]byte, 64)), CodeMalformed, 2},
		"unknown_key+bad_signature": {vA, wrap(keyIDBytes(keyOther), bodyBytes, make([]byte, 64)), CodeUnknownKey, 3},
		"unknown_key+bad_created_at": {vA, seal(t, keyOther, bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 })),
			CodeUnknownKey, 3},
		"unknown_key+invalid_body": {vA, sealBytes(keyOther, invalidBody), CodeUnknownKey, 3},
		"bad_signature+invalid_body": {vA, wrap(keyIDBytes(keyA), invalidBody, signBody(keyA, bodyBytes)),
			CodeBadSignature, 4},
		"bad_signature+S_ge_L+format_0": {vA, wrap(keyIDBytes(keyA), marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })),
			withS(make([]byte, 64), groupOrderL)), CodeBadSignature, 4},
		"body_invalid+format_2": {vA, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.FormatVersion = 2
			b.ActionId = "x"
		})), CodeBodyInvalid, 5},
		"body_invalid+wrong_host": {vB, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = ".." })),
			CodeBodyInvalid, 5},
		"body_invalid+expired": {vA, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = 1 << 40
			b.ExpiresAt = 100
		})), CodeBodyInvalid, 5},
		"format_2+created_outside_key": {vNarrow, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.FormatVersion = 2
			b.CreatedAt = nb - 1
			b.ExpiresAt = nb + 100
		})), CodeUnsupportedFormatVersion, 6},
		"format_2+wrong_host": {vB, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 2 })),
			CodeUnsupportedFormatVersion, 6},
		"format_0+expired": {vA, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.FormatVersion = 0
			b.CreatedAt = 10
			b.ExpiresAt = 20
		})), CodeUnsupportedFormatVersion, 6},
		"created_outside_key+lifetime": {vNarrow, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = nb - 1
			b.ExpiresAt = nb - 1
		})), CodeUnknownKey, 7},
		"created_outside_key+not_yet_valid": {vNarrow, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = fakeNow + 61
			b.ExpiresAt = fakeNow + 200
		})), CodeUnknownKey, 7},
		"created_outside_key+wrong_host": {mustVerifier(t, mustKeySet(t, trusted(keyA, nb, na)), serverB, fakeNow),
			seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = nb - 1; b.ExpiresAt = nb + 100 })),
			CodeUnknownKey, 7},
		"lifetime+expired": {vA, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = 1000
			b.ExpiresAt = 1000 + 601
		})), CodeLifetimeInvalid, 8},
		"lifetime+not_yet_valid": {vA, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = fakeNow + 1000
			b.ExpiresAt = fakeNow + 1000
		})), CodeLifetimeInvalid, 8},
		"lifetime+wrong_host": {vB, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = b.CreatedAt })),
			CodeLifetimeInvalid, 8},
		"not_yet_valid+wrong_host": {vB, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = fakeNow + 61
			b.ExpiresAt = fakeNow + 300
		})), CodeNotYetValid, 9},
		"expired+wrong_host": {vB, seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = fakeNow - 400
			b.ExpiresAt = fakeNow - 61
		})), CodeExpired, 10},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d0, _ := counters()
			expectReject(t, c.v, c.raw, c.code, c.check)
			d1, _ := counters()
			if c.check <= 4 && d1 != d0 {
				t.Fatalf("body decoded for a rejection at check %d", c.check)
			}
			if c.check >= 5 && d1 == d0 {
				t.Fatalf("body not decoded for a rejection at check %d", c.check)
			}
		})
	}
}

// Every code in checkOf has a canonical spelling (the reason codes are part of
// the contract with the control plane).
func TestCodeSpellings(t *testing.T) {
	want := map[Code]string{
		CodeOversized:                "OVERSIZED",
		CodeMalformed:                "MALFORMED",
		CodeUnknownKey:               "UNKNOWN_KEY",
		CodeBadSignature:             "BAD_SIGNATURE",
		CodeBodyInvalid:              "BODY_INVALID",
		CodeUnsupportedFormatVersion: "UNSUPPORTED_FORMAT_VERSION",
		CodeLifetimeInvalid:          "LIFETIME_INVALID",
		CodeNotYetValid:              "NOT_YET_VALID",
		CodeExpired:                  "EXPIRED",
		CodeWrongHost:                "WRONG_HOST",
	}
	for c, s := range want {
		if string(c) != s {
			t.Errorf("code %q, want %q", c, s)
		}
	}
	if len(want) != len(checkOf) {
		t.Fatalf("test tables out of sync")
	}
}

// --- keyset and verifier construction ----------------------------------------

func TestNewKeySetErrors(t *testing.T) {
	pub := pubOf(keyA)
	cases := map[string][]TrustedKey{
		"key_31_bytes":          {{PublicKey: pub[:31], NotBefore: 1, NotAfter: 2}},
		"key_33_bytes":          {{PublicKey: append(append(ed25519.PublicKey(nil), pub...), 0), NotBefore: 1, NotAfter: 2}},
		"key_0_bytes":           {{PublicKey: ed25519.PublicKey{}, NotBefore: 1, NotAfter: 2}},
		"key_nil":               {{PublicKey: nil, NotBefore: 1, NotAfter: 2}},
		"key_64_bytes_private":  {{PublicKey: ed25519.PublicKey(keyA), NotBefore: 1, NotAfter: 2}},
		"not_before_gt_after":   {{PublicKey: pub, NotBefore: 10, NotAfter: 9}},
		"not_before_zero":       {{PublicKey: pub, NotBefore: 0, NotAfter: 9}},
		"not_before_negative":   {{PublicKey: pub, NotBefore: -5, NotAfter: 9}},
		"duplicate_key":         {wideKey(keyA), wideKey(keyA)},
		"duplicate_diff_bounds": {wideKey(keyA), trusted(keyA, 5, 6)},
		"one_bad_among_good":    {wideKey(keyA), {PublicKey: pub[:31], NotBefore: 1, NotAfter: 2}},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			ks, err := NewKeySet(keys...)
			if err == nil {
				t.Fatalf("NewKeySet accepted invalid keys")
			}
			if ks != nil {
				t.Errorf("NewKeySet returned a non-nil set with an error")
			}
		})
	}
	for name, keys := range map[string][]TrustedKey{
		"zero_keys":      nil,
		"one_key":        {wideKey(keyA)},
		"two_keys":       {wideKey(keyA), wideKey(keyB)},
		"equal_bounds":   {trusted(keyA, 7, 7)},
		"max_not_after":  {trusted(keyA, 1, 1<<62)},
		"not_before_one": {trusted(keyA, 1, 1)},
	} {
		t.Run("ok_"+name, func(t *testing.T) {
			if _, err := NewKeySet(keys...); err != nil {
				t.Fatalf("NewKeySet: %v", err)
			}
		})
	}
}

// The key set must not alias the caller's key slice.
func TestKeySetCopiesKeys(t *testing.T) {
	pub := append(ed25519.PublicKey(nil), pubOf(keyA)...)
	ks := mustKeySet(t, TrustedKey{PublicKey: pub, NotBefore: 1, NotAfter: maxTime})
	copy(pub, pubOf(keyB))
	v := mustVerifier(t, ks, serverA, fakeNow)
	body := validBody()
	expectAccept(t, v, seal(t, keyA, body), body, keyA)
	expectReject(t, v, seal(t, keyB, body), CodeUnknownKey, 3)
}

func TestNewVerifierErrors(t *testing.T) {
	ks := mustKeySet(t, wideKey(keyA))
	cases := map[string]Config{
		"nil_now":             {Keys: ks, ServerID: serverA, Now: nil},
		"empty_server_id":     {Keys: ks, ServerID: "", Now: clockAt(fakeNow)},
		"uppercase_server_id": {Keys: ks, ServerID: strings.ToUpper(serverA), Now: clockAt(fakeNow)},
		"garbage_36_chars":    {Keys: ks, ServerID: strings.Repeat("z", 36), Now: clockAt(fakeNow)},
		"hyphens_misplaced":   {Keys: ks, ServerID: "6f1c2d3e4-a5b-4c6d-8e7f-90a1b2c3d4e5", Now: clockAt(fakeNow)},
		"trailing_newline":    {Keys: ks, ServerID: serverA + "\n", Now: clockAt(fakeNow)},
		"leading_space":       {Keys: ks, ServerID: " " + serverA[1:], Now: clockAt(fakeNow)},
		"braced":              {Keys: ks, ServerID: "{" + serverA + "}", Now: clockAt(fakeNow)},
		"no_hyphens":          {Keys: ks, ServerID: strings.ReplaceAll(serverA, "-", ""), Now: clockAt(fakeNow)},
		"with_nul":            {Keys: ks, ServerID: serverA[:35] + "\x00", Now: clockAt(fakeNow)},
		"path":                {Keys: ks, ServerID: "/etc/warden/server-id", Now: clockAt(fakeNow)},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := NewVerifier(cfg)
			if err == nil {
				t.Fatalf("NewVerifier accepted an invalid config")
			}
			if v != nil {
				t.Errorf("NewVerifier returned a verifier with an error")
			}
		})
	}
	// nil keyset is allowed at construction (fail closed at check 3).
	if _, err := NewVerifier(Config{Keys: nil, ServerID: serverA, Now: clockAt(fakeNow)}); err != nil {
		t.Fatalf("NewVerifier with nil keyset: %v", err)
	}
}

// The verifier reads the clock on every call; a later clock expires an
// envelope accepted earlier.
func TestClockReadPerCall(t *testing.T) {
	var mu sync.Mutex
	now := fakeNow
	v, err := NewVerifier(Config{Keys: mustKeySet(t, wideKey(keyA)), ServerID: serverA, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clockAt(now)()
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := validBody()
	raw := seal(t, keyA, body)
	expectAccept(t, v, raw, body, keyA)
	mu.Lock()
	now = body.ExpiresAt + 61
	mu.Unlock()
	expectReject(t, v, raw, CodeExpired, 10)
}

// --- concurrency ---------------------------------------------------------------

func TestVerifyConcurrent(t *testing.T) {
	v := mustVerifier(t, mustKeySet(t, wideKey(keyA), wideKey(keyB)), serverA, fakeNow)
	good := validBody()
	inputs := []struct {
		raw  []byte
		code Code
	}{
		{seal(t, keyA, good), ""},
		{seal(t, keyB, good), ""},
		{seal(t, keyOther, good), CodeUnknownKey},
		{wrap(keyIDBytes(keyA), marshalDet(t, good), make([]byte, 64)), CodeBadSignature},
		{seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" })), CodeBodyInvalid},
		{seal(t, keyA, bodyWith(func(b *wardenv1.EnvelopeBody) { b.TargetServerId = serverB })), CodeWrongHost},
		{[]byte{0xff}, CodeMalformed},
	}
	const workers = 64
	const rounds = 25
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				in := inputs[(w+r)%len(inputs)]
				res, err := v.Verify(in.raw)
				if in.code == "" {
					if err != nil || res == nil {
						errs <- "valid envelope rejected concurrently"
						return
					}
					continue
				}
				var rej *Rejection
				if !errors.As(err, &rej) || rej.Code != in.code || res != nil {
					errs <- "wrong concurrent rejection"
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
