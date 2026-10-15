package envelope

import (
	"fmt"
	"testing"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// codeOfCheck is the code each §4.5 check 1–11 returns.
var codeOfCheck = map[int]Code{
	1: CodeOversized, 2: CodeMalformed, 3: CodeUnknownKey, 4: CodeBadSignature,
	5: CodeBodyInvalid, 6: CodeUnsupportedFormatVersion, 7: CodeUnknownKey,
	8: CodeLifetimeInvalid, 9: CodeNotYetValid, 10: CodeExpired, 11: CodeWrongHost,
}

// failing builds a verifier and an envelope that fail every check in fail
// (and possibly later checks, never earlier ones).
func failing(t *testing.T, fail map[int]bool) (*Verifier, []byte) {
	t.Helper()
	notBefore, notAfter := fakeNow-10_000, fakeNow+10_000
	created, expires := fakeNow, fakeNow+300

	switch {
	case fail[7] && fail[9]:
		// created_at after the key's validity ends and too far ahead.
		notAfter = fakeNow + 30
		created, expires = fakeNow+61, fakeNow+361
	case fail[7]:
		// created_at before the key's validity starts (also expired).
		created, expires = notBefore-1, notBefore+299
	case fail[9]:
		created, expires = fakeNow+61, fakeNow+361
	case fail[10]:
		created, expires = fakeNow-1000, fakeNow-700
	}
	if fail[8] {
		expires = created
	}

	body := bodyWith(func(b *wardenv1.EnvelopeBody) {
		b.CreatedAt, b.ExpiresAt = created, expires
		if fail[5] {
			b.PlaybookId = "BAD"
		}
		if fail[6] {
			b.FormatVersion = 2
		}
		if fail[11] {
			b.TargetServerId = serverB
		}
	})
	v := mustVerifier(t, mustKeySet(t, trusted(keyA, notBefore, notAfter)), serverA, fakeNow)

	signer := keyA
	if fail[3] {
		signer = keyOther
	}
	bodyBytes := marshalDet(t, body)
	sig := signBody(signer, bodyBytes)
	if fail[4] {
		sig[0] ^= 0x01 // R half: S stays canonical, so Ed25519 itself rejects it
	}
	raw := wrap(keyIDBytes(signer), bodyBytes, sig)
	if fail[2] {
		raw = fVarint(raw, 99, 1)
	}
	if fail[1] {
		raw = fBytes(raw, 98, make([]byte, MaxEnvelopeBytes))
	}
	return v, raw
}

// TestAC24AllPairs covers every pair of stateless checks: an envelope that
// fails both returns the earlier check's code (AC24). Each single failure is
// run first to prove the builder fails exactly the intended check.
func TestAC24AllPairs(t *testing.T) {
	for i := 1; i <= 11; i++ {
		t.Run(fmt.Sprintf("only_%d", i), func(t *testing.T) {
			v, raw := failing(t, map[int]bool{i: true})
			expectReject(t, v, raw, codeOfCheck[i], i)
		})
	}
	for i := 1; i <= 11; i++ {
		for j := i + 1; j <= 11; j++ {
			if i == 9 && j == 10 {
				// Infeasible without also failing check 8: created_at
				// beyond now+skew and expires_at+skew before now means
				// expires_at < created_at.
				continue
			}
			t.Run(fmt.Sprintf("%d_and_%d", i, j), func(t *testing.T) {
				v, raw := failing(t, map[int]bool{i: true, j: true})
				expectReject(t, v, raw, codeOfCheck[i], i)
			})
		}
	}
}

// TestCallerBufferReuse checks that overwriting the caller's buffer after
// Verify returns does not change the returned body (the verifier keeps its
// own copy of the signed bytes).
func TestCallerBufferReuse(t *testing.T) {
	v := defaultVerifier(t)
	want := validBody()
	raw := seal(t, keyA, want)
	res, err := v.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for i := range raw {
		raw[i] = 0xff
	}
	if res.Body.GetActionId() != want.GetActionId() || res.Body.GetPlaybookId() != want.GetPlaybookId() {
		t.Fatal("returned body changed when the caller reused its buffer")
	}
}
