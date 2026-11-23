package advisory_test

// Attack tests for the agent's advisory decoders (issue #59): the envelope
// check of action-envelope R6 and the status hint of agent-api R31, R38,
// R52a. Written before the implementation; they fail against the stubs.

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/agent/advisory"
	"github.com/nofal82/warden-agent/internal/envelope"
)

const (
	serverA   = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	serverB   = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
	expiresAt = int64(1_800_000_000)
	maxEnv    = 16384 // SignedEnvelope max_message_bytes
	maxStatus = 28672 // SignedReplyReport.unsigned_body max_bytes
)

var det = proto.MarshalOptions{Deterministic: true}

func marshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := det.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func body(mut func(*wardenv1.EnvelopeBody)) *wardenv1.EnvelopeBody {
	b := &wardenv1.EnvelopeBody{
		FormatVersion:   1,
		ActionId:        "01890a5d-ac96-774b-bcce-b302099a8057",
		TargetServerId:  serverA,
		PlaybookId:      "service-recover",
		PlaybookVersion: "1.2.3",
		PlaybookDigest:  bytes.Repeat([]byte{0xab}, 32),
		StepId:          "restart",
		Params: &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_ServiceRestart{
			ServiceRestart: &wardenv1.ServiceRestartRequest{Unit: "nginx.service"},
		}},
		PolicyDecision: &wardenv1.PolicyDecision{
			DecisionId:         "6a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d",
			AutonomyLevel:      wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L2,
			PolicyBundleDigest: bytes.Repeat([]byte{0xcd}, 32),
		},
		CreatedAt:      expiresAt - 300,
		ExpiresAt:      expiresAt,
		IdempotencyKey: "FAKE-IDEM-123",
		// R52a, AC37: the counter field must not break the advisory decode.
		EnvelopeCounter: 42,
	}
	if mut != nil {
		mut(b)
	}
	return b
}

func signed(t testing.TB, bodyBytes []byte) []byte {
	t.Helper()
	return marshal(t, &wardenv1.SignedEnvelope{
		KeyId:     bytes.Repeat([]byte{1}, 32),
		Body:      bodyBytes,
		Signature: bytes.Repeat([]byte{2}, 64),
	})
}

func at(sec int64) time.Time { return time.Unix(sec, 0) }

// TestCheckEnvelope: action-envelope R6 (order size, expiry, target host;
// signature never checked), agent-api R23/R34 (reasons), R52a/AC37
// (envelope_counter decodes). Any decode failure forwards: the executor
// decides (R7).
func TestCheckEnvelope(t *testing.T) {
	t.Parallel()
	valid := signed(t, marshal(t, body(nil)))
	unknownField := signed(t, protowire.AppendVarint(protowire.AppendTag(marshal(t, body(nil)), 99, protowire.VarintType), 1))
	noAutonomy := signed(t, marshal(t, body(func(b *wardenv1.EnvelopeBody) {
		b.PolicyDecision.AutonomyLevel = wardenv1.AutonomyLevel_AUTONOMY_LEVEL_UNSPECIFIED
	})))
	// Over the limit and not decodable: proves size is checked first.
	oversized := bytes.Repeat([]byte{0xff}, maxEnv+1)
	const (
		fwd      = agentapiv1.AdvisoryReason_ADVISORY_REASON_UNSPECIFIED
		big      = agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_OVERSIZED
		expired  = agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_EXPIRED
		wrongHst = agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_WRONG_HOST
	)
	cases := []struct {
		name    string
		b       []byte
		server  string
		now     int64
		forward bool
		reason  agentapiv1.AdvisoryReason
	}{
		{"valid with envelope_counter (R52a, AC37)", valid, serverA, expiresAt - 100, true, fwd},
		{"exactly expires_at + MaxSkew forwards (R16)", valid, serverA, expiresAt + envelope.MaxSkew, true, fwd},
		{"not yet valid forwards (executor decides)", valid, serverA, expiresAt - 100_000, true, fwd},
		{"oversized, undecodable (R11 first)", oversized, serverA, expiresAt, false, big},
		{"expired by one second", valid, serverA, expiresAt + envelope.MaxSkew + 1, false, expired},
		{"wrong host", valid, serverB, expiresAt, false, wrongHst},
		{"expired and wrong host: expiry first", valid, serverB, expiresAt + envelope.MaxSkew + 1, false, expired},
		{"outer garbage forwards", []byte{0x0a, 0x05, 0x01}, serverA, expiresAt, true, fwd},
		{"body with unknown field forwards (R13)", unknownField, serverA, expiresAt, true, fwd},
		{"body autonomy UNSPECIFIED forwards (V4)", noAutonomy, serverA, expiresAt, true, fwd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := append([]byte(nil), tc.b...)
			v := advisory.CheckEnvelope(in, tc.server, at(tc.now))
			if v.Forward != tc.forward || v.Reason != tc.reason {
				t.Fatalf("CheckEnvelope = %+v; want Forward=%v Reason=%v", v, tc.forward, tc.reason)
			}
			if !bytes.Equal(in, tc.b) {
				t.Fatal("CheckEnvelope modified its input")
			}
		})
	}
}

func statusBody(mut func(*wardenv1.ExecutorStatusBody)) *wardenv1.ExecutorStatusBody {
	s := &wardenv1.ExecutorStatusBody{
		FormatVersion: 1,
		TrustState:    wardenv1.TrustState_TRUST_STATE_AVAILABLE,
		FeatureLevel: &wardenv1.FeatureLevel{
			CgroupVersion:   wardenv1.CgroupVersion_CGROUP_VERSION_V2,
			HelperLaunch:    wardenv1.HelperLaunchMethod_HELPER_LAUNCH_METHOD_CLONE_INTO_CGROUP,
			HelperCleanup:   wardenv1.HelperCleanupMethod_HELPER_CLEANUP_METHOD_CGROUP_KILL,
			ProcessIdentity: wardenv1.ProcessIdentityMethod_PROCESS_IDENTITY_METHOD_PIDFD,
		},
		RecoveryPending: true,
		RecoveryId:      bytes.Repeat([]byte{0x24}, 24),
		ResultSequence:  77,
		// R52a, AC37: fields 31 and 32.
		BootId:                 bytes.Repeat([]byte{0x16}, 16),
		HighestEnvelopeCounter: 1 << 40,
	}
	if mut != nil {
		mut(s)
	}
	return s
}

// TestDecodeStatusValid: agent-api R31, R38, R52a, AC37. The hint carries
// the fields and does not alias the input.
func TestDecodeStatusValid(t *testing.T) {
	t.Parallel()
	in := marshal(t, statusBody(nil))
	h, ok := advisory.DecodeStatus(in)
	if !ok {
		t.Fatal("DecodeStatus refused a valid body with boot_id and highest_envelope_counter")
	}
	if !bytes.Equal(h.BootID, bytes.Repeat([]byte{0x16}, 16)) || h.ResultSequence != 77 ||
		!h.RecoveryPending || !bytes.Equal(h.RecoveryID, bytes.Repeat([]byte{0x24}, 24)) {
		t.Fatalf("hint = %+v", h)
	}
	for i := range in {
		in[i] ^= 0xff
	}
	if !bytes.Equal(h.BootID, bytes.Repeat([]byte{0x16}, 16)) || !bytes.Equal(h.RecoveryID, bytes.Repeat([]byte{0x24}, 24)) {
		t.Fatal("hint slices alias the input")
	}
}

// TestDecodeStatusRefuses: agent-api R31/R38 (strict decode, R13), R12
// and V4 (declared values, boot_id required), size limit of
// SignedReplyReport.unsigned_body.
func TestDecodeStatusRefuses(t *testing.T) {
	t.Parallel()
	valid := marshal(t, statusBody(nil))
	oversized := marshal(t, statusBody(func(s *wardenv1.ExecutorStatusBody) {
		s.KeysetSignedBytes = make([]byte, maxStatus) // well-formed, just too large
		for i := range s.KeysetSignedBytes {
			s.KeysetSignedBytes[i] = 1
		}
	}))
	cases := []struct {
		name string
		b    []byte
	}{
		{"over 28672 bytes", oversized},
		{"unknown field", protowire.AppendVarint(protowire.AppendTag(append([]byte(nil), valid...), 99, protowire.VarintType), 1)},
		{"boot_id 15 bytes", marshal(t, statusBody(func(s *wardenv1.ExecutorStatusBody) { s.BootId = s.BootId[:15] }))},
		{"boot_id absent", marshal(t, statusBody(func(s *wardenv1.ExecutorStatusBody) { s.BootId = nil }))},
		{"trust_state 99", marshal(t, statusBody(func(s *wardenv1.ExecutorStatusBody) { s.TrustState = 99 }))},
	}
	if len(oversized) <= maxStatus {
		t.Fatalf("oversized case is %d bytes", len(oversized))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if h, ok := advisory.DecodeStatus(tc.b); ok {
				t.Fatalf("DecodeStatus = %+v, true; want refused", h)
			}
		})
	}
}

// FuzzCheckEnvelope: AC47, R6. Never panics, never modifies its input,
// and never refuses to forward without naming a reason.
func FuzzCheckEnvelope(f *testing.F) {
	valid := signed(f, marshal(f, body(nil)))
	f.Add(valid, expiresAt)
	f.Add(valid, expiresAt+envelope.MaxSkew+1)
	f.Add(signed(f, marshal(f, body(func(b *wardenv1.EnvelopeBody) { b.TargetServerId = serverB }))), expiresAt)
	f.Add(bytes.Repeat([]byte{0xff}, maxEnv+1), expiresAt)
	f.Add([]byte{0x0a, 0x05, 0x01}, expiresAt)
	f.Add([]byte{}, int64(0))
	f.Fuzz(func(t *testing.T, b []byte, now int64) {
		orig := append([]byte(nil), b...)
		v := advisory.CheckEnvelope(b, serverA, at(now))
		if !bytes.Equal(b, orig) {
			t.Fatal("CheckEnvelope modified its input")
		}
		if !v.Forward && v.Reason == agentapiv1.AdvisoryReason_ADVISORY_REASON_UNSPECIFIED {
			t.Fatal("not forwarded without a reason")
		}
		if v.Forward && v.Reason != agentapiv1.AdvisoryReason_ADVISORY_REASON_UNSPECIFIED {
			t.Fatalf("forwarded with reason %v", v.Reason)
		}
		if len(b) > maxEnv && (v.Forward || v.Reason != agentapiv1.AdvisoryReason_ADVISORY_REASON_NOT_FORWARDED_OVERSIZED) {
			t.Fatalf("%d bytes: %+v; want NOT_FORWARDED_OVERSIZED", len(b), v)
		}
	})
}

// FuzzDecodeStatus: AC47, R31, R38. Never panics; ok implies a 16-byte
// boot_id.
func FuzzDecodeStatus(f *testing.F) {
	valid := marshal(f, statusBody(nil))
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add(append(append([]byte(nil), valid...), valid...))
	f.Add(marshal(f, statusBody(func(s *wardenv1.ExecutorStatusBody) { s.BootId = nil })))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, ok := advisory.DecodeStatus(b)
		if ok && len(h.BootID) != 16 {
			t.Fatalf("ok with a %d-byte boot_id", len(h.BootID))
		}
		if ok && len(b) > maxStatus {
			t.Fatalf("ok with %d bytes", len(b))
		}
	})
}
