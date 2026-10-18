package envelope

// Checks 5–11 of action-envelope.md §4.5: body decode and §4.2 limits,
// format version, created_at within key validity, lifetime, skew, expiry and
// target host. Every case here is correctly signed by a trusted key, so the
// body is always decoded (AC7 decode counter).

import (
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// expectBodyReject signs body bytes with keyA and expects code/check, and
// that the body decode started exactly once.
func expectBodyReject(t *testing.T, v *Verifier, body []byte, code Code, check int) {
	t.Helper()
	d0, s0 := counters()
	expectReject(t, v, sealBytes(keyA, body), code, check)
	d1, s1 := counters()
	if s1 != s0+1 {
		t.Errorf("signature verifications %d->%d, want exactly one", s0, s1)
	}
	if d1 != d0+1 {
		t.Errorf("body decodes %d->%d, want exactly one (signature verified)", d0, d1)
	}
}

// --- check 5: field values (§4.2) -------------------------------------------

func TestCheck5FieldValues(t *testing.T) {
	v := defaultVerifier(t)
	type mut = func(b *wardenv1.EnvelopeBody)
	invalid := map[string]mut{
		// missing required fields (format_version excluded: check 6)
		"missing_action_id":            func(b *wardenv1.EnvelopeBody) { b.ActionId = "" },
		"missing_target_server_id":     func(b *wardenv1.EnvelopeBody) { b.TargetServerId = "" },
		"missing_playbook_id":          func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "" },
		"missing_playbook_version":     func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "" },
		"missing_playbook_digest":      func(b *wardenv1.EnvelopeBody) { b.PlaybookDigest = nil },
		"missing_step_id":              func(b *wardenv1.EnvelopeBody) { b.StepId = "" },
		"missing_params":               func(b *wardenv1.EnvelopeBody) { b.Params = nil },
		"params_present_no_member":     func(b *wardenv1.EnvelopeBody) { b.Params = &wardenv1.TypedRequest{} },
		"missing_policy_decision":      func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil },
		"empty_policy_decision":        func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = &wardenv1.PolicyDecision{} },
		"missing_created_at":           func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 },
		"missing_expires_at":           func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = 0 },
		"missing_idempotency_key":      func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "" },
		"missing_decision_id":          func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.DecisionId = "" },
		"missing_autonomy_level":       func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 0 },
		"missing_policy_bundle_digest": func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.PolicyBundleDigest = nil },

		// action_id: UUID v7 lowercase
		"action_id_uppercase":       func(b *wardenv1.EnvelopeBody) { b.ActionId = strings.ToUpper(validActionID) },
		"action_id_v1":              func(b *wardenv1.EnvelopeBody) { b.ActionId = "01920f3e-7c4a-1b2d-8e5f-0a1b2c3d4e5f" },
		"action_id_v4":              func(b *wardenv1.EnvelopeBody) { b.ActionId = "01920f3e-7c4a-4b2d-8e5f-0a1b2c3d4e5f" },
		"action_id_35_chars":        func(b *wardenv1.EnvelopeBody) { b.ActionId = validActionID[:35] },
		"action_id_37_chars":        func(b *wardenv1.EnvelopeBody) { b.ActionId = validActionID + "0" },
		"action_id_bad_variant":     func(b *wardenv1.EnvelopeBody) { b.ActionId = "01920f3e-7c4a-7b2d-ce5f-0a1b2c3d4e5f" },
		"action_id_no_hyphens":      func(b *wardenv1.EnvelopeBody) { b.ActionId = strings.ReplaceAll(validActionID, "-", "") },
		"action_id_braces":          func(b *wardenv1.EnvelopeBody) { b.ActionId = "{" + validActionID + "}" },
		"action_id_trailing_nl":     func(b *wardenv1.EnvelopeBody) { b.ActionId = validActionID + "\n" },
		"action_id_leading_space":   func(b *wardenv1.EnvelopeBody) { b.ActionId = " " + validActionID },
		"action_id_nul":             func(b *wardenv1.EnvelopeBody) { b.ActionId = validActionID[:35] + "\x00" },
		"action_id_fullwidth_digit": func(b *wardenv1.EnvelopeBody) { b.ActionId = "０" + validActionID[1:] },
		"action_id_non_hex":         func(b *wardenv1.EnvelopeBody) { b.ActionId = "g1920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f" },
		"action_id_10KB":            func(b *wardenv1.EnvelopeBody) { b.ActionId = strings.Repeat("a", 10*1024) },

		// target_server_id: any-version UUID, lowercase
		"target_uppercase":   func(b *wardenv1.EnvelopeBody) { b.TargetServerId = strings.ToUpper(serverA) },
		"target_35_chars":    func(b *wardenv1.EnvelopeBody) { b.TargetServerId = serverA[:35] },
		"target_non_hex":     func(b *wardenv1.EnvelopeBody) { b.TargetServerId = "zf1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5" },
		"target_path":        func(b *wardenv1.EnvelopeBody) { b.TargetServerId = "../../etc/warden/server-id" },
		"target_with_nul":    func(b *wardenv1.EnvelopeBody) { b.TargetServerId = serverA + "\x00" },
		"target_wildcard":    func(b *wardenv1.EnvelopeBody) { b.TargetServerId = "*" },
		"target_trailing_nl": func(b *wardenv1.EnvelopeBody) { b.TargetServerId = serverA + "\n" },

		// playbook_id ^[a-z][a-z0-9-]{1,62}$
		"playbook_id_1_char":       func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "a" },
		"playbook_id_64_chars":     func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "a" + strings.Repeat("b", 63) },
		"playbook_id_leading_dig":  func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "1disk" },
		"playbook_id_leading_dash": func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "-disk" },
		"playbook_id_uppercase":    func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "Disk-cleanup" },
		"playbook_id_traversal":    func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "../disk" },
		"playbook_id_slash":        func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "disk/cleanup" },
		"playbook_id_underscore":   func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "disk_cleanup" },
		"playbook_id_dot":          func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "disk.cleanup" },
		"playbook_id_space":        func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "disk cleanup" },
		"playbook_id_semicolon":    func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "disk;reboot" },
		"playbook_id_trailing_nl":  func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "disk\n" },
		"playbook_id_option":       func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "--config=/tmp/x" },

		// step_id ^[a-z][a-z0-9-]{0,62}$
		"step_id_64_chars":     func(b *wardenv1.EnvelopeBody) { b.StepId = "a" + strings.Repeat("b", 63) },
		"step_id_leading_dig":  func(b *wardenv1.EnvelopeBody) { b.StepId = "1a" },
		"step_id_underscore":   func(b *wardenv1.EnvelopeBody) { b.StepId = "a_b" },
		"step_id_uppercase":    func(b *wardenv1.EnvelopeBody) { b.StepId = "Restart" },
		"step_id_subst":        func(b *wardenv1.EnvelopeBody) { b.StepId = "a$(id)" },
		"step_id_trailing_nl":  func(b *wardenv1.EnvelopeBody) { b.StepId = "restart\n" },
		"step_id_cyrillic_a":   func(b *wardenv1.EnvelopeBody) { b.StepId = "restаrt" },
		"step_id_leading_dash": func(b *wardenv1.EnvelopeBody) { b.StepId = "-x" },

		// playbook_version: SemVer 2.0.0 without build metadata, ≤ 32
		"version_leading_zero":    func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "01.2.3" },
		"version_two_parts":       func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2" },
		"version_four_parts":      func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3.4" },
		"version_build_metadata":  func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3+build" },
		"version_pre_and_build":   func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-rc.1+b5" },
		"version_v_prefix":        func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "v1.2.3" },
		"version_prerelease_01":   func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-01" },
		"version_empty_prerel":    func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-" },
		"version_empty_ident":     func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-rc..1" },
		"version_leading_space":   func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = " 1.2.3" },
		"version_trailing_nl":     func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3\n" },
		"version_negative":        func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "-1.2.3" },
		"version_33_chars":        func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.0.0-" + strings.Repeat("a", 27) },
		"version_underscore_pre":  func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-rc_1" },
		"version_minor_lead_zero": func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.02.3" },
		"version_patch_lead_zero": func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.03" },

		// digests exactly 32 bytes
		"playbook_digest_31": func(b *wardenv1.EnvelopeBody) { b.PlaybookDigest = b.PlaybookDigest[:31] },
		"playbook_digest_33": func(b *wardenv1.EnvelopeBody) { b.PlaybookDigest = append(b.PlaybookDigest, 0) },
		"playbook_digest_64": func(b *wardenv1.EnvelopeBody) { b.PlaybookDigest = append(b.PlaybookDigest, b.PlaybookDigest...) },
		"policy_bundle_digest_31": func(b *wardenv1.EnvelopeBody) {
			b.PolicyDecision.PolicyBundleDigest = b.PolicyDecision.PolicyBundleDigest[:31]
		},
		"policy_bundle_digest_33": func(b *wardenv1.EnvelopeBody) {
			b.PolicyDecision.PolicyBundleDigest = append(b.PolicyDecision.PolicyBundleDigest, 0)
		},

		// policy_decision
		"decision_id_v7":         func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.DecisionId = validActionID },
		"decision_id_uppercase":  func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.DecisionId = strings.ToUpper(validDecisionID) },
		"decision_id_bad_var":    func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.DecisionId = "3c4d5e6f-7a8b-4c9d-0e0f-1a2b3c4d5e6f" },
		"autonomy_5":             func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 5 },
		"autonomy_99":            func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 99 },
		"autonomy_negative":      func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = -1 },
		"autonomy_max_int32":     func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = math.MaxInt32 },
		"approval_id_v7":         func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = validActionID },
		"approval_id_uppercase":  func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = strings.ToUpper(validApprovalID) },
		"approval_id_garbage":    func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = "approved" },
		"approval_id_space":      func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = " " },
		"approval_id_35":         func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = validApprovalID[:35] },
		"approval_id_trailing_n": func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = validApprovalID + "\n" },

		// timestamps 1 … 2^40-1
		"created_at_negative":  func(b *wardenv1.EnvelopeBody) { b.CreatedAt = -1 },
		"created_at_2^40":      func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 1 << 40 },
		"created_at_max_int64": func(b *wardenv1.EnvelopeBody) { b.CreatedAt = math.MaxInt64 },
		"created_at_min_int64": func(b *wardenv1.EnvelopeBody) { b.CreatedAt = math.MinInt64 },
		"expires_at_negative":  func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = -1 },
		"expires_at_2^40":      func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = 1 << 40 },
		"expires_at_max_int64": func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = math.MaxInt64 },
		"expires_at_min_int64": func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = math.MinInt64 },
		"both_max_int64":       func(b *wardenv1.EnvelopeBody) { b.CreatedAt = math.MaxInt64; b.ExpiresAt = math.MaxInt64 },
		"created_min_expires_max": func(b *wardenv1.EnvelopeBody) {
			b.CreatedAt = math.MinInt64
			b.ExpiresAt = math.MaxInt64
		},

		// idempotency_key: 1–128, ^[A-Za-z0-9._:-]+$, no ".."
		"idem_129":           func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = strings.Repeat("k", 129) },
		"idem_10KB":          func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = strings.Repeat("k", 10*1024) },
		"idem_slash":         func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a/b" },
		"idem_dotdot":        func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a..b" },
		"idem_only_dotdot":   func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = ".." },
		"idem_dotdot_slash":  func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "../x" },
		"idem_triple_dot":    func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "..." },
		"idem_nul":           func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a\x00b" },
		"idem_space":         func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a b" },
		"idem_newline":       func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a\nb" },
		"idem_trailing_nl":   func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "ab\n" },
		"idem_backslash":     func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = `a\b` },
		"idem_semicolon":     func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a;b" },
		"idem_pipe":          func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a|b" },
		"idem_dollar":        func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "$(id)" },
		"idem_backtick":      func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "`id`" },
		"idem_percent_2f":    func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "..%2f" },
		"idem_unicode_digit": func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "١" },
		"idem_fullwidth_dot": func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a．b" },
	}
	for name, m := range invalid {
		t.Run(name, func(t *testing.T) {
			expectBodyReject(t, v, marshalDet(t, bodyWith(m)), CodeBodyInvalid, 5)
		})
	}
}

func TestCheck5BoundaryValuesAccepted(t *testing.T) {
	v := defaultVerifier(t)
	type mut = func(b *wardenv1.EnvelopeBody)
	valid := map[string]mut{
		"playbook_id_2_chars":   func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "ab" },
		"playbook_id_63_chars":  func(b *wardenv1.EnvelopeBody) { b.PlaybookId = "a" + strings.Repeat("-", 61) + "9" },
		"step_id_1_char":        func(b *wardenv1.EnvelopeBody) { b.StepId = "a" },
		"step_id_63_chars":      func(b *wardenv1.EnvelopeBody) { b.StepId = "z" + strings.Repeat("0", 62) },
		"version_0.0.0":         func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "0.0.0" },
		"version_32_chars":      func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.0.0-" + strings.Repeat("a", 26) },
		"version_pre_0":         func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-0" },
		"version_pre_alnum_0a":  func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-0a" },
		"version_pre_dashes":    func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "1.2.3-alpha-beta.2" },
		"version_large_numbers": func(b *wardenv1.EnvelopeBody) { b.PlaybookVersion = "10.20.300" },
		"idem_1_char":           func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "k" },
		"idem_128_chars":        func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = strings.Repeat("K", 128) },
		"idem_single_dot":       func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a.b" },
		"idem_dot_only":         func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "." },
		"idem_dots_separated":   func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "a.b.c" },
		"idem_all_classes":      func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "Az09._:-" },
		"idem_leading_dash":     func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "-x" },
		"approval_id_empty":     func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = "" },
		"approval_id_v4":        func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = validApprovalID },
		"autonomy_L0":           func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 1 },
		"autonomy_L3":           func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 4 },
		"decision_variant_b":    func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.DecisionId = "3c4d5e6f-7a8b-4c9d-be0f-1a2b3c4d5e6f" },
		"action_id_variant_9":   func(b *wardenv1.EnvelopeBody) { b.ActionId = "01920f3e-7c4a-7b2d-9e5f-0a1b2c3d4e5f" },
		"lifetime_1_second":     func(b *wardenv1.EnvelopeBody) { b.CreatedAt = fakeNow; b.ExpiresAt = fakeNow + 1 },
		"params_mem_status_only": func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_MemStatus{MemStatus: &wardenv1.MemStatusRequest{}}}
		},
	}
	for name, m := range valid {
		t.Run(name, func(t *testing.T) {
			body := bodyWith(m)
			expectAccept(t, v, seal(t, keyA, body), body, keyA)
		})
	}
}

// Timestamps exactly on the 1 and 2^40-1 bounds are accepted when the clock
// and key validity allow them.
func TestCheck5TimestampBoundsAccepted(t *testing.T) {
	low := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 1; b.ExpiresAt = 2 })
	vLow := mustVerifier(t, mustKeySet(t, trusted(keyA, 1, 100)), serverA, 2)
	expectAccept(t, vLow, seal(t, keyA, low), low, keyA)

	high := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = maxTime - 600; b.ExpiresAt = maxTime })
	vHigh := mustVerifier(t, mustKeySet(t, trusted(keyA, 1, math.MaxInt64)), serverA, maxTime)
	expectAccept(t, vHigh, seal(t, keyA, high), high, keyA)
}

// Target server id may be any UUID version, as long as it is lowercase.
func TestCheck5TargetAnyUUIDVersion(t *testing.T) {
	for _, id := range []string{
		"6f1c2d3e-4a5b-1c6d-8e7f-90a1b2c3d4e5",
		"6f1c2d3e-4a5b-7c6d-8e7f-90a1b2c3d4e5",
		"00000000-0000-0000-0000-000000000000",
		"6f1c2d3e-4a5b-fc6d-ce7f-90a1b2c3d4e5",
	} {
		t.Run(id, func(t *testing.T) {
			v := mustVerifier(t, mustKeySet(t, wideKey(keyA)), id, fakeNow)
			body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.TargetServerId = id })
			expectAccept(t, v, seal(t, keyA, body), body, keyA)
		})
	}
}

// --- check 5: wire-level attacks inside the signed body (R13) ---------------

func TestCheck5WireAttacks(t *testing.T) {
	v := defaultVerifier(t)
	base := validBody()
	baseBytes := marshalDet(t, base)

	noParams := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	noPD := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil }))
	pdBytes := marshalDet(t, base.PolicyDecision)
	restartInner := marshalDet(t, &wardenv1.ServiceRestartRequest{Unit: "nginx.service"})
	memInner := []byte{}
	paramsWith := func(tr []byte) []byte { return fBytes(append([]byte(nil), noParams...), 8, tr) }

	clear := func(m func(b *wardenv1.EnvelopeBody)) []byte { return marshalDet(t, bodyWith(m)) }

	cases := map[string][]byte{
		"unknown_field_99_varint":  fVarint(append([]byte(nil), baseBytes...), 99, 1),
		"unknown_field_99_bytes":   fBytes(append([]byte(nil), baseBytes...), 99, []byte("x")),
		"unknown_field_13":         fVarint(append([]byte(nil), baseBytes...), 13, 0),
		"unknown_field_max_number": fVarint(append([]byte(nil), baseBytes...), 536870911, 0),
		"unknown_in_policy_decision": fBytes(append([]byte(nil), noPD...), 9,
			fVarint(append([]byte(nil), pdBytes...), 99, 1)),
		"unknown_in_params":     paramsWith(cat(fBytes(nil, 11, restartInner), fVarint(nil, 99, 1))),
		"reserved_20_in_params": paramsWith(fBytes(nil, 20, nil)),
		"unknown_in_request": paramsWith(fBytes(nil, 11,
			fVarint(append([]byte(nil), restartInner...), 99, 1))),
		"unknown_in_field_less_request": paramsWith(fBytes(nil, 7, fVarint(nil, 1, 1))),

		"duplicate_action_id":         fBytes(append([]byte(nil), baseBytes...), 2, []byte(validActionID)),
		"duplicate_action_id_differ":  fBytes(append([]byte(nil), baseBytes...), 2, []byte("01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e60")),
		"duplicate_target":            fBytes(append([]byte(nil), baseBytes...), 3, []byte(serverB)),
		"duplicate_format_version":    fVarint(append([]byte(nil), baseBytes...), 1, 1),
		"duplicate_created_at":        fVarint(append([]byte(nil), baseBytes...), 10, uint64(fakeNow-10)),
		"duplicate_expires_at":        fVarint(append([]byte(nil), baseBytes...), 11, uint64(fakeNow+290)),
		"duplicate_idempotency_key":   fBytes(append([]byte(nil), baseBytes...), 12, []byte("other")),
		"duplicate_playbook_digest":   fBytes(append([]byte(nil), baseBytes...), 6, digest("x")),
		"repeated_policy_decision":    fBytes(append([]byte(nil), baseBytes...), 9, pdBytes),
		"repeated_policy_decision_mx": fBytes(fBytes(append([]byte(nil), noPD...), 9, []byte{}), 9, pdBytes),
		"duplicate_decision_id_in_pd": fBytes(append([]byte(nil), noPD...), 9,
			fBytes(append([]byte(nil), pdBytes...), 1, []byte(validDecisionID))),
		"two_members_one_params":   paramsWith(cat(fBytes(nil, 11, restartInner), fBytes(nil, 7, memInner))),
		"same_member_twice":        paramsWith(cat(fBytes(nil, 11, restartInner), fBytes(nil, 11, restartInner))),
		"two_params_fields_differ": fBytes(fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 11, restartInner)), 8, fBytes(nil, 7, memInner)),
		"two_params_fields_same":   fBytes(append([]byte(nil), baseBytes...), 8, fBytes(nil, 11, restartInner)),
		"duplicate_unit_in_request": paramsWith(fBytes(nil, 11,
			fBytes(append([]byte(nil), restartInner...), 1, []byte("sshd.service")))),

		"group_depth0_unknown": fGroup(append([]byte(nil), baseBytes...), 99, nil),
		"group_depth0_known":   fGroup(clear(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2, nil),
		"lone_end_group":       append(append([]byte(nil), baseBytes...), 0x0c),
		"group_depth1_pd": fBytes(append([]byte(nil), noPD...), 9,
			fGroup(append([]byte(nil), pdBytes...), 5, nil)),
		"group_depth1_params": paramsWith(cat(fBytes(nil, 11, restartInner), fGroup(nil, 2, nil))),
		"group_depth2_request": paramsWith(fBytes(nil, 11,
			fGroup(append([]byte(nil), restartInner...), 2, fVarint(nil, 1, 1)))),

		"created_at_as_bytes": fBytes(clear(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 }), 10, []byte{1, 2, 3}),
		"created_at_as_fixed64": fFixed64(clear(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 }), 10,
			uint64(fakeNow-10)),
		"action_id_as_varint": fVarint(clear(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2, 7),
		"format_as_fixed32":   fFixed32(clear(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 }), 1, 1),
		"params_as_varint":    fVarint(append([]byte(nil), noParams...), 8, 11),
		"pd_as_fixed64":       fFixed64(append([]byte(nil), noPD...), 9, 0),
		"autonomy_as_bytes": fBytes(append([]byte(nil), noPD...), 9,
			fBytes(marshalDet(t, &wardenv1.PolicyDecision{DecisionId: validDecisionID, PolicyBundleDigest: digest("policy-bundle")}), 2, []byte{3})),
		"request_member_as_varint": paramsWith(fVarint(nil, 11, 1)),

		"invalid_utf8_action_id": fBytes(clear(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2,
			[]byte("01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e\xff\xfe")),
		"invalid_utf8_idem": fBytes(clear(func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "" }), 12, []byte{0xc0, 0x80}),
		"invalid_utf8_decision_id": fBytes(append([]byte(nil), noPD...), 9,
			cat(fBytes(nil, 1, []byte("\xed\xa0\x80")), fVarint(nil, 2, 3), fBytes(nil, 3, digest("policy-bundle")))),
		"invalid_utf8_in_request": paramsWith(fBytes(nil, 11, fBytes(nil, 1, []byte("nginx\xff.service")))),

		"truncated_body":          baseBytes[:len(baseBytes)-1],
		"truncated_nested_pd":     fBytes(append([]byte(nil), noPD...), 9, pdBytes[:len(pdBytes)-3]),
		"bad_length_in_params":    paramsWith([]byte{0x5a, 0x7f}),
		"field_number_zero":       append([]byte{0x00, 0x00}, baseBytes...),
		"overlong_varint":         fVarint(nil, 1, 1)[:1],
		"garbage":                 []byte{0xff, 0xff, 0xff, 0xff},
		"length_beyond_body":      append(append([]byte(nil), baseBytes...), 0x12, 0x10, 'a'),
		"overlong_varint_11bytes": append(append([]byte(nil), baseBytes...), append([]byte{0x50}, append(make([]byte, 0), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01)...)...),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			expectBodyReject(t, v, body, CodeBodyInvalid, 5)
		})
	}
}

// --- check 6: UNSUPPORTED_FORMAT_VERSION -------------------------------------

func TestCheck6FormatVersion(t *testing.T) {
	v := defaultVerifier(t)
	for _, fv := range []uint32{0, 2, 3, 255, math.MaxUint32} {
		t.Run("", func(t *testing.T) {
			body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = fv })
			expectBodyReject(t, v, marshalDet(t, body), CodeUnsupportedFormatVersion, 6)
		})
	}
	// format_version 1 encoded explicitly vs absent: absent (0) is check 6,
	// never BODY_INVALID.
	t.Run("absent_is_check6_not_body_invalid", func(t *testing.T) {
		body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })
		bb := marshalDet(t, body)
		if len(bb) > 0 && bb[0] == 0x08 {
			t.Fatalf("format_version 0 should not be on the wire")
		}
		expectBodyReject(t, v, bb, CodeUnsupportedFormatVersion, 6)
	})
	// R14, R13 (j): format_version explicitly encoded as 0 is a
	// non-canonical proto3 default and fails the strict scan first, so it is
	// BODY_INVALID at check 5, never UNSUPPORTED_FORMAT_VERSION; 2 written
	// the same way stays check 6.
	t.Run("explicit_zero_is_check5_not_check6", func(t *testing.T) {
		bb := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 }))
		expectBodyReject(t, v, fVarint(append([]byte(nil), bb...), 1, 0), CodeBodyInvalid, 5)
		expectBodyReject(t, v, cat(fVarint(nil, 1, 0), bb), CodeBodyInvalid, 5)
		expectBodyReject(t, v, cat(fVarint(nil, 1, 2), bb), CodeUnsupportedFormatVersion, 6)
	})
}

// --- check 7: created_at inside the signing key's validity -------------------

func TestCheck7CreatedAtKeyValidity(t *testing.T) {
	nb, na := fakeNow-100, fakeNow+30
	v := mustVerifier(t, mustKeySet(t, trusted(keyA, nb, na)), serverA, fakeNow)

	reject := map[string]*wardenv1.EnvelopeBody{
		"one_before_not_before": bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = nb - 1; b.ExpiresAt = nb + 200 }),
		"one_after_not_after":   bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = na + 1; b.ExpiresAt = na + 200 }),
		"far_before":            bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 1; b.ExpiresAt = 2 }),
	}
	for name, body := range reject {
		t.Run(name, func(t *testing.T) {
			expectBodyReject(t, v, marshalDet(t, body), CodeUnknownKey, 7)
		})
	}
	accept := map[string]*wardenv1.EnvelopeBody{
		"exactly_not_before": bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = nb; b.ExpiresAt = nb + 200 }),
		"exactly_not_after":  bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = na; b.ExpiresAt = na + 200 }),
	}
	for name, body := range accept {
		t.Run(name, func(t *testing.T) {
			expectAccept(t, v, seal(t, keyA, body), body, keyA)
		})
	}
	// The second key's validity is used, not the first key's.
	t.Run("validity_of_signing_key_not_other_key", func(t *testing.T) {
		v2 := mustVerifier(t, mustKeySet(t, wideKey(keyB), trusted(keyA, nb, na)), serverA, fakeNow)
		body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = nb - 1; b.ExpiresAt = nb + 200 })
		expectBodyReject(t, v2, marshalDet(t, body), CodeUnknownKey, 7)
		expectAccept(t, v2, seal(t, keyB, body), body, keyB)
	})
}

// --- checks 8–10: lifetime, skew, expiry (AC9) -------------------------------

func TestCheck8Lifetime(t *testing.T) {
	v := defaultVerifier(t)
	c := fakeNow - 10
	reject := map[string][2]int64{
		"expires_equals_created": {c, c},
		"expires_before_created": {c, c - 1},
		"expires_far_before":     {c, 1},
		"lifetime_601":           {c, c + 601},
		"lifetime_huge":          {1, maxTime},
	}
	for name, ts := range reject {
		t.Run(name, func(t *testing.T) {
			body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = ts[0]; b.ExpiresAt = ts[1] })
			expectBodyReject(t, v, marshalDet(t, body), CodeLifetimeInvalid, 8)
		})
	}
	t.Run("lifetime_600_accepted", func(t *testing.T) {
		body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = c; b.ExpiresAt = c + 600 })
		expectAccept(t, v, seal(t, keyA, body), body, keyA)
	})
}

func TestCheck9NotYetValid(t *testing.T) {
	v := defaultVerifier(t)
	t.Run("now_plus_60_accepted", func(t *testing.T) {
		body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = fakeNow + 60; b.ExpiresAt = fakeNow + 360 })
		expectAccept(t, v, seal(t, keyA, body), body, keyA)
	})
	for name, c := range map[string]int64{"now_plus_61": fakeNow + 61, "one_year_ahead": fakeNow + 365*86400, "max": maxTime - 600} {
		t.Run(name, func(t *testing.T) {
			body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = c; b.ExpiresAt = c + 300 })
			expectBodyReject(t, v, marshalDet(t, body), CodeNotYetValid, 9)
		})
	}
}

func TestCheck10Expired(t *testing.T) {
	v := defaultVerifier(t)
	t.Run("now_equals_expires_plus_60_accepted", func(t *testing.T) {
		body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = fakeNow - 60; b.CreatedAt = fakeNow - 300 })
		expectAccept(t, v, seal(t, keyA, body), body, keyA)
	})
	for name, e := range map[string]int64{"plus_1": fakeNow - 61, "one_day_old": fakeNow - 86400, "epoch_2": 2} {
		t.Run(name, func(t *testing.T) {
			body := bodyWith(func(b *wardenv1.EnvelopeBody) { b.ExpiresAt = e; b.CreatedAt = e - 1 })
			expectBodyReject(t, v, marshalDet(t, body), CodeExpired, 10)
		})
	}
	// Held by a stopped agent until after expiry, then delivered.
	t.Run("held_then_delivered", func(t *testing.T) {
		body := validBody()
		raw := seal(t, keyA, body)
		expectAccept(t, defaultVerifier(t), raw, body, keyA)
		later := mustVerifier(t, mustKeySet(t, wideKey(keyA)), serverA, body.ExpiresAt+61)
		expectReject(t, later, raw, CodeExpired, 10)
	})
}

// Extreme verifier clocks must not overflow into acceptance.
func TestExtremeClocks(t *testing.T) {
	body := validBody()
	raw := seal(t, keyA, body)
	ksAll := mustKeySet(t, trusted(keyA, 1, math.MaxInt64))
	for name, tc := range map[string]struct {
		now   int64
		code  Code
		check int
	}{
		"now_max_int64":      {math.MaxInt64, CodeExpired, 10},
		"now_max_int64_m60":  {math.MaxInt64 - 60, CodeExpired, 10},
		"now_max_int64_half": {math.MaxInt64 / 2, CodeExpired, 10},
		"now_2^40":           {1 << 40, CodeExpired, 10},
		"now_negative":       {-1, CodeUnknownKey, 3},
		"now_min_int64":      {math.MinInt64, CodeUnknownKey, 3},
		"now_min_int64_p60":  {math.MinInt64 + 60, CodeUnknownKey, 3},
		"now_zero":           {0, CodeUnknownKey, 3},
	} {
		t.Run(name, func(t *testing.T) {
			v := mustVerifier(t, ksAll, serverA, tc.now)
			expectReject(t, v, raw, tc.code, tc.check)
		})
	}
	// now = 1 with a key valid from 1: created_at is far ahead.
	t.Run("now_1_not_yet_valid", func(t *testing.T) {
		v := mustVerifier(t, ksAll, serverA, 1)
		expectReject(t, v, raw, CodeNotYetValid, 9)
	})
}

// --- check 11: WRONG_HOST (AC10) ---------------------------------------------

func TestCheck11WrongHost(t *testing.T) {
	body := validBody() // for serverA
	raw := seal(t, keyA, body)
	vB := mustVerifier(t, mustKeySet(t, wideKey(keyA)), serverB, fakeNow)
	expectReject(t, vB, raw, CodeWrongHost, 11)

	// Server rebuilt and re-enrolled with a new UUID: the old envelope fails.
	rebuilt := "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e6"
	vRebuilt := mustVerifier(t, mustKeySet(t, wideKey(keyA)), rebuilt, fakeNow)
	expectReject(t, vRebuilt, raw, CodeWrongHost, 11)

	// Differs only in the last hex digit.
	near := bodyWith(func(b *wardenv1.EnvelopeBody) { b.TargetServerId = rebuilt })
	vA := defaultVerifier(t)
	expectBodyReject(t, vA, marshalDet(t, near), CodeWrongHost, 11)

	// The returned body of an accepted envelope names this server.
	res := expectAccept(t, vA, raw, body, keyA)
	if res.Body.GetTargetServerId() != serverA {
		t.Fatalf("accepted envelope for %q on %q", res.Body.GetTargetServerId(), serverA)
	}
}

// The returned body must be decoded from the signed bytes: mutating the input
// slice after Verify must not change it, and it must equal a fresh decode.
func TestReturnedBodyIsTheSignedBody(t *testing.T) {
	v := defaultVerifier(t)
	body := validBody()
	raw := seal(t, keyA, body)
	res := expectAccept(t, v, raw, body, keyA)
	for i := range raw {
		raw[i] = 0
	}
	if !proto.Equal(res.Body, body) {
		t.Fatalf("returned body aliases the caller's buffer")
	}
}
