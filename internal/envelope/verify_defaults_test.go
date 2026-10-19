package envelope

// R13 (j) and R14 as seen by the verifier (action-envelope.md, amended
// 2026-10-18; §4.5 check 5 row; AC8). A correctly signed body that writes a
// proto3 default explicitly (0, false, enum 0, an empty string or bytes) in
// an implicit-presence field is BODY_INVALID at check 5: deterministic Go
// marshalling never writes it and proto.Unmarshal reads it as the field
// left out, so accepting it would let two different signed byte strings
// stand for one action. The same in the outer SignedEnvelope is MALFORMED
// at check 2. format_version written as 0 fails the scan (check 5); left
// out it reaches check 6.

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// defaultRecord is fd's proto3 default written explicitly. The contract
// has only varint and length-delimited kinds.
func defaultRecord(fd protoreflect.FieldDescriptor) []byte {
	if fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind {
		return fBytes(nil, fd.Number(), nil)
	}
	return fVarint(nil, fd.Number(), 0)
}

// The named AC8 / §4.5 check 5 cases, each next to the same field left out.
// The left-out form shows what the scan alone would let through: where it
// is accepted or reaches a later check, only R13 (j) tells the two apart.
func TestCheck5ExplicitDefaults(t *testing.T) {
	v := defaultVerifier(t)
	without := func(m func(b *wardenv1.EnvelopeBody)) []byte { return marshalDet(t, bodyWith(m)) }
	app := func(b []byte, more ...[]byte) []byte {
		return cat(append([][]byte{append([]byte(nil), b...)}, more...)...)
	}
	noFV := without(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })
	noCreated := without(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 })
	noAction := without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" })
	noDigest := without(func(b *wardenv1.EnvelopeBody) { b.PlaybookDigest = nil })
	noIdem := without(func(b *wardenv1.EnvelopeBody) { b.IdempotencyKey = "" })
	noPD := without(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil })
	noParams := without(func(b *wardenv1.EnvelopeBody) { b.Params = nil })
	pdWith := func(mut func(p *wardenv1.PolicyDecision), more ...[]byte) []byte {
		p := proto.Clone(validBody().PolicyDecision).(*wardenv1.PolicyDecision)
		mut(p)
		return withField(t, noPD, fBytes(nil, 9, app(marshalDet(t, p), more...)))
	}
	keepPD := func(*wardenv1.PolicyDecision) {}
	withReq := func(member protowire.Number, req []byte) []byte {
		return withField(t, noParams, fBytes(nil, 8, fBytes(nil, member, req)))
	}
	fileDelete := marshalDet(t, &wardenv1.FileDeleteByAgeRequest{Root: wardenv1.FileDeleteRoot(1), MinAgeDays: 7, MaxFiles: 10, MaxBytes: 1 << 30})
	fileDeleteNoAge := marshalDet(t, &wardenv1.FileDeleteByAgeRequest{Root: wardenv1.FileDeleteRoot(1), MaxFiles: 10, MaxBytes: 1 << 30})
	// PostgreSQL P22: server_started_at is 0, so it is left out.
	pg := marshalDet(t, &wardenv1.DbTerminateSessionRequest{
		Engine: wardenv1.Engine_ENGINE_POSTGRESQL, Instance: "postgresql.service",
		SessionIds: []uint64{101}, SessionStartedAt: []int64{1_700_000_000_000_000}, MinIdleSeconds: 600,
	})
	pgNoEngine := marshalDet(t, &wardenv1.DbTerminateSessionRequest{
		Instance: "postgresql.service", SessionIds: []uint64{101}, SessionStartedAt: []int64{1_700_000_000_000_000}, MinIdleSeconds: 600,
	})

	accepted := Code("")
	cases := []struct {
		name              string
		explicit, leftOut []byte
		leftOutCode       Code
		leftOutCheck      int
	}{
		// depth 0
		{"format_version_0_uint32", fVarint(app(noFV), 1, 0), noFV, CodeUnsupportedFormatVersion, 6},
		{"format_version_0_first", cat(fVarint(nil, 1, 0), noFV), noFV, CodeUnsupportedFormatVersion, 6},
		{"created_at_0_int64", fVarint(app(noCreated), 10, 0), noCreated, CodeBodyInvalid, 5},
		{"action_id_empty_string", fBytes(app(noAction), 2, nil), noAction, CodeBodyInvalid, 5},
		{"playbook_digest_empty_bytes", fBytes(app(noDigest), 6, nil), noDigest, CodeBodyInvalid, 5},
		{"idempotency_key_empty_string", fBytes(app(noIdem), 12, nil), noIdem, CodeBodyInvalid, 5},
		// depth 1: policy_decision
		{"approval_id_empty_string", pdWith(keepPD, fBytes(nil, 4, nil)), pdWith(keepPD), accepted, 0},
		{"autonomy_level_0_enum", pdWith(func(p *wardenv1.PolicyDecision) { p.AutonomyLevel = 0 }, fVarint(nil, 2, 0)),
			pdWith(func(p *wardenv1.PolicyDecision) { p.AutonomyLevel = 0 }), CodeBodyInvalid, 5},
		{"policy_bundle_digest_empty_bytes", pdWith(func(p *wardenv1.PolicyDecision) { p.PolicyBundleDigest = nil }, fBytes(nil, 3, nil)),
			pdWith(func(p *wardenv1.PolicyDecision) { p.PolicyBundleDigest = nil }), CodeBodyInvalid, 5},
		// depth 2: inside params (the verifier does not validate member
		// contents, so every left-out form here is accepted)
		{"dry_run_false_bool", withReq(17, fVarint(app(fileDelete), 5, 0)), withReq(17, fileDelete), accepted, 0},
		{"min_age_days_0_uint32", withReq(17, fVarint(app(fileDeleteNoAge), 2, 0)), withReq(17, fileDeleteNoAge), accepted, 0},
		{"db_server_started_at_0_int64", withReq(22, fVarint(app(pg), 5, 0)), withReq(22, pg), accepted, 0},
		{"db_engine_0_enum", withReq(22, fVarint(app(pgNoEngine), 1, 0)), withReq(22, pgNoEngine), accepted, 0},
		{"db_instance_empty_string", withReq(22, fBytes(nil, 2, nil)), withReq(22, nil), accepted, 0},
		{"unit_empty_string", withReq(11, fBytes(nil, 1, nil)), withReq(11, nil), accepted, 0},
	}
	for _, c := range cases {
		t.Run(c.name+"/explicit", func(t *testing.T) {
			expectBodyReject(t, v, c.explicit, CodeBodyInvalid, 5)
		})
		t.Run(c.name+"/left_out", func(t *testing.T) {
			if c.leftOutCode == accepted {
				if res, err := v.Verify(sealBytes(keyA, c.leftOut)); err != nil || res == nil {
					t.Fatalf("field left out rejected: %v", err)
				}
				return
			}
			expectBodyReject(t, v, c.leftOut, c.leftOutCode, c.leftOutCheck)
		})
	}

	// Exempt from R13 (j): an empty message-typed member, and packed
	// repeated elements of 0 (MySQL P22's session_started_at).
	exempt := map[string][]byte{
		"empty_params_member": withReq(7, nil),
		"mysql_zero_starts": withReq(22, marshalDet(t, &wardenv1.DbTerminateSessionRequest{
			Engine: wardenv1.Engine_ENGINE_MYSQL, Instance: "mysql.service", SessionIds: []uint64{101, 202},
			SessionStartedAt: []int64{0, 0}, ServerStartedAt: 1_700_000_000,
			SessionOwnerDigests: [][]byte{digest("owner-1"), digest("owner-2")}, MinIdleSeconds: 600,
		})),
		"packed_zero_session_id": withReq(22, fBytes(nil, 3, protowire.AppendVarint(nil, 0))),
	}
	for name, body := range exempt {
		t.Run("exempt/"+name, func(t *testing.T) {
			if res, err := v.Verify(sealBytes(keyA, body)); err != nil || res == nil {
				t.Fatalf("exempt zero value rejected: %v", err)
			}
		})
	}
}

// Every non-repeated scalar or enum field of EnvelopeBody, PolicyDecision
// and every typed request, written with its explicit default in an
// otherwise valid signed body, is BODY_INVALID at check 5 (AC8 "at any
// depth"). None of the contract's fields has explicit presence.
func TestCheck5ExplicitDefaultEveryField(t *testing.T) {
	v := defaultVerifier(t)
	checked := 0
	scalarFields := func(md protoreflect.MessageDescriptor) []protoreflect.FieldDescriptor {
		var out []protoreflect.FieldDescriptor
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if fd.IsList() || fd.Kind() == protoreflect.MessageKind {
				continue
			}
			if fd.HasPresence() {
				t.Fatalf("%s has explicit presence; this test assumes none in the contract", fd.FullName())
			}
			out = append(out, fd)
		}
		return out
	}

	for _, fd := range scalarFields(bodyDescriptor) {
		body := canonBody()
		body.ProtoReflect().Clear(fd)
		raw := cat(marshalDet(t, body), defaultRecord(fd))
		checked++
		t.Run("body."+string(fd.Name()), func(t *testing.T) { expectBodyReject(t, v, raw, CodeBodyInvalid, 5) })
	}

	pdMD := (&wardenv1.PolicyDecision{}).ProtoReflect().Descriptor()
	noPD := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil }))
	for _, fd := range scalarFields(pdMD) {
		pd := proto.Clone(canonBody().PolicyDecision).(*wardenv1.PolicyDecision)
		pd.ProtoReflect().Clear(fd)
		raw := fBytes(append([]byte(nil), noPD...), 9, cat(marshalDet(t, pd), defaultRecord(fd)))
		checked++
		t.Run("policy_decision."+string(fd.Name()), func(t *testing.T) { expectBodyReject(t, v, raw, CodeBodyInvalid, 5) })
	}

	noParams := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	oneof := (&wardenv1.TypedRequest{}).ProtoReflect().Descriptor().Oneofs().ByName("request")
	for i := 0; i < oneof.Fields().Len(); i++ {
		member := oneof.Fields().Get(i)
		for _, fd := range scalarFields(member.Message()) {
			raw := fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, member.Number(), defaultRecord(fd)))
			checked++
			t.Run(string(member.Name())+"."+string(fd.Name()), func(t *testing.T) { expectBodyReject(t, v, raw, CodeBodyInvalid, 5) })
		}
	}
	// 12 body fields minus params and policy_decision, 4 in
	// policy_decision, and well over 30 in the requests.
	if checked < 45 {
		t.Fatalf("only %d fields checked", checked)
	}
}

// R13 (j) in the outer SignedEnvelope: key_id, body and signature are
// implicit-presence bytes fields, so an explicit empty record is MALFORMED
// at check 2, before the key lookup, the signature and the body decode.
// (The same inputs also break R12 or the empty-body rule; the code and
// check are the same, so this pins that nothing reaches check 3.)
func TestCheck2ExplicitDefaultsOuter(t *testing.T) {
	v := defaultVerifier(t)
	body := marshalDet(t, validBody())
	kid, sig := keyIDBytes(keyA), signBody(keyA, body)
	cases := map[string][]byte{
		"key_id_explicit_empty":    cat(fBytes(nil, 1, nil), fBytes(nil, 2, body), fBytes(nil, 3, sig)),
		"body_explicit_empty":      cat(fBytes(nil, 1, kid), fBytes(nil, 2, nil), fBytes(nil, 3, sig)),
		"signature_explicit_empty": cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, nil)),
		"all_explicit_empty":       cat(fBytes(nil, 1, nil), fBytes(nil, 2, nil), fBytes(nil, 3, nil)),
		"empty_key_id_last":        cat(fBytes(nil, 2, body), fBytes(nil, 3, sig), fBytes(nil, 1, nil)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d0, s0 := counters()
			expectReject(t, v, raw, CodeMalformed, 2)
			if d1, s1 := counters(); d1 != d0 || s1 != s0 {
				t.Fatalf("explicit empty outer field reached signature verify or body decode")
			}
		})
	}
}
