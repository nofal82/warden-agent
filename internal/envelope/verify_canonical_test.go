package envelope

// Canonical-encoding rule (action-envelope.md R13, Nofal 2026-10-16) as seen
// by the verifier. A correctly signed body that is not canonically encoded
// is BODY_INVALID at check 5, never accepted and never decoded to a
// different value than a strict decoder would read: format_version 2^32+1
// must not become version 1, autonomy_level 2^32+4 must not become L3. An
// outer SignedEnvelope with an overlong tag or length is MALFORMED at check 2.

import (
	"fmt"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// canonBody is validBody with every optional field set, so every field of
// EnvelopeBody and PolicyDecision is on the wire.
func canonBody() *wardenv1.EnvelopeBody {
	return bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.ApprovalId = validApprovalID })
}

// Every field at every depth of a signed body, re-encoded with an overlong
// tag or an overlong value/length prefix, is BODY_INVALID at check 5.
func TestCheck5NonCanonicalEveryField(t *testing.T) {
	v := defaultVerifier(t)
	b := canonBody()
	base := marshalDet(t, b)
	expectAccept(t, v, sealBytes(keyA, base), b, keyA)

	paths := [][]protowire.Number{
		{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12},
		{9, 1}, {9, 2}, {9, 3}, {9, 4},
		{8, 11}, {8, 11, 1},
	}
	for _, p := range paths {
		for _, how := range []encMut{mutTag, mutValue} {
			name := fmt.Sprintf("path%v/%s", p, map[encMut]string{mutTag: "tag", mutValue: "value"}[how])
			t.Run(name, func(t *testing.T) {
				expectBodyReject(t, v, mutateAt(t, base, p, how), CodeBodyInvalid, 5)
			})
		}
	}
}

// Overlong encodings inside every params member that has a field.
func TestCheck5NonCanonicalInEveryParamsMember(t *testing.T) {
	v := defaultVerifier(t)
	oneof := (&wardenv1.TypedRequest{}).ProtoReflect().Descriptor().Oneofs().ByName("request")
	for i := 0; i < oneof.Fields().Len(); i++ {
		member := oneof.Fields().Get(i)
		reqMD := member.Message()
		for j := 0; j < reqMD.Fields().Len(); j++ {
			fd := reqMD.Fields().Get(j)
			var good, tagBad, valBad, unpacked []byte
			switch {
			case fd.IsList() && fd.Kind() != protoreflect.StringKind && fd.Kind() != protoreflect.BytesKind:
				// Repeated numeric field: canonical only when packed
				// (R13 (i)), so the overlong cases are built on the packed
				// record and the unpacked form is a case of its own.
				good = fBytes(nil, fd.Number(), protowire.AppendVarint(nil, 1))
				tagBad = protowire.AppendBytes(overlong(rawTag(fd.Number(), protowire.BytesType)), protowire.AppendVarint(nil, 1))
				valBad = fBytes(nil, fd.Number(), overlong(1))
				unpacked = fVarint(nil, fd.Number(), 1)
			case fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind:
				good = protowire.AppendBytes(protowire.AppendTag(nil, fd.Number(), protowire.BytesType), []byte("a"))
				tagBad = protowire.AppendBytes(overlong(rawTag(fd.Number(), protowire.BytesType)), []byte("a"))
				valBad = append(append(protowire.AppendTag(nil, fd.Number(), protowire.BytesType), overlong(1)...), 'a')
			default: // every other field in the request messages is a varint kind
				good = fVarint(nil, fd.Number(), 1)
				tagBad = protowire.AppendVarint(overlong(rawTag(fd.Number(), protowire.VarintType)), 1)
				valBad = append(protowire.AppendTag(nil, fd.Number(), protowire.VarintType), overlong(1)...)
			}
			wrapParams := func(req []byte) []byte {
				noParams := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
				return fBytes(noParams, 8, fBytes(nil, member.Number(), req))
			}
			name := string(member.Name()) + "." + string(fd.Name())
			t.Run(name+"/minimal_accepted", func(t *testing.T) {
				res, err := v.Verify(sealBytes(keyA, wrapParams(good)))
				if err != nil || res == nil {
					t.Fatalf("minimal encoding rejected: %v", err)
				}
			})
			t.Run(name+"/tag_overlong", func(t *testing.T) {
				expectBodyReject(t, v, wrapParams(tagBad), CodeBodyInvalid, 5)
			})
			t.Run(name+"/value_overlong", func(t *testing.T) {
				expectBodyReject(t, v, wrapParams(valBad), CodeBodyInvalid, 5)
			})
			if unpacked != nil {
				t.Run(name+"/unpacked", func(t *testing.T) {
					expectBodyReject(t, v, wrapParams(unpacked), CodeBodyInvalid, 5)
				})
			}
		}
	}
}

// Values that a lax decoder truncates to something valid, or that do not
// fit their type, are BODY_INVALID at check 5 even though the signature is
// good.
func TestCheck5OutOfRangeValues(t *testing.T) {
	v := defaultVerifier(t)
	noFV := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 }))
	noPD := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil }))
	noParams := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	pdNoLevel := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision.AutonomyLevel = 0 }).PolicyDecision)
	app := func(b []byte, more ...[]byte) []byte {
		out := append([]byte(nil), b...)
		for _, m := range more {
			out = append(out, m...)
		}
		return out
	}
	withFV := func(raw []byte) []byte { return app(noFV, []byte{0x08}, raw) }
	withLevel := func(raw []byte) []byte { return fBytes(app(noPD), 9, app(pdNoLevel, []byte{0x10}, raw)) }
	withReq := func(member protowire.Number, req []byte) []byte {
		return fBytes(app(noParams), 8, fBytes(nil, member, req))
	}
	fileDelete := marshalDet(t, &wardenv1.FileDeleteByAgeRequest{
		Root: wardenv1.FileDeleteRoot(1), MinAgeDays: 7, MaxFiles: 10, MaxBytes: 1 << 30,
	})
	dbTerm := marshalDet(t, &wardenv1.DbTerminateSessionRequest{
		Engine: wardenv1.Engine(1), Instance: "mysql.service", ServerStartedAt: 1_700_000_000, MinIdleSeconds: 600,
	})
	vi := func(x uint64) []byte { return protowire.AppendVarint(nil, x) }

	cases := map[string][]byte{
		"format_version_2^32+1_truncates_to_1": withFV(vi(1<<32 + 1)),
		"format_version_2^32":                  withFV(vi(1 << 32)),
		"format_version_2^33+1":                withFV(vi(1<<33 + 1)),
		"format_version_maxuint64":             withFV(vi(math.MaxUint64)),
		"format_version_2^63+1":                withFV(vi(1<<63 + 1)),
		"format_version_1_overlong":            withFV([]byte{0x81, 0x00}),
		"format_version_1_10_bytes":            withFV(overlongN(1, 10)),
		"format_version_tag_88_00":             app(noFV, []byte{0x88, 0x00, 0x01}),

		"autonomy_2^32+4_truncates_to_L3": withLevel(vi(1<<32 + 4)),
		"autonomy_2^32+1_truncates_to_L0": withLevel(vi(1<<32 + 1)),
		"autonomy_2^32+3_truncates_to_L2": withLevel(vi(1<<32 + 3)),
		"autonomy_2^31":                   withLevel(vi(1 << 31)),
		"autonomy_minInt32-1":             withLevel(vi(i64(math.MinInt32 - 1))),
		"autonomy_ff_ff_ff_ff_0f":         withLevel([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}),
		"autonomy_minInt64+4":             withLevel(vi(1<<63 + 4)),
		"autonomy_3_overlong":             withLevel([]byte{0x83, 0x00}),
		"autonomy_4_10_bytes":             withLevel(overlongN(4, 10)),

		"created_at_overlong":    mutateAt(t, marshalDet(t, validBody()), []protowire.Number{10}, mutValue),
		"created_at_10_bytes":    app(marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 })), []byte{0x50}, overlongN(uint64(fakeNow-10), 10)),
		"action_id_len_overlong": mutateAt(t, marshalDet(t, validBody()), []protowire.Number{2}, mutValue),

		"dry_run_2":           withReq(17, fVarint(app(fileDelete), 5, 2)),
		"dry_run_255":         withReq(17, fVarint(app(fileDelete), 5, 255)),
		"dry_run_2^32":        withReq(17, fVarint(app(fileDelete), 5, 1<<32)),
		"dry_run_2^32+1":      withReq(17, fVarint(app(fileDelete), 5, 1<<32+1)),
		"dry_run_1_overlong":  withReq(17, app(fileDelete, []byte{0x28, 0x81, 0x00})),
		"file_root_2^32+1":    withReq(17, fVarint(nil, 1, 1<<32+1)),
		"min_age_days_2^32+7": withReq(17, fVarint(nil, 2, 1<<32+7)),
		"max_files_maxuint64": withReq(17, fVarint(nil, 3, math.MaxUint64)),
		"pid_2^32+1":          withReq(16, fVarint(nil, 1, 1<<32+1)),
		"signal_2^32+1":       withReq(16, fVarint(nil, 3, 1<<32+1)),
		"keep_days_2^32+7":    withReq(18, fVarint(nil, 1, 1<<32+7)),
		"cpu_quota_2^32+50":   withReq(15, fVarint(nil, 2, 1<<32+50)),
		"db_engine_2^32+1":    withReq(22, fVarint(nil, 1, 1<<32+1)),
		"db_ids_elem_overlong": withReq(22, fBytes(app(dbTerm), 3,
			app(protowire.AppendVarint(nil, 7), overlong(300)))),
		"db_ids_len_overlong": withReq(22, app(dbTerm, []byte{0x1a}, overlong(2), protowire.AppendVarint(nil, 7), protowire.AppendVarint(nil, 8))),
		"db_starts_elem_overlong": withReq(22, fBytes(app(dbTerm), 4,
			app(protowire.AppendVarint(nil, math.MaxUint64), overlong(1_700_000_000)))),
		"db_min_idle_2^32+600": withReq(22, fVarint(nil, 7, 1<<32+600)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			expectBodyReject(t, v, body, CodeBodyInvalid, 5)
		})
	}
}

// In-range values in their standard encoding, including the 10-byte form
// of negative 64-bit values and the largest uint32, are still accepted
// (checks 1-11 do not look inside params).
func TestCanonicalValidValuesAccepted(t *testing.T) {
	v := defaultVerifier(t)
	cases := map[string]*wardenv1.EnvelopeBody{
		"db_terminate_negative_starts": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_DbTerminateSession{
				DbTerminateSession: &wardenv1.DbTerminateSessionRequest{
					Engine: wardenv1.Engine(1), Instance: "mysql.service",
					SessionIds:       []uint64{0, 1, math.MaxUint64},
					SessionStartedAt: []int64{-1, math.MinInt64, math.MaxInt64},
					ServerStartedAt:  -1, MinIdleSeconds: math.MaxUint32,
				},
			}}
		}),
		"file_delete_dry_run_true_maxuint32": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_FileDeleteByAge{
				FileDeleteByAge: &wardenv1.FileDeleteByAgeRequest{
					Root: wardenv1.FileDeleteRoot(1), MinAgeDays: math.MaxUint32, MaxFiles: math.MaxUint32,
					MaxBytes: math.MaxUint64, DryRun: true,
				},
			}}
		}),
		"process_signal_max_pid": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.Params = &wardenv1.TypedRequest{Request: &wardenv1.TypedRequest_ProcessSignal{
				ProcessSignal: &wardenv1.ProcessSignalRequest{Pid: math.MaxUint32, StartTimeTicks: math.MaxUint64},
			}}
		}),
		"approval_set_L3": bodyWith(func(b *wardenv1.EnvelopeBody) {
			b.PolicyDecision.ApprovalId = validApprovalID
			b.PolicyDecision.AutonomyLevel = wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L3
		}),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			raw := seal(t, keyA, body)
			if !canonicalOK(marshalDet(t, body), bodyDescriptor) {
				t.Fatalf("test oracle rejects a deterministic marshal")
			}
			expectAccept(t, v, raw, body, keyA)
		})
	}
	// R13 (j) (2026-10-18): an explicit minimal zero for a bool used to be
	// canonical; it is the proto3 default written out, so it is now
	// BODY_INVALID at check 5. dry_run=false left out is accepted.
	noParams := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	head := marshalDet(t, &wardenv1.FileDeleteByAgeRequest{Root: wardenv1.FileDeleteRoot(1)})
	if res, err := v.Verify(sealBytes(keyA, fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 17, head)))); err != nil || res == nil {
		t.Fatalf("dry_run=false left out rejected: %v", err)
	}
	expectBodyReject(t, v, fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 17, fVarint(append([]byte(nil), head...), 5, 0))), CodeBodyInvalid, 5)
}

// R13 (i): a correctly signed body whose DbTerminateSessionRequest carries
// session_ids or session_started_at unpacked (one record per element) is
// BODY_INVALID at check 5, even for a single element and when mixed with a
// packed record. proto.Unmarshal would read every one of these as the same
// list as the packed form, so accepting them would let two different signed
// byte strings stand for one action. The packed forms, and several records
// of the repeated bytes field session_owner_digests, are accepted.
//
// Since 2026-10-18 R13 (i) also requires exactly one non-empty packed
// record per field: the same list split over two packed records, an empty
// packed record alone, and an empty one before or after a valid one are
// BODY_INVALID at check 5 too (AC8). MySQL's all-zero session_started_at
// elements stay valid as packed elements (R13 (j) skips repeated elements).
func TestCheck5UnpackedRepeated(t *testing.T) {
	v := defaultVerifier(t)
	noParams := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	withReq := func(req []byte) []byte { return fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 22, req)) }
	head := marshalDet(t, &wardenv1.DbTerminateSessionRequest{
		Engine: wardenv1.Engine(1), Instance: "mysql.service", ServerStartedAt: 1_700_000_000, MinIdleSeconds: 600,
	})
	app := func(more ...[]byte) []byte { return cat(append([][]byte{append([]byte(nil), head...)}, more...)...) }
	packed := func(num protowire.Number, vals ...uint64) []byte {
		var p []byte
		for _, x := range vals {
			p = protowire.AppendVarint(p, x)
		}
		return fBytes(nil, num, p)
	}
	digests := cat(fBytes(nil, 6, digest("owner-1")), fBytes(nil, 6, digest("owner-2")))
	minus1 := uint64(math.MaxUint64)

	accepted := map[string][]byte{
		"ids_and_starts_packed":       app(packed(3, 101, 202), packed(4, 0, 0)),
		"starts_packed_negative":      app(packed(3, 101), packed(4, minus1)),
		"digests_two_records":         app(packed(3, 101, 202), packed(4, 0, 0), digests),
		"deterministic_marshal_order": marshalDet(t, &wardenv1.DbTerminateSessionRequest{Engine: wardenv1.Engine(1), Instance: "mysql.service", SessionIds: []uint64{101, 202}, SessionStartedAt: []int64{0, 0}, ServerStartedAt: 1_700_000_000, SessionOwnerDigests: [][]byte{digest("owner-1"), digest("owner-2")}, MinIdleSeconds: 600}),
		"three_ids_one_record_each":   app(packed(3, 101, 202, 303), packed(4, 0, 0, 0)),
	}
	for name, req := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			res, err := v.Verify(sealBytes(keyA, withReq(req)))
			if err != nil || res == nil {
				t.Fatalf("packed encoding rejected: %v", err)
			}
		})
	}

	rejected := map[string][]byte{
		"ids_single":                  app(fVarint(nil, 3, 101)),
		"ids_single_zero":             app(fVarint(nil, 3, 0)),
		"ids_single_max":              app(fVarint(nil, 3, math.MaxUint64)),
		"ids_two":                     app(fVarint(nil, 3, 101), fVarint(nil, 3, 202)),
		"ids_packed_then_unpacked":    app(packed(3, 101), fVarint(nil, 3, 202)),
		"ids_unpacked_then_packed":    app(fVarint(nil, 3, 101), packed(3, 202)),
		"ids_unpacked_before_head":    cat(fVarint(nil, 3, 101), head),
		"starts_single":               app(packed(3, 101), fVarint(nil, 4, 1_700_000_000_000_000)),
		"starts_single_minus1":        app(packed(3, 101), fVarint(nil, 4, minus1)),
		"starts_single_zero":          app(packed(3, 101), fVarint(nil, 4, 0)),
		"starts_packed_then_unpacked": app(packed(3, 101, 202), packed(4, 0), fVarint(nil, 4, 0)),
		"starts_unpacked_then_packed": app(packed(3, 101, 202), fVarint(nil, 4, 0), packed(4, 0)),
		"both_unpacked":               app(fVarint(nil, 3, 101), fVarint(nil, 4, 0)),
		"unpacked_with_digests":       app(fVarint(nil, 3, 101), fVarint(nil, 4, 0), digests),
		// wire-type mismatch stays BODY_INVALID too
		"ids_as_i64":    app(fFixed64(nil, 3, 101)),
		"starts_as_i32": app(packed(3, 101), fFixed32(nil, 4, 0)),

		// R13 (i), 2026-10-18: one non-empty packed record per field.
		"ids_split_one_then_two":    app(packed(3, 101), packed(3, 202, 303), packed(4, 0, 0, 0)),
		"ids_split_around_starts":   app(packed(3, 101), packed(4, 0, 0, 0), packed(3, 202, 303)),
		"ids_empty_alone":           app(fBytes(nil, 3, nil)),
		"ids_empty_before_valid":    app(fBytes(nil, 3, nil), packed(3, 101, 202, 303), packed(4, 0, 0, 0)),
		"ids_empty_after_valid":     app(packed(3, 101, 202, 303), fBytes(nil, 3, nil), packed(4, 0, 0, 0)),
		"starts_split_one_then_two": app(packed(3, 101, 202, 303), packed(4, 0), packed(4, 0, 0)),
		"starts_empty_alone":        app(packed(3, 101), fBytes(nil, 4, nil)),
		"starts_empty_before_valid": app(packed(3, 101), fBytes(nil, 4, nil), packed(4, 0)),
		"starts_empty_after_valid":  app(packed(3, 101), packed(4, 0), fBytes(nil, 4, nil)),
	}
	for name, req := range rejected {
		t.Run("rejected/"+name, func(t *testing.T) {
			expectBodyReject(t, v, withReq(req), CodeBodyInvalid, 5)
		})
	}
}

// The outer SignedEnvelope: an overlong tag or length prefix on any field
// is MALFORMED at check 2, before the key lookup, signature or body decode.
// The body and signature bytes are unchanged, so the signature would verify.
func TestCheck2NonCanonicalOuter(t *testing.T) {
	v := defaultVerifier(t)
	body := marshalDet(t, validBody())
	good := sealBytes(keyA, body)
	expectAccept(t, v, good, validBody(), keyA)

	cases := map[string][]byte{}
	for _, num := range []protowire.Number{1, 2, 3} {
		cases[fmt.Sprintf("field%d_tag_overlong", num)] = mutateAt(t, good, []protowire.Number{num}, mutTag)
		cases[fmt.Sprintf("field%d_len_overlong", num)] = mutateAt(t, good, []protowire.Number{num}, mutValue)
	}
	kid, sig := keyIDBytes(keyA), signBody(keyA, body)
	cases["key_id_len_32_as_a0_00"] = cat([]byte{0x0a, 0xa0, 0x00}, kid, fBytes(nil, 2, body), fBytes(nil, 3, sig))
	cases["signature_len_64_as_c0_00"] = cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), []byte{0x1a, 0xc0, 0x00}, sig)
	cases["body_len_10_bytes"] = cat(fBytes(nil, 1, kid), []byte{0x12}, overlongN(uint64(len(body)), 10), body, fBytes(nil, 3, sig))
	cases["key_id_tag_10_bytes"] = cat(overlongN(rawTag(1, protowire.BytesType), 10), protowire.AppendBytes(nil, kid), fBytes(nil, 2, body), fBytes(nil, 3, sig))
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d0, s0 := counters()
			expectReject(t, v, raw, CodeMalformed, 2)
			if d1, s1 := counters(); d1 != d0 || s1 != s0 {
				t.Fatalf("non-canonical outer envelope reached signature verify or body decode")
			}
		})
	}
}

// Ordering against check 1: an oversized envelope is OVERSIZED even when it
// is also non-canonical.
func TestNonCanonicalOversizedIsCheck1(t *testing.T) {
	v := defaultVerifier(t)
	body := marshalDet(t, validBody())
	raw := cat(overlong(rawTag(1, protowire.BytesType)), protowire.AppendBytes(nil, keyIDBytes(keyA)),
		fBytes(nil, 2, body), fBytes(nil, 3, signBody(keyA, body)))
	raw = fBytes(raw, 4, make([]byte, MaxEnvelopeBytes))
	expectReject(t, v, raw, CodeOversized, 1)
}
