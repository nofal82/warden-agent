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
			var good, tagBad, valBad []byte
			switch {
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
	// An explicit minimal zero for a bool is canonical.
	noParams := marshalDet(t, bodyWith(func(b *wardenv1.EnvelopeBody) { b.Params = nil }))
	req := fVarint(marshalDet(t, &wardenv1.FileDeleteByAgeRequest{Root: wardenv1.FileDeleteRoot(1)}), 5, 0)
	if res, err := v.Verify(sealBytes(keyA, fBytes(noParams, 8, fBytes(nil, 17, req)))); err != nil || res == nil {
		t.Fatalf("explicit dry_run=false rejected: %v", err)
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
