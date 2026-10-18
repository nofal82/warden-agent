package wirescan_test

import (
	"errors"
	"math"
	"math/bits"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/wrapperspb"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// nativeWireType is the wire type of a non-packed encoding of fd.
func nativeWireType(fd protoreflect.FieldDescriptor) protowire.Type {
	switch fd.Kind() {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return protowire.BytesType
	case protoreflect.GroupKind:
		return protowire.StartGroupType
	default:
		return protowire.VarintType
	}
}

// strictClean is an independent oracle for R13 b–d: true if b has no unknown
// field, no duplicate non-repeated field or oneof member, no group, no wire
// type mismatch, and parses at the tag/length level. It does not check UTF-8
// or packed contents.
func strictClean(b []byte, md protoreflect.MessageDescriptor, depth int) bool {
	if depth > 64 {
		return false
	}
	seen := map[protowire.Number]bool{}
	seenOneof := map[protoreflect.FullName]bool{}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return false
		}
		if typ == protowire.StartGroupType || typ == protowire.EndGroupType {
			return false
		}
		fd := md.Fields().ByNumber(num)
		if fd == nil {
			return false
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return false
		}
		val := b[n : n+m]
		b = b[n+m:]
		if fd.IsList() {
			native := nativeWireType(fd)
			packable := native != protowire.BytesType
			if typ != native && (!packable || typ != protowire.BytesType) {
				return false
			}
			if fd.Kind() == protoreflect.MessageKind {
				v, k := protowire.ConsumeBytes(val)
				if k < 0 || !strictClean(v, fd.Message(), depth+1) {
					return false
				}
			}
			continue
		}
		if typ != nativeWireType(fd) {
			return false
		}
		if seen[num] {
			return false
		}
		seen[num] = true
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() {
			if seenOneof[od.FullName()] {
				return false
			}
			seenOneof[od.FullName()] = true
		}
		if fd.Kind() == protoreflect.MessageKind {
			v, k := protowire.ConsumeBytes(val)
			if k < 0 || !strictClean(v, fd.Message(), depth+1) {
				return false
			}
		}
	}
	return true
}

func hasUnknown(m protoreflect.Message) bool {
	if len(m.GetUnknown()) != 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() == protoreflect.MessageKind {
			if fd.IsList() {
				for i := 0; i < v.List().Len(); i++ {
					if hasUnknown(v.List().Get(i).Message()) {
						found = true
					}
				}
			} else if !fd.IsMap() && hasUnknown(v.Message()) {
				found = true
			}
		}
		return !found
	})
	return found
}

func FuzzCheck(f *testing.F) {
	body := marshalDet(f, validBody())
	pd := marshalDet(f, validBody().PolicyDecision)
	restart := marshalDet(f, &wardenv1.ServiceRestartRequest{Unit: "nginx.service"})
	noParams := func() []byte { b := validBody(); b.Params = nil; return marshalDet(f, b) }()
	outer := cat(fBytes(nil, 1, make([]byte, 32)), fBytes(nil, 2, body), fBytes(nil, 3, make([]byte, 64)))
	seeds := [][]byte{
		nil,
		body,
		outer,
		body[:len(body)-1],
		fVarint(append([]byte(nil), body...), 99, 1),
		fBytes(append([]byte(nil), body...), 2, []byte("x")),
		fBytes(append([]byte(nil), body...), 9, pd),
		fBytes(append([]byte(nil), noParams...), 8, cat(fBytes(nil, 11, restart), fBytes(nil, 7, nil))),
		fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 11, fVarint(append([]byte(nil), restart...), 99, 1))),
		fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 20, nil)),
		fGroup(append([]byte(nil), body...), 99, nil),
		fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 11, fGroup(nil, 1, nil))),
		append(append([]byte(nil), body...), 0x0c),
		fBytes(nil, 10, []byte{1}),
		fVarint(nil, 2, 1),
		fBytes(nil, 8, fBytes(nil, 22, fBytes(nil, 3, packedVarints(1, 2, 3)))),
		fBytes(nil, 8, fBytes(nil, 22, fFixed64(nil, 3, 1))),
		fBytes(nil, 2, []byte("\xff")),
		{0x00, 0x00},
		{0x08, 0x80},
		{0x12, 0xff, 0xff, 0xff, 0xff, 0x0f},
		protowire.AppendVarint(nil, uint64(protowire.MaxValidNumber+1)<<3),
		fBytes(append([]byte(nil), outer...), 1, make([]byte, 32)),
	}
	seeds = append(seeds, nonCanonicalSeeds(f)...)
	seeds = append(seeds, unpackedSeeds(f)...)
	seeds = append(seeds, packedRecordSeeds(f)...)
	seeds = append(seeds, explicitDefaultSeeds(f)...)
	for _, s := range seeds {
		f.Add(s)
	}
	mds := []protoreflect.MessageDescriptor{bodyMD, outerMD}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, md := range mds {
			checkErr := wirescan.Check(b, md)
			if checkErr != nil && countSentinels(checkErr) != 1 {
				t.Fatalf("Check error %v wraps %d sentinels, want 1", checkErr, countSentinels(checkErr))
			}
			if checkErr == nil && !canonicalOK(b, md) {
				t.Fatalf("Check accepted a non-canonical encoding (%s): %x", md.FullName(), b)
			}
			clean := strictClean(b, md, 0) && canonicalOK(b, md)
			if checkErr == nil && !clean {
				t.Fatalf("Check accepted input the strict oracle rejects (%s): %x", md.FullName(), b)
			}

			var m proto.Message = new(wardenv1.EnvelopeBody)
			if md == outerMD {
				m = new(wardenv1.SignedEnvelope)
			}
			protoErr := proto.Unmarshal(b, proto.Clone(m))
			// Completeness, now including split and empty packed records
			// and explicit defaults (R13 (i), (j)): the oracle decides them.
			if clean && protoErr == nil && checkErr != nil {
				t.Fatalf("Check rejected input that is strictly clean and decodes: %v (%x)", checkErr, b)
			}

			unErr := wirescan.Unmarshal(b, m)
			if unErr != nil && countSentinels(unErr) != 1 {
				t.Fatalf("Unmarshal error %v wraps %d sentinels", unErr, countSentinels(unErr))
			}
			if checkErr != nil && unErr == nil {
				t.Fatalf("Unmarshal accepted input that Check rejects: %v", checkErr)
			}
			if checkErr == nil && unErr != nil && !errors.Is(unErr, wirescan.ErrMalformed) {
				t.Fatalf("Check passed but Unmarshal failed with a non-malformed error: %v", unErr)
			}
			if unErr != nil {
				continue
			}
			if hasUnknown(m.ProtoReflect()) {
				t.Fatalf("Unmarshal result carries unknown fields")
			}
			re, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if err := wirescan.Check(re, md); err != nil {
				t.Fatalf("re-marshalled message fails Check: %v", err)
			}
			m2 := proto.Clone(m)
			proto.Reset(m2)
			if err := wirescan.Unmarshal(re, m2); err != nil || !proto.Equal(m, m2) {
				t.Fatalf("re-marshalled message does not round trip: %v", err)
			}
		}
	})
}

// Independent oracle for the canonical-encoding rule (R13) ----------------

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

// inRange reports whether a varint wire value fits the field's type.
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

func varintKind(k protoreflect.Kind) bool {
	switch k {
	case protoreflect.BoolKind, protoreflect.EnumKind,
		protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Uint32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		return true
	}
	return false
}

// canonicalOK is true if every tag, length prefix, varint value and packed
// element in b (recursively, by md) is minimally encoded, every int32/enum,
// uint32/sint32 and bool value is in range, every repeated numeric or enum
// field is exactly one non-empty packed record per message (no record with
// a varint, I32 or I64 wire type for a repeated field, no second packed
// record, no empty one, R13 (i)), and no non-repeated, non-message field
// with implicit presence holds its explicitly encoded proto3 default (R13
// (j)). It returns false for anything it cannot parse or does not know, so
// it is only meaningful as "Check accepted => canonicalOK".
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
		typ := protowire.Type(tag & 7)
		if fd.IsList() && typ != protowire.BytesType {
			// An unpacked element of a repeated numeric or enum field.
			return false
		}
		// R13 (j): a zero value here would be the proto3 default written out.
		implicit := !fd.IsList() && fd.Kind() != protoreflect.MessageKind && !fd.HasPresence()
		switch typ {
		case protowire.VarintType:
			v, k := readVarint(b)
			if k < 0 || k != minimalLen(v) || !inRange(fd.Kind(), v) || (implicit && v == 0) {
				return false
			}
			b = b[k:]
		case protowire.Fixed32Type:
			if len(b) < 4 || (implicit && allZero(b[:4])) {
				return false
			}
			b = b[4:]
		case protowire.Fixed64Type:
			if len(b) < 8 || (implicit && allZero(b[:8])) {
				return false
			}
			b = b[8:]
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
			if fd.IsList() && nativeWireType(fd) != protowire.BytesType {
				// R13 (i): one non-empty packed record per field per message.
				if packedSeen[num] || l == 0 {
					return false
				}
				packedSeen[num] = true
			}
			switch {
			case fd.Kind() == protoreflect.MessageKind:
				if !canonicalOK(payload, fd.Message()) {
					return false
				}
			case fd.IsList() && varintKind(fd.Kind()):
				for len(payload) > 0 {
					v, k := readVarint(payload)
					if k < 0 || k != minimalLen(v) || !inRange(fd.Kind(), v) {
						return false
					}
					payload = payload[k:]
				}
			}
		default:
			return false
		}
	}
	return true
}

// allZero reports whether every byte of b is 0: a fixed-width proto3
// default (0, or +0.0 for float and double; -0.0 has its sign bit set).
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// packedRecordSeeds is one input for each rejected R13 (i) record layout
// (split list, empty record alone, before or after a valid one, mixed with
// an unpacked record) on the contract's P22 fields, directly and through a
// body, and on the test-only descriptors.
func packedRecordSeeds(tb testing.TB) [][]byte {
	noParams := func() []byte { b := validBody(); b.Params = nil; return marshalDet(tb, b) }()
	withReq := func(req []byte) []byte { return fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 22, req)) }
	rec := func(num protowire.Number, vals ...uint64) []byte { return fBytes(nil, num, packedVarints(vals...)) }
	var out [][]byte
	for _, num := range []protowire.Number{3, 4} {
		for _, req := range [][]byte{
			cat(rec(num, 1), rec(num, 2, 3)),
			fBytes(nil, num, nil),
			cat(fBytes(nil, num, nil), rec(num, 1, 2, 3)),
			cat(rec(num, 1, 2, 3), fBytes(nil, num, nil)),
			cat(rec(num, 1), fVarint(nil, num, 2)),
			cat(rec(num, 1), fBytes(nil, num, []byte{0x80})),
			rec(num, 0, 0, 0),
		} {
			out = append(out, req, withReq(req))
		}
	}
	return append(out,
		// kindsMD: repeated enum (17) and uint32 (15), and per-child records.
		cat(rec(17, 1), rec(17, 1, 0)),
		fBytes(nil, 17, nil),
		cat(rec(15, 1), rec(15, 2)),
		cat(fBytes(nil, 22, rec(15, 1)), fBytes(nil, 22, rec(15, 2))),
		fBytes(nil, 12, cat(rec(15, 1), rec(15, 2))),
		// fixedKindsMD: repeated fixed32 (1) split.
		cat(fBytes(nil, 1, protowire.AppendFixed32(nil, 1)), fBytes(nil, 1, protowire.AppendFixed32(nil, 2))),
		// presenceMD: repeated uint32 (24) split and empty.
		cat(rec(pRU32, 1), rec(pRU32, 2)),
		fBytes(nil, pREnum, nil),
	)
}

// explicitDefaultSeeds is one input for each R13 (j) case: explicit
// defaults in implicit-presence fields at depths 0-2 and in the outer
// envelope, and their exempt counterparts (oneof member, optional field,
// empty message, repeated element).
func explicitDefaultSeeds(tb testing.TB) [][]byte {
	without := func(m func(b *wardenv1.EnvelopeBody)) []byte { b := validBody(); m(b); return marshalDet(tb, b) }
	noFV := without(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })
	noCreated := without(func(b *wardenv1.EnvelopeBody) { b.CreatedAt = 0 })
	noPD := without(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil })
	noParams := without(func(b *wardenv1.EnvelopeBody) { b.Params = nil })
	body := marshalDet(tb, validBody())
	pd := marshalDet(tb, validBody().PolicyDecision)
	withReq := func(member protowire.Number, req []byte) []byte {
		return fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, member, req))
	}
	kid, sig := make([]byte, 32), make([]byte, 64)
	return [][]byte{
		fVarint(append([]byte(nil), noFV...), 1, 0),
		cat([]byte{0x08, 0x80, 0x00}, noFV),
		fVarint(append([]byte(nil), noCreated...), 10, 0),
		fBytes(append([]byte(nil), noPD...), 9, fBytes(append([]byte(nil), pd...), 4, nil)),
		fBytes(append([]byte(nil), noPD...), 9, cat(pd, fVarint(nil, 2, 0))),
		withReq(11, fBytes(nil, 1, nil)),
		withReq(17, fVarint(nil, 5, 0)),
		withReq(22, fVarint(nil, 1, 0)),
		withReq(22, fVarint(nil, 5, 0)),
		withReq(7, nil),
		cat(fBytes(nil, 1, nil), fBytes(nil, 2, body), fBytes(nil, 3, sig)),
		cat(fBytes(nil, 1, kid), fBytes(nil, 2, nil), fBytes(nil, 3, sig)),
		cat(fBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, nil)),
		// test-only descriptors
		fVarint(nil, pU32, 0),
		fBytes(nil, pByt, nil),
		fFixed64(nil, pDbl, 0),
		fFixed64(nil, pDbl, 1<<63), // -0.0: not the default
		fVarint(nil, pOI32, 0),     // oneof member: exempt
		fBytes(nil, pOStr, nil),    // oneof member: exempt
		fVarint(nil, pOptU32, 0),   // optional: exempt
		fBytes(nil, pOptByt, nil),  // optional: exempt
		fBytes(nil, pChild, fVarint(nil, pBool, 0)),
		fBytes(nil, pChildren, fBytes(nil, pStr, nil)),
		fBytes(nil, 12, fVarint(nil, 3, 0)), // kindsMD child.u32 = 0
		fBytes(nil, 11, nil),                // kindsMD str = ""
		fVarint(nil, 1, 0),                  // wrapper value = 0
	}
}

// unpackedSeeds is one input for each unpacked form of a repeated numeric
// or enum field (R13 (i)), for the descriptors the fuzz targets use.
func unpackedSeeds(tb testing.TB) [][]byte {
	noParams := func() []byte { b := validBody(); b.Params = nil; return marshalDet(tb, b) }()
	withReq := func(req []byte) []byte { return fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, 22, req)) }
	return [][]byte{
		withReq(fVarint(nil, 3, 1)),
		withReq(cat(fVarint(nil, 3, 1), fVarint(nil, 3, 2))),
		withReq(cat(fBytes(nil, 3, packedVarints(1, 2)), fVarint(nil, 3, 3))),
		withReq(cat(fVarint(nil, 3, 1), fBytes(nil, 3, packedVarints(2)))),
		withReq(fVarint(nil, 4, math.MaxUint64)),
		withReq(cat(fBytes(nil, 3, packedVarints(1)), fVarint(nil, 4, 0))),
		withReq(cat(fBytes(nil, 3, packedVarints(1)), fBytes(nil, 3, packedVarints(2)))),
		withReq(fBytes(nil, 3, nil)),
		fVarint(nil, 3, 1),
		cat(fVarint(nil, 4, 1), fVarint(nil, 4, 2)),
		fFixed32(nil, 3, 1),
		fFixed64(nil, 4, 1),
		fVarint(nil, 16, 0),
		fVarint(nil, 17, 1),
		fFixed32(nil, 21, 1),
		cat(fBytes(nil, 21, protowire.AppendFixed32(nil, 1)), fFixed32(nil, 21, 2)),
		fBytes(nil, 12, fVarint(nil, 13, i64(-1))),
		fBytes(nil, 22, fVarint(nil, 20, 1)),
	}
}

// nonCanonicalSeeds is one input for each rejected form.
func nonCanonicalSeeds(tb testing.TB) [][]byte {
	body := marshalDet(tb, validBody())
	without := func(m func(b *wardenv1.EnvelopeBody)) []byte { b := validBody(); m(b); return marshalDet(tb, b) }
	noFV := without(func(b *wardenv1.EnvelopeBody) { b.FormatVersion = 0 })
	noPD := without(func(b *wardenv1.EnvelopeBody) { b.PolicyDecision = nil })
	noParams := without(func(b *wardenv1.EnvelopeBody) { b.Params = nil })
	pdNoLevel := marshalDet(tb, &wardenv1.PolicyDecision{DecisionId: "3c4d5e6f-7a8b-4c9d-ae0f-1a2b3c4d5e6f", PolicyBundleDigest: make([]byte, 32)})
	withLevel := func(v []byte) []byte { return fBytes(append([]byte(nil), noPD...), 9, cat(pdNoLevel, []byte{0x10}, v)) }
	withReq := func(member protowire.Number, req []byte) []byte {
		return fBytes(append([]byte(nil), noParams...), 8, fBytes(nil, member, req))
	}
	kid, sig := make([]byte, 32), make([]byte, 64)
	return [][]byte{
		cat(noFV, []byte{0x08, 0x81, 0x00}),
		cat(noFV, []byte{0x88, 0x00, 0x01}),
		cat(noFV, []byte{0x08}, overlongN(1, 10)),
		fVarint(append([]byte(nil), noFV...), 1, 1<<32+1),
		fVarint(append([]byte(nil), noFV...), 1, 1<<32),
		fVarint(append([]byte(nil), noFV...), 1, math.MaxUint64),
		withLevel(protowire.AppendVarint(nil, 1<<32+4)),
		withLevel(protowire.AppendVarint(nil, 1<<31)),
		withLevel(protowire.AppendVarint(nil, i64(math.MinInt32-1))),
		withLevel([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}),
		withLevel(protowire.AppendVarint(nil, math.MaxUint64)),
		withLevel(overlong(3)),
		fBytesOverlongLen(without(func(b *wardenv1.EnvelopeBody) { b.ActionId = "" }), 2, []byte("abc")),
		fBytesOverlongLen(append([]byte(nil), noPD...), 9, pdNoLevel),
		withReq(17, fVarint(nil, 5, 2)),
		withReq(17, fVarint(nil, 5, 1<<32)),
		withReq(17, fVarint(nil, 2, 1<<32+7)),
		withReq(22, fBytes(nil, 3, cat(packedVarints(1), overlong(2)))),
		withReq(22, fBytesOverlongLen(nil, 3, packedVarints(1, 2))),
		withReq(22, fBytes(nil, 4, packedVarints(math.MaxUint64, 1<<63))),
		withReq(11, fBytesOverlongLen(nil, 1, []byte("nginx.service"))),
		append(append([]byte(nil), body...), 0x88, 0x80),
		cat(fOverlongTagBytes(nil, 1, kid), fBytes(nil, 2, body), fBytes(nil, 3, sig)),
		cat(fBytes(nil, 1, kid), fBytesOverlongLen(nil, 2, body), fBytes(nil, 3, sig)),
		cat([]byte{0x0a, 0xa0, 0x00}, kid, fBytes(nil, 2, body), fBytes(nil, 3, sig)),
	}
}

// FuzzCanonical: whenever Check accepts, every varint is minimal, every
// 32-bit and bool value is in range, every repeated numeric or enum field
// is one non-empty packed record and no implicit-presence field holds an
// explicit default; whenever the input is strictly clean, canonical and
// decodes, Check accepts. It runs over the contract and over descriptors
// that have int32, sint32, bool, packed 32-bit and 64-bit fields, scalar
// oneof members and proto3 optional fields.
func FuzzCanonical(f *testing.F) {
	for _, s := range nonCanonicalSeeds(f) {
		f.Add(s)
	}
	for _, s := range unpackedSeeds(f) {
		f.Add(s)
	}
	for _, s := range packedRecordSeeds(f) {
		f.Add(s)
	}
	for _, s := range explicitDefaultSeeds(f) {
		f.Add(s)
	}
	f.Add(marshalDet(f, validBody()))
	f.Add(fVarint(nil, 1, 1<<31))
	f.Add([]byte{0x08, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add(fVarint(nil, 1, math.MaxUint64))
	f.Add(fVarint(nil, 2, 1<<32))
	f.Add(fVarint(nil, 4, 2))
	f.Add(fBytes(nil, 16, packedVarints(0, 1, 2)))
	f.Add(fBytes(nil, 13, packedVarints(math.MaxUint64, 1<<32+4)))
	f.Add(fBytes(nil, 12, fBytes(nil, 12, fVarintOverlong(nil, 1, 1))))
	f.Add(fBytes(nil, 22, fVarint(nil, 5, 1<<32+1)))
	mds := []protoreflect.MessageDescriptor{
		bodyMD, outerMD, dbTermMD, kindsMD, fixedKindsMD, locationMD, presenceMD,
		(&wrapperspb.Int32Value{}).ProtoReflect().Descriptor(),
		(&wrapperspb.UInt32Value{}).ProtoReflect().Descriptor(),
		(&wrapperspb.BoolValue{}).ProtoReflect().Descriptor(),
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, md := range mds {
			checkErr := wirescan.Check(b, md)
			if checkErr != nil && countSentinels(checkErr) != 1 {
				t.Fatalf("Check error %v wraps %d sentinels, want 1", checkErr, countSentinels(checkErr))
			}
			canon := canonicalOK(b, md)
			if checkErr == nil && !canon {
				t.Fatalf("Check accepted a non-canonical encoding (%s): %x", md.FullName(), b)
			}
			if checkErr != nil && errors.Is(checkErr, wirescan.ErrNonCanonical) && canon && strictClean(b, md, 0) {
				t.Fatalf("ErrNonCanonical for an input the oracle finds canonical and clean (%s): %x", md.FullName(), b)
			}
			if !canon || !strictClean(b, md, 0) || errors.Is(checkErr, wirescan.ErrTooDeep) {
				continue
			}
			if proto.Unmarshal(b, newMessage(md)) == nil && checkErr != nil {
				t.Fatalf("Check rejected a clean canonical input (%s): %v (%x)", md.FullName(), checkErr, b)
			}
		}
	})
}
