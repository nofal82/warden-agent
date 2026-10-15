package wirescan_test

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

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
			clean := strictClean(b, md, 0)
			if checkErr == nil && !clean {
				t.Fatalf("Check accepted input the strict oracle rejects (%s): %x", md.FullName(), b)
			}

			var m proto.Message = new(wardenv1.EnvelopeBody)
			if md == outerMD {
				m = new(wardenv1.SignedEnvelope)
			}
			protoErr := proto.Unmarshal(b, proto.Clone(m))
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
