package wirescan

import (
	"errors"
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Sentinel errors. Every error returned by this package wraps exactly one.
var (
	// ErrMalformed: the bytes are not a valid encoding (truncated, bad
	// varint or length, a 10-byte varint above 2^64 - 1, invalid field
	// number or wire type). Unmarshal also reports invalid UTF-8 in a
	// string field with it; Check does not look at string contents.
	ErrMalformed = errors.New("wirescan: malformed encoding")
	// ErrUnknownField: a field number the schema does not define.
	ErrUnknownField = errors.New("wirescan: unknown field")
	// ErrDuplicateField: a non-repeated field, or a second member of the
	// same oneof, occurs more than once.
	ErrDuplicateField = errors.New("wirescan: duplicate field")
	// ErrGroup: the deprecated group wire types 3 and 4.
	ErrGroup = errors.New("wirescan: group wire type")
	// ErrWireType: a known field encoded with a wire type that does not
	// match its kind.
	ErrWireType = errors.New("wirescan: wire type does not match schema")
	// ErrTooDeep: nesting beyond maxDepth.
	ErrTooDeep = errors.New("wirescan: nesting too deep")
	// ErrNonCanonical: a varint (tag, length or value) that is not minimally
	// encoded, a value outside the range of its field's type, a repeated
	// numeric or enum field that is not exactly one non-empty packed
	// record, an explicitly encoded default in a field with implicit
	// presence, or fields out of ascending number order. Generated
	// decoders silently truncate or normalise such encodings (2^32+1 in a
	// uint32 reads as 1), and decoders in other languages may not, so the
	// same signed bytes could be read two ways, or two different signed
	// byte strings could decode to one value.
	ErrNonCanonical = errors.New("wirescan: non-canonical encoding")
)

// maxDepth bounds recursion. Warden's schemas are not recursive and nest at
// most a few levels, so this only guards against a future schema mistake.
const maxDepth = 16

// maxVarintLen is the longest valid varint: 64 bits in 7-bit groups.
const maxVarintLen = 10

// Check scans b as the encoding of a message described by md, recursing into
// known message-typed fields. It rejects what generated proto.Unmarshal
// silently accepts: unknown fields, repeated non-repeated fields (where the
// last one wins or messages merge), two members of one oneof, groups and
// wire-type mismatches (action-envelope R13), and non-canonical encodings:
// overlong varints, int32, enum, uint32, sint32 or bool values outside
// their type's range, repeated numeric or enum fields that are not exactly
// one non-empty packed record, explicitly encoded proto3 defaults, and
// fields out of strictly ascending number order.
//
// Check does not validate string contents (UTF-8), so it must not be the
// only check on untrusted bytes; use Unmarshal.
func Check(b []byte, md protoreflect.MessageDescriptor) error {
	return check(b, md, 0)
}

// Unmarshal runs Check on b, then decodes it into m and confirms that no
// message, nested ones included, kept unknown fields.
func Unmarshal(b []byte, m proto.Message) error {
	if err := Check(b, m.ProtoReflect().Descriptor()); err != nil {
		return err
	}
	if err := proto.Unmarshal(b, m); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if hasUnknown(m.ProtoReflect()) {
		return ErrUnknownField
	}
	return nil
}

func check(b []byte, md protoreflect.MessageDescriptor, depth int) error {
	if depth > maxDepth {
		return ErrTooDeep
	}
	fields := md.Fields()
	seen := make(map[protowire.Number]bool)
	seenOneof := make(map[int]bool)
	var prev protoreflect.FieldDescriptor
	for len(b) > 0 {
		if err := checkVarintEnd(b); err != nil {
			return fmt.Errorf("tag: %w", err)
		}
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fmt.Errorf("%w: tag: %w", ErrMalformed, protowire.ParseError(n))
		}
		if !num.IsValid() {
			return fmt.Errorf("%w: field number %d", ErrMalformed, num)
		}
		if n != protowire.SizeTag(num) {
			return fmt.Errorf("field %d: tag: %w", num, ErrNonCanonical)
		}
		b = b[n:]
		if typ == protowire.StartGroupType || typ == protowire.EndGroupType {
			return fmt.Errorf("field %d: %w", num, ErrGroup)
		}
		fd := fields.ByNumber(num)
		if fd == nil {
			return fmt.Errorf("field %d: %w", num, ErrUnknownField)
		}
		if err := markSeen(fd, typ, seen, seenOneof); err != nil {
			return err
		}
		if typ == protowire.VarintType || typ == protowire.BytesType {
			// A varint value or a length prefix (R13 (l)).
			if err := checkVarintEnd(b); err != nil {
				return fmt.Errorf("field %d: %w", num, err)
			}
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return fmt.Errorf("%w: field %d: %w", ErrMalformed, num, protowire.ParseError(n))
		}
		if err := checkValue(fd, typ, b[:n], depth); err != nil {
			return err
		}
		if !inOrder(prev, fd) {
			return fmt.Errorf("field %d after field %d: %w", num, prev.Number(), ErrNonCanonical)
		}
		prev = fd
		b = b[n:]
	}
	return nil
}

// inOrder reports whether a record of fd may follow a record of prev
// (R13 (k)): field numbers strictly ascend, except that the records of one
// repeated string, bytes or message field, which cannot be packed, form one
// consecutive run. Deterministic marshalling of generated Go types writes
// this order (AC8a), so with it the scan accepts one encoding per message,
// byte for byte. Two records
// of any other field never reach here (markSeen and checkValue reject
// them).
func inOrder(prev, fd protoreflect.FieldDescriptor) bool {
	switch {
	case prev == nil || fd.Number() > prev.Number():
		return true
	case fd.Number() == prev.Number():
		return fd.IsList() && !isPackable(scalarWireType(fd.Kind()))
	default:
		return false
	}
}

// checkVarintEnd rejects a varint at the start of b that is 10 bytes long
// and does not end in 0x01 (R13 (l)): a larger last byte encodes 2^64 or
// more, and longer varints are never valid. protowire refuses these today;
// the rule is checked here so it does not depend on library internals. A
// last byte of 0x00 is left to the minimal-encoding check (R13 (e)).
func checkVarintEnd(b []byte) error {
	for i := 0; i < len(b) && i < maxVarintLen; i++ {
		if b[i] < 0x80 {
			if i == maxVarintLen-1 && b[i] > 0x01 {
				return fmt.Errorf("%w: 10-byte varint above 2^64 - 1", ErrMalformed)
			}
			return nil
		}
	}
	if len(b) >= maxVarintLen {
		return fmt.Errorf("%w: varint longer than 10 bytes", ErrMalformed)
	}
	return nil // truncated: protowire reports it
}

func markSeen(fd protoreflect.FieldDescriptor, typ protowire.Type, seen map[protowire.Number]bool, seenOneof map[int]bool) error {
	if fd.IsList() && typ == protowire.BytesType && isPackable(scalarWireType(fd.Kind())) {
		// A second packed record decodes to the concatenation of both, the
		// same list as one record, so only one is accepted (R13 (i)).
		if seen[fd.Number()] {
			return fmt.Errorf("field %d: split packed record: %w", fd.Number(), ErrNonCanonical)
		}
		seen[fd.Number()] = true
		return nil
	}
	if fd.IsList() || fd.IsMap() {
		return nil
	}
	if seen[fd.Number()] {
		return fmt.Errorf("field %d: %w", fd.Number(), ErrDuplicateField)
	}
	seen[fd.Number()] = true
	if od := fd.ContainingOneof(); od != nil {
		if seenOneof[od.Index()] {
			return fmt.Errorf("oneof %s: %w", od.Name(), ErrDuplicateField)
		}
		seenOneof[od.Index()] = true
	}
	return nil
}

// checkValue checks one field value (v is the encoded value without its tag;
// ConsumeFieldValue has already confirmed it is complete).
func checkValue(fd protoreflect.FieldDescriptor, typ protowire.Type, v []byte, depth int) error {
	want := scalarWireType(fd.Kind())
	packed := typ == protowire.BytesType && fd.IsList() && isPackable(want)
	if typ != want && !packed {
		return fmt.Errorf("field %d: %w", fd.Number(), ErrWireType)
	}
	if fd.IsList() && isPackable(want) && !packed {
		// One record per element decodes to the same list as the packed
		// form, so only the packed form is accepted (R13 (i)).
		return fmt.Errorf("field %d: unpacked repeated: %w", fd.Number(), ErrNonCanonical)
	}
	switch typ {
	case protowire.VarintType:
		x, _, err := consumeVarintValue(fd, v)
		if err == nil && x == 0 && implicitPresence(fd) {
			return explicitDefault(fd)
		}
		return err
	case protowire.Fixed32Type, protowire.Fixed64Type:
		// All-zero bits is 0 or +0.0; -0.0 is not the default and Go
		// marshalling emits it.
		if implicitPresence(fd) && allZero(v) {
			return explicitDefault(fd)
		}
	case protowire.BytesType:
		l, n := protowire.ConsumeVarint(v)
		if n != protowire.SizeVarint(l) {
			return fmt.Errorf("field %d: length: %w", fd.Number(), ErrNonCanonical)
		}
		switch {
		case packed && l == 0:
			// An empty list is encoded by leaving the field out (R13 (i)).
			return fmt.Errorf("field %d: empty packed record: %w", fd.Number(), ErrNonCanonical)
		case packed:
			return checkPacked(fd, want, v[n:])
		case fd.Kind() == protoreflect.MessageKind:
			return check(v[n:], fd.Message(), depth+1)
		case l == 0 && implicitPresence(fd):
			return explicitDefault(fd)
		}
	}
	return nil
}

// implicitPresence reports whether fd is a non-repeated scalar or enum
// field without presence: deterministic Go marshalling leaves it out when
// it holds its default, so an explicit default is a second encoding of the
// same message (R13 (j)). Oneof members, proto3 optional fields, proto2
// fields and message fields have presence and are exempt; so are
// repeated elements.
func implicitPresence(fd protoreflect.FieldDescriptor) bool {
	return !fd.IsList() && !fd.IsMap() && !fd.HasPresence() && fd.Kind() != protoreflect.MessageKind
}

func explicitDefault(fd protoreflect.FieldDescriptor) error {
	return fmt.Errorf("field %d: explicit default: %w", fd.Number(), ErrNonCanonical)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// checkPacked confirms that a packed repeated field holds whole, canonical
// values only.
func checkPacked(fd protoreflect.FieldDescriptor, want protowire.Type, b []byte) error {
	for len(b) > 0 {
		var n int
		if want == protowire.VarintType {
			var err error
			if _, n, err = consumeVarintValue(fd, b); err != nil {
				return err
			}
		} else if n = protowire.ConsumeFieldValue(fd.Number(), want, b); n < 0 {
			return fmt.Errorf("%w: packed field %d: %w", ErrMalformed, fd.Number(), protowire.ParseError(n))
		}
		b = b[n:]
	}
	return nil
}

// consumeVarintValue reads one varint value of field fd from the start of b
// and returns it and its length. The value must be minimally encoded and
// within the range of the field's type.
func consumeVarintValue(fd protoreflect.FieldDescriptor, b []byte) (uint64, int, error) {
	if err := checkVarintEnd(b); err != nil {
		return 0, 0, fmt.Errorf("field %d: %w", fd.Number(), err)
	}
	x, n := protowire.ConsumeVarint(b)
	if n < 0 {
		return 0, 0, fmt.Errorf("%w: field %d: %w", ErrMalformed, fd.Number(), protowire.ParseError(n))
	}
	if n != protowire.SizeVarint(x) || !inRange(fd.Kind(), x) {
		return 0, 0, fmt.Errorf("field %d: %w", fd.Number(), ErrNonCanonical)
	}
	return x, n, nil
}

// minNegInt32 is math.MinInt32 as the uint64 a varint carries for it: a
// negative int32 is sign-extended to 64 bits on the wire.
const minNegInt32 = 1<<64 - 1<<31

// inRange reports whether the varint x, decoded as a uint64, is a value of
// kind k without truncation (R13 (f)–(h)). 64-bit kinds take any value.
// For int32 and enum a negative value is sign-extended to 64 bits, so it is
// at least 2^64 - 2^31 and, minimally encoded, exactly 10 bytes long; the
// 5-byte FF FF FF FF 0F is 4,294,967,295, not -1, and is rejected.
func inRange(k protoreflect.Kind, x uint64) bool {
	switch k {
	case protoreflect.BoolKind:
		return x <= 1
	case protoreflect.Int32Kind, protoreflect.EnumKind:
		return x <= math.MaxInt32 || x >= minNegInt32
	case protoreflect.Uint32Kind, protoreflect.Sint32Kind:
		return x <= math.MaxUint32
	default:
		return true
	}
}

func isPackable(t protowire.Type) bool {
	return t == protowire.VarintType || t == protowire.Fixed32Type || t == protowire.Fixed64Type
}

// scalarWireType is the wire type of one value of kind k.
func scalarWireType(k protoreflect.Kind) protowire.Type {
	switch k {
	case protoreflect.BoolKind, protoreflect.EnumKind,
		protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Uint32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		return protowire.VarintType
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return protowire.BytesType
	default: // GroupKind: never valid here.
		return protowire.StartGroupType
	}
}

// hasUnknown reports whether m or any message reachable from it holds
// unknown fields.
func hasUnknown(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}
		switch {
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len() && !found; i++ {
				found = hasUnknown(l.Get(i).Message())
			}
		case fd.IsMap():
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					found = hasUnknown(mv.Message())
					return !found
				})
			}
		default:
			found = hasUnknown(v.Message())
		}
		return !found
	})
	return found
}
