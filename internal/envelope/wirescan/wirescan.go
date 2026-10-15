package wirescan

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Sentinel errors. Every error returned by this package wraps exactly one.
var (
	// ErrMalformed: the bytes are not a valid encoding (truncated, bad
	// varint or length, invalid field number or wire type, invalid UTF-8).
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
)

// maxDepth bounds recursion. Warden's schemas are not recursive and nest at
// most a few levels, so this only guards against a future schema mistake.
const maxDepth = 16

// Check scans b as the encoding of a message described by md, recursing into
// known message-typed fields. It rejects what generated proto.Unmarshal
// silently accepts: unknown fields, repeated non-repeated fields (where the
// last one wins or messages merge), two members of one oneof, groups and
// wire-type mismatches (action-envelope R13).
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
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fmt.Errorf("%w: tag: %w", ErrMalformed, protowire.ParseError(n))
		}
		if !num.IsValid() {
			return fmt.Errorf("%w: field number %d", ErrMalformed, num)
		}
		b = b[n:]
		if typ == protowire.StartGroupType || typ == protowire.EndGroupType {
			return fmt.Errorf("field %d: %w", num, ErrGroup)
		}
		fd := fields.ByNumber(num)
		if fd == nil {
			return fmt.Errorf("field %d: %w", num, ErrUnknownField)
		}
		if err := markSeen(fd, seen, seenOneof); err != nil {
			return err
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return fmt.Errorf("%w: field %d: %w", ErrMalformed, num, protowire.ParseError(n))
		}
		if err := checkValue(fd, typ, b[:n], depth); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func markSeen(fd protoreflect.FieldDescriptor, seen map[protowire.Number]bool, seenOneof map[int]bool) error {
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

// checkValue checks one field value (v is the encoded value without its tag).
func checkValue(fd protoreflect.FieldDescriptor, typ protowire.Type, v []byte, depth int) error {
	want := scalarWireType(fd.Kind())
	if typ == want {
		if fd.Kind() == protoreflect.MessageKind {
			payload, _ := protowire.ConsumeBytes(v) // length already validated by ConsumeFieldValue
			return check(payload, fd.Message(), depth+1)
		}
		return nil
	}
	if typ == protowire.BytesType && fd.IsList() && isPackable(want) {
		payload, _ := protowire.ConsumeBytes(v)
		return checkPacked(fd, want, payload)
	}
	return fmt.Errorf("field %d: %w", fd.Number(), ErrWireType)
}

// checkPacked confirms that a packed repeated field holds whole values only.
func checkPacked(fd protoreflect.FieldDescriptor, want protowire.Type, b []byte) error {
	for len(b) > 0 {
		n := protowire.ConsumeFieldValue(fd.Number(), want, b)
		if n < 0 {
			return fmt.Errorf("%w: packed field %d: %w", ErrMalformed, fd.Number(), protowire.ParseError(n))
		}
		b = b[n:]
	}
	return nil
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
