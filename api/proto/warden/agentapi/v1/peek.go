package agentapiv1

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// ErrMessageSeqUnreadable: OutboxMessage field 1 is missing, duplicated,
// of the wrong wire type, zero, or the bytes around it are malformed
// (R32a).
var ErrMessageSeqUnreadable = errors.New("agentapiv1: message_seq unreadable")

// ErrMemberUnreadable: the first field key of a oneof-only message is not
// a member of its oneof (R11).
var ErrMemberUnreadable = errors.New("agentapiv1: oneof member unreadable")

// ErrUndeclared: an enum value the contract does not declare, or a field
// marked (warden.v1.required) that is absent (R12; V4 of PR #60).
var ErrUndeclared = errors.New("agentapiv1: undeclared enum value or missing required field")

// consumeKey reads one field key and refuses what the strict scanner
// refuses in a key: malformed or overlong varints (R13 (e)), invalid field
// numbers and the group wire types.
func consumeKey(b []byte) (protowire.Number, protowire.Type, int, bool) {
	num, typ, n := protowire.ConsumeTag(b)
	if n < 0 || protowire.SizeTag(num) != n || typ == protowire.StartGroupType || typ == protowire.EndGroupType {
		return 0, 0, 0, false
	}
	return num, typ, n, true
}

// ReadMessageSeq extracts OutboxMessage field 1 with the strict wire
// scanner before anything else is decoded (R11, R32a). Every top-level
// field is walked so a malformed message is refused, but only field 1 is
// read; it must occur once, as a minimal varint, and be non-zero.
func ReadMessageSeq(b []byte) (uint64, error) {
	var seq uint64
	seen := false
	for len(b) > 0 {
		num, typ, n, ok := consumeKey(b)
		if !ok {
			return 0, fmt.Errorf("%w: bad field key", ErrMessageSeqUnreadable)
		}
		b = b[n:]
		if num == 1 {
			if seen || typ != protowire.VarintType {
				return 0, fmt.Errorf("%w: field 1 duplicated or of the wrong wire type", ErrMessageSeqUnreadable)
			}
			v, m := protowire.ConsumeVarint(b)
			if m < 0 || protowire.SizeVarint(v) != m {
				return 0, fmt.Errorf("%w: field 1 is not a minimal varint", ErrMessageSeqUnreadable)
			}
			seq, seen, b = v, true, b[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return 0, fmt.Errorf("%w: malformed field %d", ErrMessageSeqUnreadable, num)
		}
		b = b[m:]
	}
	if !seen || seq == 0 {
		return 0, fmt.Errorf("%w: field 1 missing or zero", ErrMessageSeqUnreadable)
	}
	return seq, nil
}

// PeekMember returns the field number of b's first field key, which must
// be a length-delimited member of a oneof of md (R11). Only the key is
// read; the caller checks the member's size limit and then decodes the
// whole message with StrictUnmarshal.
func PeekMember(b []byte, md protoreflect.MessageDescriptor) (protoreflect.FieldNumber, error) {
	num, typ, _, ok := consumeKey(b)
	if !ok || typ != protowire.BytesType {
		return 0, fmt.Errorf("%w: bad first field key", ErrMemberUnreadable)
	}
	fd := md.Fields().ByNumber(num)
	if fd == nil || fd.ContainingOneof() == nil || fd.Kind() != protoreflect.MessageKind {
		return 0, fmt.Errorf("%w: field %d is not a oneof member of %s", ErrMemberUnreadable, num, md.FullName())
	}
	return num, nil
}

// CheckDeclared refuses a decoded message m in which any enum value,
// nested messages included, is not declared by the contract, or any field
// marked (warden.v1.required) is absent. The strict scanner accepts any
// int32 for an enum (R13 (f) checks only the range), so callers run this
// after StrictUnmarshal (R12: an enum value outside the listed values is
// MALFORMED; PR #60 V4: where UNSPECIFIED is invalid the field is
// required and the decoder refuses it).
func CheckDeclared(m proto.Message) error {
	return checkDeclared(m.ProtoReflect(), 0)
}

// maxDeclaredDepth bounds the walk. It is the scanner's nesting limit
// (wirescan maxDepth, 16), so a message the scanner accepted is never too
// deep here, and a message built in memory cannot recurse without bound.
const maxDeclaredDepth = 16

func checkDeclared(m protoreflect.Message, depth int) error {
	if depth > maxDeclaredDepth {
		return fmt.Errorf("%w: nesting too deep", ErrUndeclared)
	}
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if req, _ := proto.GetExtension(fd.Options(), wardenv1.E_Required).(bool); req && !m.Has(fd) {
			return fmt.Errorf("%w: %s is required", ErrUndeclared, fd.FullName())
		}
	}
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		err = checkValue(fd, v, depth)
		return err == nil
	})
	return err
}

func checkValue(fd protoreflect.FieldDescriptor, v protoreflect.Value, depth int) error {
	switch {
	case fd.IsMap():
		var err error
		v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
			err = checkSingle(fd.MapValue(), mv, depth)
			return err == nil
		})
		return err
	case fd.IsList():
		l := v.List()
		for i := range l.Len() {
			if err := checkSingle(fd, l.Get(i), depth); err != nil {
				return err
			}
		}
		return nil
	}
	return checkSingle(fd, v, depth)
}

func checkSingle(fd protoreflect.FieldDescriptor, v protoreflect.Value, depth int) error {
	switch fd.Kind() {
	case protoreflect.EnumKind:
		if fd.Enum().Values().ByNumber(v.Enum()) == nil {
			return fmt.Errorf("%w: %s = %d is not declared", ErrUndeclared, fd.FullName(), v.Enum())
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return checkDeclared(v.Message(), depth+1)
	}
	return nil
}
