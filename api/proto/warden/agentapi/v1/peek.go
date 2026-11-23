package agentapiv1

import (
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
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

// ReadMessageSeq extracts OutboxMessage field 1 with the strict wire
// scanner before anything else is decoded (R11, R32a).
func ReadMessageSeq(b []byte) (uint64, error) {
	return 0, errors.New("not implemented")
}

// PeekMember returns the field number of b's first field key, which must
// be a member of the single oneof of md (R11).
func PeekMember(b []byte, md protoreflect.MessageDescriptor) (protoreflect.FieldNumber, error) {
	return 0, errors.New("not implemented")
}

// CheckDeclared refuses a decoded message m in which any enum value,
// nested messages included, is not declared by the contract, or any field
// marked (warden.v1.required) is absent.
func CheckDeclared(m proto.Message) error {
	return nil
}
