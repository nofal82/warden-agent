// Package wirescan is the shared strict Protocol Buffers wire scanner used
// by both warden-agent and warden-executor (action-envelope R13, §5.3).
//
// Generated proto.Unmarshal is lenient: it keeps unknown fields, lets a
// repeated scalar win, merges repeated messages, and accepts the last of
// two oneof members. For signed data that leniency means two parties can
// read the same bytes differently. This package scans the raw bytes against
// the schema first and refuses unknown fields, duplicates, two members of
// one oneof, group wire types and wire-type mismatches, at every depth. It
// also refuses non-canonical encodings that decoders silently truncate or
// normalise: overlong varints, 10-byte varints whose value does not fit in
// 64 bits, out-of-range 32-bit and bool values, repeated numbers or enums
// that are not one non-empty packed record, explicitly encoded proto3
// defaults, and fields that are not in strictly ascending number order.
//
// # Signers
//
// Signers MUST marshal the generated contract types with
// proto.MarshalOptions{Deterministic: true} (action-envelope R3). Rule (k),
// strictly ascending field order, is proven only for that encoding: AC8a
// marshals every contract message that way and requires the scan to accept
// the bytes unchanged. Deterministic itself fixes map order (the contract
// has no maps); field order comes from protobuf-go. In a message with a
// oneof, protobuf-go writes the fields outside any oneof first, then each
// oneof in declaration order, with or without Deterministic, and its
// reflection-based marshaller (dynamicpb) does the same
// (TestOrderReflectionMarshalOneofLast). So the contract declares every
// message's fields in ascending number order, and a message that contains
// a oneof contains nothing but that oneof (OQ28 option (a); today that is
// TypedRequest). TestContractFieldOrder in api/proto/warden/v1 enforces
// both rules.
//
// # Entry point
//
// Unmarshal is the only entry point. It runs the wire scan, then
// proto.Unmarshal (which rejects string fields that are not valid UTF-8),
// then a check that no message kept unknown fields. The scan alone is not
// exported: accepting bytes on the strength of the scan would let invalid
// UTF-8 through.
package wirescan
