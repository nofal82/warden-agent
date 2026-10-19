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
// strictly ascending field order, depends on it: for that encoding of the
// generated types the scan accepts exactly the bytes the signer produced,
// byte for byte (AC8a). It also depends on how the contract is declared.
// protobuf-go writes a field numbered between two members of a oneof out
// of order, with or without Deterministic, so every contract message
// declares its fields in ascending number order and keeps each oneof's
// members together (OQ28 ruling, enforced by TestContractFieldOrder in
// api/proto/warden/v1).
//
// # Entry point
//
// Unmarshal is the only entry point. It runs the wire scan, then
// proto.Unmarshal (which rejects string fields that are not valid UTF-8),
// then a check that no message kept unknown fields. The scan alone is not
// exported: accepting bytes on the strength of the scan would let invalid
// UTF-8 through.
package wirescan
