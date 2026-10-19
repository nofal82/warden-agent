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
// With these rules the scan accepts exactly the bytes deterministic Go
// marshalling produces.
//
// Untrusted input must go through Unmarshal (which the envelope verifier
// uses), never through Check alone. Check looks only at the wire structure;
// it does not validate that string fields hold UTF-8. That check, and the
// final decode, happen in proto.Unmarshal, which Unmarshal runs after
// Check. Accepting bytes on the strength of Check alone would let invalid
// UTF-8 through.
package wirescan
