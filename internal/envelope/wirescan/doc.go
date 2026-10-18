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
// normalise: overlong varints, out-of-range 32-bit and bool values,
// repeated numbers or enums that are not one non-empty packed record, and
// explicitly encoded proto3 defaults. Field order is not checked.
package wirescan
