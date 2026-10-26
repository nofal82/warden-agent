// Package agentapiv1 holds the Go code generated from the agent API
// contract: the gRPC services between warden-agent and the control plane
// and every message of specs/agent-api.md §4 (decision 0008, as amended
// 2026-10-25).
//
// It imports wardenv1 for the types it shares with the executor side
// (PrimitiveResult, IpcRefusalCode, TrustKind), never the other way round.
// warden-executor and warden-dbhelper never import this package, so the
// gRPC library and its network stack never reach the root process.
//
// Field limits and redaction classes are written in the .proto files as
// the options of warden/v1/options.proto (agent-api R52c). rules.go holds
// the few rules an option cannot state, next to the options they complete
// (ValidUnitID's "no .."), and reads the rest from the options. The .pb.go
// files are generated, never edited. Regenerate them with the pinned tools
// listed in ../../v1/README.md.
//
// classtable_gen.go is the redaction field-class table (redaction.md R5,
// §4.1): the class of every non-message field the agent sends, at any
// depth, PrimitiveResult variants and the three executor bodies included.
// It is generated from the redact_class options by the contract test
// (go test -run TestClassTableGenerated -update-class-table), never
// written by hand, and the same test fails the build when the committed
// table differs from a fresh generation or a string or bytes field in
// R5's scope has no class. FieldClass reads it. It lives here, not in the
// shared redact/ package, because it is keyed by contract field names and
// holds the classes that are never scanned (S, X, I, U): redact/ handles
// text only and imports no protobuf code, and both the agent and the
// control plane already import this package.
package agentapiv1
