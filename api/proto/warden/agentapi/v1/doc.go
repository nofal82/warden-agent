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
// the options of warden/v1/options.proto (agent-api R52c). The .pb.go
// files are generated, never edited. Regenerate them with the pinned tools
// listed in ../../v1/README.md.
package agentapiv1
