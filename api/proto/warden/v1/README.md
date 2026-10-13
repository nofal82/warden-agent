# Agent ↔ control plane contract (v1)

Protocol Buffers definitions for the gRPC API between warden-agent and the
control plane, and for the signed action envelope.

Defined by `~/cloudvertex/warden/specs/agent-api.md` and
`~/cloudvertex/warden/specs/action-envelope.md`. Write no `.proto` file until those
specs are Approved. Generated Go code is committed alongside the `.proto`
files so both repositories build without extra tooling.
