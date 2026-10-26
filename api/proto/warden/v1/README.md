# Warden contract (v1)

Protocol Buffers definitions shared by warden-agent, warden-executor and the
control plane, in two proto packages (decision 0008, amended 2026-10-25):

- `warden.v1` (this directory, Go package `wardenv1`): the executor side.
  warden-executor links only this package.
- `warden.agentapi.v1` (`../agentapi/v1/`, Go package `agentapiv1`): the
  agent API gRPC services and messages. It imports `warden.v1`; `warden.v1`
  never imports it, and the executor never links it.

| File | Defined by |
| --- | --- |
| `v1/envelope.proto` | `~/cloudvertex/warden/specs/action-envelope.md` §4.1–§4.3 |
| `v1/typed_request.proto` | `~/cloudvertex/warden/specs/typed-action-catalog.md` §4.1, §4.4 |
| `v1/options.proto` | `agent-api.md` §4.10, §4.10.1 (R52c) |
| `v1/primitive_result.proto` | `typed-action-catalog.md` §4.8, §4.8.1 |
| `v1/executor.proto` | `executor-ipc.md` §4.3, §4.5–§4.9; `action-envelope.md` §4.4–§4.6 |
| `agentapi/v1/enrollment.proto` | `agent-api.md` §4.3 |
| `agentapi/v1/stream.proto` | `agent-api.md` §4.4, §4.5 |
| `agentapi/v1/outbox.proto` | `agent-api.md` §4.6 |
| `agentapi/v1/telemetry.proto` | `agent-api.md` §4.7 |
| `agentapi/v1/errors.proto` | `agent-api.md` §4.8, R45 |
| `agentapi/v1/service.proto` | `agent-api.md` §4.1 |

Redaction classes (`redact_class`) follow `redaction.md` §4.1. The field-class
table `agentapi/v1/classtable_gen.go` is generated from them; after changing a
`redact_class` or adding a field the agent sends, regenerate it with
`go test ./api/proto/warden/agentapi/v1/ -run TestClassTableGenerated -update-class-table`
(the contract test fails until you do). In M1,
`warden.v1` messages carry only `redact_class`; their limits stay in
hand-written validators until the M2 envelope change (agent-api R52c).

Write no `.proto` file until its spec is Approved. Generated Go code is
committed alongside the `.proto` files so both repositories build without
extra tooling. Never edit a `.pb.go` file by hand.

## Field numbers are frozen

Envelope and typed-request field numbers are part of the signed wire format.
Never renumber or reuse one. Remove a field only by reserving its number and
name (as `TypedRequest` does for P20).

## Fields are declared in ascending number order

Within every message, declare fields in strictly ascending number order. A
message that contains a `oneof` contains nothing but that oneof: no other
field, no proto3 `optional` field, no second oneof (action-envelope R13 (k),
OQ28 option (a)). `TypedRequest` is the example. `TestContractFieldOrder`
enforces both rules.

The reason: in a message with a oneof, protobuf-go writes the fields outside
any oneof first, then the oneof, even with
`proto.MarshalOptions{Deterministic: true}`. A oneof member numbered below
another field would come out of order, and the strict scanner would reject
every envelope that used it.

## Regenerating

Pinned tools (exact versions; the generated headers record them):

| Tool | Version | Source |
| --- | --- | --- |
| `protoc` | 36.2 | `https://github.com/protocolbuffers/protobuf/releases/download/v36.2/protoc-36.2-linux-x86_64.zip`, SHA-256 `121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278` |
| `protoc-gen-go` | v1.36.12 | `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12` (same version as the `google.golang.org/protobuf` runtime in `go.mod`) |
| `protoc-gen-go-grpc` | v1.6.2 | `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2` (for `agentapi/v1/service.proto`; runtime `google.golang.org/grpc` v1.84.0 in `go.mod`) |

From the repository root, with the three tools on `PATH` and the `include/`
directory of the protoc release (for `google/protobuf/descriptor.proto`)
next to its `bin/`:

```
protoc -I api/proto \
  --go_out=. --go_opt=module=github.com/nofal82/warden-agent \
  --go-grpc_out=. --go-grpc_opt=module=github.com/nofal82/warden-agent \
  api/proto/warden/v1/*.proto api/proto/warden/agentapi/v1/*.proto
```

A `make proto` target and a CI check that the committed code matches a fresh
generation are proposed to Nofal (guardrail files are not edited by agents).
