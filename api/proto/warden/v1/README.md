# Agent ↔ control plane contract (v1)

Protocol Buffers definitions for the gRPC API between warden-agent and the
control plane, and for the signed action envelope.

| File | Defined by |
| --- | --- |
| `envelope.proto` | `~/cloudvertex/warden/specs/action-envelope.md` §4.1–§4.3 |
| `typed_request.proto` | `~/cloudvertex/warden/specs/typed-action-catalog.md` §4.1, §4.4 |
| (gRPC service, later) | `~/cloudvertex/warden/specs/agent-api.md` (not written yet) |

Write no `.proto` file until its spec is Approved. Generated Go code is
committed alongside the `.proto` files so both repositories build without
extra tooling. Never edit a `.pb.go` file by hand.

## Field numbers are frozen

Envelope and typed-request field numbers are part of the signed wire format.
Never renumber or reuse one. Remove a field only by reserving its number and
name (as `TypedRequest` does for P20).

## Fields are declared in ascending number order

Within every message, declare fields in strictly ascending number order, and
give no other field a number between the members of a `oneof`. protobuf-go
otherwise writes some fields out of order, even with
`proto.MarshalOptions{Deterministic: true}`, and the strict scanner rejects
the bytes (action-envelope R13 (k), OQ28 ruling). `TestContractFieldOrder`
enforces this.

## Regenerating

Pinned tools (exact versions; the generated headers record them):

| Tool | Version | Source |
| --- | --- | --- |
| `protoc` | 36.2 | `https://github.com/protocolbuffers/protobuf/releases/download/v36.2/protoc-36.2-linux-x86_64.zip`, SHA-256 `121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278` |
| `protoc-gen-go` | v1.36.12 | `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12` (same version as the `google.golang.org/protobuf` runtime in `go.mod`) |

From the repository root, with both tools on `PATH`:

```
protoc -I api/proto \
  --go_out=. --go_opt=module=github.com/nofal82/warden-agent \
  api/proto/warden/v1/envelope.proto api/proto/warden/v1/typed_request.proto
```

A `make proto` target and a CI check that the committed code matches a fresh
generation are proposed to Nofal (guardrail files are not edited by agents).
