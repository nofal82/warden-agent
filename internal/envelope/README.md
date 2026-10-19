# internal/envelope

Verification of signed action envelopes, the only way a change reaches a
client server. Spec: `~/cloudvertex/warden/specs/action-envelope.md`.

| Package | Purpose |
| --- | --- |
| `envelope` | `Verifier.Verify`: the stateless checks 1–11 of §4.5, in order, returning one rejection code |
| `envelope/wirescan` | The shared strict wire scanner (R13), used by both warden-agent and warden-executor |

## How to decode untrusted bytes

Untrusted bytes (an envelope, or any signed trust document) must go through
`Verifier.Verify`, or through `wirescan.Unmarshal` for documents that have
their own verifier.

`wirescan.Unmarshal` is the package's only entry point. It scans the wire
structure against the schema (unknown and duplicate fields, wire types,
canonical varints, value ranges, packed records, explicit defaults and
field order), then runs `proto.Unmarshal`, which also checks that `string`
fields hold valid UTF-8, then checks that no message kept unknown fields.
Only the three steps together are the R13 decode. The scan alone is
unexported, so no caller can accept bytes because the scan passed.

Signers must marshal the generated types with
`proto.MarshalOptions{Deterministic: true}` (R3). The field-order rule
R13 (k) depends on it, and on the contract declaring every message's
fields in ascending number order with each oneof's members kept together;
`TestContractFieldOrder` in `api/proto/warden/v1` enforces the second part.

Store keys and idempotency keys are taken only from verified, decoded body
fields, never from the outer `SignedEnvelope` bytes (R13 notes).
