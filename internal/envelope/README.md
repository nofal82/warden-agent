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
their own verifier. Never accept bytes because `wirescan.Check` returned
`nil`.

`wirescan.Check` only scans the wire structure against the schema: unknown
and duplicate fields, wire types, canonical varints, value ranges, packed
records, explicit defaults and field order. It does not check that `string`
fields hold valid UTF-8. That check happens in `proto.Unmarshal`, which
`wirescan.Unmarshal` runs after `Check`, followed by a check that no
message kept unknown fields. Only the three steps together are the R13
decode.

Store keys and idempotency keys are taken only from verified, decoded body
fields, never from the outer `SignedEnvelope` bytes (R13 notes).
