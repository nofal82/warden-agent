// Package envelope verifies signed action envelopes, the only way a change
// reaches a client server (warden/specs/action-envelope.md).
//
// The control plane signs one envelope per typed action with Ed25519 over
// the domain prefix and the exact body bytes. This package runs the
// stateless checks 1–11 of §4.5 in order and returns exactly one rejection
// code for the first that fails:
//
//  1. size, before any parsing;
//  2. the outer message (three length-checked byte fields, nothing else);
//  3. the signing key is trusted and valid now;
//  4. the signature (canonical S checked first, then pure Ed25519);
//  5. the body, decoded only after the signature verified, strictly
//     (no unknown or duplicate fields) and within every §4.2 limit;
//  6. the format version;
//  7. the key was valid when the envelope was created;
//  8. to 10. lifetime, not-yet-valid and expiry with bounded clock skew;
//  11. the envelope is for this server.
//
// The stateful checks (trust documents, replay, idempotency, rate limits)
// build on this package and live elsewhere. Nothing here trusts a value
// sent by the agent: keys, server identity and clock all come from the
// verifier's own configuration.
package envelope
