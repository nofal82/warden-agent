// Package redact removes secrets and personal data from text before it
// leaves a client server (warden/specs/redaction.md).
//
// It is the shared core of the redaction pipeline: the agent runs it
// before anything reaches its outbox or telemetry buffer, and the control
// plane runs the same code again at intake and egress (R3, §4.5, OQ4). The
// control plane must never reimplement it.
//
// For one item the order is fixed (§4.4): input limits (R39), textual
// escapes (R25a) and normalisation (R25–R28a), repeated to a fixed point
// within a pass cap (R28b), user-name pseudonyms (R12a), detection
// (§4.2), span replacement with markers and the growth cap (R31), the
// output limit (R40), and a post-check over the final output (R32). Every failure means "drop the item" (R35); the error values carry
// no content from the input (R4).
//
// The rule table is compiled in (R43): nothing outside this package can
// add, remove, narrow or reorder a detector. The package never reads a
// file, the network or the environment; the agent's pseudonym key is
// handed in by the caller as a *Pseudonymizer, and is nil at the control
// plane (R12b, R12d).
//
// Not here: the field-class table and its contract test (generated from
// the .proto, in api/proto/warden/agentapi/v1: FieldClass), the per-minute byte budget, counters and key
// loading of the agent (internal/redact), and the intake, egress and audit
// callers.
package redact
