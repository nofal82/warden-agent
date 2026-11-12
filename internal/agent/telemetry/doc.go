// Package telemetry is the agent's in-memory telemetry buffer
// (warden/specs/agent-api.md R43, R44, §4.7): redacted log events are
// sealed into TelemetryBatch messages, each with a batch_seq persisted in
// the runtime directory before the batch can be sent, and kept in memory
// (never in the outbox) until the control plane acknowledges them. When
// the buffer would pass TELEMETRY_BUFFER_BYTES the oldest whole batches
// are dropped and counted, and the count travels in the next batch's
// dropped_batches and in the HealthReport.
//
// Only events that already passed the redaction pipeline (internal/redact)
// may be added (redaction.md R1, R2).
package telemetry
