// Package redact is the agent's redaction component (warden/specs/redaction.md
// R1): the one path through which a log extract leaves the agent. It wraps
// the public redact/ package, which does the actual scanning, and adds what
// only the agent has: the per-minute byte budget for telemetry (R37), the
// drop and replacement counters (R41), the health-report drop counts
// (R41a, §4.6a) and the "rules unavailable" behaviour (R42).
//
// Every failure drops the item and counts it (R35); an item is never
// returned partly redacted. Errors and counters never carry input content
// (R4).
package redact
