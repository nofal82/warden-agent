# internal/

Packages are created when a spec calls for them. Planned layout:

| Package | Milestone | Purpose |
| --- | --- | --- |
| `agent/` | M1 | Telemetry, discovery, log matching, buffering, gRPC client |
| `redact/` | M1 | Remove secrets and personal data before anything leaves the server |
| `identity/` | M1 | Enrollment, certificate issuance, rotation, revocation, mTLS |
| `supervisor/` | M1 | Watchdog and self-healing for the agent process |
| `envelope/` | M1–M2 | Signed action envelope: stateless verification (M1); digest, idempotency, replay (M2) |
| `envelope/wirescan/` | M1 | Shared strict Protocol Buffers wire scanner (agent and executor) |
| `testproto/ordertest/` | M1 | Test-only messages that break the contract field-order rule on purpose (R13 (k), OQ28); imported only by tests |
| `ipc/` | M2 | Agent ↔ executor Unix-socket protocol and peer-credential checks |
| `executor/` | M2 | Executor server |
| `executor/primitives/` | M2–M3 | Typed actions; the only place `os/exec` is allowed |
