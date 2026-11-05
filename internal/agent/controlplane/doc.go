// Package controlplane is the agent's gRPC client to the control plane
// (warden/specs/agent-api.md). This slice holds only enrollment: the
// Enroll call on the enrollment endpoint and the retry loop around
// identity.Enroll. Connect, Renew and UploadTelemetry come later.
//
// What it does:
//
//   - dials the enrollment endpoint by the rules of R2: an explicit
//     dns:/// or passthrough:/// target, no proxy, no service config from
//     name resolution, no gRPC retry, no compressor, an 8 KiB header-list
//     limit and fixed flow-control windows;
//   - uses only the TLS 1.3 configuration of identity.ClientTLSConfig
//     (R3, agent-identity R24), with no client certificate;
//   - bounds every attempt: one dial deadline of 10 s for name
//     resolution, TCP and the TLS handshake together, inside the 30 s
//     ENROLL_DEADLINE (R47); one new connection per attempt, closed after
//     it;
//   - refuses a response larger than its §4.2 limit before decoding it,
//     decodes it with agentapiv1.StrictUnmarshal and checks its field
//     limits (R16), before identity.Enroll applies R15;
//   - decides retry only from the gRPC code and the strictly decoded
//     EndDetail (R45), never from the status message;
//   - retries enrollment with the same pending key under the backoff of
//     §4.9 (1 min doubling to 1 h, ±20 % jitter) until the token expires
//     (agent-identity R12a, R18a case 3).
//
// What it does not do: listen, choose trust (the caller passes the R10d
// set), read the executor binding file, or log. Errors carry the gRPC
// code and reason name only, never the peer's status message, a token or
// a key (R20, R45).
package controlplane
