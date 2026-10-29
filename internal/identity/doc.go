// Package identity holds the agent's side of server identity
// (warden/specs/agent-identity.md): the building blocks of enrollment and
// of the mutual-TLS client configuration. It opens no network connection.
//
// What it does:
//
//   - generates the agent's ECDSA P-256 private key and the certificate
//     signing request for it (§4.4); the key never leaves this process
//     except into the agent's own 0600 state files;
//   - builds the EnrollRequest of agent-api §4.3 from the enrollment token,
//     the server UUID, the CSR and the executor binding values (R12, R12b);
//   - reads root-owned trust files only when they cannot have been replaced
//     by the agent user (R10e), and reads and writes the agent's own state
//     files atomically with the §4.7 rules;
//   - checks a certificate returned by enrollment before anything is stored
//     (R15): it must name exactly this server, carry our key and be signed
//     directly by the stored agent CA. Only a pair that passed this check
//     can be written as identity.pem;
//   - builds the TLS 1.3 client configuration of R24, trusting only the
//     control-plane CAs it is given, never the system roots.
//
// What it does not do: decide which control-plane CAs are trusted (that
// set comes from the root-signed keyset, R10d), run the start-up states of
// R18a, dial, retry or renew. Those build on this package.
//
// Nothing here logs. Errors name the file or the check that failed and
// never contain a token, a private key or file contents (R20).
package identity
