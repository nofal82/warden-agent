// Package labtrust is the M1 lab-only control-plane CA trust fallback of
// decision 0013 (warden/decisions/0013-m1-lab-trust-bootstrap.md). Only
// cmd/warden-agent-lab imports it; the release binary cmd/warden-agent
// must never link it, and a test there checks that.
//
// It is used only when both switches are on: the lab binary, and the
// root-owned marker file /etc/warden-agent/lab-trust read under the R10e
// file rules with the exact content "warden-lab-trust-m1\n". It is a
// fallback, not an override: when the keyset check returns anything other
// than "trust check impossible", that result stands.
//
// The only thing it changes is where the CA entries come from: one entry
// per certificate of controlplane-ca.pem, with that certificate's own
// fingerprint and validity. They go to the unchanged
// identity.TrustedControlPlaneCAs, so the 1–2 CA bound, duplicate
// rejection, validity and the empty-set refusal still apply, and the TLS
// configuration is the unchanged identity.ClientTLSConfig. What is skipped
// is the root-key signature and the keyset sequence, nothing else.
//
// Sunset: deleted in M2, when the executor, the keyset messages and the
// verifier land.
package labtrust
