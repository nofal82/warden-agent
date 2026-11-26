// Package trustdoc verifies the signed trust documents a server installs:
// the keyset, signed by the installation's offline root key, and the
// server manifest, signed by a manifest-role key from that keyset
// (signing-and-updates §4.1–§4.4, §4.6).
//
// The agent and the executor use this same package, so both apply the same
// rules (signing-and-updates §5.4). It never reads files, keeps no state
// and never decides on sequence numbers; rollback and replay checks belong
// to the executor's store (action-envelope R32–R34).
//
// Every document is handled in the same order: raw size limit, strict
// decode of the outer SignedDocument, key_id computed from the trusted key,
// signature over DOMAIN || 0x00 || body, and only then a strict decode of
// the body and its field limits. A failure is reported as the kind's one
// code, KEYSET_INVALID or MANIFEST_INVALID (action-envelope D1, D5).
//
// The keyset's audit checkpoint keys (field 7) are validated like every
// other field and then dropped: a verified Keyset has no way to reach them,
// so nothing on a server can ever be accepted because of them (R11a).
//
// This package does not import internal/envelope, because the agent may
// not link the envelope verifier. It has its own copy of the Ed25519
// canonical-S check and of MAX_SKEW; drift tests keep the copies equal.
package trustdoc
