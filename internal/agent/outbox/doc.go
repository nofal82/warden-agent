// Package outbox is the agent's durable on-disk outbox
// (warden/specs/agent-api.md R28–R33). Every message the agent must get to
// the control plane — signed executor replies and the unsigned reports of
// §4.6 — is written here before the agent treats it as queued, and stays
// until the control plane acknowledges it.
//
// What it guarantees:
//
//   - one file per message, holding the exact OutboxMessage bytes that are
//     sent, every time, with the same message_seq (R29); files are 0600 in
//     a 0700 directory owned by the agent user, opened without following
//     symlinks; the file and the directory are fsync'ed before Enqueue
//     returns;
//   - message_seq comes from a next-sequence watermark file that is
//     written and fsync'ed before the message file that uses the value, so
//     a sequence is never reused, even after the outbox drains or a crash
//     removes the last file (R29);
//   - on Open every file is re-read and checked with the strict decoder;
//     a file that fails is removed, logged and counted (R29, R32a);
//   - delivery in message_seq order with at most Window messages
//     unacknowledged (R31); a message is removed only on ACCEPTED,
//     DUPLICATE or REJECTED, never on RETRY_LATER (R32);
//   - hard caps (R33): a general part, an in-flight reserve for replies to
//     requests already outstanding, and a trust reserve that only
//     trust-document results and oversize reports may use; nothing queued
//     is ever dropped or overwritten to make room; before every write into
//     the general part, the statfs free space minus the new file's
//     allocation must stay at or above FreeSpaceFloor;
//   - the OUTBOX_HIGH_WATER and OUTBOX_FULL conditions for the health
//     report (R33 items 1, 2).
//
// What it does not do: send anything (the stream is a later slice), the
// R26 priority status, the R31 reorder hold, and the gating of STATUS
// requests and envelope acknowledgements while the outbox is full. Those
// read Condition from here.
package outbox
