// Package logs is the agent's M1 log collection (warden/specs/README.md,
// "M1 loop": logs the agent collects in M1). A small fixed rule set,
// compiled in and not configurable, names the error logs of Nginx,
// Apache, PHP-FPM, MySQL/MariaDB and PostgreSQL at the package-default
// locations of the V1 distributions. The collector tails those files,
// selects error lines, and hands each one to the agent redaction pipeline
// (internal/redact) before anything else sees it (redaction.md R1, R9).
//
// What it guarantees:
//
//   - files are opened without following a symlink in any path component,
//     must be regular files with one link, and are refused when owned by
//     the agent's own user (so the agent never reads its own key through a
//     planted link); the agent reads only what its user may read and never
//     changes a permission; an unreadable source is listed locally
//     (Unreadable), never escalated;
//   - rename rotation, copytruncate and truncation are followed; a partial
//     last line waits for its newline; a line longer than MaxLineRead is cut
//     so the redactor replaces it whole (R39), and its tail is skipped;
//   - read positions are persisted (fsync'ed) past the lines of a poll
//     before any of those lines reaches the redactor (R9a), so a line that
//     crashes the process is skipped after the restart; a first start
//     ships no history;
//   - no file content is ever logged.
//
// journald is not read: reading it needs cgo (sd-journal) or running
// journalctl, both forbidden in this repository (recorded in issue #44).
package logs
