---
name: milestone-handoff
description: Prepares the package for the human code reviewer at the end of a milestone (M0–M5) — what was built, how to run every test, lab results, known gaps, and the reviewer's priority targets. Use when Nofal says a milestone is complete.
argument-hint: "[milestone e.g. M1]"
disable-model-invocation: true
---

# Milestone handoff: $ARGUMENTS

Produce `docs/handoffs/$ARGUMENTS.md` on a branch named
`handoff-$ARGUMENTS` and open a pull request for Nofal. Do not change code.

## Contents of the handoff document

1. **Scope** — the milestone's deliverables and exit test from the
   implementation plan, each marked done / partial / not done, with links.
2. **How to run everything** — exact commands, from a clean clone:
   prerequisites and versions, `make tools`, `make ci`, `make fuzz-short`,
   `make lab` (and which lab VMs it needs). Verify each command actually works
   before writing it down.
3. **Results** — paste the summary of `make ci`, coverage per package (executor
   must be at least 90%), fuzz run duration and findings, and the latest lab run.
4. **Reviewer priority targets** — always include, with file paths:
   - executor typed-primitive input validation (path traversal, resource
     exhaustion, injection into anything reaching a process or a database)
   - action envelope checks: signature, expiry, target host, playbook
     version/digest, idempotency, replay
   - mTLS enrollment, rotation and revocation paths
   - redaction pipeline and the canary-secret leak test (from M1)
   - the milestone's fault-injection list and its lab results
5. **Security-critical PRs in this milestone** — number, title, link, and
   whether expert approval is still pending.
6. **Known gaps and decisions** — anything deferred, with the reason and the
   decision record link.
7. **Questions for the reviewer** — from Nofal and from the PR walkthroughs.

Keep it factual. Never state that a test passed unless you ran it in this
session and saw it pass.
