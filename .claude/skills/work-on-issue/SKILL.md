---
name: work-on-issue
description: The standard way to take one GitHub issue from start to a ready pull request in Warden — branch, spec, tests first, implementation, checks, reviews, walkthrough. Use whenever starting work on an issue.
argument-hint: "[issue-number]"
---

# Work on issue $ARGUMENTS

Follow every step in order. Do not skip steps to save time.

## 1. Understand
- `gh issue view $ARGUMENTS` — read the issue fully.
- Find the spec section it references in `specs/` (from warden-agent:
  `~/cloudvertex/warden/specs/`). If the issue names no spec section, stop and ask Nofal.
- Read CLAUDE.md again if this is the first task of the session.

## 2. Branch
- In the main checkout: `git switch main && git pull --ff-only`, then
  `git switch -c $ARGUMENTS-<short-kebab-name>`.
- In a worktree (path contains `.claude/worktrees/`): `main` is checked out
  elsewhere, so do not switch to it. Run `git fetch origin` and
  `git rebase origin/main`, then rename the branch:
  `git branch -m $ARGUMENTS-<short-kebab-name>`.
- One issue = one branch = one pull request.

## 3. Tests first
- If the work touches anything security-critical (see CLAUDE.md), delegate to
  the `attack-test-writer` subagent first.
- Otherwise write the tests for the acceptance criteria yourself.
- Commit the failing tests: `git commit -m "test: <what> (#$ARGUMENTS)"`.

## 4. Implement
- Implement only what the spec section says. Anything else goes in the PR
  description under "Suggestions", not in the code.
- Keep commits small, messages `<type>: <what> (#$ARGUMENTS)` where type is
  feat, fix, test, docs, refactor or chore.

## 5. Check
- `make ci` must pass locally (lint, test, security scans).
- For executor or validator changes also `make fuzz-short`.

## 6. Review (all three, every time)
- `spec-checker` subagent → fix gaps, remove extras.
- `security-reviewer` subagent → fix all CRITICAL and HIGH findings, explain
  any you disagree with.
- Re-run `make ci` after fixes.

## 7. Open the pull request
- Push the branch (the user approves the push) and open the PR with
  `gh pr create`, filling every section of the PR template.
- Add the `security-critical` label if CLAUDE.md says so.
- Delegate to `pr-walkthrough` and paste its output into the PR under
  "Walkthrough for Nofal".

## 8. Stop
Never merge. Nofal merges after the lab check.
