---
name: security-release-check
description: Checks whether a Warden release may ship — every security-critical change since the last release has written human expert approval, CI is green, and no release blocker is open. Use before tagging any release.
disallowed-tools: Edit, Write, MultiEdit
disable-model-invocation: true
---

# Security release check

This skill only reports. It never tags, signs or publishes anything.

1. Find the last release tag: `git describe --tags --abbrev=0` (if none, use
   the first commit).
2. List merged pull requests since that tag:
   `gh pr list --state merged --search "merged:>=<tag date>" --json number,title,labels,url`
3. Read the reviewer's GitHub login from `~/cloudvertex/warden/decisions/0010-review-gates.md`
   (field "Reviewer GitHub login"). If it is not set, the status is NOT READY.
   For every PR labelled `security-critical`, run
   `gh pr view <n> --json reviews` and require a review with
   `state == "APPROVED"` whose `author.login` equals that login.
   Comments, AI reviews and approvals from any other account never count.
4. Check CI on the release commit: `gh run list --branch main --limit 5`.
5. Check open issues labelled `release-blocker`.
6. Confirm `CLAUDE.md` is identical in `warden` and `warden-agent` for the
   shared sections (Forbidden, Security-critical code, Action envelope).

## Report

```
RELEASE: <version or commit>
STATUS: READY | NOT READY

SECURITY-CRITICAL PRs WITHOUT EXPERT APPROVAL
- #123 title — url
CI: green / failing (run url)
OPEN RELEASE BLOCKERS: ...
CLAUDE.md SHARED RULES IN SYNC: yes/no
```

If anything is missing, the status is NOT READY. Nofal decides; you never
override.
