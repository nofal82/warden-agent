## Issue and spec

Closes #
Spec: `specs/<file>.md` § <section>

## What changed

<!-- What Warden can do after this PR that it could not do before. -->

## How it was tested

- [ ] `make ci` passes locally
- [ ] New or changed validators have failure, attack and fuzz tests (`make fuzz-short`)
- [ ] Lab scenarios added or updated (playbooks and executor changes)

## Security

- [ ] This PR is **security-critical** (executor, primitives, action envelope, identity/mTLS, policy enforcement, signing/updates, redaction, audit chain) and carries the `security-critical` label
- [ ] No shell, no raw process start, no new network listener on client servers
- [ ] No secrets, real client data or signing material in code, tests or logs
- [ ] New dependencies are justified below (name, license, why)

## Reviews

- [ ] spec-checker: verdict pasted below
- [ ] security-reviewer: verdict pasted below, all CRITICAL/HIGH resolved
- AI reviews are an engineering aid. Security-critical changes still need an Approve review on GitHub from the human Go reviewer's account before a release.

<details><summary>spec-checker</summary>

</details>

<details><summary>security-reviewer</summary>

</details>

## Walkthrough for Nofal

<!-- Output of the pr-walkthrough subagent. -->

## Suggestions (not implemented)

<!-- Ideas outside the spec. They need Nofal's decision and a spec change first. -->
