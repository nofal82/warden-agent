# Security policy

CloudVertex Warden runs with privileged access on customer servers, so we treat
every security report as urgent.

## Reporting a vulnerability

Please do **not** open a public GitHub issue.

Email **security@cloudvertex.net** with:
- what you found and where (file, version or commit)
- how to reproduce it
- the impact you expect

We acknowledge reports within 2 business days and give an assessment within
7 days. We credit reporters who wish to be named once a fix ships.

## Scope

- `warden-agent`: the unprivileged agent, the privileged executor, the
  agent–control plane API
- `warden`: the control plane, policy engine, playbook registry, dashboard,
  install bundle

## How Warden is built to be safe

- Only a tiny executor runs as root; it accepts only signed, typed, expiring
  actions over a local socket and never runs a shell.
- Agents connect outward only, over mutual TLS.
- Releases and playbooks are signed; installs verify offline against a pinned key.
- Every action is recorded in a tamper-evident audit trail.
- Security-critical changes require written approval from an independent human
  expert before release.
