# warden-agent

The part of **CloudVertex Warden** that runs on customer Linux servers:

- **warden-agent** runs as an unprivileged user. It collects telemetry,
  discovers services, matches log patterns, redacts secrets, and connects
  *out* to the Warden control plane over mutual TLS.
- **warden-executor** is a tiny root process with no network access. It
  accepts only signed, typed, expiring actions from the agent over a local
  Unix socket, checks them again, and runs one validated primitive. It never
  runs a shell.
- **api/** holds the Protocol Buffers contract shared with the control plane.

This repository will be published under the Apache 2.0 license at milestone
M5 so customers' security teams can read the code that runs on their servers.
Until then it is private. (Add the LICENSE file when publishing.)

Status: **M0 – Foundations.** No product code yet; specs come first.

## First-time setup

Follow `docs/SETUP.md` in the `warden` repository (WSL2 tools, Claude Code,
GitHub rulesets, labels). The short version:

## Prerequisites (Ubuntu or WSL2 Ubuntu)

```bash
sudo apt update && sudo apt install -y git make build-essential python3 jq
# Go: install the version in go.mod or newer from https://go.dev/dl/
gh --version   # GitHub CLI, for pull requests
```

Clone both repositories side by side; each reads the other:

```
~/cloudvertex/
  warden/          specs, decisions, control plane, lab
  warden-agent/    this repository
```

## Commands

| Command | What it does |
| --- | --- |
| `make tools` | Install golangci-lint, gosec, govulncheck, gitleaks |
| `make ci` | Everything CI runs: rules, hook tests, lint, security scans, tests |
| `make test` | Tests with race detector, coverage, and the 90% executor coverage gate |
| `make fuzz-short` | Every fuzz test for 30 s each (`FUZZTIME=2m make fuzz-short` for longer) |
| `make build` | Static binaries into `./bin` |
| `make rules` | Warden rule checker: no shell, no secrets, `os/exec` only in executor primitives |
| `make hooks-test` | Self-test of the Claude Code guard hooks |

## For reviewers

Start with `SECURITY.md`, then `CLAUDE.md` (the rules every contributor and
AI agent follows). Priority review targets:
`internal/executor/primitives/` (input validation), `internal/envelope/`
(signature, expiry, host, idempotency, replay), `internal/identity/` (mTLS
enrollment, rotation, revocation) and `internal/redact/`.
Milestone handoff packages are in `docs/handoffs/`.
