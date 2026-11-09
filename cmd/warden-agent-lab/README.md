# cmd/warden-agent-lab

M1 lab-only agent binary (decision 0013). Same start-up as
`cmd/warden-agent`, plus the lab control-plane CA trust fallback, active
only when no keyset verifies and the root-owned marker
`/etc/warden-agent/lab-trust` holds exactly `warden-lab-trust-m1` and a
newline. Logs a fixed WARN line at start while lab trust is on. Never
shipped; removed in M2.
