# cmd/warden-agent-lab

M1 lab-only agent binary (decision 0013). Same start-up as
`cmd/warden-agent`, plus the lab control-plane CA trust fallback, active
only when no keyset verifies and the root-owned marker
`/etc/warden-agent/lab-trust` holds exactly `warden-lab-trust-m1` and a
newline. Logs a fixed WARN line at start while lab trust is on. Never
shipped; removed in M2.

## Lab install: the outbox filesystem

The agent's outbox (agent-api R29, R33 "Storage") must sit on its own
filesystem of at most 96 MiB, so a full outbox can never fill the
server's disk. The installer runs no other program, so the admin makes
this filesystem first, as root:

```
useradd --system --no-create-home --shell /usr/sbin/nologin warden-agent   # if not done yet
install -d -o warden-agent -g warden-agent -m 0700 /var/lib/warden-agent
install -d -o root -g root -m 0755 /var/lib/warden-agent/outbox
truncate -s 96M /var/lib/warden-agent-outbox.img
chmod 0600 /var/lib/warden-agent-outbox.img
mkfs.ext4 -q /var/lib/warden-agent-outbox.img
mount -o loop,nodev,nosuid,noexec /var/lib/warden-agent-outbox.img /var/lib/warden-agent/outbox
```

Then run `warden-agent-lab-install`. It refuses, writing nothing, unless
`/var/lib/warden-agent/outbox` is a separate filesystem of at most 96 MiB
with no `queue` directory. It creates `queue` (owner `warden-agent`, mode
0700) and writes `var-lib-warden\x2dagent-outbox.mount`, so the image is
mounted again after a reboot; the agent unit requires that mount. The
agent writes the outbox's first watermark itself, right after its first
enrollment; a later start that finds no watermark refuses to run, so
`message_seq` never restarts.

The instance ID (agent-identity R31d) lives in `/run/warden-agent`
(`RuntimeDirectory=`, kept across restarts, cleared at boot).
