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

## Lab install: read access to the M1 logs

The agent runs as the unprivileged `warden-agent` user. It reads only what
that user can read and never changes a permission or a group membership
to read more (warden `specs/README.md`, "M1 loop"). A source it cannot
read is logged locally ("logs: source not read") and is not escalated.
The admin grants read access once, as root.

The files the agent tails (log rule set version 1, `internal/agent/logs`):

| Rule | Path | Unit |
| --- | --- | --- |
| `nginx-error` | `/var/log/nginx/error.log` | `nginx.service` |
| `apache-error` | `/var/log/apache2/error.log` (Ubuntu, Debian) | `apache2.service` |
| `httpd-error` | `/var/log/httpd/error_log` (RHEL family) | `httpd.service` |
| `php-fpm-error` | `/var/log/php<X.Y>-fpm.log` (Ubuntu, Debian) | `php<X.Y>-fpm.service` |
| `php-fpm-rhel-error` | `/var/log/php-fpm/error.log` | `php-fpm.service` |
| `mysql-error` | `/var/log/mysql/error.log` (Ubuntu, Debian) | `mysql.service` |
| `mysqld-rhel-error` | `/var/log/mysql/mysqld.log` (RHEL MySQL) | `mysqld.service` |
| `mariadb-rhel-error` | `/var/log/mariadb/mariadb.log` (RHEL MariaDB) | `mariadb.service` |
| `postgresql-error` | `/var/log/postgresql/postgresql-<N>-main.log` | `postgresql@<N>-main.service` |
| `postgresql-rhel-error` | `/var/lib/pgsql/data/log/postgresql-<Day>.log` | `postgresql.service` |
| `postgresql-pgdg-error` | `/var/lib/pgsql/<N>/data/log/postgresql-<Day>.log` | `postgresql-<N>.service` |

Only error-level lines are selected, and each is redacted before it is
buffered. journald is not read in M1.

**Ubuntu and Debian.** These logs belong to group `adm`:

```
usermod -aG adm warden-agent
systemctl restart warden-agent-lab
```

**RHEL, Rocky and Alma.** There is no `adm` group for these logs, and the
directories are root-only or service-only. Use ACLs. The default ACLs keep
files that logrotate or the service creates later readable:

```
for d in /var/log/nginx /var/log/httpd /var/log/php-fpm /var/log/mariadb /var/log/mysql; do
  [ -d "$d" ] || continue
  setfacl -m u:warden-agent:rx "$d"
  setfacl -d -m u:warden-agent:r "$d"
  find "$d" -maxdepth 1 -type f -exec setfacl -m u:warden-agent:r {} +
done
# PostgreSQL (AppStream). For PGDG use /var/lib/pgsql/<N>/data/log, and x on /var/lib/pgsql/<N> too.
setfacl -m u:warden-agent:x /var/lib/pgsql /var/lib/pgsql/data
setfacl -m u:warden-agent:rx /var/lib/pgsql/data/log
setfacl -d -m u:warden-agent:r /var/lib/pgsql/data/log
find /var/lib/pgsql/data/log -maxdepth 1 -type f -exec setfacl -m u:warden-agent:r {} +
```

PostgreSQL checks its data directory's permissions at start. An `x`-only
ACL entry leaves the mode bits unchanged, but restart PostgreSQL once on
the lab server to confirm.

The agent refuses a log that is a symlink, has a symlink anywhere in its
path, has more than one hard link, or is owned by `warden-agent` itself.
Read positions are kept in `/var/lib/warden-agent/log-offsets`. On the
first start every log is read from its end, so no history is sent.
