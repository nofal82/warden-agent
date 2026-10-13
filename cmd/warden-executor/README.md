# cmd/warden-executor

Entry point of the privileged executor. No network imports, ever. Listens
only on the local Unix socket defined in `~/cloudvertex/warden/specs/executor-ipc.md`.
Built from milestone M2.
