# cmd/warden-agent

Entry point of the unprivileged agent binary. Keep `main.go` thin: parse
config, build the components from `internal/`, run until the context is
cancelled. Built from milestone M1.
