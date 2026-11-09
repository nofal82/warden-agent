// Command warden-agent is the release agent binary. It never trusts a
// control-plane CA without a verified keyset (signing-and-updates R38).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nofal82/warden-agent/internal/agent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	code := agent.Main(ctx, agent.DefaultDeps(agent.KeysetTrust), log)
	stop()
	os.Exit(code)
}
