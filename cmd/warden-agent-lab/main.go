// Command warden-agent-lab is the M1 lab agent (decision 0013): the
// release agent plus the lab CA trust fallback of package labtrust. It is
// never part of a release image.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nofal82/warden-agent/internal/agent"
	"github.com/nofal82/warden-agent/internal/agent/labtrust"
	"github.com/nofal82/warden-agent/internal/identity"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if labtrust.MarkerOK(identity.ReadRootFile) {
		log.Warn(labtrust.WarnLine)
	}
	code := agent.Main(ctx, agent.DefaultDeps(labtrust.Trust(agent.KeysetTrust, identity.ReadRootFile)), log)
	stop()
	os.Exit(code)
}
