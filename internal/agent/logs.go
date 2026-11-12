package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/agent/logs"
	"github.com/nofal82/warden-agent/internal/agent/telemetry"
	"github.com/nofal82/warden-agent/internal/redact"
	pubredact "github.com/nofal82/warden-agent/redact"
)

// LogOffsetsPath is the collector's persisted read positions (redaction
// R9a), in the agent's state directory (lab layout until
// agent-packaging.md exists).
const LogOffsetsPath = "/var/lib/warden-agent/log-offsets"

// Telemetry is what the Connect stream needs from log collection.
type Telemetry struct {
	Source controlplane.TelemetrySource
	Stats  func() telemetry.Stats
	Drops  func() []*agentapiv1.RedactDropCount
}

// startLogs starts the M1 log collection: the fixed rule set, the
// redaction pipeline and the telemetry buffer, until ctx is done. Every
// line goes through the pipeline before the buffer (redaction R1, R2).
func startLogs(ctx context.Context, serverID, instanceID string, log *slog.Logger) (Telemetry, error) {
	pipe := redact.New(pubredact.New(), nil) // no pseudonym key in M1: user names get the R12c marker
	if !pipe.RulesAvailable() {
		// R42: nothing scanned is sent; every item is dropped and counted.
		log.Error("agent: redaction unavailable — data not sent")
	}
	buf, err := telemetry.New(telemetry.Config{ServerID: serverID, InstanceID: instanceID, RuntimeDir: RuntimeDir})
	if err != nil {
		return Telemetry{}, fmt.Errorf("agent: telemetry buffer: %w", err)
	}
	col, err := logs.NewCollector(logs.Config{
		Rules: logs.Rules(), StatePath: LogOffsetsPath, Pipeline: pipe, Sink: buf.Add,
		Interval: logs.DefaultInterval, Log: log,
	})
	if err != nil {
		return Telemetry{}, fmt.Errorf("agent: log collector: %w", err)
	}
	log.Info("agent: log collection started", "log_rules_version", logs.RulesVersion, "redact_rules_version", pubredact.RulesVersion)
	go func() { _ = col.Run(ctx) }()
	go flushLoop(ctx, buf, log)
	return Telemetry{Source: buf, Stats: buf.Stats, Drops: pipe.Drops}, nil
}

// flushLoop seals a batch every BatchInterval (TELEMETRY_BATCHES_PER_MIN).
func flushLoop(ctx context.Context, buf *telemetry.Buffer, log *slog.Logger) {
	tick := time.NewTicker(telemetry.BatchInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := buf.Flush(); err != nil {
				log.Warn("agent: telemetry batch not sealed", "error", err.Error())
			}
		}
	}
}
