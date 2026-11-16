package agent

import (
	"log/slog"
	"time"
)

// ReportEnd is reportEnd, the Connect stream's OnEnd logger (issue #46).
func ReportEnd(log *slog.Logger) func(error, time.Duration) { return reportEnd(log) }
