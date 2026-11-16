package agent

import (
	"context"
	"log/slog"

	"github.com/phischl/paddock-mdm/agent/internal/integrity"
	"github.com/phischl/paddock-mdm/agent/internal/state"
)

// tickIntegrity runs the integrity check of the drift pass on an enrolled device, in both enforcement modes (ADR
// 0056). It only reads and reports.
func (a *Agent) tickIntegrity(ctx context.Context) {
	if a.d.Integrity == nil || a.st.Status != state.StatusActive {
		return
	}
	var skip []string
	if a.conversionBusy {
		// The conversion worker writes or removes disk-setup.json long before it returns and syncs the baseline.
		skip = append(skip, a.d.Layout.DiskSetupConfig())
	}
	a.d.Integrity.Check(ctx, integrity.Pass{ReportedUpdateAt: a.st.ReportedUpdateAt,
		ReportedSupervisorAt: a.st.ReportedSupervisorUpgradeAt, SkipFiles: skip})
}

// syncIntegrity moves the integrity baseline of agent-written files after Paddock's own write (plan M5a C7); a
// failure is logged and never stops the writer.
func (a *Agent) syncIntegrity(files ...string) {
	if err := integrity.SyncFiles(a.d.Layout, files...); err != nil {
		slog.Warn("recording Paddock's own write in the integrity baseline failed", "files", files, "error", err)
	}
}
