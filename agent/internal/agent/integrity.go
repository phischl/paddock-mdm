package agent

import (
	"context"
	"log/slog"
	"time"

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
	r := a.d.Integrity.Check(ctx, integrity.Pass{ReportedUpdateAt: a.st.ReportedUpdateAt,
		ReportedSupervisorAt: a.st.ReportedSupervisorUpgradeAt, SkipFiles: skip,
		Interval: integrity.Interval(a.d.Config.DriftInterval), Established: a.st.IntegrityEstablishedAt != nil,
		Suspended: a.st.IntegritySuspended})
	save := r.SuspendedChanged
	a.st.IntegritySuspended = r.Suspended
	if r.Established && a.st.IntegrityEstablishedAt == nil {
		at := a.d.Now().UTC()
		a.st.IntegrityEstablishedAt = &at
		save = true
	}
	if save {
		a.saveState()
	}
}

// integrityInterval is the interval of the integrity check; it logs once when the cap of plan M5a R15.5 applies.
func (a *Agent) integrityInterval() time.Duration {
	used := integrity.Interval(a.d.Config.DriftInterval)
	if used != a.d.Config.DriftInterval {
		slog.Warn("the integrity check runs more often than the drift interval", "drift_interval", a.d.Config.DriftInterval,
			"integrity_interval", used)
	}
	return used
}

// syncIntegrity moves the integrity baseline of agent-written files after Paddock's own write (plan M5a C7); a
// failure is logged, never stops the writer, and defers the files to the next pass (R7.1).
func (a *Agent) syncIntegrity(files ...string) {
	if err := integrity.SyncFiles(a.d.Layout, files...); err != nil {
		slog.Warn("recording Paddock's own write in the integrity baseline failed", "files", files, "error", err)
		a.deferIntegrity(files...)
	}
}

// syncIntegrityIfChanged is syncIntegrity for a call that may not have written the file: before is its fingerprint
// taken immediately before the call (plan M5a R8).
func (a *Agent) syncIntegrityIfChanged(full string, before integrity.Fingerprint) {
	changed, err := integrity.SyncFileIfChanged(a.d.Layout, full, before)
	if err != nil {
		slog.Warn("recording Paddock's own write in the integrity baseline failed", "file", full, "error", err)
		if changed {
			a.deferIntegrity(full)
		}
	}
}

func (a *Agent) deferIntegrity(files ...string) {
	if a.d.Integrity != nil {
		a.d.Integrity.Defer(files...)
	}
}

// integrityRetry reports whether the caller must stop and retry later: err is non-nil and the first failure for key
// is younger than integrity.StateBound. A nil err forgets key. Past the bound the flow proceeds with a Warn: an
// unwritable baseline must not withhold update results or block updates for good (plan M5a R7.2, design contract 8).
func (a *Agent) integrityRetry(key string, err error) bool {
	if err == nil {
		delete(a.integrityFailed, key)
		return false
	}
	if a.integrityFailed == nil {
		a.integrityFailed = map[string]time.Time{}
	}
	first, ok := a.integrityFailed[key]
	if !ok {
		first = a.d.Now()
		a.integrityFailed[key] = first
		slog.Warn("the integrity bookkeeping failed; the step it guards waits for it", "key", key, "error", err)
	}
	if a.d.Now().Sub(first) < integrity.StateBound {
		return true
	}
	slog.Warn("the integrity bookkeeping is missed; the step it guards proceeds without it", "key", key, "error", err)
	return false
}
