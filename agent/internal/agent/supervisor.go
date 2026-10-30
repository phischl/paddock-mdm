package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// handleSupervisorPackage installs the supervisor package of the applied bundle when supervisorpkg.Plan allows it
// (plan M8d decision 31): it stages the package and starts `paddockd supervisor-upgrade` in a transient unit. A
// pending agent update, a running upgrade or an accepted uninstall waits.
func (a *Agent) handleSupervisorPackage(ctx context.Context) {
	if a.current == nil || a.d.Sys == nil {
		return
	}
	ref, ok := a.current.Agent.SupervisorPackages[runtime.GOARCH]
	if !ok {
		return
	}
	running, _ := a.supervisorUpgradeHolds()
	result, rerr := supervisorpkg.ReadResult(a.d.Layout)
	// An accepted uninstall removes the supervisor package; an upgrade started now would race the removal.
	busy := running || result != nil || rerr != nil || update.Pending(a.d.Layout) || a.st.PendingUninstall != nil
	// The conversion worker may hold dpkg's locks and must not be interrupted by a supervisor restart (plan M8e
	// decision 37 as amended on 2026-10-21, items 16 to 18): only while it runs. A preparation waiting between its
	// passes, possibly for a long time for a foreign dpkg run, and a cleanup waiting for its next attempt do not hold
	// the agent's update channel; a lock collision only defers the upgrade.
	busy = busy || a.conversionBusy
	installed := a.d.Sys.PackageVersion(supervisorpkg.Package)
	retry := a.st.SupervisorRetry
	backoff := retry != nil && retry.Version == ref.Version && a.d.Now().Before(retry.NotBefore)
	install, reason := supervisorpkg.Plan(ref, installed, a.updatesAllowed(), a.st.FailedSupervisorVersion, busy, backoff)
	if !install {
		if key := ref.Version + "\x00" + reason; a.supervisorSkipped != key && reason != supervisorpkg.ReasonInProgress {
			a.supervisorSkipped = key
			if reason == supervisorpkg.ReasonPolicy {
				slog.InfoContext(ctx, "supervisor package ignored by the organization's policy", "version", ref.Version)
			} else {
				slog.DebugContext(ctx, "supervisor package not installed", "version", ref.Version, "installed", installed, "reason", reason)
			}
		}
		return
	}
	base := BundlesURL(a.d.Config.ServerURL)
	if base == "" {
		slog.WarnContext(ctx, "supervisor package offered but no package store is configured", "version", ref.Version)
		return
	}
	deb, err := supervisorpkg.Stage(ctx, a.d.Download, a.d.Layout, base+"/"+ref.URLPath, ref)
	if err != nil {
		slog.WarnContext(ctx, "staging the supervisor package failed; retrying at the next check-in", "version", ref.Version, "error", err)
		return
	}
	if err := supervisorpkg.Launch(ctx, a.d.RunUnit, a.d.Layout, deb, ref.Version, installed); err != nil {
		slog.ErrorContext(ctx, "starting the supervisor upgrade failed; retrying at the next check-in", "version", ref.Version, "error", err)
		return
	}
	slog.InfoContext(ctx, "supervisor upgrade started", "version", ref.Version, "from_version", installed)
}

// reportSupervisorUpgrade turns the result of `paddockd supervisor-upgrade` into the event agent.supervisor_updated,
// once (plan M8d decision 32). A version that failed is not installed again; one rolled back only because the server
// was unreachable is retried after supervisorpkg.RetryAfter, up to supervisorpkg.MaxAttempts times (design contract
// 8). A marker older than supervisorpkg.StaleAfter without a result counts as install_failed: the helper died.
func (a *Agent) reportSupervisorUpgrade() {
	r, err := supervisorpkg.ReadResult(a.d.Layout)
	if err != nil {
		slog.Error("reading the supervisor upgrade result failed", "error", err)
		return
	}
	if r == nil {
		if r = a.staleSupervisorUpgrade(); r == nil {
			return
		}
	}
	if a.st.ReportedSupervisorUpgradeAt != nil && a.st.ReportedSupervisorUpgradeAt.Equal(r.At) {
		return
	}
	if r.Outcome == supervisorpkg.OutcomeDeferred {
		a.deferSupervisor(r)
		return
	}
	slog.Info("supervisor upgrade finished", "version", r.Version, "from_version", r.FromVersion, "outcome", r.Outcome)
	a.event(protocol.EventAgentSupervisorUpdated, map[string]string{"version": r.Version, "from_version": r.FromVersion, "outcome": r.Outcome})
	switch r.Outcome {
	case protocol.SupervisorOutcomeUpdated:
		a.st.SupervisorRetry = nil
	case protocol.SupervisorOutcomeRolledBackUnreachable:
		a.retrySupervisor(r)
	default:
		a.st.FailedSupervisorVersion = r.Version
	}
	at := r.At
	a.st.ReportedSupervisorUpgradeAt = &at
	a.saveState()
}

// deferSupervisor schedules the next attempt of an upgrade dpkg refused for a held lock (plan M8e amendment 2026-10-21,
// item 16): no event, no failure, no attempt counted; the wait doubles with every deferral of the version.
func (a *Agent) deferSupervisor(r *supervisorpkg.Result) {
	retry := a.st.SupervisorRetry
	if retry == nil || retry.Version != r.Version {
		retry = &state.SupervisorRetry{Version: r.Version}
	}
	retry.Deferrals++
	wait := supervisorpkg.DeferMax
	if retry.Deferrals <= 10 {
		wait = min(supervisorpkg.DeferFirst<<(retry.Deferrals-1), supervisorpkg.DeferMax)
	}
	retry.NotBefore = r.At.Add(wait)
	a.st.SupervisorRetry = retry
	at := r.At
	a.st.ReportedSupervisorUpgradeAt = &at
	// No event waits for it: the result goes at once, so that it holds no later upgrade back.
	if err := supervisorpkg.RemoveResult(a.d.Layout); err != nil {
		slog.Error("removing the supervisor upgrade result failed", "error", err)
	}
	slog.Info("supervisor upgrade deferred: dpkg is locked by another package run", "version", r.Version, "retry_at", retry.NotBefore)
	a.saveState()
}

// retrySupervisor schedules the next attempt of a version rolled back because the server was unreachable, or marks it
// failed after supervisorpkg.MaxAttempts such rollbacks.
func (a *Agent) retrySupervisor(r *supervisorpkg.Result) {
	retry := a.st.SupervisorRetry
	if retry == nil || retry.Version != r.Version {
		retry = &state.SupervisorRetry{Version: r.Version}
	}
	retry.Attempts++
	retry.NotBefore = r.At.Add(supervisorpkg.RetryAfter)
	a.st.SupervisorRetry = retry
	if retry.Attempts >= supervisorpkg.MaxAttempts {
		a.st.FailedSupervisorVersion, a.st.SupervisorRetry = r.Version, nil
	}
}

// supervisorUpgradeHolds reports whether supervisor-upgrade.json holds back other work (an agent update, a further
// supervisor upgrade, the removal of Paddock). A readable marker holds until staleSupervisorUpgrade turns it into a
// result. An unreadable one holds only until its mtime is older than supervisorpkg.StaleAfter: staleSupervisorUpgrade
// cannot clear a marker it cannot read, and nothing may wait longer than the 30 minutes of the ADR 0037 amendment. err
// is the read error of an unreadable marker, for the caller's log.
func (a *Agent) supervisorUpgradeHolds() (bool, error) {
	marker, err := supervisorpkg.ReadMarker(a.d.Layout)
	if marker != nil {
		return true, nil
	}
	if err == nil {
		return false, nil
	}
	info, statErr := os.Stat(a.d.Layout.SupervisorUpgrade())
	if errors.Is(statErr, os.ErrNotExist) {
		return false, nil
	}
	if statErr == nil && a.d.Now().Sub(info.ModTime()) >= supervisorpkg.StaleAfter {
		return false, err
	}
	return true, err
}

// staleSupervisorUpgrade writes and returns an install_failed result for a marker older than StaleAfter.
func (a *Agent) staleSupervisorUpgrade() *supervisorpkg.Result {
	m, err := supervisorpkg.ReadMarker(a.d.Layout)
	if err != nil || m == nil || a.d.Now().Sub(m.StartedAt) < supervisorpkg.StaleAfter {
		return nil
	}
	r := supervisorpkg.Result{Version: m.Version, FromVersion: m.FromVersion, Outcome: protocol.SupervisorOutcomeInstallFailed,
		At: a.d.Now().UTC()}
	if err := supervisorpkg.WriteResult(a.d.Layout, r); err != nil {
		slog.Error("recording the stale supervisor upgrade failed", "error", err)
		return nil
	}
	slog.Warn("the supervisor upgrade did not finish; counting it as failed", "version", m.Version, "started_at", m.StartedAt)
	return &r
}

// clearSupervisorResult deletes the supervisor upgrade result once its event left the spool (accepted by the server).
func (a *Agent) clearSupervisorResult() {
	r, err := supervisorpkg.ReadResult(a.d.Layout)
	if err != nil || r == nil || a.st.ReportedSupervisorUpgradeAt == nil || !a.st.ReportedSupervisorUpgradeAt.Equal(r.At) {
		return
	}
	if pending, err := a.d.Spool.Pending(); err != nil || len(pending) > 0 {
		return
	}
	if err := supervisorpkg.RemoveResult(a.d.Layout); err != nil {
		slog.Error("removing the supervisor upgrade result failed", "error", err)
	}
}

// runUnit runs systemd-run, which returns once the transient unit is queued (--no-block).
func runUnit(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed tool (systemd-run)
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
