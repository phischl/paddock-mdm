package agent

import (
	"context"
	"log/slog"

	"github.com/paddock-mdm/paddock/agent/internal/buildinfo"
	"github.com/paddock-mdm/paddock/agent/internal/update"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// reportUpdate turns the supervisor's update result into an event, once (plan M2b decision 16). A version that
// failed is not staged again.
func (a *Agent) reportUpdate() {
	r, err := update.ReadResult(a.d.Layout)
	if err != nil {
		slog.Error("reading the update result failed", "error", err)
		return
	}
	if r == nil || (a.st.ReportedUpdateAt != nil && a.st.ReportedUpdateAt.Equal(r.At)) {
		return
	}
	slog.Info("agent update finished", "version", r.Version, "from_version", r.FromVersion, "outcome", r.Outcome)
	a.event(r.EventType(), map[string]string{"version": r.Version, "from_version": r.FromVersion, "outcome": r.Outcome})
	if r.Outcome != update.OutcomeUpdated {
		a.st.FailedUpdateVersion = r.Version
	}
	a.st.ReportedUpdateAt = &r.At
	a.saveState()
}

// clearUpdateResult deletes the update result once its event left the spool (accepted by the server).
func (a *Agent) clearUpdateResult() {
	r, err := update.ReadResult(a.d.Layout)
	if err != nil || r == nil || a.st.ReportedUpdateAt == nil || !a.st.ReportedUpdateAt.Equal(r.At) {
		return
	}
	if pending, err := a.d.Spool.Pending(); err != nil || len(pending) > 0 {
		return
	}
	if err := update.RemoveResult(a.d.Layout); err != nil {
		slog.Error("removing the update result failed", "error", err)
	}
}

// handleUpdate stages an offered release and asks the supervisor to install it. The agent never replaces itself.
func (a *Agent) handleUpdate(ctx context.Context, offer *protocol.AgentUpdate) {
	if offer == nil || offer.Version == buildinfo.Version || offer.Version == a.st.FailedUpdateVersion || update.Pending(a.d.Layout) {
		return
	}
	pid, err := a.d.Supervisor()
	if err != nil {
		slog.WarnContext(ctx, "agent update offered but not installable", "version", offer.Version, "error", err)
		return
	}
	if err := update.Stage(ctx, a.d.Layout, a.d.Client, *offer); err != nil {
		slog.WarnContext(ctx, "staging the agent update failed; retrying at the next check-in", "version", offer.Version, "error", err)
		return
	}
	slog.InfoContext(ctx, "agent update staged; asking the supervisor to install it", "version", offer.Version)
	if err := a.d.Signal(pid); err != nil {
		slog.ErrorContext(ctx, "notifying the supervisor failed", "error", err)
	}
}
