package agent

import (
	"context"
	"log/slog"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
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

// sweepStaging removes release directories left without a request (update.Sweep); a failure does not stop the agent.
func (a *Agent) sweepStaging() {
	if err := update.Sweep(a.d.Layout); err != nil {
		slog.Warn("removing leftover staged releases failed", "error", err)
	}
}

// updatePolicy is the agent update policy of the applied bundle ("" = automatic).
func (a *Agent) updatePolicy() string {
	if a.current == nil {
		return ""
	}
	return a.current.Agent.UpdatePolicy
}

// updatesAllowed reports whether package upgrades (fleetd, the supervisor) may run now: the policy is automatic, or
// the last check-in carried a requested update (plan M8d decision 23).
func (a *Agent) updatesAllowed() bool {
	return a.updatePolicy() != bundle.UpdatePolicyManual || a.updateRequested
}

// handleUpdate stages an offered release and asks the supervisor to install it. The agent never replaces itself.
// Under the manual update policy only a requested offer is staged (plan M8d decision 23). A fresh update-now
// request — requested_at after the last handled one — overrides the policy and a failed version once (decision 28).
func (a *Agent) handleUpdate(ctx context.Context, offer *protocol.AgentUpdate) {
	a.sweepStaging()
	a.updateRequested = offer != nil && offer.Requested
	fresh := a.updateRequested && offer.RequestedAt != nil &&
		(a.st.UpdateRequestHandledAt == nil || offer.RequestedAt.After(*a.st.UpdateRequestHandledAt))
	if offer == nil || offer.Version == buildinfo.Version || (offer.Version == a.st.FailedUpdateVersion && !fresh) ||
		update.Pending(a.d.Layout) {
		return
	}
	// A running supervisor upgrade restarts the supervisor; an agent update staged meanwhile would meet the old or the
	// new supervisor at random (review finding 12). A marker that cannot be read counts as running.
	if marker, err := supervisorpkg.ReadMarker(a.d.Layout); marker != nil || err != nil {
		slog.InfoContext(ctx, "agent update waits for the running supervisor upgrade", "version", offer.Version)
		return
	}
	if a.updatePolicy() == bundle.UpdatePolicyManual && !fresh {
		if a.policySkipped != offer.Version {
			a.policySkipped = offer.Version
			slog.InfoContext(ctx, "agent update offer ignored by the organization's policy", "version", offer.Version)
		}
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
	slog.InfoContext(ctx, "agent update staged; asking the supervisor to install it", "version", offer.Version, "requested", fresh)
	if fresh {
		at := offer.RequestedAt.UTC()
		a.st.UpdateRequestHandledAt = &at
		a.saveState()
	}
	if err := a.d.Signal(pid); err != nil {
		slog.ErrorContext(ctx, "notifying the supervisor failed", "error", err)
	}
}
