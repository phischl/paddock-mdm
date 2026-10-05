package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/paddock-mdm/paddock/agent/internal/apply"
	"github.com/paddock-mdm/paddock/agent/internal/fsutil"
	"github.com/paddock-mdm/paddock/agent/internal/paths"
	"github.com/paddock-mdm/paddock/agent/internal/spool"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// maxBundle bounds a bundle download.
const maxBundle = 16 << 20

// loadCurrent reads the last applied bundle for the drift loop. A cached bundle that no longer verifies is ignored
// (the next check-in delivers a fresh one).
func (a *Agent) loadCurrent() {
	env, err := os.ReadFile(a.d.Layout.Bundle())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		a.current, err = bundle.VerifyVersions(env, a.d.Trust, a.st.DeviceID, a.d.Config.OrganizationID, a.st.AppliedBundleVersion-1, apply.SchemaVersions)
	}
	if err != nil {
		slog.Warn("cached bundle unusable; waiting for the next one", "error", err)
		a.current = nil
	}
}

// handleBundle downloads, verifies and applies a newer bundle (plan M2b decision 9). A transient download error
// is retried at the next check-in; a bundle that fails verification or has a resource type this agent does not know
// leaves the state unchanged and is reported once with bundle.rejected.
func (a *Agent) handleBundle(ctx context.Context, ref *protocol.BundleRef) {
	if ref == nil || ref.Version <= a.st.AppliedBundleVersion || ref.Version == a.st.RejectedBundleVersion {
		return
	}
	env, err := a.d.Client.Download(ctx, ref.URL, maxBundle)
	if err != nil {
		slog.WarnContext(ctx, "bundle download failed; retrying at the next check-in", "version", ref.Version, "error", err)
		return
	}
	sum := sha256.Sum256(env)
	var b *bundle.Bundle
	if hex.EncodeToString(sum[:]) != ref.SHA256 {
		err = errors.New("sha256_mismatch")
	} else {
		b, err = bundle.VerifyVersions(env, a.d.Trust, a.st.DeviceID, a.d.Config.OrganizationID, a.st.AppliedBundleVersion, apply.SchemaVersions)
	}
	if err == nil {
		err = a.d.Applier.CheckTypes(b)
	}
	if err != nil {
		slog.ErrorContext(ctx, "bundle rejected", "version", ref.Version, "error", err)
		a.st.RejectedBundleVersion = ref.Version
		a.event(protocol.EventBundleRejected, map[string]any{"version": ref.Version, "reason": apply.RejectReason(err)})
		a.saveState()
		return
	}
	rep := a.d.Applier.Apply(ctx, b)
	if err := fsutil.WriteFile(a.d.Layout.Bundle(), env, 0o600, 0o700); err != nil {
		slog.ErrorContext(ctx, "caching the bundle failed", "error", err)
	}
	a.current = b
	a.st.AppliedBundleVersion = b.BundleVersion
	a.saveState()
	a.refreshHealth()
	slog.InfoContext(ctx, "bundle applied", "version", b.BundleVersion, "changed", rep.Changed, "errors", len(rep.Errors))
	a.event(protocol.EventBundleApplied, rep)
}

// drift re-plans the current bundle and corrects what changed locally (plan M2b decision 11).
func (a *Agent) drift(ctx context.Context) {
	if a.current == nil {
		return
	}
	ids := apply.Drifted(a.d.Applier.Plan(ctx, a.current))
	if len(ids) == 0 {
		return
	}
	rep := a.d.Applier.ApplyResources(ctx, a.current, ids)
	for _, e := range rep.Errors {
		slog.WarnContext(ctx, "drift correction failed", "resource", e.ID, "error", e.Message)
	}
	if len(rep.ChangedIDs) == 0 {
		return
	}
	slog.InfoContext(ctx, "drift corrected", "resources", rep.ChangedIDs)
	a.event(protocol.EventConfigDriftCorrected, map[string]any{"version": a.current.BundleVersion, "resource_ids": rep.ChangedIDs})
}

// event spools an event; a spool failure is logged (the device keeps working).
func (a *Agent) event(typ string, data any) {
	if err := a.d.Spool.Add(typ, a.d.Now(), data); err != nil {
		slog.Error("spooling event failed", "type", typ, "error", err)
	}
}

// nextEventSeq assigns and persists the next event sequence number.
func (a *Agent) nextEventSeq() (int64, error) {
	a.st.EventSeq++
	if err := state.Save(a.d.Layout.State(), a.st); err != nil {
		return 0, fmt.Errorf("persist event sequence: %w", err)
	}
	return a.st.EventSeq, nil
}

// flush sends spooled events in batches and deletes what the server accepted.
func (a *Agent) flush(ctx context.Context) {
	events, err := a.d.Spool.Pending()
	if err != nil {
		slog.ErrorContext(ctx, "reading the event spool failed", "error", err)
		return
	}
	for len(events) > 0 {
		batch := events[:min(len(events), protocol.MaxEventsPerBatch)]
		events = events[len(batch):]
		if err := a.d.Client.Events(ctx, a.st.DeviceID, a.st.Seq, batch); err != nil {
			slog.WarnContext(ctx, "sending events failed; keeping them spooled", "error", err)
			return
		}
		sent := map[int64]bool{}
		for _, ev := range batch {
			sent[ev.EventSeq] = true
		}
		if err := a.d.Spool.Remove(sent); err != nil {
			slog.ErrorContext(ctx, "removing sent events from the spool failed", "error", err)
			return
		}
	}
}

func (a *Agent) saveState() {
	if err := state.Save(a.d.Layout.State(), a.st); err != nil {
		slog.Error("saving agent state failed", "error", err)
	}
}

// newSpool opens the event spool of the agent.
func (a *Agent) newSpool() *spool.Spool {
	return spool.New(a.d.Layout.Spool(), spool.DefaultCap, a.nextEventSeq)
}

// PlanCurrent plans the cached bundle of the device at layout without changing anything (`paddockd plan`).
func PlanCurrent(ctx context.Context, l paths.Layout) ([]apply.Planned, int64, error) {
	d, err := Load(l)
	if err != nil {
		return nil, 0, err
	}
	a, err := New(d)
	if err != nil {
		return nil, 0, err
	}
	if a.current == nil {
		return nil, 0, errors.New("no applied bundle")
	}
	return d.Applier.Plan(ctx, a.current), a.current.BundleVersion, nil
}
