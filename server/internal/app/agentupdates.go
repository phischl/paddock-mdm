package app

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/components"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecAgentUpdateRequest is the privileged action device.agent_update_requested (plan M8d decision 26).
var SpecAgentUpdateRequest = ActionSpec{Code: audit.CodeDeviceAgentUpdateRequested, AllowedRoles: RolesWrite}

// OfferSource reads the release the gateway currently offers (devicecache ar:current, written by the worker's rollout
// round): the request checks against exactly what devices are offered.
type OfferSource interface {
	Offer(ctx context.Context) (agentrelease.Offer, bool, error)
}

// AgentUpdates are the update-now use cases of a device (ADR 0037 decision 2).
type AgentUpdates struct {
	runner *ActionRunner
	org    *db.OrgPool
	offers OfferSource
}

// NewAgentUpdates creates the use cases.
func NewAgentUpdates(runner *ActionRunner, org *db.OrgPool, offers OfferSource) *AgentUpdates {
	return &AgentUpdates{runner: runner, org: org, offers: offers}
}

// RequestNow asks an active device to install the offered agent release at its next check-in, outside its rollout
// wave and regardless of its update policy (audited: device.agent_update_requested). A device that already runs the
// release can be asked again while its paddock-supervisor or fleetd is outdated: the request lets it upgrade them
// under the manual policy. The request is cleared by the device's report for that version — its supervisor result
// when the supervisor or fleetd still have to follow — or after 24 hours.
func (u *AgentUpdates) RequestNow(ctx context.Context, deviceID uuid.UUID) (pgstore.Device, error) {
	var out pgstore.Device
	spec := SpecAgentUpdateRequest
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if dev.State != device.StateActive {
			return problem.InvalidState.WithDetail("only active devices can be updated")
		}
		offer, ok, err := u.offers.Offer(ctx)
		if err != nil {
			return err
		}
		if !ok || offer.Status == agentrelease.RolloutHalted {
			return problem.InvalidState.WithDetail("no agent release is being offered")
		}
		rec.SetParam("version", offer.Version)
		status, err := q.GetDeviceStatus(ctx, deviceID)
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		from := ""
		if status.AgentVersion != nil {
			from = *status.AgentVersion
		}
		rec.SetParam("from_version", from)
		if !offer.Newer(from) && (from != offer.Version || !slices.ContainsFunc(status.ComponentsOutdated, func(c string) bool {
			return c == components.Supervisor || c == components.Fleetd
		})) {
			return problem.InvalidState.WithDetail("the device already runs " + from)
		}
		if status.Arch != "" {
			if _, ok := offer.Artifacts[status.Arch]; !ok {
				return problem.InvalidState.WithDetail("no artifact for " + status.Arch)
			}
		}
		if err := q.SetAgentUpdateRequest(ctx, pgstore.SetAgentUpdateRequestParams{ID: deviceID, Version: &offer.Version}); err != nil {
			return err
		}
		out, err = q.GetDevice(ctx, deviceID)
		return err
	})
	return out, err
}

// ExpireAgentUpdateRequests clears the update-now requests older than 24 hours at now (worker, unaudited).
func (d *DeviceCommands) ExpireAgentUpdateRequests(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		n, err = q.ExpireAgentUpdateRequests(ctx, now.Add(-24*time.Hour))
		return err
	})
	return n, err
}
