package admin

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// The list definitions of the configuration rollouts and their devices (plan M11 decision 34).
var (
	configRolloutList       = listing.Spec{Sort: []string{"started_at", "status"}, DefaultSort: "-started_at"}
	configRolloutDeviceList = listing.Spec{Sort: []string{"hostname", "in_wave", "report_outcome"}, DefaultSort: "hostname"}
)

// rolloutReportOutcomes are the values of the report_outcome filter; a free-text parameter in the contract.
var rolloutReportOutcomes = []string{app.RolloutReportApplied, app.RolloutReportRejected, app.RolloutReportReportOnly, app.RolloutReportNone}

func (h *handlers) ListConfigRollouts(ctx context.Context, req adminapi.ListConfigRolloutsRequestObject) (adminapi.ListConfigRolloutsResponseObject, error) {
	params, err := listing.Parse(configRolloutList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	res, err := h.configRollouts.List(ctx, params.ListPage(), statuses)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ConfigRollout, len(res.Items))
	for i, r := range res.Items {
		items[i] = toConfigRollout(r.ConfigRollout, r.Counts)
	}
	return adminapi.ListConfigRollouts200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) GetConfigRollout(ctx context.Context, req adminapi.GetConfigRolloutRequestObject) (adminapi.GetConfigRolloutResponseObject, error) {
	d, err := h.configRollouts.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	cs, err := toChangeSet(d.ChangeSet)
	if err != nil {
		return nil, err
	}
	staged := d.StagedResourceIDs
	if staged == nil {
		staged = []string{}
	}
	return adminapi.GetConfigRollout200JSONResponse{
		Rollout: toConfigRollout(d.ConfigRollout, d.Counts), ChangeSet: cs, StagedResourceIds: staged,
	}, nil
}

func (h *handlers) ListConfigRolloutDevices(ctx context.Context, req adminapi.ListConfigRolloutDevicesRequestObject) (adminapi.ListConfigRolloutDevicesResponseObject, error) {
	params, err := listing.Parse(configRolloutDeviceList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	outcomes := listing.Strings(req.Params.ReportOutcome)
	for _, v := range outcomes {
		if !slices.Contains(rolloutReportOutcomes, v) {
			return nil, problem.InvalidRequest.WithDetail(fmt.Sprintf("unknown report_outcome %q", v))
		}
	}
	res, err := h.configRollouts.ListDevices(ctx, req.Id, app.ConfigRolloutDeviceQuery{
		Page: params.ListPage(), InWave: req.Params.InWave, ReportOutcomes: outcomes,
	})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ConfigRolloutDevice, len(res.Items))
	for i, d := range res.Items {
		items[i] = adminapi.ConfigRolloutDevice{
			DeviceId: d.DeviceID, Hostname: d.Hostname, InWave: d.InWave, BundleVersion: d.BundleVersion,
			CarriesRollout: d.CarriesRollout, ReportOutcome: d.ReportOutcome, FailedResourceIds: d.FailedResourceIDs,
		}
	}
	return adminapi.ListConfigRolloutDevices200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) HaltConfigRollout(ctx context.Context, req adminapi.HaltConfigRolloutRequestObject) (adminapi.HaltConfigRolloutResponseObject, error) {
	var reason string
	if req.Body != nil {
		reason = req.Body.Reason
	}
	r, err := h.configRollouts.Halt(ctx, req.Id, reason)
	if err != nil {
		return nil, err
	}
	return adminapi.HaltConfigRollout200JSONResponse(h.rolloutAfterAction(ctx, r)), nil
}

func (h *handlers) ResumeConfigRollout(ctx context.Context, req adminapi.ResumeConfigRolloutRequestObject) (adminapi.ResumeConfigRolloutResponseObject, error) {
	r, err := h.configRollouts.Resume(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.ResumeConfigRollout200JSONResponse(h.rolloutAfterAction(ctx, r)), nil
}

func (h *handlers) AdvanceConfigRollout(ctx context.Context, req adminapi.AdvanceConfigRolloutRequestObject) (adminapi.AdvanceConfigRolloutResponseObject, error) {
	r, err := h.configRollouts.Advance(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.AdvanceConfigRollout200JSONResponse(h.rolloutAfterAction(ctx, r)), nil
}

func (h *handlers) CompleteConfigRollout(ctx context.Context, req adminapi.CompleteConfigRolloutRequestObject) (adminapi.CompleteConfigRolloutResponseObject, error) {
	r, err := h.configRollouts.Complete(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.CompleteConfigRollout200JSONResponse(h.rolloutAfterAction(ctx, r)), nil
}

// rolloutAfterAction is the response of a wave action: the changed rollout with its counts, zero when they cannot be
// read after the action.
func (h *handlers) rolloutAfterAction(ctx context.Context, r pgstore.ConfigRollout) adminapi.ConfigRollout {
	d, err := h.configRollouts.Get(ctx, r.ID)
	if err != nil {
		// The action committed and was audited: a 500 would make a client repeat it (an advance widens one more wave).
		slog.WarnContext(ctx, "read the counts after a rollout action; answering with zero counts", "rollout", r.ID, "error", err)
		return toConfigRollout(r, app.RolloutCounts{})
	}
	return toConfigRollout(r, d.Counts)
}

func toConfigRollout(r pgstore.ConfigRollout, c app.RolloutCounts) adminapi.ConfigRollout {
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	out := adminapi.ConfigRollout{
		Id: r.ID, ChangeSetId: r.ChangeSetID, Waves: waves, CurrentWaveIndex: int(r.CurrentWaveIndex),
		WaveStartedAt: r.WaveStartedAt.UTC(), MinWaveMinutes: int(r.MinWaveMinutes),
		FailureThresholdPercent: int(r.FailureThresholdPercent), FailureThresholdMin: int(r.FailureThresholdMin),
		Status: adminapi.ConfigRolloutStatus(r.Status), HaltedReason: r.HaltedReason, StartedBy: r.StartedBy,
		StartedAt: r.StartedAt.UTC(), EndedAt: utcPtr(r.EndedAt), EndedReason: r.EndedReason,
		Counts: adminapi.ConfigRolloutCounts{Eligible: c.Eligible, Applied: c.Applied, Failed: c.Failed, Pending: c.Pending},
	}
	if r.CanaryDeviceGroupID.Valid {
		out.CanaryDeviceGroupId = &r.CanaryDeviceGroupID.UUID
	}
	return out
}
