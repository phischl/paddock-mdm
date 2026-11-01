package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// List definitions of the apply status endpoints (plan M11 decision 14); they match x-paddock-list.
var (
	deviceResourceStatusList = listing.Spec{Sort: []string{"resource_id", "status", "occurred_at"}, DefaultSort: "resource_id"}
	deviceBundleList         = listing.Spec{Sort: []string{"version", "created_at"}, DefaultSort: "-version"}
	configStatusList         = listing.Spec{Sort: []string{"resource_id", "failed", "pending", "applied"}, DefaultSort: "-failed"}
)

func (h *handlers) ListDeviceConfigStatus(ctx context.Context, req adminapi.ListDeviceConfigStatusRequestObject) (adminapi.ListDeviceConfigStatusResponseObject, error) {
	params, err := listing.Parse(deviceResourceStatusList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	res, err := h.configStatus.DeviceResources(ctx, req.Id, app.ConfigStatusQuery{Page: params.ListPage(), Statuses: statuses})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.DeviceResourceStatus, len(res.Items))
	for i, r := range res.Items {
		items[i] = toDeviceResourceStatus(r)
	}
	return adminapi.ListDeviceConfigStatus200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func toDeviceResourceStatus(r pgstore.ListDeviceResourceStatusRow) adminapi.DeviceResourceStatus {
	changes := r.Changes
	if changes == nil {
		changes = []string{}
	}
	return adminapi.DeviceResourceStatus{
		ResourceId: r.ResourceID, Type: app.ResourceType(r.ResourceID), Status: adminapi.ResourceState(r.Status),
		Message: r.Message, Changes: changes, BundleVersion: r.BundleVersion, OccurredAt: r.OccurredAt.UTC(),
	}
}

func (h *handlers) ListDeviceBundles(ctx context.Context, req adminapi.ListDeviceBundlesRequestObject) (adminapi.ListDeviceBundlesResponseObject, error) {
	params, err := listing.Parse(deviceBundleList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	outcomes, err := bundleOutcomes(listing.Strings(req.Params.Outcome))
	if err != nil {
		return nil, err
	}
	res, err := h.configStatus.DeviceBundles(ctx, req.Id, app.BundleQuery{Page: params.ListPage(), Outcomes: outcomes})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.DeviceBundle, len(res.Items))
	for i, r := range res.Items {
		items[i] = toDeviceBundle(r)
	}
	return adminapi.ListDeviceBundles200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func toDeviceBundle(r pgstore.ListDeviceBundlesRow) adminapi.DeviceBundle {
	out := adminapi.DeviceBundle{Version: r.Version, CreatedAt: r.CreatedAt.UTC(), SchemaVersion: int(r.SchemaVersion)}
	if r.ReportOutcome == nil || r.ReportMode == nil || r.ReportOccurredAt == nil {
		return out
	}
	out.Report = &adminapi.DeviceBundleReport{
		Outcome: adminapi.DeviceBundleReportOutcome(*r.ReportOutcome), Mode: adminapi.DeviceBundleReportMode(*r.ReportMode),
		Reason: r.ReportReason, OccurredAt: r.ReportOccurredAt.UTC(),
	}
	if r.ReportChanged != nil {
		out.Report.Changed = int(*r.ReportChanged)
	}
	if r.ReportErrorCount != nil {
		out.Report.ErrorCount = int(*r.ReportErrorCount)
	}
	return out
}

func (h *handlers) ListConfigStatus(ctx context.Context, req adminapi.ListConfigStatusRequestObject) (adminapi.ListConfigStatusResponseObject, error) {
	params, err := listing.Parse(configStatusList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	res, err := h.configStatus.Fleet(ctx, app.ConfigStatusQuery{Page: params.ListPage(), Statuses: statuses})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ResourceStatus, len(res.Items))
	for i, r := range res.Items {
		items[i] = adminapi.ResourceStatus{
			ResourceId: r.ResourceID, Type: app.ResourceType(r.ResourceID), Applied: int(r.Applied), Failed: int(r.Failed),
			Pending: int(r.Pending), DriftCorrected: int(r.DriftCorrected), LastFailureAt: lastFailureAt(r.LastFailureAt),
		}
	}
	return adminapi.ListConfigStatus200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

// lastFailureAt reads max(occurred_at): sqlc types an aggregate as interface{}, and NULL (no failure) is nil.
func lastFailureAt(v any) *time.Time {
	t, ok := v.(time.Time)
	if !ok {
		return nil
	}
	t = t.UTC()
	return &t
}

// bundleOutcomes validates the outcome filter; it is a free-text parameter in the contract (see the spec).
func bundleOutcomes(values []string) ([]string, error) {
	for _, v := range values {
		if v != "applied" && v != "rejected" && v != "none" {
			return nil, problem.InvalidRequest.WithDetail(fmt.Sprintf("unknown outcome %q", v))
		}
	}
	return values, nil
}
