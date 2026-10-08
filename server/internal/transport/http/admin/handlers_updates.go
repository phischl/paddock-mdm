package admin

import (
	"context"
	"encoding/json"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/updates"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// packageHoldList is the list definition of GET /api/v1/package-holds (plan M5b decision 2).
var packageHoldList = listing.Spec{Sort: []string{"package", "created_at", "updated_at"}, DefaultSort: "package"}

func (h *handlers) GetUpdateSettings(ctx context.Context, _ adminapi.GetUpdateSettingsRequestObject) (adminapi.GetUpdateSettingsResponseObject, error) {
	s, err := h.updates.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetUpdateSettings200JSONResponse(toUpdateSettings(s)), nil
}

func (h *handlers) UpdateUpdateSettings(ctx context.Context, req adminapi.UpdateUpdateSettingsRequestObject) (adminapi.UpdateUpdateSettingsResponseObject, error) {
	b := req.Body
	s, err := h.updates.UpdateSettings(ctx, updates.Settings{
		SecurityDailyAt: b.SecurityDailyAt, RegularSchedule: b.RegularSchedule, RegularUpdatesEnabled: b.RegularUpdatesEnabled,
		MaxRandomDelayMin: b.MaxRandomDelayMin, StalenessWarningH: b.StalenessWarningH, StalenessCriticalH: b.StalenessCriticalH,
	})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateUpdateSettings200JSONResponse(toUpdateSettings(s)), nil
}

func toUpdateSettings(s app.UpdateSettings) adminapi.UpdateSettings {
	return adminapi.UpdateSettings{
		SecurityDailyAt: s.SecurityDailyAt, RegularSchedule: s.RegularSchedule, RegularUpdatesEnabled: s.RegularUpdatesEnabled,
		MaxRandomDelayMin: s.MaxRandomDelayMin, StalenessWarningH: s.StalenessWarningH, StalenessCriticalH: s.StalenessCriticalH,
		UpdatedAt: utcPtr(s.UpdatedAt),
	}
}

func (h *handlers) ListPackageHolds(ctx context.Context, req adminapi.ListPackageHoldsRequestObject) (adminapi.ListPackageHoldsResponseObject, error) {
	params, err := listing.Parse(packageHoldList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.updates.ListHolds(ctx, app.HoldQuery{Page: params.ListPage(), GroupID: req.Params.DeviceGroupId})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.PackageHold, len(res.Items))
	for i, p := range res.Items {
		items[i] = toPackageHold(p)
	}
	return adminapi.ListPackageHolds200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreatePackageHold(ctx context.Context, req adminapi.CreatePackageHoldRequestObject) (adminapi.CreatePackageHoldResponseObject, error) {
	reason := ""
	if req.Body.Reason != nil {
		reason = *req.Body.Reason
	}
	p, err := h.updates.CreateHold(ctx, app.HoldInput{
		DeviceGroupID: req.Body.DeviceGroupId, Package: req.Body.Package, Version: req.Body.Version, Reason: reason,
	})
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/package-holds/" + p.ID.String()
	return adminapi.CreatePackageHold201JSONResponse{
		Body: toPackageHold(p), Headers: adminapi.CreatePackageHold201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetPackageHold(ctx context.Context, req adminapi.GetPackageHoldRequestObject) (adminapi.GetPackageHoldResponseObject, error) {
	p, err := h.updates.GetHold(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetPackageHold200JSONResponse(toPackageHold(p)), nil
}

func (h *handlers) UpdatePackageHold(ctx context.Context, req adminapi.UpdatePackageHoldRequestObject) (adminapi.UpdatePackageHoldResponseObject, error) {
	p, err := h.updates.UpdateHold(ctx, req.Id, req.Body.Version, req.Body.Reason)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdatePackageHold200JSONResponse(toPackageHold(p)), nil
}

func (h *handlers) DeletePackageHold(ctx context.Context, req adminapi.DeletePackageHoldRequestObject) (adminapi.DeletePackageHoldResponseObject, error) {
	if err := h.updates.DeleteHold(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeletePackageHold204Response{}, nil
}

func toPackageHold(p pgstore.PackageHold) adminapi.PackageHold {
	return adminapi.PackageHold{
		Id: p.ID, DeviceGroupId: idPtr(p.DeviceGroupID), Package: p.Package, Version: p.Version, Reason: p.Reason,
		CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(),
	}
}

func (h *handlers) InstallNowOnDevice(ctx context.Context, req adminapi.InstallNowOnDeviceRequestObject) (adminapi.InstallNowOnDeviceResponseObject, error) {
	c, err := h.updates.InstallNow(ctx, req.Id, req.Body.Packages)
	if err != nil {
		return nil, err
	}
	return adminapi.InstallNowOnDevice202JSONResponse(toDeviceCommand(c)), nil
}

func (h *handlers) InstallNowOnDeviceGroup(ctx context.Context, req adminapi.InstallNowOnDeviceGroupRequestObject) (adminapi.InstallNowOnDeviceGroupResponseObject, error) {
	n, err := h.updates.InstallNowGroup(ctx, req.Id, req.Body.Packages)
	if err != nil {
		return nil, err
	}
	return adminapi.InstallNowOnDeviceGroup202JSONResponse{Commands: n}, nil
}

func (h *handlers) GetDeviceUpdates(ctx context.Context, req adminapi.GetDeviceUpdatesRequestObject) (adminapi.GetDeviceUpdatesResponseObject, error) {
	s, err := h.updates.DeviceUpdates(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out := adminapi.GetDeviceUpdates200JSONResponse{
		LastSecurityRun: toDeviceReport(s.LastSecurityRun), LastRegularRun: toDeviceReport(s.LastRegularRun),
		RebootRequired: s.RebootRequired, Holds: []adminapi.DeviceUpdateHold{}, Conflicts: []adminapi.DeviceUpdateConflict{},
	}
	for _, hold := range s.Holds {
		out.Holds = append(out.Holds, adminapi.DeviceUpdateHold{Package: hold.Package, Version: hold.Version, DeviceGroupId: hold.DeviceGroupID})
	}
	for _, c := range s.Conflicts {
		out.Conflicts = append(out.Conflicts, adminapi.DeviceUpdateConflict{Package: c.Package, Versions: c.Versions, Chosen: c.Chosen})
	}
	return out, nil
}

// toDeviceReport decodes a login_state entry ({type, occurred_at, params}); nil when absent or malformed.
func toDeviceReport(raw json.RawMessage) *adminapi.DeviceReport {
	var r adminapi.DeviceReport
	if len(raw) == 0 || json.Unmarshal(raw, &r) != nil || r.Type == "" {
		return nil
	}
	return &r
}
