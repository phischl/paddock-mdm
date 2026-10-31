package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// GetWatchedUnits answers the third-party units of the presence policy.
func (h *handlers) GetWatchedUnits(ctx context.Context, _ adminapi.GetWatchedUnitsRequestObject) (adminapi.GetWatchedUnitsResponseObject, error) {
	s, err := h.watchedUnits.Get(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetWatchedUnits200JSONResponse(toWatchedUnits(s)), nil
}

// UpdateWatchedUnits replaces the third-party units of the presence policy (org_admin with a step-up).
func (h *handlers) UpdateWatchedUnits(ctx context.Context, req adminapi.UpdateWatchedUnitsRequestObject) (adminapi.UpdateWatchedUnitsResponseObject, error) {
	s, err := h.watchedUnits.Set(ctx, req.Body.Units)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateWatchedUnits200JSONResponse(toWatchedUnits(s)), nil
}

func toWatchedUnits(s app.WatchedUnitSettings) adminapi.WatchedUnits {
	return adminapi.WatchedUnits{Units: s.Units, UpdatedAt: utcPtr(s.UpdatedAt)}
}
