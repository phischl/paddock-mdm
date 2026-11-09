package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicegroup"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetDeviceGroupMaintenanceWindow(ctx context.Context, req adminapi.GetDeviceGroupMaintenanceWindowRequestObject) (adminapi.GetDeviceGroupMaintenanceWindowResponseObject, error) {
	w, err := h.groups.MaintenanceWindow(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetDeviceGroupMaintenanceWindow200JSONResponse(toMaintenanceWindow(w)), nil
}

func (h *handlers) SetDeviceGroupMaintenanceWindow(ctx context.Context, req adminapi.SetDeviceGroupMaintenanceWindowRequestObject) (adminapi.SetDeviceGroupMaintenanceWindowResponseObject, error) {
	b := req.Body
	w, err := h.groups.SetMaintenanceWindow(ctx, req.Id, devicegroup.Window{Days: b.Days, StartMinute: b.StartMinute,
		DurationMinutes: b.DurationMinutes, Timezone: b.Timezone})
	if err != nil {
		return nil, err
	}
	return adminapi.SetDeviceGroupMaintenanceWindow200JSONResponse(toMaintenanceWindow(w)), nil
}

func (h *handlers) DeleteDeviceGroupMaintenanceWindow(ctx context.Context, req adminapi.DeleteDeviceGroupMaintenanceWindowRequestObject) (adminapi.DeleteDeviceGroupMaintenanceWindowResponseObject, error) {
	if err := h.groups.DeleteMaintenanceWindow(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteDeviceGroupMaintenanceWindow204Response{}, nil
}

func toMaintenanceWindow(row app.MaintenanceWindow) adminapi.MaintenanceWindow {
	w := app.WindowOf(row)
	return adminapi.MaintenanceWindow{DeviceGroupId: row.DeviceGroupID, Days: w.Days, StartMinute: w.StartMinute,
		DurationMinutes: w.DurationMinutes, Timezone: w.Timezone, UpdatedAt: row.UpdatedAt.UTC()}
}
