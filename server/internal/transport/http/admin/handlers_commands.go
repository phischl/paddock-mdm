package admin

import (
	"context"
	"encoding/json"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/adminapi"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/listing"
)

// deviceCommandList is the list definition of GET /api/v1/devices/{id}/commands (plan M4a decision 1).
var deviceCommandList = listing.Spec{Sort: []string{"issued_at", "expires_at", "type", "status"}, DefaultSort: "-issued_at"}

func (h *handlers) ListDeviceCommands(ctx context.Context, req adminapi.ListDeviceCommandsRequestObject) (adminapi.ListDeviceCommandsResponseObject, error) {
	params, err := listing.Parse(deviceCommandList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	types, err := listing.Enum("type", req.Params.Type)
	if err != nil {
		return nil, err
	}
	res, err := h.commands.List(ctx, req.Id, app.CommandQuery{Page: params.ListPage(), Statuses: statuses, Types: types})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.DeviceCommand, len(res.Items))
	for i, c := range res.Items {
		items[i] = toDeviceCommand(c)
	}
	return adminapi.ListDeviceCommands200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) RotateDeviceLocalAdmin(ctx context.Context, req adminapi.RotateDeviceLocalAdminRequestObject) (adminapi.RotateDeviceLocalAdminResponseObject, error) {
	c, err := h.localAdmin.Rotate(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.RotateDeviceLocalAdmin202JSONResponse(toDeviceCommand(c)), nil
}

func toDeviceCommand(c pgstore.DeviceCommand) adminapi.DeviceCommand {
	out := adminapi.DeviceCommand{
		Id: c.ID, DeviceId: c.DeviceID, Type: adminapi.DeviceCommandType(c.Type), Status: adminapi.DeviceCommandStatus(c.Status),
		IssuedAt: c.IssuedAt.UTC(), ExpiresAt: c.ExpiresAt.UTC(), NotBefore: utcPtr(c.NotBefore),
		DeliveredAt: utcPtr(c.DeliveredAt), FinishedAt: utcPtr(c.FinishedAt),
	}
	var result map[string]any
	if len(c.Result) > 0 && json.Unmarshal(c.Result, &result) == nil && result != nil {
		out.Result = &result
	}
	return out
}

func (h *handlers) GetDeviceLocalAdmin(ctx context.Context, req adminapi.GetDeviceLocalAdminRequestObject) (adminapi.GetDeviceLocalAdminResponseObject, error) {
	s, err := h.localAdmin.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out := adminapi.GetDeviceLocalAdmin200JSONResponse{
		Username: s.Username, ActiveGeneration: s.ActiveGeneration, PendingGeneration: s.PendingGeneration,
		LastRotatedAt: utcPtr(s.LastRotatedAt), NextRotationAt: utcPtr(s.NextRotationAt),
	}
	if e := s.LastRotationError; e != nil {
		out.LastRotationError = &struct {
			At         time.Time                                  `json:"at"`
			Generation int                                        `json:"generation"`
			Reason     adminapi.LocalAdminLastRotationErrorReason `json:"reason"`
		}{At: e.At.UTC(), Generation: int(e.Generation), Reason: adminapi.LocalAdminLastRotationErrorReason(e.Reason)}
	}
	return out, nil
}

func (h *handlers) RevealDeviceLocalAdmin(ctx context.Context, req adminapi.RevealDeviceLocalAdminRequestObject) (adminapi.RevealDeviceLocalAdminResponseObject, error) {
	passwords, err := h.localAdmin.Reveal(ctx, req.Id, req.Body.ConfirmHostname)
	if err != nil {
		return nil, err
	}
	out := adminapi.RevealDeviceLocalAdmin200JSONResponse{}
	for _, p := range passwords {
		out.Passwords = append(out.Passwords, struct {
			Generation int                                       `json:"generation"`
			Password   string                                    `json:"password"`
			State      adminapi.LocalAdminRevealedPasswordsState `json:"state"`
		}{Generation: p.Generation, Password: p.Password, State: adminapi.LocalAdminRevealedPasswordsState(p.State)})
	}
	return out, nil
}
