package admin

import (
	"context"
	"encoding/json"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/paddock-mdm/paddock/server/internal/adapters/auditpg/auditstore"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/adminapi"
)

// handlers implements the generated strict server. Errors are returned as *problem.Error and rendered by the
// response error handler.
type handlers struct {
	groups   *app.DeviceGroups
	orgs     *app.Organizations
	accounts *app.Accounts
	audit    *app.AuditLog
}

var _ adminapi.StrictServerInterface = (*handlers)(nil)

func (h *handlers) GetMe(ctx context.Context, _ adminapi.GetMeRequestObject) (adminapi.GetMeResponseObject, error) {
	me, err := h.accounts.GetMe(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetMe200JSONResponse(toMe(me)), nil
}

func (h *handlers) UpdateMe(ctx context.Context, req adminapi.UpdateMeRequestObject) (adminapi.UpdateMeResponseObject, error) {
	me, err := h.accounts.UpdateLocale(ctx, string(req.Body.Locale))
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateMe200JSONResponse(toMe(me)), nil
}

func toMe(me app.Me) adminapi.Me {
	out := adminapi.Me{
		Id: me.ID, Username: me.Username, DisplayName: me.DisplayName, Role: adminapi.MeRole(me.Role),
		Locale: adminapi.MeLocale(me.Locale),
	}
	if me.Organization != nil {
		out.Organization = &adminapi.MeOrganization{Id: me.Organization.ID, Slug: me.Organization.Slug, Name: me.Organization.Name}
	}
	return out
}

func (h *handlers) ListDeviceGroups(ctx context.Context, req adminapi.ListDeviceGroupsRequestObject) (adminapi.ListDeviceGroupsResponseObject, error) {
	page, err := h.groups.List(ctx, req.Params.Cursor, req.Params.Limit)
	if err != nil {
		return nil, err
	}
	out := adminapi.DeviceGroupPage{Items: make([]adminapi.DeviceGroup, len(page.Items)), NextCursor: page.NextCursor}
	for i, g := range page.Items {
		out.Items[i] = toDeviceGroup(g)
	}
	return adminapi.ListDeviceGroups200JSONResponse(out), nil
}

func (h *handlers) CreateDeviceGroup(ctx context.Context, req adminapi.CreateDeviceGroupRequestObject) (adminapi.CreateDeviceGroupResponseObject, error) {
	g, err := h.groups.Create(ctx, req.Body.Name, req.Body.Description)
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/device-groups/" + g.ID.String()
	return adminapi.CreateDeviceGroup201JSONResponse{
		Body: toDeviceGroup(g), Headers: adminapi.CreateDeviceGroup201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetDeviceGroup(ctx context.Context, req adminapi.GetDeviceGroupRequestObject) (adminapi.GetDeviceGroupResponseObject, error) {
	g, err := h.groups.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetDeviceGroup200JSONResponse(toDeviceGroup(g)), nil
}

func (h *handlers) UpdateDeviceGroup(ctx context.Context, req adminapi.UpdateDeviceGroupRequestObject) (adminapi.UpdateDeviceGroupResponseObject, error) {
	g, err := h.groups.Update(ctx, req.Id, req.Body.Name, req.Body.Description)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateDeviceGroup200JSONResponse(toDeviceGroup(g)), nil
}

func (h *handlers) DeleteDeviceGroup(ctx context.Context, req adminapi.DeleteDeviceGroupRequestObject) (adminapi.DeleteDeviceGroupResponseObject, error) {
	if err := h.groups.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteDeviceGroup204Response{}, nil
}

func toDeviceGroup(g pgstore.DeviceGroup) adminapi.DeviceGroup {
	return adminapi.DeviceGroup{Id: g.ID, Name: g.Name, Description: g.Description, CreatedAt: g.CreatedAt.UTC(), UpdatedAt: g.UpdatedAt.UTC()}
}

func (h *handlers) ListAuditEvents(ctx context.Context, req adminapi.ListAuditEventsRequestObject) (adminapi.ListAuditEventsResponseObject, error) {
	page, err := h.audit.List(ctx, app.AuditQuery{
		From: req.Params.From, To: req.Params.To, Code: req.Params.Code, Cursor: req.Params.Cursor, Limit: req.Params.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := adminapi.AuditEventPage{Items: make([]adminapi.AuditEvent, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, e := range page.Items {
		ev, err := toAuditEvent(e)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, ev)
	}
	return adminapi.ListAuditEvents200JSONResponse(out), nil
}

// toAuditEvent maps an index row to the API. The writer keeps error_code inside params in the index (there is no
// column for it); it is presented in its own field again.
func toAuditEvent(e auditstore.AuditEvent) (adminapi.AuditEvent, error) {
	out := adminapi.AuditEvent{
		EventId: e.EventID, OccurredAt: e.OccurredAt.UTC(), RecordedAt: e.RecordedAt.UTC(), Code: e.Code,
		Outcome: adminapi.AuditEventOutcome(e.Outcome), Source: e.Source, CorrelationId: e.CorrelationID,
		Params: map[string]any{},
	}
	if err := json.Unmarshal(e.Actor, &out.Actor); err != nil {
		return out, err
	}
	if len(e.Target) > 0 && string(e.Target) != "null" {
		out.Target = &adminapi.AuditTarget{}
		if err := json.Unmarshal(e.Target, out.Target); err != nil {
			return out, err
		}
	}
	if err := json.Unmarshal(e.Params, &out.Params); err != nil {
		return out, err
	}
	if code, ok := out.Params["error_code"].(string); ok {
		out.ErrorCode = &code
		delete(out.Params, "error_code")
	}
	return out, nil
}

func (h *handlers) ListOrganizations(ctx context.Context, req adminapi.ListOrganizationsRequestObject) (adminapi.ListOrganizationsResponseObject, error) {
	page, err := h.orgs.List(ctx, req.Params.Cursor, req.Params.Limit)
	if err != nil {
		return nil, err
	}
	out := adminapi.OrganizationPage{Items: make([]adminapi.Organization, len(page.Items)), NextCursor: page.NextCursor}
	for i, o := range page.Items {
		out.Items[i] = toOrganization(o)
	}
	return adminapi.ListOrganizations200JSONResponse(out), nil
}

func (h *handlers) CreateOrganization(ctx context.Context, req adminapi.CreateOrganizationRequestObject) (adminapi.CreateOrganizationResponseObject, error) {
	org, reprovisioned, err := h.orgs.Create(ctx, req.Body.Slug, req.Body.Name)
	if err != nil {
		return nil, err
	}
	if reprovisioned {
		return adminapi.CreateOrganization200JSONResponse(toOrganization(org)), nil
	}
	loc := "/api/platform/v1/organizations/" + org.ID.String()
	return adminapi.CreateOrganization201JSONResponse{
		Body: toOrganization(org), Headers: adminapi.CreateOrganization201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetOrganization(ctx context.Context, req adminapi.GetOrganizationRequestObject) (adminapi.GetOrganizationResponseObject, error) {
	org, err := h.orgs.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetOrganization200JSONResponse(toOrganization(org)), nil
}

func toOrganization(o pgstore.Organization) adminapi.Organization {
	return adminapi.Organization{
		Id: openapi_types.UUID(o.ID), Slug: o.Slug, Name: o.Name, Status: adminapi.OrganizationStatus(o.Status), CreatedAt: o.CreatedAt.UTC(),
	}
}
