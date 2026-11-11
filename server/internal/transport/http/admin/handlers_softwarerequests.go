package admin

import (
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// softwareRequestList is the list definition of GET /api/v1/software-requests (plan M13c decision 10).
var softwareRequestList = listing.Spec{Sort: []string{"requested_at", "username", "state", "expires_at"}, DefaultSort: "-requested_at"}

func (h *handlers) ListSoftwareRequests(ctx context.Context, req adminapi.ListSoftwareRequestsRequestObject) (adminapi.ListSoftwareRequestsResponseObject, error) {
	params, err := listing.Parse(softwareRequestList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	states, err := listing.Enum("state", req.Params.State)
	if err != nil {
		return nil, err
	}
	res, err := h.softwareRequests.List(ctx, app.SoftwareRequestQuery{
		Page: params.ListPage(), States: states, CatalogEntryID: req.Params.CatalogEntryId, DeviceID: req.Params.DeviceId,
	})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.SoftwareRequest, len(res.Items))
	for i, r := range res.Items {
		items[i] = toSoftwareRequest(r)
	}
	return adminapi.ListSoftwareRequests200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) GetSoftwareRequest(ctx context.Context, req adminapi.GetSoftwareRequestRequestObject) (adminapi.GetSoftwareRequestResponseObject, error) {
	r, err := h.softwareRequests.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetSoftwareRequest200JSONResponse(toSoftwareRequest(r)), nil
}

func (h *handlers) ApproveSoftwareRequest(ctx context.Context, req adminapi.ApproveSoftwareRequestRequestObject) (adminapi.ApproveSoftwareRequestResponseObject, error) {
	reason := ""
	if req.Body != nil {
		reason = deref(req.Body.Reason, "")
	}
	r, err := h.softwareRequests.Approve(ctx, req.Id, reason)
	if err != nil {
		return nil, err
	}
	return adminapi.ApproveSoftwareRequest200JSONResponse(toSoftwareRequest(r)), nil
}

func (h *handlers) DenySoftwareRequest(ctx context.Context, req adminapi.DenySoftwareRequestRequestObject) (adminapi.DenySoftwareRequestResponseObject, error) {
	reason := ""
	if req.Body != nil {
		reason = req.Body.Reason
	}
	r, err := h.softwareRequests.Deny(ctx, req.Id, reason)
	if err != nil {
		return nil, err
	}
	return adminapi.DenySoftwareRequest200JSONResponse(toSoftwareRequest(r)), nil
}

func toSoftwareRequest(r app.SoftwareRequest) adminapi.SoftwareRequest {
	var user *uuid.UUID
	if r.UserID.Valid {
		user = &r.UserID.UUID
	}
	out := adminapi.SoftwareRequest{
		Id: r.ID, CatalogEntryId: r.CatalogEntryID, EntryName: r.EntryName, EntryApproval: adminapi.SoftwareApproval(r.EntryApproval),
		DeviceId: r.DeviceID, Hostname: r.Hostname, UserId: user, Username: r.Username, State: adminapi.SoftwareRequestState(r.State),
		RequestedAt: r.RequestedAt.UTC(), ExpiresAt: r.ExpiresAt.UTC(), DecidedBy: r.DecidedBy, DecisionReason: r.DecisionReason,
		Justification: r.Justification,
	}
	if r.DecidedAt != nil {
		at := r.DecidedAt.UTC()
		out.DecidedAt = &at
	}
	return out
}
