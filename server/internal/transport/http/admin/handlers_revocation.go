package admin

import (
	"context"
	"encoding/json"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// revocationRequestList is the list definition of GET /api/v1/revocation-requests (plan M4c decision 7).
var revocationRequestList = listing.Spec{Sort: []string{"requested_at", "status", "action", "hostname"}, DefaultSort: "-requested_at"}

func (h *handlers) LockDevice(ctx context.Context, req adminapi.LockDeviceRequestObject) (adminapi.LockDeviceResponseObject, error) {
	r, err := h.requestRevocation(ctx, revocation.ActionLock, req.Id, req.Body)
	if err != nil {
		return nil, err
	}
	return adminapi.LockDevice201JSONResponse(r), nil
}

func (h *handlers) DestroyDevice(ctx context.Context, req adminapi.DestroyDeviceRequestObject) (adminapi.DestroyDeviceResponseObject, error) {
	r, err := h.requestRevocation(ctx, revocation.ActionDestroy, req.Id, req.Body)
	if err != nil {
		return nil, err
	}
	return adminapi.DestroyDevice201JSONResponse(r), nil
}

func (h *handlers) requestRevocation(ctx context.Context, action string, id adminapi.Id, body *adminapi.RevocationCreate) (adminapi.RevocationRequest, error) {
	in := app.RevocationInput{DeviceID: id, Action: action, ConfirmHostname: body.ConfirmHostname}
	if body.Reason != nil {
		in.Reason = *body.Reason
	}
	r, err := h.revocations.Request(ctx, in)
	if err != nil {
		return adminapi.RevocationRequest{}, err
	}
	return h.revocationRequest(ctx, r)
}

func (h *handlers) ApproveRevocationRequest(ctx context.Context, req adminapi.ApproveRevocationRequestRequestObject) (adminapi.ApproveRevocationRequestResponseObject, error) {
	r, err := h.revocations.Approve(ctx, req.Id, req.Body.ConfirmHostname)
	if err != nil {
		return nil, err
	}
	out, err := h.revocationRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	return adminapi.ApproveRevocationRequest200JSONResponse(out), nil
}

func (h *handlers) RejectRevocationRequest(ctx context.Context, req adminapi.RejectRevocationRequestRequestObject) (adminapi.RejectRevocationRequestResponseObject, error) {
	r, err := h.revocations.Reject(ctx, req.Id, req.Body.ConfirmHostname)
	if err != nil {
		return nil, err
	}
	out, err := h.revocationRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	return adminapi.RejectRevocationRequest200JSONResponse(out), nil
}

func (h *handlers) CancelRevocationRequest(ctx context.Context, req adminapi.CancelRevocationRequestRequestObject) (adminapi.CancelRevocationRequestResponseObject, error) {
	r, err := h.revocations.Cancel(ctx, req.Id, req.Body.ConfirmHostname)
	if err != nil {
		return nil, err
	}
	out, err := h.revocationRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	return adminapi.CancelRevocationRequest200JSONResponse(out), nil
}

func (h *handlers) ListRevocationRequests(ctx context.Context, req adminapi.ListRevocationRequestsRequestObject) (adminapi.ListRevocationRequestsResponseObject, error) {
	params, err := listing.Parse(revocationRequestList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	actions, err := listing.Enum("action", req.Params.Action)
	if err != nil {
		return nil, err
	}
	res, err := h.revocations.List(ctx, app.RevocationQuery{Page: params.ListPage(), Statuses: statuses, Actions: actions, DeviceID: req.Params.DeviceId})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.RevocationRequest, len(res.Items))
	for i, it := range res.Items {
		items[i] = toRevocationRequest(it)
	}
	return adminapi.ListRevocationRequests200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

// revocationRequest returns a request as the list shows it (with hostname and approvals).
func (h *handlers) revocationRequest(ctx context.Context, r pgstore.RevocationRequest) (adminapi.RevocationRequest, error) {
	it, err := h.revocations.Get(ctx, r.ID)
	if err != nil {
		return adminapi.RevocationRequest{}, err
	}
	return toRevocationRequest(it), nil
}

func toRevocationRequest(it app.RevocationItem) adminapi.RevocationRequest {
	r := it.Request
	out := adminapi.RevocationRequest{
		Id: r.ID, DeviceId: r.DeviceID, Hostname: it.Hostname, Action: adminapi.RevocationAction(r.Action),
		Status: adminapi.RevocationStatus(r.Status), RequestedAt: r.RequestedAt.UTC(), Reason: r.Reason,
		ApprovedAt: utcPtr(r.ApprovedAt), IssuedAt: utcPtr(r.IssuedAt), ExpiresAt: utcPtr(r.ExpiresAt),
		DeliveredAt: utcPtr(r.DeliveredAt), ConfirmedAt: utcPtr(r.ConfirmedAt), FinishedAt: utcPtr(r.FinishedAt),
		Rejection: r.Rejection, Approvals: make([]adminapi.RevocationApproval, len(it.Approvals)),
	}
	if r.RequestedBy.Valid {
		out.RequestedBy, out.RequestedByUsername = &r.RequestedBy.UUID, &it.RequestedByUsername
	}
	var result map[string]any
	if len(r.Result) > 0 && json.Unmarshal(r.Result, &result) == nil && result != nil {
		out.Result = &result
	}
	for i, a := range it.Approvals {
		out.Approvals[i] = adminapi.RevocationApproval{Role: adminapi.RevocationApprovalRole(a.Role), AdminId: a.AdminID,
			Username: a.Username, ApprovedAt: a.ApprovedAt.UTC()}
	}
	return out
}
