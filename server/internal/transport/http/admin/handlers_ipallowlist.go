package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/ipallowlist"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// ipAllowlistList is the list definition of GET /api/platform/v1/ip-allowlist (plan M7a decision 16).
var ipAllowlistList = listing.Spec{Sort: []string{"cidr", "label", "created_at"}, DefaultSort: "cidr"}

func toIPAllowlistEntry(i app.IPAllowlistItem) adminapi.IpAllowlistEntry {
	return adminapi.IpAllowlistEntry{
		Id: i.ID, Cidr: i.CIDR.String(), Label: i.Label, CreatedBy: i.CreatedBy,
		CreatedAt: i.CreatedAt.UTC(), UpdatedAt: i.UpdatedAt.UTC(), CoversCaller: i.CoversCaller,
	}
}

// confirmOf maps the optional confirm query parameter; the use case validates the value.
func confirmOf[T ~string](c *T) ipallowlist.Consequence {
	if c == nil {
		return ipallowlist.Unconfirmed
	}
	return ipallowlist.Consequence(*c)
}

func (h *handlers) ListIpAllowlist(ctx context.Context, req adminapi.ListIpAllowlistRequestObject) (adminapi.ListIpAllowlistResponseObject, error) {
	params, err := listing.Parse(ipAllowlistList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.ipAllowlist.List(ctx, params.ListPage())
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.IpAllowlistEntry, len(res.Items))
	for i, e := range res.Items {
		items[i] = toIPAllowlistEntry(e)
	}
	return adminapi.ListIpAllowlist200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateIpAllowlistEntry(ctx context.Context, req adminapi.CreateIpAllowlistEntryRequestObject) (adminapi.CreateIpAllowlistEntryResponseObject, error) {
	e, err := h.ipAllowlist.Create(ctx, req.Body.Cidr, req.Body.Label, confirmOf(req.Params.Confirm))
	if err != nil {
		return nil, err
	}
	loc := "/api/platform/v1/ip-allowlist/" + e.ID.String()
	return adminapi.CreateIpAllowlistEntry201JSONResponse{
		Body: toIPAllowlistEntry(e), Headers: adminapi.CreateIpAllowlistEntry201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetIpAllowlistEntry(ctx context.Context, req adminapi.GetIpAllowlistEntryRequestObject) (adminapi.GetIpAllowlistEntryResponseObject, error) {
	e, err := h.ipAllowlist.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetIpAllowlistEntry200JSONResponse(toIPAllowlistEntry(e)), nil
}

func (h *handlers) UpdateIpAllowlistEntry(ctx context.Context, req adminapi.UpdateIpAllowlistEntryRequestObject) (adminapi.UpdateIpAllowlistEntryResponseObject, error) {
	e, err := h.ipAllowlist.Update(ctx, req.Id, req.Body.Cidr, req.Body.Label, confirmOf(req.Params.Confirm))
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateIpAllowlistEntry200JSONResponse(toIPAllowlistEntry(e)), nil
}

func (h *handlers) DeleteIpAllowlistEntry(ctx context.Context, req adminapi.DeleteIpAllowlistEntryRequestObject) (adminapi.DeleteIpAllowlistEntryResponseObject, error) {
	if err := h.ipAllowlist.Delete(ctx, req.Id, confirmOf(req.Params.Confirm)); err != nil {
		return nil, err
	}
	return adminapi.DeleteIpAllowlistEntry204Response{}, nil
}
