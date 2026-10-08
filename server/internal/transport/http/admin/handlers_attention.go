package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// attentionList is the list definition of GET /api/v1/attention (plan M5b decision 11).
var attentionList = listing.Spec{Sort: []string{"since", "kind", "hostname"}, DefaultSort: "-since"}

func (h *handlers) ListAttention(ctx context.Context, req adminapi.ListAttentionRequestObject) (adminapi.ListAttentionResponseObject, error) {
	params, err := listing.Parse(attentionList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	kinds, err := listing.Enum("kind", req.Params.Kind)
	if err != nil {
		return nil, err
	}
	res, err := h.attention.List(ctx, app.AttentionQuery{Page: params.ListPage(), Kinds: kinds})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.Attention, len(res.Items))
	for i, c := range res.Items {
		items[i] = adminapi.Attention{Id: c.ID, Kind: adminapi.AttentionKind(c.Kind), DeviceId: c.DeviceID, Hostname: c.Hostname,
			Since: c.Since.UTC(), Detail: c.Detail}
	}
	return adminapi.ListAttention200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}
