package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// accountList is the list definition of GET /api/v1/accounts (plan M9 decision 34).
var accountList = listing.Spec{Sort: []string{"username", "display_name", "role"}, DefaultSort: "username"}

func (h *handlers) ListAccounts(ctx context.Context, req adminapi.ListAccountsRequestObject) (adminapi.ListAccountsResponseObject, error) {
	params, err := listing.Parse(accountList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	roles, err := listing.Enum("role", req.Params.Role)
	if err != nil {
		return nil, err
	}
	res, err := h.accountList.List(ctx, app.AccountQuery{Page: params.ListPage(), Roles: roles})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.Account, len(res.Items))
	for i, a := range res.Items {
		items[i] = adminapi.Account{Id: a.ID, Username: a.Username, DisplayName: a.DisplayName, Role: adminapi.AccountRole(a.Role)}
	}
	return adminapi.ListAccounts200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}
