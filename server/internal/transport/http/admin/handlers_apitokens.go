package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// apiTokenList is the list definition of GET /api/v1/api-tokens (plan M6c decision 11).
var apiTokenList = listing.Spec{Sort: []string{"name", "created_at", "expires_at", "last_used_at"}, DefaultSort: "name"}

func (h *handlers) ListApiTokens(ctx context.Context, req adminapi.ListApiTokensRequestObject) (adminapi.ListApiTokensResponseObject, error) {
	params, err := listing.Parse(apiTokenList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	res, err := h.apiTokens.List(ctx, app.APITokenQuery{Page: params.ListPage(), Statuses: statuses})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ApiToken, len(res.Items))
	for i, t := range res.Items {
		items[i] = toAPIToken(t)
	}
	return adminapi.ListApiTokens200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateApiToken(ctx context.Context, req adminapi.CreateApiTokenRequestObject) (adminapi.CreateApiTokenResponseObject, error) {
	created, err := h.apiTokens.Create(ctx, app.APITokenInput{
		Name: req.Body.Name, Role: principal.Role(req.Body.Role), ExpiresAt: req.Body.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/api-tokens/" + created.Token.ID.String()
	return adminapi.CreateApiToken201JSONResponse{
		Body:    adminapi.ApiTokenCreated{Token: toAPIToken(created.Token), Secret: created.Secret},
		Headers: adminapi.CreateApiToken201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetApiToken(ctx context.Context, req adminapi.GetApiTokenRequestObject) (adminapi.GetApiTokenResponseObject, error) {
	t, err := h.apiTokens.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetApiToken200JSONResponse(toAPIToken(t)), nil
}

func (h *handlers) RevokeApiToken(ctx context.Context, req adminapi.RevokeApiTokenRequestObject) (adminapi.RevokeApiTokenResponseObject, error) {
	t, err := h.apiTokens.Revoke(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.RevokeApiToken200JSONResponse(toAPIToken(t)), nil
}

func toAPIToken(t pgstore.ApiTokenListed) adminapi.ApiToken {
	return adminapi.ApiToken{
		Id: t.ID, Name: t.Name, Prefix: t.Prefix, Role: adminapi.ApiTokenRole(t.Role), Status: adminapi.ApiTokenStatus(t.Status),
		CreatedBy: adminapi.ApiTokenCreator{Id: t.CreatedBy, Display: t.CreatedByDisplay},
		CreatedAt: t.CreatedAt.UTC(), ExpiresAt: t.ExpiresAt.UTC(), LastUsedAt: utcPtr(t.LastUsedAt), RevokedAt: utcPtr(t.RevokedAt),
	}
}
