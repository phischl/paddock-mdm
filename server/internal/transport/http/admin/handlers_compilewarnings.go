package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// compileWarningList is the list definition of GET /api/v1/compile-warnings (PDK-918).
var compileWarningList = listing.Spec{Sort: []string{"created_at", "hostname", "code"}, DefaultSort: "-created_at"}

func (h *handlers) ListCompileWarnings(ctx context.Context, req adminapi.ListCompileWarningsRequestObject) (adminapi.ListCompileWarningsResponseObject, error) {
	params, err := listing.Parse(compileWarningList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.compileWarnings.List(ctx, app.CompileWarningQuery{
		Page: params.ListPage(), DeviceID: req.Params.DeviceId, AssignmentID: req.Params.AssignmentId,
		CatalogEntryID: req.Params.CatalogEntryId, Code: req.Params.Code,
	})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.CompileWarning, len(res.Items))
	for i, w := range res.Items {
		items[i] = adminapi.CompileWarning{Id: w.ID, DeviceId: w.DeviceID, Hostname: w.Hostname,
			AssignmentId: idPtr(w.AssignmentID), CatalogEntryId: idPtr(w.CatalogEntryID), Code: w.Code, Params: w.Params,
			CreatedAt: w.CreatedAt.UTC()}
	}
	return adminapi.ListCompileWarnings200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}
