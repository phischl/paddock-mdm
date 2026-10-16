package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) EndAllSessions(ctx context.Context, _ adminapi.EndAllSessionsRequestObject) (adminapi.EndAllSessionsResponseObject, error) {
	gen, err := h.sessions.EndAll(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.EndAllSessions200JSONResponse{Generation: gen}, nil
}
