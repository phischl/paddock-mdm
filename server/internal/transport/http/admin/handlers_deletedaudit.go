package admin

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// The retained audit evidence of a deleted organization for platform administrators (ADR 0052 decision 7, plan M17
// §6): the same lists, filters and export package as the organization's own audit endpoints.

func (h *handlers) ListDeletedOrganizationAuditEvents(ctx context.Context, req adminapi.ListDeletedOrganizationAuditEventsRequestObject) (adminapi.ListDeletedOrganizationAuditEventsResponseObject, error) {
	params, err := listing.Parse(auditEventList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	var outcomes, actorTypes []string
	if err == nil {
		outcomes, err = listing.Enum("outcome", req.Params.Outcome)
	}
	if err == nil {
		actorTypes, err = listing.Enum("actor_type", req.Params.ActorType)
	}
	query := app.AuditQuery{
		From: req.Params.From, To: req.Params.To, Codes: listing.Strings(req.Params.Code), Outcomes: outcomes,
		ActorTypes: actorTypes, TargetID: req.Params.TargetId, Page: params.ListPage(), Now: h.now(),
	}
	res, err := h.deletedAudit.Events(ctx, req.Id, query, err)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AuditEvent, len(res.Items))
	for i, e := range res.Items {
		if items[i], err = toAuditEvent(e); err != nil {
			return nil, err
		}
	}
	return adminapi.ListDeletedOrganizationAuditEvents200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) ListDeletedOrganizationAuditExports(ctx context.Context, req adminapi.ListDeletedOrganizationAuditExportsRequestObject) (adminapi.ListDeletedOrganizationAuditExportsResponseObject, error) {
	params, err := listing.Parse(auditExportList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	var statuses []string
	if err == nil {
		statuses, err = listing.Enum("status", req.Params.Status)
	}
	res, err := h.deletedAudit.Exports(ctx, req.Id, app.AuditExportQuery{Statuses: statuses, Page: params.ListPage()}, err)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AuditExport, len(res.Items))
	for i, e := range res.Items {
		if items[i], err = toAuditExport(e); err != nil {
			return nil, err
		}
	}
	return adminapi.ListDeletedOrganizationAuditExports200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateDeletedOrganizationAuditExport(ctx context.Context, req adminapi.CreateDeletedOrganizationAuditExportRequestObject) (adminapi.CreateDeletedOrganizationAuditExportResponseObject, error) {
	e, err := h.deletedAudit.RequestExport(ctx, req.Id, app.AuditExportRequest{
		FromDay: req.Body.FromDay.Time, ToDay: req.Body.ToDay.Time, Purpose: req.Body.Purpose,
	})
	if err != nil {
		return nil, err
	}
	out, err := toAuditExport(e)
	if err != nil {
		return nil, err
	}
	return adminapi.CreateDeletedOrganizationAuditExport202JSONResponse(out), nil
}

// DownloadDeletedOrganizationAuditExport streams the package like DownloadAuditExport.
func (h *handlers) DownloadDeletedOrganizationAuditExport(ctx context.Context, req adminapi.DownloadDeletedOrganizationAuditExportRequestObject) (adminapi.DownloadDeletedOrganizationAuditExportResponseObject, error) {
	org := req.Id
	download := func(ctx context.Context, id uuid.UUID, begin func(app.ExportPackage), stream func(chunk []byte) error) error {
		return h.deletedAudit.Download(ctx, org, id, begin, stream)
	}
	s, err := streamExport(ctx, req.ExportId, download, exportBounds())
	if err != nil {
		return nil, err
	}
	return deletedExportStream{s}, nil
}

// deletedExportStream is exportStream as the answer of DownloadDeletedOrganizationAuditExport.
type deletedExportStream struct{ exportStream }

// VisitDownloadDeletedOrganizationAuditExportResponse writes the package as VisitDownloadAuditExportResponse does.
func (s deletedExportStream) VisitDownloadDeletedOrganizationAuditExportResponse(w http.ResponseWriter) error {
	return s.VisitDownloadAuditExportResponse(w)
}
