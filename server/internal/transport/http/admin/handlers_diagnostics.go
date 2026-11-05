package admin

import (
	"context"
	"mime"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// List definitions of the diagnostics bundles (plan M12 decision 13).
var (
	deviceDiagnosticsList = listing.Spec{Sort: []string{"requested_at", "state"}, DefaultSort: "-requested_at"}
	diagnosticsList       = listing.Spec{Sort: []string{"requested_at", "hostname", "state"}, DefaultSort: "-requested_at"}
)

func (h *handlers) RequestDeviceDiagnostics(ctx context.Context, req adminapi.RequestDeviceDiagnosticsRequestObject) (adminapi.RequestDeviceDiagnosticsResponseObject, error) {
	b, err := h.diagnostics.Request(ctx, req.Id, req.Body.Reason)
	if err != nil {
		return nil, err
	}
	return adminapi.RequestDeviceDiagnostics202JSONResponse(toDiagnostics(b)), nil
}

func (h *handlers) ListDeviceDiagnostics(ctx context.Context, req adminapi.ListDeviceDiagnosticsRequestObject) (adminapi.ListDeviceDiagnosticsResponseObject, error) {
	params, err := listing.Parse(deviceDiagnosticsList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	states, err := listing.Enum("state", req.Params.State)
	if err != nil {
		return nil, err
	}
	res, err := h.diagnostics.List(ctx, req.Id, app.DiagnosticsQuery{Page: params.ListPage(), States: states})
	if err != nil {
		return nil, err
	}
	return adminapi.ListDeviceDiagnostics200JSONResponse(listing.NewPage(diagnosticsItems(res.Items), params, res.Count)), nil
}

func (h *handlers) ListDiagnostics(ctx context.Context, req adminapi.ListDiagnosticsRequestObject) (adminapi.ListDiagnosticsResponseObject, error) {
	params, err := listing.Parse(diagnosticsList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	states, err := listing.Enum("state", req.Params.State)
	if err != nil {
		return nil, err
	}
	res, err := h.diagnostics.ListAll(ctx, app.DiagnosticsQuery{Page: params.ListPage(), States: states})
	if err != nil {
		return nil, err
	}
	return adminapi.ListDiagnostics200JSONResponse(listing.NewPage(diagnosticsItems(res.Items), params, res.Count)), nil
}

func (h *handlers) GetDiagnostics(ctx context.Context, req adminapi.GetDiagnosticsRequestObject) (adminapi.GetDiagnosticsResponseObject, error) {
	b, err := h.diagnostics.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetDiagnostics200JSONResponse(toDiagnostics(b)), nil
}

func (h *handlers) DownloadDiagnostics(ctx context.Context, req adminapi.DownloadDiagnosticsRequestObject) (adminapi.DownloadDiagnosticsResponseObject, error) {
	b, err := h.diagnostics.Download(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	// Hostnames are any printable text the device reported; FormatMediaType quotes or encodes them.
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": b.Name})
	return adminapi.DownloadDiagnostics200ApplicationgzipResponse{Body: b.Reader, ContentLength: b.Size,
		Headers: adminapi.DownloadDiagnostics200ResponseHeaders{ContentDisposition: &disposition}}, nil
}

func (h *handlers) PurgeDiagnostics(ctx context.Context, req adminapi.PurgeDiagnosticsRequestObject) (adminapi.PurgeDiagnosticsResponseObject, error) {
	b, err := h.diagnostics.Purge(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.PurgeDiagnostics200JSONResponse(toDiagnostics(b)), nil
}

func diagnosticsItems(rows []app.DiagnosticsRow) []adminapi.Diagnostics {
	items := make([]adminapi.Diagnostics, len(rows))
	for i, b := range rows {
		items[i] = toDiagnostics(b)
	}
	return items
}

func toDiagnostics(b app.DiagnosticsRow) adminapi.Diagnostics {
	out := adminapi.Diagnostics{
		Id: b.ID, DeviceId: b.DeviceID, Hostname: b.Hostname, RequestedBy: b.RequestedBy, RequestedAt: b.RequestedAt.UTC(),
		Reason: b.Reason, State: adminapi.DiagnosticsState(b.State), Size: b.Size, Sha256: b.Sha256,
		TruncatedEntries: b.TruncatedEntries, StoredAt: utcPtr(b.StoredAt), ExpiresAt: utcPtr(b.ExpiresAt),
		FailedReason: b.FailedReason, DownloadCount: int(b.DownloadCount), LastDownloadedAt: utcPtr(b.LastDownloadedAt),
	}
	if out.TruncatedEntries == nil {
		out.TruncatedEntries = []string{}
	}
	if b.Files != nil {
		files := int(*b.Files)
		out.Files = &files
	}
	if b.NotifiedSessions != nil {
		sessions := int(*b.NotifiedSessions)
		out.NotifiedSessions = &sessions
	}
	return out
}
