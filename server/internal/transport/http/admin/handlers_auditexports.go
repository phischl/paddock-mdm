package admin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// auditExportList is the list definition of the evidence exports (plan M10 decision 29).
var auditExportList = listing.Spec{Sort: []string{"requested_at", "status", "from_day", "to_day"}, DefaultSort: "-requested_at"}

func (h *handlers) ListAuditExports(ctx context.Context, req adminapi.ListAuditExportsRequestObject) (adminapi.ListAuditExportsResponseObject, error) {
	params, err := listing.Parse(auditExportList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	res, err := h.exports.List(ctx, app.AuditExportQuery{Statuses: statuses, Page: params.ListPage()})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AuditExport, len(res.Items))
	for i, e := range res.Items {
		if items[i], err = toAuditExport(e); err != nil {
			return nil, err
		}
	}
	return adminapi.ListAuditExports200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateAuditExport(ctx context.Context, req adminapi.CreateAuditExportRequestObject) (adminapi.CreateAuditExportResponseObject, error) {
	e, err := h.exports.Request(ctx, app.AuditExportRequest{
		FromDay: req.Body.FromDay.Time, ToDay: req.Body.ToDay.Time, Purpose: req.Body.Purpose,
	})
	if err != nil {
		return nil, err
	}
	out, err := toAuditExport(e)
	if err != nil {
		return nil, err
	}
	return adminapi.CreateAuditExport202JSONResponse(out), nil
}

func (h *handlers) GetAuditExport(ctx context.Context, req adminapi.GetAuditExportRequestObject) (adminapi.GetAuditExportResponseObject, error) {
	e, err := h.exports.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out, err := toAuditExport(e)
	if err != nil {
		return nil, err
	}
	return adminapi.GetAuditExport200JSONResponse(out), nil
}

// DownloadAuditExport streams the package through a pipe: the use case writes each chunk as it reads it, and the
// response body reads from the pipe, so the package is never held in memory (plan M10 decision 35). The use case runs
// in its own goroutine because the headers need the export row it reads first.
func (h *handlers) DownloadAuditExport(ctx context.Context, req adminapi.DownloadAuditExportRequestObject) (adminapi.DownloadAuditExportResponseObject, error) {
	type started struct {
		pkg app.ExportPackage
		err error
	}
	pr, pw := io.Pipe()
	first := make(chan started, 1)
	go func() {
		begun := false
		err := h.exports.Download(ctx, req.Id,
			func(pkg app.ExportPackage) { begun = true; first <- started{pkg: pkg} },
			func(chunk []byte) error { _, err := pw.Write(chunk); return err })
		if !begun {
			first <- started{err: err}
		} else if err != nil {
			slog.WarnContext(ctx, "audit export download broke off", "export_id", req.Id, "error", err)
		}
		// A reader that is closed already makes this a no-op; a broken transfer ends the body early, which the client
		// sees as fewer bytes than Content-Length.
		pw.CloseWithError(err)
	}()
	res := <-first
	if res.err != nil {
		pr.Close()
		return nil, res.err
	}
	disposition := `attachment; filename="` + res.pkg.Filename + `"`
	sum := hex.EncodeToString(res.pkg.Export.PackageSha256)
	return adminapi.DownloadAuditExport200ApplicationxTarResponse{
		Body: pr, ContentLength: *res.pkg.Export.Size,
		Headers: adminapi.DownloadAuditExport200ResponseHeaders{ContentDisposition: &disposition, XPaddockPackageSHA256: &sum},
	}, nil
}

// toAuditExport maps an export row to the API; requested_by is stored as an audit actor, verify_problems as a JSON
// array of strings by the audit writer.
func toAuditExport(e auditstore.AuditExport) (adminapi.AuditExport, error) {
	out := adminapi.AuditExport{
		Id: e.ID, Status: adminapi.AuditExportStatus(e.Status), FromDay: openapi_types.Date{Time: e.FromDay},
		ToDay: openapi_types.Date{Time: e.ToDay}, Purpose: e.Purpose, RequestedAt: e.RequestedAt.UTC(),
		ReadyAt: utcPtr(e.ReadyAt), ExpiresAt: utcPtr(e.ExpiresAt), EventCount: e.EventCount, Size: e.Size,
		VerifyOk: e.VerifyOk, Error: e.Error, VerifyProblems: []string{},
	}
	if err := json.Unmarshal(e.RequestedBy, &out.RequestedBy); err != nil {
		return out, fmt.Errorf("requester of export %s: %w", e.ID, err)
	}
	out.RequestedBy.Ip = nil
	if e.ObjectCount != nil {
		n := int(*e.ObjectCount)
		out.ObjectCount = &n
	}
	if e.KeyVersion != nil {
		v := int(*e.KeyVersion)
		out.KeyVersion = &v
	}
	if e.PackageSha256 != nil {
		sum := hex.EncodeToString(e.PackageSha256)
		out.PackageSha256 = &sum
	}
	if len(e.VerifyProblems) > 0 {
		if err := json.Unmarshal(e.VerifyProblems, &out.VerifyProblems); err != nil {
			return out, fmt.Errorf("problems of export %s: %w", e.ID, err)
		}
		if out.VerifyProblems == nil {
			out.VerifyProblems = []string{}
		}
	}
	return out, nil
}
