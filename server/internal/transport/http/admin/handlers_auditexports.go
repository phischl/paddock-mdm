package admin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/problem"
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

// exportChunkDeadline bounds the write of each piece of a package download in place of the server's write timeout
// (plan M8s decision 33): a slow but moving client finishes a package of any size, and a stalled one ends the transfer
// and releases its reader connection within this bound.
const exportChunkDeadline = 60 * time.Second

// DownloadAuditExport streams the package through a pipe: the use case writes each chunk as it reads it, and the
// response body reads from the pipe, so the package is never held in memory (plan M10 decision 35).
func (h *handlers) DownloadAuditExport(ctx context.Context, req adminapi.DownloadAuditExportRequestObject) (adminapi.DownloadAuditExportResponseObject, error) {
	return streamExport(ctx, req.Id, h.exports.Download, exportChunkDeadline)
}

// exportDownload is the use case behind a package download (app.AuditExports.Download).
type exportDownload func(ctx context.Context, id uuid.UUID, begin func(app.ExportPackage), stream func(chunk []byte) error) error

// streamExport runs download in its own goroutine because the headers need the export row it reads first.
func streamExport(ctx context.Context, id uuid.UUID, download exportDownload, chunkDeadline time.Duration) (adminapi.DownloadAuditExportResponseObject, error) {
	type started struct {
		pkg app.ExportPackage
		err error
	}
	pr, pw := io.Pipe()
	first := make(chan started, 1)
	go func() {
		begun := false
		// net/http's recover does not reach this goroutine, and the ActionRunner re-panics after recording the failure.
		defer func() {
			if v := recover(); v != nil {
				slog.ErrorContext(ctx, "panic in audit export download", "export_id", id, "panic", v, "stack", string(debug.Stack()))
				pw.CloseWithError(fmt.Errorf("panic in audit export download: %v", v))
				if !begun {
					first <- started{err: problem.Internal}
				}
			}
		}()
		err := download(ctx, id,
			func(pkg app.ExportPackage) { begun = true; first <- started{pkg: pkg} },
			func(chunk []byte) error { _, err := pw.Write(chunk); return err })
		switch {
		case !begun:
			first <- started{err: err}
		case errors.Is(err, io.ErrClosedPipe):
			slog.InfoContext(ctx, "audit export download ended by the client", "export_id", id, "error", err)
		case err != nil:
			slog.WarnContext(ctx, "audit export download broke off", "export_id", id, "error", err)
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
	return exportStream{
		res: adminapi.DownloadAuditExport200ApplicationxTarResponse{
			Body: pr, ContentLength: *res.pkg.Export.Size,
			Headers: adminapi.DownloadAuditExport200ResponseHeaders{ContentDisposition: &disposition, XPaddockPackageSHA256: &sum},
		},
		chunkDeadline: chunkDeadline,
	}, nil
}

// exportStream is the 200 answer of a package download with a rolling write deadline per piece of the body.
type exportStream struct {
	res           adminapi.DownloadAuditExport200ApplicationxTarResponse
	chunkDeadline time.Duration
}

// VisitDownloadAuditExportResponse never returns an error: once the 200 headers are out, the strict handler's problem
// answer would only append JSON to the package. The body ends early instead, and net/http closes the connection
// because fewer bytes than Content-Length were written.
func (s exportStream) VisitDownloadAuditExportResponse(w http.ResponseWriter) error {
	s.res.Body = &deadlineReader{r: s.res.Body, rc: http.NewResponseController(w), bound: s.chunkDeadline}
	if err := s.res.VisitDownloadAuditExportResponse(w); err != nil {
		slog.Info("audit export download ended early", "error", err)
	}
	return nil
}

// deadlineReader extends the write deadline each time it hands a piece of the body to the response writer.
type deadlineReader struct {
	r     io.Reader
	rc    *http.ResponseController
	bound time.Duration
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if n > 0 {
		// A writer without deadline support (HTTP/2 streams, tests) has no connection timeout to extend either.
		_ = d.rc.SetWriteDeadline(time.Now().Add(d.bound))
	}
	return n, err
}

// Close closes the underlying pipe reader, so the generated answer's deferred Close still stops the use case.
func (d *deadlineReader) Close() error {
	if c, ok := d.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
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
