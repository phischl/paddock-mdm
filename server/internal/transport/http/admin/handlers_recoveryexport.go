package admin

import (
	"context"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/recoveryexport"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// recoveryExportDeadline replaces the server's write timeout while an export streams: the escrow-reader decrypts the
// whole organization during the response.
const recoveryExportDeadline = app.RecoveryExportTimeout

// recoveryExportResponse runs the export while the response is written (ADR 0052 amendment b): the download's headers
// are set when the escrow-reader accepted it, and the message streams through. An error before that is answered as a
// problem; after it the response is cut off, so the requester never holds a complete message of a failed export.
type recoveryExportResponse struct {
	ctx context.Context
	run func(ctx context.Context, open func(app.RecoveryExportFile) io.Writer) error
}

func (x recoveryExportResponse) visit(w http.ResponseWriter) error {
	// A writer without deadline support (HTTP/2 streams, tests) has no connection timeout to extend either.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(recoveryExportDeadline))
	started := false
	err := x.run(x.ctx, func(f app.RecoveryExportFile) io.Writer {
		started = true
		h := w.Header()
		h.Set("Content-Type", recoveryexport.ContentType)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name()}))
		w.WriteHeader(http.StatusOK)
		return w
	})
	if err != nil && started {
		panic(http.ErrAbortHandler)
	}
	return err
}

func (x recoveryExportResponse) VisitExportRecoveryKeysResponse(w http.ResponseWriter) error {
	return x.visit(w)
}

func (x recoveryExportResponse) VisitExportOrganizationRecoveryKeysResponse(w http.ResponseWriter) error {
	return x.visit(w)
}

func recoveryExportInput(body *adminapi.RecoveryExportRequest) app.RecoveryExportInput {
	var in app.RecoveryExportInput
	if body == nil {
		return in
	}
	in.Recipient = string(body.Recipient)
	if body.PublicKey != nil {
		in.PublicKey = *body.PublicKey
	}
	if body.Passphrase != nil {
		in.Passphrase = *body.Passphrase
	}
	return in
}

func (h *handlers) ExportRecoveryKeys(ctx context.Context, req adminapi.ExportRecoveryKeysRequestObject) (adminapi.ExportRecoveryKeysResponseObject, error) {
	in := recoveryExportInput(req.Body)
	return recoveryExportResponse{ctx: ctx, run: func(ctx context.Context, open func(app.RecoveryExportFile) io.Writer) error {
		return h.recoveryExports.Export(ctx, in, open)
	}}, nil
}

func (h *handlers) ExportOrganizationRecoveryKeys(ctx context.Context, req adminapi.ExportOrganizationRecoveryKeysRequestObject) (adminapi.ExportOrganizationRecoveryKeysResponseObject, error) {
	in, org := recoveryExportInput(req.Body), uuid.UUID(req.Id)
	return recoveryExportResponse{ctx: ctx, run: func(ctx context.Context, open func(app.RecoveryExportFile) io.Writer) error {
		return h.recoveryExports.ExportPlatform(ctx, org, in, open)
	}}, nil
}
