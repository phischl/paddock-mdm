package admin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
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

func (h *handlers) ListAuditEvidenceKeys(ctx context.Context, _ adminapi.ListAuditEvidenceKeysRequestObject) (adminapi.ListAuditEvidenceKeysResponseObject, error) {
	rows, err := h.exports.Keys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]adminapi.AuditEvidenceKey, len(rows))
	for i, k := range rows {
		keys[i] = adminapi.AuditEvidenceKey{
			KeyVersion: int(k.KeyVersion), PublicKey: k.PublicKey, Fingerprint: auditevidence.Fingerprint(k.PublicKey),
			FirstSeenAt: k.FirstSeenAt.UTC(),
		}
	}
	return adminapi.ListAuditEvidenceKeys200JSONResponse(adminapi.AuditEvidenceKeys{Keys: keys}), nil
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
