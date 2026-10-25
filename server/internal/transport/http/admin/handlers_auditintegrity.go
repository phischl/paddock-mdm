package admin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// auditVerificationRunList and auditManifestList are the list definitions of the evidence integrity routes (plan
// M8b decision 30).
var (
	auditVerificationRunList = listing.Spec{Sort: []string{"started_at", "from_day", "ok"}, DefaultSort: "-started_at"}
	auditManifestList        = listing.Spec{Sort: []string{"day"}, DefaultSort: "-day"}
)

func (h *handlers) GetAuditIntegrity(ctx context.Context, _ adminapi.GetAuditIntegrityRequestObject) (adminapi.GetAuditIntegrityResponseObject, error) {
	s, err := h.integrity.Summary(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.GetAuditIntegrity200JSONResponse{
		Manifests: s.Manifests, VerificationWindowDays: app.VerificationWindowDays,
		LastSuccessAt: utcPtr(s.LastSuccessAt), LastFailureAt: utcPtr(s.LastFailureAt),
	}
	if s.SealedThrough != nil {
		out.SealedThrough = &openapi_types.Date{Time: *s.SealedThrough}
	}
	if s.LastRun != nil {
		run, err := toAuditVerificationRun(*s.LastRun)
		if err != nil {
			return nil, err
		}
		out.LastRun = &run
	}
	return out, nil
}

func (h *handlers) ListAuditVerificationRuns(ctx context.Context, req adminapi.ListAuditVerificationRunsRequestObject) (adminapi.ListAuditVerificationRunsResponseObject, error) {
	params, err := listing.Parse(auditVerificationRunList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	triggers, err := listing.Enum("trigger", req.Params.Trigger)
	if err != nil {
		return nil, err
	}
	res, err := h.integrity.ListRuns(ctx, app.RunQuery{OK: req.Params.Ok, Triggers: triggers, Page: params.ListPage()})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AuditVerificationRun, len(res.Items))
	for i, r := range res.Items {
		if items[i], err = toAuditVerificationRun(r); err != nil {
			return nil, err
		}
	}
	return adminapi.ListAuditVerificationRuns200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) ListAuditManifests(ctx context.Context, req adminapi.ListAuditManifestsRequestObject) (adminapi.ListAuditManifestsResponseObject, error) {
	params, err := listing.Parse(auditManifestList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	q := app.ManifestQuery{Verified: req.Params.Verified, Page: params.ListPage()}
	if req.Params.From != nil {
		q.From = &req.Params.From.Time
	}
	if req.Params.To != nil {
		q.To = &req.Params.To.Time
	}
	res, err := h.integrity.ListManifests(ctx, q)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AuditManifest, len(res.Items))
	for i, m := range res.Items {
		items[i] = adminapi.AuditManifest{
			Day: openapi_types.Date{Time: m.Day}, Sha256: hex.EncodeToString(m.Sha256), KeyVersion: int(m.KeyVersion),
			ObjectKey: m.ObjectKey, LastVerifiedAt: utcPtr(m.LastVerifiedAt), LastVerifiedOk: m.LastVerifiedOk,
		}
		if m.PrevSha256 != nil {
			prev := hex.EncodeToString(m.PrevSha256)
			items[i].PrevSha256 = &prev
		}
	}
	return adminapi.ListAuditManifests200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

// toAuditVerificationRun maps a run row to the API; problems are stored as a JSON array of strings by the writer.
func toAuditVerificationRun(r auditstore.AuditVerificationRun) (adminapi.AuditVerificationRun, error) {
	out := adminapi.AuditVerificationRun{
		Id: r.ID, Trigger: adminapi.AuditVerificationTrigger(r.Trigger), FromDay: openapi_types.Date{Time: r.FromDay},
		ToDay: openapi_types.Date{Time: r.ToDay}, StartedAt: r.StartedAt.UTC(), FinishedAt: r.FinishedAt.UTC(),
		Days: int(r.Days), Objects: int(r.Objects), Ok: r.Ok, Problems: []string{}, EventId: r.EventID,
	}
	if err := json.Unmarshal(r.Problems, &out.Problems); err != nil {
		return out, fmt.Errorf("problems of verification run %s: %w", r.ID, err)
	}
	if out.Problems == nil {
		out.Problems = []string{}
	}
	return out, nil
}
