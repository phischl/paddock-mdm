package admin

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// changeSetList is the list definition of GET /api/v1/change-sets (plan M6c decision 17).
var changeSetList = listing.Spec{Sort: []string{"applied_at"}, DefaultSort: "-applied_at"}

// configDocument answers GET /api/v1/config with the document encoded from its Go type, so the keys keep the order of
// the schema (the generated response type is a map, whose keys encoding/json sorts).
type configDocument []byte

func (c configDocument) VisitGetConfigResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(c)
	return err
}

func (h *handlers) GetConfig(ctx context.Context, _ adminapi.GetConfigRequestObject) (adminapi.GetConfigResponseObject, error) {
	doc, err := h.declarative.Export(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return configDocument(append(raw, '\n')), nil
}

func (h *handlers) ApplyConfig(ctx context.Context, req adminapi.ApplyConfigRequestObject) (adminapi.ApplyConfigResponseObject, error) {
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.InvalidRequest.WithDetail(err.Error())
	}
	out := adminapi.ConfigApplyResult{DryRun: req.Params.DryRun != nil && *req.Params.DryRun}
	expected := ""
	if req.Params.ExpectedPlan != nil {
		expected = *req.Params.ExpectedPlan
	}
	var plan declarative.Plan
	if out.DryRun {
		plan, err = h.declarative.Plan(ctx, raw)
	} else {
		var id uuid.UUID
		id, plan, err = h.declarative.Apply(ctx, raw, expected)
		if id != uuid.Nil {
			out.ChangeSetId = &id
		}
	}
	if err != nil {
		return nil, err
	}
	out.Plan, out.PlanSha256 = toConfigPlan(plan), plan.SHA256()
	return adminapi.ApplyConfig200JSONResponse(out), nil
}

func (h *handlers) ListChangeSets(ctx context.Context, req adminapi.ListChangeSetsRequestObject) (adminapi.ListChangeSetsResponseObject, error) {
	params, err := listing.Parse(changeSetList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	sources, err := listing.Enum("source", req.Params.Source)
	if err != nil {
		return nil, err
	}
	res, err := h.declarative.ListChangeSets(ctx, app.ChangeSetQuery{Page: params.ListPage(), Sources: sources})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ChangeSet, len(res.Items))
	for i, cs := range res.Items {
		if items[i], err = toChangeSet(cs); err != nil {
			return nil, err
		}
	}
	return adminapi.ListChangeSets200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) GetChangeSet(ctx context.Context, req adminapi.GetChangeSetRequestObject) (adminapi.GetChangeSetResponseObject, error) {
	cs, err := h.declarative.GetChangeSet(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out, err := toChangeSet(cs)
	if err != nil {
		return nil, err
	}
	return adminapi.GetChangeSet200JSONResponse(out), nil
}

func toChangeSet(cs pgstore.ChangeSet) (adminapi.ChangeSet, error) {
	out := adminapi.ChangeSet{
		Id: cs.ID, AppliedAt: cs.AppliedAt.UTC(), Source: adminapi.ChangeSetSource(cs.Source),
		Summary: adminapi.ChangeSetSummary{Created: int(cs.CreatedN), Updated: int(cs.UpdatedN), Deleted: int(cs.DeletedN), Sections: cs.Sections},
	}
	if out.Summary.Sections == nil {
		out.Summary.Sections = []string{}
	}
	var actor struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		Display string `json:"display"`
	}
	if err := json.Unmarshal(cs.Actor, &actor); err != nil {
		return out, err
	}
	out.Actor = adminapi.ChangeSetActor{Type: actor.Type, Display: actor.Display}
	if actor.ID != "" {
		out.Actor.Id = &actor.ID
	}
	var plan declarative.Plan
	if err := json.Unmarshal(cs.Plan, &plan); err != nil {
		return out, err
	}
	out.Plan = toConfigPlan(plan)
	return out, nil
}

func toConfigPlan(p declarative.Plan) adminapi.ConfigPlan {
	out := adminapi.ConfigPlan{Changes: make([]adminapi.ConfigChange, len(p.Changes)), Created: p.Created, Updated: p.Updated, Deleted: p.Deleted}
	for i, c := range p.Changes {
		fields := make([]adminapi.ConfigFieldChange, len(c.Fields))
		for j, f := range c.Fields {
			fields[j] = adminapi.ConfigFieldChange{Name: f.Name, Before: f.Before, After: f.After}
		}
		out.Changes[i] = adminapi.ConfigChange{Section: c.Section, Key: c.Key, Action: adminapi.ConfigChangeAction(c.Action), Fields: fields}
	}
	return out
}
