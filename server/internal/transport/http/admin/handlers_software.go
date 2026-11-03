package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// softwareSourceList is the list definition of GET /api/v1/software-sources (plan M13a §6.1).
var softwareSourceList = listing.Spec{Sort: []string{"name", "created_at", "updated_at"}, DefaultSort: "name"}

func (h *handlers) ListSoftwareSources(ctx context.Context, req adminapi.ListSoftwareSourcesRequestObject) (adminapi.ListSoftwareSourcesResponseObject, error) {
	params, err := listing.Parse(softwareSourceList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.softwareSources.List(ctx, params.ListPage())
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.SoftwareSourceSummary, len(res.Items))
	for i, s := range res.Items {
		items[i] = toSoftwareSourceSummary(s)
	}
	return adminapi.ListSoftwareSources200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateSoftwareSource(ctx context.Context, req adminapi.CreateSoftwareSourceRequestObject) (adminapi.CreateSoftwareSourceResponseObject, error) {
	b := req.Body
	in := software.SourceInput{
		Slug: b.Slug, Name: b.Name, URIs: b.Uris, Suites: b.Suites, SigningKey: b.SigningKey, Fingerprint: b.Fingerprint,
	}
	if b.Components != nil {
		in.Components = *b.Components
	}
	if b.Architectures != nil {
		in.Architectures = fromSoftwareArchitectures(*b.Architectures)
	}
	s, err := h.softwareSources.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/software-sources/" + s.ID.String()
	return adminapi.CreateSoftwareSource201JSONResponse{
		Body: toSoftwareSource(s), Headers: adminapi.CreateSoftwareSource201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetSoftwareSource(ctx context.Context, req adminapi.GetSoftwareSourceRequestObject) (adminapi.GetSoftwareSourceResponseObject, error) {
	s, err := h.softwareSources.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetSoftwareSource200JSONResponse(toSoftwareSource(s)), nil
}

func (h *handlers) UpdateSoftwareSource(ctx context.Context, req adminapi.UpdateSoftwareSourceRequestObject) (adminapi.UpdateSoftwareSourceResponseObject, error) {
	b := req.Body
	in := app.SourceUpdate{
		Slug: b.Slug, Name: b.Name, URIs: b.Uris, Suites: b.Suites, Components: b.Components, SigningKey: b.SigningKey,
		Fingerprint: b.Fingerprint,
	}
	if b.Architectures != nil {
		archs := fromSoftwareArchitectures(*b.Architectures)
		in.Architectures = &archs
	}
	s, err := h.softwareSources.Update(ctx, req.Id, in)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateSoftwareSource200JSONResponse(toSoftwareSource(s)), nil
}

func (h *handlers) DeleteSoftwareSource(ctx context.Context, req adminapi.DeleteSoftwareSourceRequestObject) (adminapi.DeleteSoftwareSourceResponseObject, error) {
	if err := h.softwareSources.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteSoftwareSource204Response{}, nil
}

func fromSoftwareArchitectures(in []adminapi.SoftwareArchitecture) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = string(a)
	}
	return out
}

func toSoftwareSourceSummary(s pgstore.SoftwareSource) adminapi.SoftwareSourceSummary {
	archs := make([]adminapi.SoftwareArchitecture, len(s.Architectures))
	for i, a := range s.Architectures {
		archs[i] = adminapi.SoftwareArchitecture(a)
	}
	return adminapi.SoftwareSourceSummary{
		Id: s.ID, Slug: s.Slug, Name: s.Name, Uris: s.Uris, Suites: s.Suites, Components: s.Components,
		Architectures: archs, Fingerprint: s.Fingerprint, WeakKey: s.WeakKey, CreatedAt: s.CreatedAt.UTC(),
		UpdatedAt: s.UpdatedAt.UTC(),
	}
}

func toSoftwareSource(s pgstore.SoftwareSource) adminapi.SoftwareSource {
	sum := toSoftwareSourceSummary(s)
	return adminapi.SoftwareSource{
		Id: sum.Id, Slug: sum.Slug, Name: sum.Name, Uris: sum.Uris, Suites: sum.Suites, Components: sum.Components,
		Architectures: sum.Architectures, Fingerprint: sum.Fingerprint, WeakKey: sum.WeakKey, SigningKey: s.SigningKey,
		CreatedAt: sum.CreatedAt, UpdatedAt: sum.UpdatedAt,
	}
}
