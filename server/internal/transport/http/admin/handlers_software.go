package admin

import (
	"bytes"
	"context"
	"io"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/problem"
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

func toSoftwareSourceSummary(v app.SoftwareSourceView) adminapi.SoftwareSourceSummary {
	s := v.SoftwareSource
	archs := make([]adminapi.SoftwareArchitecture, len(s.Architectures))
	for i, a := range s.Architectures {
		archs[i] = adminapi.SoftwareArchitecture(a)
	}
	return adminapi.SoftwareSourceSummary{
		Id: s.ID, Slug: s.Slug, Name: s.Name, Uris: s.Uris, Suites: s.Suites, Components: s.Components,
		Architectures: archs, Fingerprint: s.Fingerprint, WeakKey: s.WeakKey, EntryCount: int(v.EntryCount), CreatedAt: s.CreatedAt.UTC(),
		UpdatedAt: s.UpdatedAt.UTC(),
	}
}

func toSoftwareSource(s app.SoftwareSourceView) adminapi.SoftwareSource {
	sum := toSoftwareSourceSummary(s)
	return adminapi.SoftwareSource{
		Id: sum.Id, Slug: sum.Slug, Name: sum.Name, Uris: sum.Uris, Suites: sum.Suites, Components: sum.Components,
		Architectures: sum.Architectures, Fingerprint: sum.Fingerprint, WeakKey: sum.WeakKey, EntryCount: sum.EntryCount, SigningKey: s.SigningKey,
		CreatedAt: sum.CreatedAt, UpdatedAt: sum.UpdatedAt,
	}
}

// softwareCatalogList and softwareAssignmentList are the list definitions of GET /api/v1/software-catalog and
// GET /api/v1/software-assignments (plan M13a §6.1).
var (
	softwareCatalogList    = listing.Spec{Sort: []string{"name", "category", "created_at", "updated_at"}, DefaultSort: "name"}
	softwareAssignmentList = listing.Spec{Sort: []string{"created_at", "updated_at", "intent"}, DefaultSort: "-created_at"}
	// The derived states are computed in memory (ADR 0028), so these lists sort there too.
	deviceManagedSoftwareList = listing.Spec{Sort: []string{"name", "state", "reported_at"}, DefaultSort: "name"}
	softwareCatalogDeviceList = listing.Spec{Sort: []string{"hostname", "state", "reported_at"}, DefaultSort: "hostname"}
)

func (h *handlers) ListSoftwareCatalog(ctx context.Context, req adminapi.ListSoftwareCatalogRequestObject) (adminapi.ListSoftwareCatalogResponseObject, error) {
	params, err := listing.Parse(softwareCatalogList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.softwareCatalog.List(ctx, app.CatalogQuery{Page: params.ListPage(), Category: req.Params.Category, SourceID: req.Params.SourceId})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.SoftwareCatalogEntry, len(res.Items))
	for i, e := range res.Items {
		if items[i], err = toSoftwareCatalogEntry(e); err != nil {
			return nil, err
		}
	}
	return adminapi.ListSoftwareCatalog200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateSoftwareCatalogEntry(ctx context.Context, req adminapi.CreateSoftwareCatalogEntryRequestObject) (adminapi.CreateSoftwareCatalogEntryResponseObject, error) {
	b := req.Body
	e, err := h.softwareCatalog.Create(ctx, app.EntryInput{
		Name: b.Name, Description: deref(b.Description, ""), Category: deref(b.Category, ""), SourceID: b.SourceId,
		Packages: fromPackageRefs(b.Packages),
	})
	if err != nil {
		return nil, err
	}
	body, err := toSoftwareCatalogEntry(e)
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/software-catalog/" + e.ID.String()
	return adminapi.CreateSoftwareCatalogEntry201JSONResponse{
		Body: body, Headers: adminapi.CreateSoftwareCatalogEntry201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetSoftwareCatalogEntry(ctx context.Context, req adminapi.GetSoftwareCatalogEntryRequestObject) (adminapi.GetSoftwareCatalogEntryResponseObject, error) {
	e, err := h.softwareCatalog.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	body, err := toSoftwareCatalogEntry(e)
	if err != nil {
		return nil, err
	}
	return adminapi.GetSoftwareCatalogEntry200JSONResponse(body), nil
}

func (h *handlers) UpdateSoftwareCatalogEntry(ctx context.Context, req adminapi.UpdateSoftwareCatalogEntryRequestObject) (adminapi.UpdateSoftwareCatalogEntryResponseObject, error) {
	b := req.Body
	e, err := h.softwareCatalog.Update(ctx, req.Id, app.EntryInput{
		Name: b.Name, Description: deref(b.Description, ""), Category: deref(b.Category, ""), SourceID: b.SourceId,
		Packages: fromPackageRefs(b.Packages),
	})
	if err != nil {
		return nil, err
	}
	body, err := toSoftwareCatalogEntry(e)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateSoftwareCatalogEntry200JSONResponse(body), nil
}

func (h *handlers) DeleteSoftwareCatalogEntry(ctx context.Context, req adminapi.DeleteSoftwareCatalogEntryRequestObject) (adminapi.DeleteSoftwareCatalogEntryResponseObject, error) {
	if err := h.softwareCatalog.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteSoftwareCatalogEntry204Response{}, nil
}

func (h *handlers) GetSoftwareCatalogIcon(ctx context.Context, req adminapi.GetSoftwareCatalogIconRequestObject) (adminapi.GetSoftwareCatalogIconResponseObject, error) {
	icon, err := h.softwareCatalog.Icon(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	cache := "private, max-age=300"
	return adminapi.GetSoftwareCatalogIcon200ImagepngResponse{
		Body: bytes.NewReader(icon), ContentLength: int64(len(icon)), Headers: adminapi.GetSoftwareCatalogIcon200ResponseHeaders{CacheControl: &cache},
	}, nil
}

// SetSoftwareCatalogIcon reads one byte more than the icon limit, so that the use case can refuse a larger body
// with its detail instead of the handler cutting it silently.
func (h *handlers) SetSoftwareCatalogIcon(ctx context.Context, req adminapi.SetSoftwareCatalogIconRequestObject) (adminapi.SetSoftwareCatalogIconResponseObject, error) {
	icon, err := io.ReadAll(io.LimitReader(req.Body, software.MaxIconBytes+1))
	if err != nil {
		return nil, problem.InvalidRequest.WithDetail("unreadable body")
	}
	if err := h.softwareCatalog.SetIcon(ctx, req.Id, icon); err != nil {
		return nil, err
	}
	return adminapi.SetSoftwareCatalogIcon204Response{}, nil
}

func (h *handlers) ListSoftwareAssignments(ctx context.Context, req adminapi.ListSoftwareAssignmentsRequestObject) (adminapi.ListSoftwareAssignmentsResponseObject, error) {
	params, err := listing.Parse(softwareAssignmentList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	query := app.SoftwareAssignmentQuery{Page: params.ListPage(), CatalogEntryID: req.Params.CatalogEntryId, DeviceGroupID: req.Params.DeviceGroupId}
	if req.Params.Intent != nil {
		intent := string(*req.Params.Intent)
		query.Intent = &intent
	}
	res, err := h.softwareCatalog.ListAssignments(ctx, query)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.SoftwareAssignment, len(res.Items))
	for i, a := range res.Items {
		items[i] = toSoftwareAssignment(a)
	}
	return adminapi.ListSoftwareAssignments200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateSoftwareAssignment(ctx context.Context, req adminapi.CreateSoftwareAssignmentRequestObject) (adminapi.CreateSoftwareAssignmentResponseObject, error) {
	b := req.Body
	a, err := h.softwareCatalog.CreateAssignment(ctx, app.AssignmentInput{
		CatalogEntryID: &b.CatalogEntryId, DeviceGroupID: b.DeviceGroupId, Intent: string(b.Intent),
		UpdateRule: string(deref(b.UpdateRule, "")), Version: b.Version, Reason: deref(b.Reason, ""),
	})
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/software-assignments/" + a.ID.String()
	return adminapi.CreateSoftwareAssignment201JSONResponse{
		Body: toSoftwareAssignment(a), Headers: adminapi.CreateSoftwareAssignment201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetSoftwareAssignment(ctx context.Context, req adminapi.GetSoftwareAssignmentRequestObject) (adminapi.GetSoftwareAssignmentResponseObject, error) {
	a, err := h.softwareCatalog.GetAssignment(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetSoftwareAssignment200JSONResponse(toSoftwareAssignment(a)), nil
}

func (h *handlers) UpdateSoftwareAssignment(ctx context.Context, req adminapi.UpdateSoftwareAssignmentRequestObject) (adminapi.UpdateSoftwareAssignmentResponseObject, error) {
	b := req.Body
	a, err := h.softwareCatalog.UpdateAssignment(ctx, req.Id, app.AssignmentInput{
		CatalogEntryID: b.CatalogEntryId, DeviceGroupID: b.DeviceGroupId, Intent: string(b.Intent),
		UpdateRule: string(deref(b.UpdateRule, "")), Version: b.Version, Reason: deref(b.Reason, ""),
	})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateSoftwareAssignment200JSONResponse(toSoftwareAssignment(a)), nil
}

func (h *handlers) DeleteSoftwareAssignment(ctx context.Context, req adminapi.DeleteSoftwareAssignmentRequestObject) (adminapi.DeleteSoftwareAssignmentResponseObject, error) {
	if err := h.softwareCatalog.DeleteAssignment(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteSoftwareAssignment204Response{}, nil
}

func fromPackageRefs(in []adminapi.PackageRef) []software.PackageRef {
	out := make([]software.PackageRef, len(in))
	for i, p := range in {
		out[i] = software.PackageRef{Distribution: p.Distribution, Release: p.Release, Architecture: string(p.Architecture), Package: p.Package}
	}
	return out
}

func toSoftwareCatalogEntry(e app.CatalogEntry) (adminapi.SoftwareCatalogEntry, error) {
	refs, err := software.DecodePackages(e.Packages)
	if err != nil {
		return adminapi.SoftwareCatalogEntry{}, err
	}
	packages := make([]adminapi.PackageRef, len(refs))
	for i, p := range refs {
		packages[i] = adminapi.PackageRef{
			Distribution: p.Distribution, Release: p.Release, Architecture: adminapi.PackageRefArchitecture(p.Architecture), Package: p.Package,
		}
	}
	var source *uuid.UUID
	if e.SourceID.Valid {
		source = &e.SourceID.UUID
	}
	return adminapi.SoftwareCatalogEntry{
		Id: e.ID, Name: e.Name, Description: e.Description, Category: e.Category, SourceId: source, SourceSlug: e.SourceSlug,
		Packages: packages, HasIcon: e.HasIcon, AssignmentCount: int(e.AssignmentCount), CreatedAt: e.CreatedAt.UTC(),
		UpdatedAt: e.UpdatedAt.UTC(),
	}, nil
}

func toSoftwareAssignment(a app.Assignment) adminapi.SoftwareAssignment {
	var group *uuid.UUID
	if a.DeviceGroupID.Valid {
		group = &a.DeviceGroupID.UUID
	}
	return adminapi.SoftwareAssignment{
		Id: a.ID, AppName: a.AppName, CatalogEntryId: a.CatalogEntryID, DeviceGroupId: group,
		Intent: adminapi.SoftwareIntent(a.Intent), UpdateRule: adminapi.SoftwareUpdateRule(a.UpdateRule), Version: a.Version,
		Reason: a.Reason, CreatedAt: a.CreatedAt.UTC(), UpdatedAt: a.UpdatedAt.UTC(),
	}
}

func (h *handlers) ListDeviceManagedSoftware(ctx context.Context, req adminapi.ListDeviceManagedSoftwareRequestObject) (adminapi.ListDeviceManagedSoftwareResponseObject, error) {
	params, err := listing.Parse(deviceManagedSoftwareList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	query := app.DeviceManagedSoftwareQuery{Page: params.ListPage()}
	if req.Params.State != nil {
		if !req.Params.State.Valid() {
			return nil, problem.InvalidRequest.WithDetail("unknown state")
		}
		state := string(*req.Params.State)
		query.State = &state
	}
	if req.Params.Intent != nil {
		if !req.Params.Intent.Valid() {
			return nil, problem.InvalidRequest.WithDetail("unknown intent")
		}
		intent := string(*req.Params.Intent)
		query.Intent = &intent
	}
	res, err := h.softwareStatus.DeviceManagedSoftware(ctx, req.Id, query)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.DeviceManagedSoftware, len(res.Items))
	for i, m := range res.Items {
		items[i] = adminapi.DeviceManagedSoftware{
			CatalogEntryId: m.CatalogEntryID, Name: m.Name, Package: m.Package, Intent: adminapi.SoftwareIntent(m.Intent),
			State: adminapi.DeviceSoftwareState(m.State), Version: m.Version, Reason: m.Reason, Error: m.Error, ReportedAt: m.ReportedAt,
		}
	}
	page := listing.NewPage(items, params, res.Count)
	return adminapi.ListDeviceManagedSoftware200JSONResponse{
		Items: page.Items, Page: page.Page, PageSize: page.PageSize, Sort: page.Sort, Total: page.Total, TotalCapped: page.TotalCapped,
		Truncated: res.Truncated,
	}, nil
}

func (h *handlers) ListSoftwareCatalogDevices(ctx context.Context, req adminapi.ListSoftwareCatalogDevicesRequestObject) (adminapi.ListSoftwareCatalogDevicesResponseObject, error) {
	params, err := listing.Parse(softwareCatalogDeviceList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	query := app.SoftwareCatalogDeviceQuery{Page: params.ListPage(), DeviceGroupID: req.Params.DeviceGroupId}
	if req.Params.State != nil {
		if !req.Params.State.Valid() {
			return nil, problem.InvalidRequest.WithDetail("unknown state")
		}
		state := string(*req.Params.State)
		query.State = &state
	}
	res, err := h.softwareStatus.CatalogDevices(ctx, req.Id, query)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.SoftwareCatalogDevice, len(res.Items))
	for i, d := range res.Items {
		items[i] = adminapi.SoftwareCatalogDevice{
			DeviceId: d.DeviceID, Hostname: d.Hostname, Name: d.Name, DeviceGroupIds: d.DeviceGroupIDs, Package: d.Package, Intent: adminapi.SoftwareIntent(d.Intent),
			State: adminapi.DeviceSoftwareState(d.State), Version: d.Version, Reason: d.Reason, Error: d.Error, ReportedAt: d.ReportedAt,
		}
	}
	return adminapi.ListSoftwareCatalogDevices200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}
