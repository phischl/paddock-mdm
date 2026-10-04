package admin

import (
	"context"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/adminapi"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/listing"
)

func (h *handlers) ListManagedFiles(ctx context.Context, req adminapi.ListManagedFilesRequestObject) (adminapi.ListManagedFilesResponseObject, error) {
	params, err := listing.Parse(managedFileList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.managed.ListFiles(ctx, app.ManagedQuery{Page: params.ListPage(), GroupID: req.Params.DeviceGroupId})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ManagedFile, len(res.Items))
	for i, f := range res.Items {
		items[i] = toManagedFile(f)
	}
	return adminapi.ListManagedFiles200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateManagedFile(ctx context.Context, req adminapi.CreateManagedFileRequestObject) (adminapi.CreateManagedFileResponseObject, error) {
	f, err := h.managed.CreateFile(ctx, app.FileInput{
		DeviceGroupID: req.Body.DeviceGroupId, Path: &req.Body.Path, Mode: req.Body.Mode, Owner: req.Body.Owner,
		Group: req.Body.Group, Content: &req.Body.Content,
	})
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/managed-files/" + f.ID.String()
	return adminapi.CreateManagedFile201JSONResponse{
		Body: toManagedFile(f), Headers: adminapi.CreateManagedFile201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetManagedFile(ctx context.Context, req adminapi.GetManagedFileRequestObject) (adminapi.GetManagedFileResponseObject, error) {
	f, err := h.managed.GetFile(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetManagedFile200JSONResponse(toManagedFile(f)), nil
}

func (h *handlers) UpdateManagedFile(ctx context.Context, req adminapi.UpdateManagedFileRequestObject) (adminapi.UpdateManagedFileResponseObject, error) {
	f, err := h.managed.UpdateFile(ctx, req.Id, app.FileInput{
		Path: req.Body.Path, Mode: req.Body.Mode, Owner: req.Body.Owner, Group: req.Body.Group, Content: req.Body.Content,
	})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateManagedFile200JSONResponse(toManagedFile(f)), nil
}

func (h *handlers) DeleteManagedFile(ctx context.Context, req adminapi.DeleteManagedFileRequestObject) (adminapi.DeleteManagedFileResponseObject, error) {
	if err := h.managed.DeleteFile(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteManagedFile204Response{}, nil
}

func toManagedFile(f pgstore.ManagedFile) adminapi.ManagedFile {
	return adminapi.ManagedFile{
		Id: f.ID, DeviceGroupId: idPtr(f.DeviceGroupID), Path: f.Path, Mode: f.Mode, Owner: f.Owner, Group: f.Grp,
		Content: f.Content, CreatedAt: f.CreatedAt.UTC(), UpdatedAt: f.UpdatedAt.UTC(),
	}
}

func (h *handlers) ListManagedUnits(ctx context.Context, req adminapi.ListManagedUnitsRequestObject) (adminapi.ListManagedUnitsResponseObject, error) {
	params, err := listing.Parse(managedUnitList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.managed.ListUnits(ctx, app.ManagedQuery{Page: params.ListPage(), GroupID: req.Params.DeviceGroupId})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ManagedUnit, len(res.Items))
	for i, u := range res.Items {
		items[i] = toManagedUnit(u)
	}
	return adminapi.ListManagedUnits200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateManagedUnit(ctx context.Context, req adminapi.CreateManagedUnitRequestObject) (adminapi.CreateManagedUnitResponseObject, error) {
	u, err := h.managed.CreateUnit(ctx, app.UnitInput{
		DeviceGroupID: req.Body.DeviceGroupId, Unit: &req.Body.Unit, Enabled: req.Body.Enabled, Active: req.Body.Active,
	})
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/managed-units/" + u.ID.String()
	return adminapi.CreateManagedUnit201JSONResponse{
		Body: toManagedUnit(u), Headers: adminapi.CreateManagedUnit201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetManagedUnit(ctx context.Context, req adminapi.GetManagedUnitRequestObject) (adminapi.GetManagedUnitResponseObject, error) {
	u, err := h.managed.GetUnit(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetManagedUnit200JSONResponse(toManagedUnit(u)), nil
}

func (h *handlers) UpdateManagedUnit(ctx context.Context, req adminapi.UpdateManagedUnitRequestObject) (adminapi.UpdateManagedUnitResponseObject, error) {
	u, err := h.managed.UpdateUnit(ctx, req.Id, app.UnitInput{Unit: req.Body.Unit, Enabled: req.Body.Enabled, Active: req.Body.Active})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateManagedUnit200JSONResponse(toManagedUnit(u)), nil
}

func (h *handlers) DeleteManagedUnit(ctx context.Context, req adminapi.DeleteManagedUnitRequestObject) (adminapi.DeleteManagedUnitResponseObject, error) {
	if err := h.managed.DeleteUnit(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteManagedUnit204Response{}, nil
}

func toManagedUnit(u pgstore.ManagedUnit) adminapi.ManagedUnit {
	return adminapi.ManagedUnit{
		Id: u.ID, DeviceGroupId: idPtr(u.DeviceGroupID), Unit: u.Unit, Enabled: u.Enabled, Active: u.Active,
		CreatedAt: u.CreatedAt.UTC(), UpdatedAt: u.UpdatedAt.UTC(),
	}
}
