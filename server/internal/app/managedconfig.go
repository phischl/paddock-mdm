package app

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/policy"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/managedconfig"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// ManagedConfig are the use cases of managed files and systemd units (plan M2a decisions 7 and 8).
type ManagedConfig struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewManagedConfig creates the use cases.
func NewManagedConfig(runner *ActionRunner, org *db.OrgPool) *ManagedConfig {
	return &ManagedConfig{runner: runner, org: org}
}

// Specs of the privileged managed configuration actions.
var (
	SpecManagedFileCreate = ActionSpec{Code: audit.CodeManagedFileCreated, AllowedRoles: RolesWrite}
	SpecManagedFileUpdate = ActionSpec{Code: audit.CodeManagedFileUpdated, AllowedRoles: RolesWrite}
	SpecManagedFileDelete = ActionSpec{Code: audit.CodeManagedFileDeleted, AllowedRoles: RolesWrite}
	SpecManagedUnitCreate = ActionSpec{Code: audit.CodeManagedUnitCreated, AllowedRoles: RolesWrite}
	SpecManagedUnitUpdate = ActionSpec{Code: audit.CodeManagedUnitUpdated, AllowedRoles: RolesWrite}
	SpecManagedUnitDelete = ActionSpec{Code: audit.CodeManagedUnitDeleted, AllowedRoles: RolesWrite}
)

// ManagedQuery selects a page of managed files or units.
type ManagedQuery struct {
	Page    ListPage
	GroupID *uuid.UUID
}

// ListFiles returns one page of managed files.
func (m *ManagedConfig) ListFiles(ctx context.Context, query ManagedQuery) (Listed[pgstore.ManagedFile], error) {
	var out Listed[pgstore.ManagedFile]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := m.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		group := nullID(query.GroupID)
		n, err := q.CountManagedFiles(ctx, pgstore.CountManagedFilesParams{QPattern: query.Page.QPattern, DeviceGroupID: group, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count managed files: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListManagedFiles(ctx, pgstore.ListManagedFilesParams{
			QPattern: query.Page.QPattern, DeviceGroupID: group, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		return err
	})
	return out, err
}

// GetFile returns one managed file.
func (m *ManagedConfig) GetFile(ctx context.Context, id uuid.UUID) (pgstore.ManagedFile, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.ManagedFile{}, err
	}
	var f pgstore.ManagedFile
	err := m.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		f, err = q.GetManagedFile(ctx, id)
		return notFound(err)
	})
	return f, err
}

// FileInput are the fields of a managed file; nil keeps the current value on update (Path, Mode, Owner, Group,
// Content) or means "organization-wide" on create (DeviceGroupID).
type FileInput struct {
	DeviceGroupID *uuid.UUID
	Path          *string
	Mode          *string
	Owner         *string
	Group         *string
	Content       *string
}

// CreateFile defines a managed file (audited: managed_file.created).
func (m *ManagedConfig) CreateFile(ctx context.Context, in FileInput) (pgstore.ManagedFile, error) {
	var f pgstore.ManagedFile
	spec := SpecManagedFileCreate
	spec.Params = map[string]any{"path": deref(in.Path, ""), "device_group_id": idParam(in.DeviceGroupID)}
	err := m.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		next := pgstore.ManagedFile{
			Path: deref(in.Path, ""), Mode: deref(in.Mode, "0644"), Owner: deref(in.Owner, "root"),
			Grp: deref(in.Group, "root"), Content: deref(in.Content, ""),
		}
		recordFile(rec, next, in.DeviceGroupID)
		if err := validateFile(next); err != nil {
			return err
		}
		if err := requireGroups(ctx, q, optionalID(in.DeviceGroupID)); err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		f, err = q.InsertManagedFile(ctx, pgstore.InsertManagedFileParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, DeviceGroupID: nullID(in.DeviceGroupID), Path: next.Path,
			Mode: next.Mode, Owner: next.Owner, Grp: next.Grp, Content: next.Content,
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("this path is already managed in this scope")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "managed_file", ID: f.ID.String(), Display: f.Path})
		stateChangedFor(rec, f.OrganizationID, f.DeviceGroupID)
		return nil
	})
	return f, err
}

// UpdateFile changes a managed file; its scope is fixed (audited: managed_file.updated).
func (m *ManagedConfig) UpdateFile(ctx context.Context, id uuid.UUID, in FileInput) (pgstore.ManagedFile, error) {
	var f pgstore.ManagedFile
	spec := SpecManagedFileUpdate
	spec.Target = &audit.Target{Type: "managed_file", ID: id.String()}
	err := m.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetManagedFile(ctx, id)
		if err != nil {
			return notFound(err)
		}
		next := old
		next.Path, next.Mode, next.Owner = deref(in.Path, old.Path), deref(in.Mode, old.Mode), deref(in.Owner, old.Owner)
		next.Grp, next.Content = deref(in.Group, old.Grp), deref(in.Content, old.Content)
		rec.SetTarget(audit.Target{Type: "managed_file", ID: id.String(), Display: next.Path})
		recordFile(rec, next, groupPtr(old.DeviceGroupID))
		rec.SetParam("content_changed", next.Content != old.Content)
		if next.Path != old.Path {
			rec.SetParam("old_path", old.Path)
		}
		if err := validateFile(next); err != nil {
			return err
		}
		f, err = q.UpdateManagedFile(ctx, pgstore.UpdateManagedFileParams{
			ID: id, Path: next.Path, Mode: next.Mode, Owner: next.Owner, Grp: next.Grp, Content: next.Content,
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("this path is already managed in this scope")
		}
		if err != nil {
			return notFound(err)
		}
		stateChangedFor(rec, f.OrganizationID, f.DeviceGroupID)
		return nil
	})
	return f, err
}

// DeleteFile deletes a managed file definition (audited: managed_file.deleted).
func (m *ManagedConfig) DeleteFile(ctx context.Context, id uuid.UUID) error {
	spec := SpecManagedFileDelete
	spec.Target = &audit.Target{Type: "managed_file", ID: id.String()}
	return m.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetManagedFile(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "managed_file", ID: id.String(), Display: old.Path})
		rec.SetParam("path", old.Path)
		rec.SetParam("device_group_id", idParam(groupPtr(old.DeviceGroupID)))
		if _, err := q.DeleteManagedFile(ctx, id); err != nil {
			return err
		}
		stateChangedFor(rec, old.OrganizationID, old.DeviceGroupID)
		return nil
	})
}

func recordFile(rec Recorder, f pgstore.ManagedFile, group *uuid.UUID) {
	rec.SetParam("path", f.Path)
	rec.SetParam("device_group_id", idParam(group))
	rec.SetParam("mode", f.Mode)
	rec.SetParam("owner", f.Owner)
	rec.SetParam("group", f.Grp)
}

func validateFile(f pgstore.ManagedFile) error {
	if err := policy.ValidatePath(f.Path); err != nil {
		return problem.PathNotAllowed.WithDetail(err.Error())
	}
	for _, err := range []error{
		policy.ValidateMode(f.Mode), policy.ValidateOwner(f.Owner), policy.ValidateOwner(f.Grp),
		managedconfig.ValidateContent(f.Content),
	} {
		if err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
	}
	return nil
}

// ListUnits returns one page of managed units.
func (m *ManagedConfig) ListUnits(ctx context.Context, query ManagedQuery) (Listed[pgstore.ManagedUnit], error) {
	var out Listed[pgstore.ManagedUnit]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := m.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		group := nullID(query.GroupID)
		n, err := q.CountManagedUnits(ctx, pgstore.CountManagedUnitsParams{QPattern: query.Page.QPattern, DeviceGroupID: group, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count managed units: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListManagedUnits(ctx, pgstore.ListManagedUnitsParams{
			QPattern: query.Page.QPattern, DeviceGroupID: group, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		return err
	})
	return out, err
}

// GetUnit returns one managed unit.
func (m *ManagedConfig) GetUnit(ctx context.Context, id uuid.UUID) (pgstore.ManagedUnit, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.ManagedUnit{}, err
	}
	var u pgstore.ManagedUnit
	err := m.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		u, err = q.GetManagedUnit(ctx, id)
		return notFound(err)
	})
	return u, err
}

// UnitInput are the fields of a managed unit; nil keeps the current value on update.
type UnitInput struct {
	DeviceGroupID *uuid.UUID
	Unit          *string
	Enabled       *bool
	Active        *bool
}

// CreateUnit defines a managed systemd unit (audited: managed_unit.created).
func (m *ManagedConfig) CreateUnit(ctx context.Context, in UnitInput) (pgstore.ManagedUnit, error) {
	var u pgstore.ManagedUnit
	spec := SpecManagedUnitCreate
	spec.Params = map[string]any{"unit": deref(in.Unit, ""), "device_group_id": idParam(in.DeviceGroupID)}
	err := m.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		next := pgstore.ManagedUnit{Unit: deref(in.Unit, ""), Enabled: deref(in.Enabled, true), Active: deref(in.Active, true)}
		recordUnit(rec, next, in.DeviceGroupID)
		if err := policy.ValidateUnit(next.Unit); err != nil {
			return problem.UnitNotAllowed.WithDetail(err.Error())
		}
		if err := requireGroups(ctx, q, optionalID(in.DeviceGroupID)); err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		u, err = q.InsertManagedUnit(ctx, pgstore.InsertManagedUnitParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, DeviceGroupID: nullID(in.DeviceGroupID), Unit: next.Unit,
			Enabled: next.Enabled, Active: next.Active,
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("this unit is already managed in this scope")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "managed_unit", ID: u.ID.String(), Display: u.Unit})
		stateChangedFor(rec, u.OrganizationID, u.DeviceGroupID)
		return nil
	})
	return u, err
}

// UpdateUnit changes a managed unit; its scope is fixed (audited: managed_unit.updated).
func (m *ManagedConfig) UpdateUnit(ctx context.Context, id uuid.UUID, in UnitInput) (pgstore.ManagedUnit, error) {
	var u pgstore.ManagedUnit
	spec := SpecManagedUnitUpdate
	spec.Target = &audit.Target{Type: "managed_unit", ID: id.String()}
	err := m.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetManagedUnit(ctx, id)
		if err != nil {
			return notFound(err)
		}
		next := pgstore.ManagedUnit{Unit: deref(in.Unit, old.Unit), Enabled: deref(in.Enabled, old.Enabled), Active: deref(in.Active, old.Active)}
		rec.SetTarget(audit.Target{Type: "managed_unit", ID: id.String(), Display: next.Unit})
		recordUnit(rec, next, groupPtr(old.DeviceGroupID))
		if next.Unit != old.Unit {
			rec.SetParam("old_unit", old.Unit)
		}
		if err := policy.ValidateUnit(next.Unit); err != nil {
			return problem.UnitNotAllowed.WithDetail(err.Error())
		}
		u, err = q.UpdateManagedUnit(ctx, pgstore.UpdateManagedUnitParams{ID: id, Unit: next.Unit, Enabled: next.Enabled, Active: next.Active})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("this unit is already managed in this scope")
		}
		if err != nil {
			return notFound(err)
		}
		stateChangedFor(rec, u.OrganizationID, u.DeviceGroupID)
		return nil
	})
	return u, err
}

// DeleteUnit deletes a managed unit definition (audited: managed_unit.deleted).
func (m *ManagedConfig) DeleteUnit(ctx context.Context, id uuid.UUID) error {
	spec := SpecManagedUnitDelete
	spec.Target = &audit.Target{Type: "managed_unit", ID: id.String()}
	return m.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetManagedUnit(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "managed_unit", ID: id.String(), Display: old.Unit})
		rec.SetParam("unit", old.Unit)
		rec.SetParam("device_group_id", idParam(groupPtr(old.DeviceGroupID)))
		if _, err := q.DeleteManagedUnit(ctx, id); err != nil {
			return err
		}
		stateChangedFor(rec, old.OrganizationID, old.DeviceGroupID)
		return nil
	})
}

func recordUnit(rec Recorder, u pgstore.ManagedUnit, group *uuid.UUID) {
	rec.SetParam("unit", u.Unit)
	rec.SetParam("device_group_id", idParam(group))
	rec.SetParam("enabled", u.Enabled)
	rec.SetParam("active", u.Active)
}

// stateChangedFor queues a recompile of the definition's scope: its device group or the whole organization.
func stateChangedFor(rec Recorder, org uuid.UUID, group uuid.NullUUID) {
	if group.Valid {
		rec.StateChanged(statechange.ScopeDeviceGroup, group.UUID)
		return
	}
	rec.StateChanged(statechange.ScopeOrg, org)
}

func deref[T any](v *T, def T) T {
	if v == nil {
		return def
	}
	return *v
}

// idParam is the audit form of an optional ID: the ID or nil (organization-wide).
func idParam(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id.String()
}
