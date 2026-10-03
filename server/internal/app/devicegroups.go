package app

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/devicegroup"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// DeviceGroups are the device group use cases.
type DeviceGroups struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewDeviceGroups creates the use cases.
func NewDeviceGroups(runner *ActionRunner, org *db.OrgPool) *DeviceGroups {
	return &DeviceGroups{runner: runner, org: org}
}

// Specs of the privileged device group actions (shared with the transport for rejected requests).
var (
	SpecDeviceGroupCreate = ActionSpec{Code: audit.CodeDeviceGroupCreated, AllowedRoles: RolesWrite}
	SpecDeviceGroupUpdate = ActionSpec{Code: audit.CodeDeviceGroupUpdated, AllowedRoles: RolesWrite}
	SpecDeviceGroupDelete = ActionSpec{Code: audit.CodeDeviceGroupDeleted, AllowedRoles: RolesAdmin}
)

// DeviceGroupPage is one page of device groups.
type DeviceGroupPage struct {
	Items      []pgstore.DeviceGroup
	NextCursor *string
}

// List returns one page, newest first.
func (d *DeviceGroups) List(ctx context.Context, cursor *string, limit *int) (DeviceGroupPage, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return DeviceGroupPage{}, err
	}
	before, err := DecodeCursor(cursor)
	if err != nil {
		return DeviceGroupPage{}, err
	}
	n, err := PageLimit(limit)
	if err != nil {
		return DeviceGroupPage{}, err
	}
	var page DeviceGroupPage
	err = d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.ListDeviceGroups(ctx, pgstore.ListDeviceGroupsParams{Before: before, MaxRows: n + 1})
		if err != nil {
			return err
		}
		if len(rows) > int(n) {
			rows = rows[:n]
			c := EncodeCursor(rows[len(rows)-1].ID)
			page.NextCursor = &c
		}
		page.Items = rows
		return nil
	})
	return page, err
}

// Get returns one device group; missing and foreign groups are both not_found.
func (d *DeviceGroups) Get(ctx context.Context, id uuid.UUID) (pgstore.DeviceGroup, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.DeviceGroup{}, err
	}
	var g pgstore.DeviceGroup
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		g, err = q.GetDeviceGroup(ctx, id)
		return notFound(err)
	})
	return g, err
}

// Create creates a device group (audited: device_group.created).
func (d *DeviceGroups) Create(ctx context.Context, name string, description *string) (pgstore.DeviceGroup, error) {
	var g pgstore.DeviceGroup
	spec := SpecDeviceGroupCreate
	spec.Params = map[string]any{"name": name}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		name := devicegroup.NormalizeName(name)
		desc := ""
		if description != nil {
			desc = strings.TrimSpace(*description)
		}
		rec.SetParam("name", name)
		if err := validateGroup(name, desc); err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		g, err = q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Name: name, Description: desc,
		})
		if db.IsUniqueViolation(err, "device_group_organization_id_name_key") {
			return problem.NameTaken.WithDetail("a device group with this name exists")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: g.ID.String(), Display: g.Name})
		return nil
	})
	return g, err
}

// Update renames a device group or changes its description (audited: device_group.updated).
func (d *DeviceGroups) Update(ctx context.Context, id uuid.UUID, name, description *string) (pgstore.DeviceGroup, error) {
	var g pgstore.DeviceGroup
	spec := SpecDeviceGroupUpdate
	spec.Target = &audit.Target{Type: "device_group", ID: id.String()}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetDeviceGroup(ctx, id)
		if err != nil {
			return notFound(err)
		}
		newName, newDesc := old.Name, old.Description
		if name != nil {
			newName = devicegroup.NormalizeName(*name)
		}
		if description != nil {
			newDesc = strings.TrimSpace(*description)
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: id.String(), Display: newName})
		rec.SetParam("name", newName)
		if newName != old.Name {
			rec.SetParam("old_name", old.Name)
		}
		rec.SetParam("description_changed", newDesc != old.Description)
		if err := validateGroup(newName, newDesc); err != nil {
			return err
		}
		g, err = q.UpdateDeviceGroup(ctx, pgstore.UpdateDeviceGroupParams{ID: id, Name: newName, Description: newDesc})
		if db.IsUniqueViolation(err, "device_group_organization_id_name_key") {
			return problem.NameTaken.WithDetail("a device group with this name exists")
		}
		return notFound(err)
	})
	return g, err
}

// Delete deletes a device group (audited: device_group.deleted).
func (d *DeviceGroups) Delete(ctx context.Context, id uuid.UUID) error {
	spec := SpecDeviceGroupDelete
	spec.Target = &audit.Target{Type: "device_group", ID: id.String()}
	return d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetDeviceGroup(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: id.String(), Display: old.Name})
		rec.SetParam("name", old.Name)
		n, err := q.DeleteDeviceGroup(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		return nil
	})
}

func validateGroup(name, description string) error {
	if err := devicegroup.ValidateName(name); err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	if err := devicegroup.ValidateDescription(description); err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	return nil
}

// notFound maps "no row" (missing or hidden by RLS) to not_found.
func notFound(err error) error {
	if db.IsNoRows(err) {
		return problem.NotFound
	}
	return err
}
