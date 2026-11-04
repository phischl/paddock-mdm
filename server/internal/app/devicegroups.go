package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicegroup"
	"github.com/phischl/paddock-mdm/server/internal/domain/disk"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/domain/updates"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
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

// GroupStaleness is a device group's override of the contact thresholds, in hours (plan M8d decision 11).
type GroupStaleness struct {
	WarningH, CriticalH int
}

// DeviceGroupPolicy are the policy overrides of a device group (plan M8d decision 11); a nil field inherits the
// organization's setting.
type DeviceGroupPolicy struct {
	Staleness         *GroupStaleness
	AgentUpdatePolicy *string
	DiskUnlockMode    *string
}

// Change is one field of a partial update: Set false keeps the stored value, Set with a nil Value clears it.
type Change[T any] struct {
	Set   bool
	Value *T
}

// DeviceGroupPolicyPatch changes some policy overrides of a device group.
type DeviceGroupPolicyPatch struct {
	Staleness         Change[GroupStaleness]
	AgentUpdatePolicy Change[string]
	DiskUnlockMode    Change[string]
}

// PolicyOf returns the stored policy overrides of a device group.
func PolicyOf(g pgstore.DeviceGroup) DeviceGroupPolicy {
	var p DeviceGroupPolicy
	if g.StalenessWarningH != nil && g.StalenessCriticalH != nil {
		p.Staleness = &GroupStaleness{WarningH: int(*g.StalenessWarningH), CriticalH: int(*g.StalenessCriticalH)}
	}
	p.AgentUpdatePolicy, p.DiskUnlockMode = g.AgentUpdatePolicy, g.DiskUnlockMode
	return p
}

func (p DeviceGroupPolicyPatch) apply(old DeviceGroupPolicy) DeviceGroupPolicy {
	if p.Staleness.Set {
		old.Staleness = p.Staleness.Value
	}
	if p.AgentUpdatePolicy.Set {
		old.AgentUpdatePolicy = p.AgentUpdatePolicy.Value
	}
	if p.DiskUnlockMode.Set {
		old.DiskUnlockMode = p.DiskUnlockMode.Value
	}
	return old
}

// validate checks the overrides with the bounds of the organization's settings; the message names the field.
func (p DeviceGroupPolicy) validate() error {
	if s := p.Staleness; s != nil {
		if err := updates.ValidateThresholds("staleness.", s.WarningH, s.CriticalH); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
	}
	if p.AgentUpdatePolicy != nil && !updates.ValidUpdatePolicy(*p.AgentUpdatePolicy) {
		return problem.InvalidRequest.WithDetail("agent_update_policy must be automatic or manual")
	}
	if p.DiskUnlockMode != nil && !disk.ValidUnlockMode(*p.DiskUnlockMode) {
		return problem.InvalidRequest.WithDetail("disk_unlock_mode must be tpm_pin or tpm_only")
	}
	return nil
}

// record sets the policy params of device_group.created and device_group.updated (null when unset).
func (p DeviceGroupPolicy) record(rec Recorder) {
	var warning, critical any
	if p.Staleness != nil {
		warning, critical = p.Staleness.WarningH, p.Staleness.CriticalH
	}
	rec.SetParam("staleness_warning_h", warning)
	rec.SetParam("staleness_critical_h", critical)
	rec.SetParam("agent_update_policy", nullableParam(p.AgentUpdatePolicy))
	rec.SetParam("disk_unlock_mode", nullableParam(p.DiskUnlockMode))
}

func nullableParam(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// store writes the overrides of a device group.
func (p DeviceGroupPolicy) store(ctx context.Context, q *pgstore.Queries, id uuid.UUID) (pgstore.DeviceGroup, error) {
	params := pgstore.SetDeviceGroupPoliciesParams{ID: id, AgentUpdatePolicy: p.AgentUpdatePolicy, DiskUnlockMode: p.DiskUnlockMode}
	if s := p.Staleness; s != nil {
		w, c := int32(s.WarningH), int32(s.CriticalH) //nolint:gosec // validated: at most 2160
		params.StalenessWarningH, params.StalenessCriticalH = &w, &c
	}
	return q.SetDeviceGroupPolicies(ctx, params)
}

// bundleRelevant reports whether a change of the overrides changes what the compiler renders for the members: the
// agent update policy and the disk unlock mode are bundle fields, the thresholds are read by the worker.
func (p DeviceGroupPolicy) bundleRelevant(old DeviceGroupPolicy) bool {
	return !equalPtr(p.AgentUpdatePolicy, old.AgentUpdatePolicy) || !equalPtr(p.DiskUnlockMode, old.DiskUnlockMode)
}

func equalPtr(a, b *string) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// List returns one page of device groups and the capped number of matches (ADR 0018).
func (d *DeviceGroups) List(ctx context.Context, page ListPage) (Listed[pgstore.DeviceGroup], error) {
	var out Listed[pgstore.DeviceGroup]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountDeviceGroups(ctx, pgstore.CountDeviceGroupsParams{QPattern: page.QPattern, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count device groups: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListDeviceGroups(ctx, pgstore.ListDeviceGroupsParams{
			QPattern: page.QPattern, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list device groups: %w", err)
		}
		return nil
	})
	return out, err
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

// Create creates a device group with its policy overrides (audited: device_group.created).
func (d *DeviceGroups) Create(ctx context.Context, name string, description *string, policy DeviceGroupPolicy) (pgstore.DeviceGroup, error) {
	var g pgstore.DeviceGroup
	spec := SpecDeviceGroupCreate
	spec.Params = map[string]any{"name": name}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		name := devicegroup.NormalizeName(name)
		desc := ""
		if description != nil {
			desc = strings.TrimSpace(*description)
		}
		rec.SetParam("name", name)
		policy.record(rec)
		if err := validateGroup(name, desc); err != nil {
			return err
		}
		if err := policy.validate(); err != nil {
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
		g, err = policy.store(ctx, q, g.ID)
		return err
	}))
	return g, err
}

// Update renames a device group, changes its description or its policy overrides (audited: device_group.updated). A
// change of the agent update policy or the disk unlock mode recompiles the members.
func (d *DeviceGroups) Update(ctx context.Context, id uuid.UUID, name, description *string, patch DeviceGroupPolicyPatch) (pgstore.DeviceGroup, error) {
	var g pgstore.DeviceGroup
	spec := SpecDeviceGroupUpdate
	spec.Target = &audit.Target{Type: "device_group", ID: id.String()}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
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
		oldPolicy := PolicyOf(old)
		policy := patch.apply(oldPolicy)
		policy.record(rec)
		if err := validateGroup(newName, newDesc); err != nil {
			return err
		}
		if err := policy.validate(); err != nil {
			return err
		}
		if _, err = q.UpdateDeviceGroup(ctx, pgstore.UpdateDeviceGroupParams{ID: id, Name: newName, Description: newDesc}); err != nil {
			if db.IsUniqueViolation(err, "device_group_organization_id_name_key") {
				return problem.NameTaken.WithDetail("a device group with this name exists")
			}
			return notFound(err)
		}
		if g, err = policy.store(ctx, q, id); err != nil {
			return err
		}
		if policy.bundleRelevant(oldPolicy) {
			rec.StateChanged(statechange.ScopeDeviceGroup, id)
		}
		return nil
	}))
	return g, err
}

// Delete deletes a device group (audited: device_group.deleted).
func (d *DeviceGroups) Delete(ctx context.Context, id uuid.UUID) error {
	spec := SpecDeviceGroupDelete
	spec.Target = &audit.Target{Type: "device_group", ID: id.String()}
	return d.runner.RunTx(ctx, ScopeOrg, spec, withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		// A cascading delete serializes with the changes the root-grant guards compare (plan M8s decision 7g-bis).
		if err := q.LockOrganizationPrivileges(ctx); err != nil {
			return err
		}
		old, err := q.GetDeviceGroup(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: id.String(), Display: old.Name})
		rec.SetParam("name", old.Name)
		if err := q.DetachInactiveEnrollmentTokens(ctx, uuid.NullUUID{UUID: id, Valid: true}); err != nil {
			return err
		}
		n, err := q.DeleteDeviceGroup(ctx, id)
		if db.IsForeignKeyViolation(err) {
			return problem.InUse.WithDetail("an enrollment token still assigns devices to this group")
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		// Memberships and group-scoped definitions are gone with the group; recompile the organization.
		rec.StateChanged(statechange.ScopeOrg, old.OrganizationID)
		return nil
	}))
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
