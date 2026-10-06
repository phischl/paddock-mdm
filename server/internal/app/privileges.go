package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Privileges are the use cases of permission profiles, their assignments and the effective profiles (plan M3a
// decisions 12–14).
type Privileges struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewPrivileges creates the use cases.
func NewPrivileges(runner *ActionRunner, org *db.OrgPool) *Privileges {
	return &Privileges{runner: runner, org: org}
}

// Specs of the privileged profile actions.
var (
	SpecProfileCreate    = ActionSpec{Code: audit.CodePermissionProfileCreated, AllowedRoles: RolesWrite}
	SpecProfileUpdate    = ActionSpec{Code: audit.CodePermissionProfileUpdated, AllowedRoles: RolesWrite}
	SpecProfileDelete    = ActionSpec{Code: audit.CodePermissionProfileDeleted, AllowedRoles: RolesWrite}
	SpecAssignmentCreate = ActionSpec{Code: audit.CodeProfileAssignmentCreated, AllowedRoles: RolesWrite}
	SpecAssignmentUpdate = ActionSpec{Code: audit.CodeProfileAssignmentUpdated, AllowedRoles: RolesWrite}
	SpecAssignmentDelete = ActionSpec{Code: audit.CodeProfileAssignmentDeleted, AllowedRoles: RolesWrite}
)

// ListProfiles returns one page of permission profiles.
func (p *Privileges) ListProfiles(ctx context.Context, page ListPage, classes []string) (Listed[pgstore.PermissionProfile], error) {
	var out Listed[pgstore.PermissionProfile]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountPermissionProfiles(ctx, pgstore.CountPermissionProfilesParams{QPattern: page.QPattern, Classes: classes, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count profiles: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListPermissionProfiles(ctx, pgstore.ListPermissionProfilesParams{
			QPattern: page.QPattern, Classes: classes, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list profiles: %w", err)
		}
		return nil
	})
	return out, err
}

// GetProfile returns one permission profile.
func (p *Privileges) GetProfile(ctx context.Context, id uuid.UUID) (pgstore.PermissionProfile, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.PermissionProfile{}, err
	}
	var out pgstore.PermissionProfile
	err := p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetPermissionProfile(ctx, id)
		return notFound(err)
	})
	return out, err
}

// validProfile normalizes and validates a profile; an invalid command is 422 invalid_command.
func validProfile(in privilege.Profile) (privilege.Profile, error) {
	in = privilege.NormalizeProfile(in)
	err := privilege.ValidateProfile(in)
	switch {
	case errors.Is(err, privilege.ErrInvalidCommand):
		return in, problem.InvalidCommand.WithDetail(err.Error())
	case err != nil:
		return in, problem.InvalidRequest.WithDetail(err.Error())
	}
	if in.Commands == nil {
		in.Commands = []string{}
	}
	return in, nil
}

func profileParams(rec Recorder, in privilege.Profile) {
	rec.SetParam("name", in.Name)
	rec.SetParam("class", string(in.Class))
	rec.SetParam("commands", in.Commands)
	rec.SetParam("root_equivalent", len(privilege.RootEquivalentCommands(in.Commands)) > 0)
}

// CreateProfile creates a permission profile (audited: permission_profile.created).
func (p *Privileges) CreateProfile(ctx context.Context, in privilege.Profile) (pgstore.PermissionProfile, error) {
	var out pgstore.PermissionProfile
	err := p.runner.RunTx(ctx, ScopeOrg, SpecProfileCreate, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		in, err := validProfile(in)
		profileParams(rec, in)
		if err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		out, err = q.InsertPermissionProfile(ctx, pgstore.InsertPermissionProfileParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Name: in.Name, Class: string(in.Class), Commands: in.Commands,
			RequirePassword: in.RequirePassword, TimestampTimeoutMin: int32(in.TimestampTimeoutMin), //nolint:gosec // validated 0–60
			Lecture: string(in.Lecture),
		})
		if db.IsUniqueViolation(err, "permission_profile_organization_id_name_key") {
			return problem.NameTaken.WithDetail("a permission profile with this name exists")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "permission_profile", ID: out.ID.String(), Display: out.Name})
		return nil
	})
	return out, err
}

// ProfilePatch changes the given fields of a profile; nil fields stay.
type ProfilePatch struct {
	Name                *string
	Class               *privilege.Class
	Commands            *[]string
	RequirePassword     *bool
	TimestampTimeoutMin *int
	Lecture             *privilege.Lecture
}

func (pp ProfilePatch) apply(p privilege.Profile) privilege.Profile {
	p.Name = deref(pp.Name, p.Name)
	p.Class = deref(pp.Class, p.Class)
	p.Commands = deref(pp.Commands, p.Commands)
	if pp.Class != nil && *pp.Class != privilege.ClassRestricted && pp.Commands == nil {
		p.Commands = nil // none and full profiles have no commands
	}
	p.RequirePassword = deref(pp.RequirePassword, p.RequirePassword)
	p.TimestampTimeoutMin = deref(pp.TimestampTimeoutMin, p.TimestampTimeoutMin)
	p.Lecture = deref(pp.Lecture, p.Lecture)
	return p
}

// UpdateProfile changes a permission profile (audited: permission_profile.updated) and recompiles the organization.
// Changing the class to full requires a step-up (plan M4a decision 7).
func (p *Privileges) UpdateProfile(ctx context.Context, id uuid.UUID, patch ProfilePatch) (pgstore.PermissionProfile, error) {
	spec := SpecProfileUpdate
	spec.Target = &audit.Target{Type: "permission_profile", ID: id.String()}
	var out pgstore.PermissionProfile
	err := p.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.GetPermissionProfile(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetParam("old_class", cur.Class)
		in, err := validProfile(patch.apply(profileOf(cur)))
		profileParams(rec, in)
		rec.SetTarget(audit.Target{Type: "permission_profile", ID: id.String(), Display: in.Name})
		if err != nil {
			return err
		}
		if in.Class == privilege.ClassFull && cur.Class != string(privilege.ClassFull) {
			if err := rec.RequireStepUp(); err != nil {
				return err
			}
		}
		out, err = q.UpdatePermissionProfile(ctx, pgstore.UpdatePermissionProfileParams{
			ID: id, Name: in.Name, Class: string(in.Class), Commands: in.Commands, RequirePassword: in.RequirePassword,
			TimestampTimeoutMin: int32(in.TimestampTimeoutMin), Lecture: string(in.Lecture), //nolint:gosec // validated 0–60
		})
		if db.IsUniqueViolation(err, "permission_profile_organization_id_name_key") {
			return problem.NameTaken.WithDetail("a permission profile with this name exists")
		}
		if err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, cur.OrganizationID)
		return nil
	})
	return out, err
}

// DeleteProfile deletes a profile without assignments (audited: permission_profile.deleted); a profile that is
// still assigned is 409 in_use.
func (p *Privileges) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	spec := SpecProfileDelete
	spec.Target = &audit.Target{Type: "permission_profile", ID: id.String()}
	return p.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.GetPermissionProfile(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "permission_profile", ID: id.String(), Display: cur.Name})
		rec.SetParam("name", cur.Name)
		rec.SetParam("class", cur.Class)
		if _, err := q.DeletePermissionProfile(ctx, id); db.IsForeignKeyViolation(err) {
			return problem.InUse.WithDetail("the profile is still assigned; remove its assignments first")
		} else if err != nil {
			return err
		}
		return nil
	})
}

// AssignmentQuery selects a page of profile assignments.
type AssignmentQuery struct {
	Page          ListPage
	ProfileID     *uuid.UUID
	SubjectTypes  []string
	SubjectID     *uuid.UUID
	DeviceGroupID *uuid.UUID
}

// ListAssignments returns one page of profile assignments.
func (p *Privileges) ListAssignments(ctx context.Context, query AssignmentQuery) (Listed[pgstore.ProfileAssignment], error) {
	var out Listed[pgstore.ProfileAssignment]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountProfileAssignments(ctx, pgstore.CountProfileAssignmentsParams{
			QPattern: query.Page.QPattern, ProfileID: nullID(query.ProfileID), SubjectTypes: query.SubjectTypes,
			SubjectID: nullID(query.SubjectID), DeviceGroupID: nullID(query.DeviceGroupID), CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count assignments: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListProfileAssignments(ctx, pgstore.ListProfileAssignmentsParams{
			QPattern: query.Page.QPattern, ProfileID: nullID(query.ProfileID), SubjectTypes: query.SubjectTypes,
			SubjectID: nullID(query.SubjectID), DeviceGroupID: nullID(query.DeviceGroupID), Sort: query.Page.Sort,
			SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list assignments: %w", err)
		}
		return nil
	})
	return out, err
}

// GetAssignment returns one profile assignment.
func (p *Privileges) GetAssignment(ctx context.Context, id uuid.UUID) (pgstore.ProfileAssignment, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.ProfileAssignment{}, err
	}
	var out pgstore.ProfileAssignment
	err := p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetProfileAssignment(ctx, id)
		return notFound(err)
	})
	return out, err
}

// NewAssignment is an assignment to create.
type NewAssignment struct {
	ProfileID     uuid.UUID
	SubjectType   privilege.SubjectType
	SubjectID     *uuid.UUID
	DeviceGroupID *uuid.UUID
}

// CreateAssignment assigns a profile (audited: profile_assignment.created) and recompiles the organization.
// Assigning a full profile requires a step-up (plan M4a decision 7).
func (p *Privileges) CreateAssignment(ctx context.Context, in NewAssignment) (pgstore.ProfileAssignment, error) {
	var out pgstore.ProfileAssignment
	err := p.runner.RunTx(ctx, ScopeOrg, SpecAssignmentCreate, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		subject := uuid.Nil
		if in.SubjectID != nil {
			subject = *in.SubjectID
		}
		rec.SetParam("subject_type", string(in.SubjectType))
		rec.SetParam("subject_id", idParam(in.SubjectID))
		rec.SetParam("device_group_id", idParam(in.DeviceGroupID))
		profile, err := q.GetPermissionProfile(ctx, in.ProfileID)
		if err != nil {
			return problem.InvalidRequest.WithDetail("unknown permission profile")
		}
		assignmentProfileParams(rec, profile)
		if profile.Class == string(privilege.ClassFull) {
			if err := rec.RequireStepUp(); err != nil {
				return err
			}
		}
		if err := privilege.ValidateAssignmentSubject(in.SubjectType, subject); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if err := requireSubject(ctx, q, in.SubjectType, subject); err != nil {
			return err
		}
		if in.DeviceGroupID != nil {
			if _, err := q.GetDeviceGroup(ctx, *in.DeviceGroupID); err != nil {
				return problem.InvalidRequest.WithDetail("unknown device group")
			}
		}
		out, err = q.InsertProfileAssignment(ctx, pgstore.InsertProfileAssignmentParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: profile.OrganizationID, ProfileID: profile.ID,
			SubjectType: string(in.SubjectType), SubjectID: nullID(in.SubjectID), DeviceGroupID: nullID(in.DeviceGroupID),
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("the profile is already assigned to this subject and scope")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "profile_assignment", ID: out.ID.String(), Display: profile.Name})
		rec.StateChanged(statechange.ScopeOrg, profile.OrganizationID)
		return nil
	})
	return out, err
}

func assignmentProfileParams(rec Recorder, profile pgstore.PermissionProfile) {
	rec.SetParam("profile", profile.Name)
	rec.SetParam("class", profile.Class)
	rec.SetParam("root_equivalent", len(privilege.RootEquivalentCommands(profile.Commands)) > 0)
}

// requireSubject checks that a group or user subject exists in the organization.
func requireSubject(ctx context.Context, q *pgstore.Queries, t privilege.SubjectType, id uuid.UUID) error {
	var err error
	switch t {
	case privilege.SubjectGroup:
		_, err = q.GetUserGroup(ctx, id)
	case privilege.SubjectUser:
		_, err = q.GetAppUser(ctx, id)
	}
	if db.IsNoRows(err) {
		return problem.InvalidRequest.WithDetail("unknown " + string(t))
	}
	return err
}

// UpdateAssignmentScope changes the device group scope of an assignment (audited: profile_assignment.updated).
func (p *Privileges) UpdateAssignmentScope(ctx context.Context, id uuid.UUID, deviceGroupID *uuid.UUID) (pgstore.ProfileAssignment, error) {
	spec := SpecAssignmentUpdate
	spec.Target = &audit.Target{Type: "profile_assignment", ID: id.String()}
	var out pgstore.ProfileAssignment
	err := p.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, profile, err := loadAssignment(ctx, q, rec, id)
		if err != nil {
			return err
		}
		assignmentProfileParams(rec, profile)
		rec.SetParam("old_device_group_id", idParam(groupPtr(cur.DeviceGroupID)))
		rec.SetParam("device_group_id", idParam(deviceGroupID))
		if deviceGroupID != nil {
			if _, err := q.GetDeviceGroup(ctx, *deviceGroupID); err != nil {
				return problem.InvalidRequest.WithDetail("unknown device group")
			}
		}
		out, err = q.UpdateProfileAssignmentScope(ctx, pgstore.UpdateProfileAssignmentScopeParams{ID: id, DeviceGroupID: nullID(deviceGroupID)})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("the profile is already assigned to this subject and scope")
		}
		if err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, cur.OrganizationID)
		return nil
	})
	return out, err
}

// DeleteAssignment removes an assignment (audited: profile_assignment.deleted).
func (p *Privileges) DeleteAssignment(ctx context.Context, id uuid.UUID) error {
	spec := SpecAssignmentDelete
	spec.Target = &audit.Target{Type: "profile_assignment", ID: id.String()}
	return p.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, profile, err := loadAssignment(ctx, q, rec, id)
		if err != nil {
			return err
		}
		rec.SetParam("profile", profile.Name)
		rec.SetParam("class", profile.Class)
		rec.SetParam("device_group_id", idParam(groupPtr(cur.DeviceGroupID)))
		if _, err := q.DeleteProfileAssignment(ctx, id); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, cur.OrganizationID)
		return nil
	})
}

func loadAssignment(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID) (pgstore.ProfileAssignment, pgstore.PermissionProfile, error) {
	cur, err := q.GetProfileAssignment(ctx, id)
	if err != nil {
		return cur, pgstore.PermissionProfile{}, notFound(err)
	}
	profile, err := q.GetPermissionProfile(ctx, cur.ProfileID)
	if err != nil {
		return cur, profile, err
	}
	rec.SetTarget(audit.Target{Type: "profile_assignment", ID: id.String(), Display: profile.Name})
	rec.SetParam("subject_type", cur.SubjectType)
	rec.SetParam("subject_id", idParam(groupPtr(cur.SubjectID)))
	return cur, profile, nil
}

// EffectiveProfile computes the effective profile of a user on a device; without a device, on a device in no device
// group (only unscoped assignments apply). names maps the organization's profile IDs to their names.
func (p *Privileges) EffectiveProfile(ctx context.Context, userID uuid.UUID, deviceID *uuid.UUID) (
	user pgstore.AppUser, out privilege.EffectiveProfile, names map[uuid.UUID]string, err error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return user, out, nil, err
	}
	names = map[uuid.UUID]string{}
	err = p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if user, err = q.GetAppUser(ctx, userID); err != nil {
			return notFound(err)
		}
		var groups []uuid.UUID
		if deviceID != nil {
			if _, err := q.GetDevice(ctx, *deviceID); err != nil {
				return problem.InvalidRequest.WithDetail("unknown device")
			}
			if groups, err = q.ListDeviceGroupIDsOfDevice(ctx, *deviceID); err != nil {
				return err
			}
		}
		id, err := LoadIdentity(ctx, q)
		if err != nil {
			return err
		}
		for _, pr := range id.Profiles {
			names[pr.ID] = pr.Name
		}
		out = id.Effective(userID, groups)
		return nil
	})
	return user, out, names, err
}

// SudoUser is the effective profile of one user allowed on a device.
type SudoUser struct {
	User      pgstore.AppUser
	Effective privilege.EffectiveProfile
}

// EffectiveSudo returns the effective profiles of the users allowed on a device whose class is not none, sorted by
// username (the content of the device's sudo resource, plan M3a decision 16).
func (p *Privileges) EffectiveSudo(ctx context.Context, deviceID uuid.UUID) ([]SudoUser, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return nil, err
	}
	out := []SudoUser{}
	err := p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound(err)
		}
		groups, err := q.ListDeviceGroupIDsOfDevice(ctx, deviceID)
		if err != nil {
			return err
		}
		id, err := LoadIdentity(ctx, q)
		if err != nil {
			return err
		}
		for _, u := range id.AllowedUsers(deviceID) {
			if e := id.Effective(u, groups); e.Class != privilege.ClassNone {
				out = append(out, SudoUser{User: id.Users[u], Effective: e})
			}
		}
		return nil
	})
	return out, err
}
