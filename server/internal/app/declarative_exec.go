package app

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/policy"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/loginsettings"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/domain/updates"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// configExec executes a plan in one transaction with the validation and the queries of the per-resource use cases;
// their rules apply unchanged, including the roles of the actions that only organization administrators may perform
// (device group deletion, both settings) and the step-ups of full profiles.
type configExec struct {
	q       *pgstore.Queries
	st      configState
	desired declarative.Document
	p       principal.Principal
	stepUp  func() error
	index   map[string]map[string]int
	// steppedUp: a change needed a step-up and it was fresh; the change set's actor records it like the event's.
	steppedUp bool
}

// requireStepUp refuses the change unless the step-up is fresh (full profiles, plan M4a decision 7).
func (ex *configExec) requireStepUp() error {
	if err := ex.stepUp(); err != nil {
		return err
	}
	ex.steppedUp = true
	return nil
}

func (ex *configExec) run(ctx context.Context, plan declarative.Plan) error {
	ex.index = declarative.Index(ex.desired)
	for _, c := range plan.Changes {
		path := ex.path(c)
		if err := ex.change(ctx, c); err != nil {
			return atPath(path, err)
		}
	}
	return nil
}

// path is where a change is in the document; a deleted item is not in it and is named by its key.
func (ex *configExec) path(c declarative.Change) string {
	if c.Action == declarative.ActionDelete {
		return "/" + c.Section + " (delete " + strconv.Quote(c.Key) + ")"
	}
	return declarative.Path(c.Section, ex.index[c.Section][c.Key])
}

// atPath prefixes the detail of a problem with the document path it refers to.
func atPath(path string, err error) error {
	var p *problem.Error
	if !errors.As(err, &p) {
		return err
	}
	detail := p.Detail
	if detail == "" {
		detail = p.Code
	}
	return p.WithDetail(path + ": " + detail)
}

func (ex *configExec) requireAdmin(what string) error {
	if ex.p.Kind != principal.KindSystem && ex.p.Role != principal.RoleOrgAdmin {
		return problem.Forbidden.WithDetail("only organization administrators " + what)
	}
	return nil
}

func (ex *configExec) item(c declarative.Change) int { return ex.index[c.Section][c.Key] }

func (ex *configExec) id(c declarative.Change) uuid.UUID { return ex.st.ids[c.Section][c.Key] }

// group resolves a device group name of the document; nil is every device of the organization.
func (ex *configExec) group(name *string) (*uuid.UUID, error) {
	if name == nil {
		return nil, nil
	}
	id, ok := ex.st.groups[*name]
	if !ok {
		return nil, problem.InvalidRequest.WithDetail("device group " + strconv.Quote(*name) + " does not exist")
	}
	return &id, nil
}

func (ex *configExec) change(ctx context.Context, c declarative.Change) error {
	switch c.Section {
	case declarative.SectionDeviceGroups:
		return ex.deviceGroup(ctx, c)
	case declarative.SectionPermissionProfiles:
		return ex.profile(ctx, c)
	case declarative.SectionManagedFiles:
		return ex.file(ctx, c)
	case declarative.SectionManagedUnits:
		return ex.unit(ctx, c)
	case declarative.SectionPackageHolds:
		return ex.hold(ctx, c)
	case declarative.SectionProfileAssignments:
		return ex.assignment(ctx, c)
	case declarative.SectionSettingsUpdates:
		return ex.updateSettings(ctx)
	case declarative.SectionSettingsLogin:
		return ex.loginSettings(ctx)
	}
	return problem.InvalidDocument.WithDetail("unknown section " + c.Section)
}

func (ex *configExec) deviceGroup(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		if err := ex.requireAdmin("delete device groups"); err != nil {
			return err
		}
		n, err := ex.q.DeleteDeviceGroup(ctx, ex.id(c))
		if db.IsForeignKeyViolation(err) {
			return problem.InUse.WithDetail("an enrollment token still assigns devices to this group")
		}
		if err == nil && n == 0 {
			return problem.NotFound
		}
		delete(ex.st.groups, c.Key)
		return err
	}
	g := (*ex.desired.DeviceGroups)[ex.item(c)]
	if err := validateGroup(g.Name, g.Description); err != nil {
		return err
	}
	var err error
	if c.Action == declarative.ActionCreate {
		var row pgstore.DeviceGroup
		row, err = ex.q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, Name: g.Name, Description: g.Description,
		})
		ex.st.groups[g.Name] = row.ID
	} else {
		_, err = ex.q.UpdateDeviceGroup(ctx, pgstore.UpdateDeviceGroupParams{ID: ex.id(c), Name: g.Name, Description: g.Description})
	}
	if db.IsUniqueViolation(err, "device_group_organization_id_name_key") {
		return problem.NameTaken.WithDetail("a device group with this name exists")
	}
	return err
}

func (ex *configExec) profile(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		_, err := ex.q.DeletePermissionProfile(ctx, ex.id(c))
		if db.IsForeignKeyViolation(err) {
			return problem.InUse.WithDetail("the profile is still assigned; remove its assignments first")
		}
		delete(ex.st.profiles, c.Key)
		return err
	}
	d := (*ex.desired.PermissionProfiles)[ex.item(c)]
	in, err := validProfile(privilege.Profile{Name: d.Name, Class: privilege.Class(d.Class), Commands: d.Commands,
		RequirePassword: d.RequirePassword, TimestampTimeoutMin: d.TimestampTimeoutMin, Lecture: privilege.Lecture(d.Lecture)})
	if err != nil {
		return err
	}
	var row pgstore.PermissionProfile
	if c.Action == declarative.ActionCreate {
		row, err = ex.q.InsertPermissionProfile(ctx, pgstore.InsertPermissionProfileParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, Name: in.Name, Class: string(in.Class),
			Commands: in.Commands, RequirePassword: in.RequirePassword,
			TimestampTimeoutMin: int32(in.TimestampTimeoutMin), //nolint:gosec // validated 0–60
			Lecture:             string(in.Lecture),
		})
	} else {
		if in.Class == privilege.ClassFull && ex.st.profiles[c.Key].Class != string(privilege.ClassFull) {
			if err := ex.requireStepUp(); err != nil {
				return err
			}
		}
		row, err = ex.q.UpdatePermissionProfile(ctx, pgstore.UpdatePermissionProfileParams{
			ID: ex.id(c), Name: in.Name, Class: string(in.Class), Commands: in.Commands, RequirePassword: in.RequirePassword,
			TimestampTimeoutMin: int32(in.TimestampTimeoutMin), Lecture: string(in.Lecture), //nolint:gosec // validated 0–60
		})
	}
	if db.IsUniqueViolation(err, "permission_profile_organization_id_name_key") {
		return problem.NameTaken.WithDetail("a permission profile with this name exists")
	}
	if err != nil {
		return err
	}
	ex.st.profiles[row.Name] = row
	return nil
}

func (ex *configExec) file(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		_, err := ex.q.DeleteManagedFile(ctx, ex.id(c))
		return err
	}
	f := (*ex.desired.ManagedFiles)[ex.item(c)]
	next := pgstore.ManagedFile{Path: f.Path, Mode: f.Mode, Owner: f.Owner, Grp: f.Group, Content: f.Content}
	if err := validateFile(next); err != nil {
		return err
	}
	var err error
	if c.Action == declarative.ActionCreate {
		group, gerr := ex.group(f.DeviceGroup)
		if gerr != nil {
			return gerr
		}
		_, err = ex.q.InsertManagedFile(ctx, pgstore.InsertManagedFileParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, DeviceGroupID: nullID(group), Path: next.Path,
			Mode: next.Mode, Owner: next.Owner, Grp: next.Grp, Content: next.Content,
		})
	} else {
		_, err = ex.q.UpdateManagedFile(ctx, pgstore.UpdateManagedFileParams{
			ID: ex.id(c), Path: next.Path, Mode: next.Mode, Owner: next.Owner, Grp: next.Grp, Content: next.Content,
		})
	}
	if db.IsUniqueViolation(err, "") {
		return problem.AlreadyExists.WithDetail("this path is already managed in this scope")
	}
	return err
}

func (ex *configExec) unit(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		_, err := ex.q.DeleteManagedUnit(ctx, ex.id(c))
		return err
	}
	u := (*ex.desired.ManagedUnits)[ex.item(c)]
	if err := policy.ValidateUnit(u.Unit); err != nil {
		return problem.UnitNotAllowed.WithDetail(err.Error())
	}
	var err error
	if c.Action == declarative.ActionCreate {
		group, gerr := ex.group(u.DeviceGroup)
		if gerr != nil {
			return gerr
		}
		_, err = ex.q.InsertManagedUnit(ctx, pgstore.InsertManagedUnitParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, DeviceGroupID: nullID(group), Unit: u.Unit,
			Enabled: u.Enabled, Active: u.Active,
		})
	} else {
		_, err = ex.q.UpdateManagedUnit(ctx, pgstore.UpdateManagedUnitParams{ID: ex.id(c), Unit: u.Unit, Enabled: u.Enabled, Active: u.Active})
	}
	if db.IsUniqueViolation(err, "") {
		return problem.AlreadyExists.WithDetail("this unit is already managed in this scope")
	}
	return err
}

func (ex *configExec) hold(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		_, err := ex.q.DeletePackageHold(ctx, ex.id(c))
		return err
	}
	h := (*ex.desired.PackageHolds)[ex.item(c)]
	if err := updates.ValidateHold(h.Package, h.Version, h.Reason); err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	if c.Action == declarative.ActionUpdate {
		_, err := ex.q.UpdatePackageHold(ctx, pgstore.UpdatePackageHoldParams{ID: ex.id(c), Version: h.Version, Reason: h.Reason})
		return err
	}
	group, err := ex.group(h.DeviceGroup)
	if err != nil {
		return err
	}
	_, err = ex.q.InsertPackageHold(ctx, pgstore.InsertPackageHoldParams{
		ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, DeviceGroupID: nullID(group), Package: h.Package,
		Version: h.Version, Reason: h.Reason, CreatedBy: uuid.NullUUID{UUID: ex.p.ID, Valid: ex.p.ID != uuid.Nil},
	})
	if db.IsUniqueViolation(err, "") {
		return problem.AlreadyExists.WithDetail("this package is already held in this scope")
	}
	return err
}

// assignment creates or deletes an assignment; every field is part of its key, so there are no updates.
func (ex *configExec) assignment(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		_, err := ex.q.DeleteProfileAssignment(ctx, ex.id(c))
		return err
	}
	a := (*ex.desired.ProfileAssignments)[ex.item(c)]
	profile, ok := ex.st.profiles[a.Profile]
	if !ok {
		return problem.InvalidRequest.WithDetail("unknown permission profile " + strconv.Quote(a.Profile))
	}
	if profile.Class == string(privilege.ClassFull) {
		if err := ex.requireStepUp(); err != nil {
			return err
		}
	}
	var subject *uuid.UUID
	switch a.Subject.Type {
	case declarative.SubjectGroup:
		id, ok := ex.st.userGroups[a.Subject.Slug]
		if !ok {
			return problem.InvalidRequest.WithDetail("unknown group " + strconv.Quote(a.Subject.Slug))
		}
		subject = &id
	case declarative.SubjectUser:
		id, ok := ex.st.users[a.Subject.Username]
		if !ok {
			return problem.InvalidRequest.WithDetail("unknown user " + strconv.Quote(a.Subject.Username))
		}
		subject = &id
	}
	subjectID := uuid.Nil
	if subject != nil {
		subjectID = *subject
	}
	if err := privilege.ValidateAssignmentSubject(privilege.SubjectType(a.Subject.Type), subjectID); err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	group, err := ex.group(a.DeviceGroup)
	if err != nil {
		return err
	}
	_, err = ex.q.InsertProfileAssignment(ctx, pgstore.InsertProfileAssignmentParams{
		ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, ProfileID: profile.ID,
		SubjectType: a.Subject.Type, SubjectID: nullID(subject), DeviceGroupID: nullID(group),
	})
	if db.IsUniqueViolation(err, "") {
		return problem.AlreadyExists.WithDetail("the profile is already assigned to this subject and scope")
	}
	return err
}

func (ex *configExec) updateSettings(ctx context.Context) error {
	if err := ex.requireAdmin("change the update settings"); err != nil {
		return err
	}
	s := ex.desired.Settings.Updates
	in := updates.Settings{
		SecurityDailyAt: s.SecurityDailyAt, RegularSchedule: s.RegularSchedule, RegularUpdatesEnabled: s.RegularUpdatesEnabled,
		MaxRandomDelayMin: s.MaxRandomDelayMin, StalenessWarningH: s.StalenessWarningH, StalenessCriticalH: s.StalenessCriticalH,
	}
	if err := in.Validate(); errors.Is(err, updates.ErrSchedule) {
		return problem.InvalidSchedule.WithDetail(err.Error())
	} else if err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	_, err := ex.q.UpsertUpdateSettings(ctx, pgstore.UpsertUpdateSettingsParams{
		OrganizationID: ex.p.OrganizationID, SecurityDailyAt: in.SecurityDailyAt, RegularSchedule: in.RegularSchedule,
		RegularUpdatesEnabled: in.RegularUpdatesEnabled,
		MaxRandomDelayMin:     int32(in.MaxRandomDelayMin),  //nolint:gosec // validated
		StalenessWarningH:     int32(in.StalenessWarningH),  //nolint:gosec // validated
		StalenessCriticalH:    int32(in.StalenessCriticalH), //nolint:gosec // validated
		UpdatedBy:             uuid.NullUUID{UUID: ex.p.ID, Valid: ex.p.ID != uuid.Nil},
	})
	return err
}

func (ex *configExec) loginSettings(ctx context.Context) error {
	if err := ex.requireAdmin("change the login settings"); err != nil {
		return err
	}
	in := loginsettings.Normalize(loginSettingsOf(*ex.desired.Settings.Login))
	if err := loginsettings.Validate(in); err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	cur := ex.st.doc.Settings.Login
	if cur.LocalAdminUsername != in.LocalAdminUsername {
		locked, err := ex.q.OrganizationHasActiveLocalAdmin(ctx)
		if err != nil {
			return err
		}
		if locked {
			return problem.SettingLocked.WithDetail("local_admin_username cannot change: devices have an active password for " + cur.LocalAdminUsername)
		}
	}
	_, err := ex.q.UpdateLoginSettings(ctx, pgstore.UpdateLoginSettingsParams{
		HelloEnabled: in.HelloEnabled, HelloPinMinLength: int32(in.HelloPinMinLength), //nolint:gosec // validated 6–32
		UserLockSessionAction: in.UserLockSessionAction, BreakGlassAccounts: in.BreakGlassAccounts,
		SudoersDAllowlist: in.SudoersDAllowlist, SudoLectureText: in.SudoLectureText,
		LocalAdminUsername: in.LocalAdminUsername, LocalAdminRotationDays: int32(in.LocalAdminRotationDays), //nolint:gosec // validated 1–365
		RotateAfterRevealHours: int32Ptr(in.RotateAfterRevealHours), NoticeText: in.NoticeText,
		BootPinMinLength: int32(in.BootPinMinLength), //nolint:gosec // validated 6–32
	})
	return err
}
