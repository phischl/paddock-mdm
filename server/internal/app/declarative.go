package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicegroup"
	"github.com/phischl/paddock-mdm/server/internal/domain/loginsettings"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Declarative is the declarative configuration of an organization (plan M6c §3.2): export, dry run and apply of the
// paddock.v1 document, and the change sets of applies. Applies use the domain validation and the queries of the
// per-resource use cases, all changes in one transaction (decision 12).
type Declarative struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewDeclarative creates the use cases.
func NewDeclarative(runner *ActionRunner, org *db.OrgPool) *Declarative {
	return &Declarative{runner: runner, org: org}
}

// SpecConfigApply is the privileged action config.applied.
var SpecConfigApply = ActionSpec{Code: audit.CodeConfigApplied, AllowedRoles: RolesWrite}

// MaxDocumentBytes bounds a declarative configuration (plan M6c decision 16).
const MaxDocumentBytes = 1 << 20

// expectedPlanPattern is the form of expected_plan, a hex SHA-256.
var expectedPlanPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// errDryRun rolls back the transaction of a dry run after the plan was executed in it.
var errDryRun = errors.New("app: dry run")

// Export returns the organization's configuration with every section present.
func (d *Declarative) Export(ctx context.Context) (declarative.Document, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return declarative.Document{}, err
	}
	var doc declarative.Document
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		st, err := loadConfig(ctx, q)
		doc = st.doc
		return err
	})
	return doc, err
}

// Plan computes the changes of raw without applying them (dry run, not audited). It executes them in a transaction
// that is rolled back, so it refuses exactly what Apply would refuse.
func (d *Declarative) Plan(ctx context.Context, raw []byte) (declarative.Plan, error) {
	p, err := RequireOrg(ctx, RolesWrite)
	if err != nil {
		return declarative.Plan{}, err
	}
	desired, err := parseDocument(raw)
	if err != nil {
		return declarative.Plan{}, err
	}
	var plan declarative.Plan
	err = d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		st, err := loadConfig(ctx, q)
		if err != nil {
			return err
		}
		plan = declarative.Diff(st.doc, desired)
		ex := &configExec{q: q, st: st, desired: desired, p: p, stepUp: func() error { return d.runner.checkStepUp(p) }}
		if err := ex.run(ctx, plan); err != nil {
			return err
		}
		return errDryRun
	})
	if errors.Is(err, errDryRun) {
		return plan, nil
	}
	return declarative.Plan{}, err
}

// Apply applies raw in one transaction (audited: config.applied) and records a change set unless the plan is empty.
// It returns the change set ID (uuid.Nil without changes) and the plan. expectedPlan, when not empty, is the SHA-256 of
// the plan the client confirmed (plan M6c amendment 2026-10-08): a different plan is refused with plan_changed and
// nothing is applied, so a deletion that appeared after the dry run is never applied unconfirmed.
func (d *Declarative) Apply(ctx context.Context, raw []byte, expectedPlan string) (uuid.UUID, declarative.Plan, error) {
	var id uuid.UUID
	var plan declarative.Plan
	spec := SpecConfigApply
	spec.Params = map[string]any{"change_set_id": nil, "created": 0, "updated": 0, "deleted": 0, "sections": []string{}}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		// Checked inside the action, so a malformed value is recorded like every other refused apply.
		if expectedPlan != "" && !expectedPlanPattern.MatchString(expectedPlan) {
			return problem.InvalidRequest.WithDetail("expected_plan must be 64 lowercase hex digits")
		}
		p, _ := principal.From(ctx)
		desired, err := parseDocument(raw)
		if err != nil {
			return err
		}
		st, err := loadConfig(ctx, q)
		if err != nil {
			return err
		}
		plan = declarative.Diff(st.doc, desired)
		sections := plan.SectionsOf()
		if expectedPlan != "" && plan.SHA256() != expectedPlan {
			return problem.PlanChanged.WithDetail("the plan differs from the confirmed plan " + expectedPlan + "; review the new plan and apply again")
		}
		rec.SetParam("created", plan.Created)
		rec.SetParam("updated", plan.Updated)
		rec.SetParam("deleted", plan.Deleted)
		rec.SetParam("sections", sections)
		ex := &configExec{q: q, st: st, desired: desired, p: p, stepUp: rec.RequireStepUp}
		if err := ex.run(ctx, plan); err != nil {
			return err
		}
		if len(plan.Changes) == 0 {
			return nil
		}
		id = uuid.Must(uuid.NewV7())
		if err := insertChangeSet(ctx, q, id, p, ex.steppedUp, plan, sections); err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "change_set", ID: id.String()})
		rec.SetParam("change_set_id", id.String())
		rec.StateChanged(statechange.ScopeOrg, p.OrganizationID)
		return nil
	})
	if err != nil {
		return uuid.Nil, declarative.Plan{}, err
	}
	return id, plan, nil
}

func insertChangeSet(ctx context.Context, q *pgstore.Queries, id uuid.UUID, p principal.Principal, steppedUp bool,
	plan declarative.Plan, sections []string) error {
	a := actorOf(p)
	a.StepUp = steppedUp
	actor, err := json.Marshal(a)
	if err != nil {
		return err
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	source := ChangeSetSourceSession
	if p.APITokenID != uuid.Nil {
		source = ChangeSetSourceAPIToken
	}
	return q.InsertChangeSet(ctx, pgstore.InsertChangeSetParams{
		ID: id, OrganizationID: p.OrganizationID, Actor: actor, Source: source,
		CreatedN: int32(plan.Created), UpdatedN: int32(plan.Updated), DeletedN: int32(plan.Deleted), //nolint:gosec // bounded by the 1 MiB document
		Sections: sections, Plan: planJSON,
	})
}

// Sources of a change set.
const (
	ChangeSetSourceSession  = "session"
	ChangeSetSourceAPIToken = "api_token"
)

// ChangeSetQuery selects a page of change sets.
type ChangeSetQuery struct {
	Page    ListPage
	Sources []string // session, api_token; nil: all
}

// ListChangeSets returns one page of change sets.
func (d *Declarative) ListChangeSets(ctx context.Context, query ChangeSetQuery) (Listed[pgstore.ChangeSet], error) {
	var out Listed[pgstore.ChangeSet]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountChangeSets(ctx, pgstore.CountChangeSetsParams{QPattern: query.Page.QPattern, Sources: query.Sources, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count change sets: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListChangeSets(ctx, pgstore.ListChangeSetsParams{
			QPattern: query.Page.QPattern, Sources: query.Sources, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list change sets: %w", err)
		}
		return nil
	})
	return out, err
}

// GetChangeSet returns one change set; missing and foreign change sets are both not_found.
func (d *Declarative) GetChangeSet(ctx context.Context, id uuid.UUID) (pgstore.ChangeSet, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.ChangeSet{}, err
	}
	var cs pgstore.ChangeSet
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		cs, err = q.GetChangeSet(ctx, id)
		return notFound(err)
	})
	return cs, err
}

// parseDocument checks the size and the schema of raw, decodes it and normalizes it as the per-resource use cases
// normalize their input, so that the diff compares like with like.
func parseDocument(raw []byte) (declarative.Document, error) {
	if len(raw) > MaxDocumentBytes {
		return declarative.Document{}, problem.InvalidRequest.WithDetail("the document is larger than 1 MiB")
	}
	var verr *declarative.ValidationError
	if err := declarative.ValidateJSON(raw); errors.As(err, &verr) {
		return declarative.Document{}, problem.InvalidDocument.WithDetail(verr.Error())
	} else if err != nil {
		return declarative.Document{}, err
	}
	doc, err := declarative.Decode(raw)
	if err != nil {
		return declarative.Document{}, problem.InvalidDocument.WithDetail(err.Error())
	}
	normalize(&doc)
	if verr := declarative.Duplicates(doc); verr != nil {
		return declarative.Document{}, problem.InvalidDocument.WithDetail(verr.Error())
	}
	return doc, nil
}

func normalize(doc *declarative.Document) {
	if doc.DeviceGroups != nil {
		for i, g := range *doc.DeviceGroups {
			(*doc.DeviceGroups)[i] = declarative.DeviceGroup{Name: devicegroup.NormalizeName(g.Name), Description: strings.TrimSpace(g.Description)}
		}
	}
	if doc.PermissionProfiles != nil {
		for i, p := range *doc.PermissionProfiles {
			n := privilege.NormalizeProfile(privilege.Profile{Name: p.Name, Commands: p.Commands})
			p.Name, p.Commands = n.Name, n.Commands
			if p.Commands == nil {
				p.Commands = []string{}
			}
			(*doc.PermissionProfiles)[i] = p
		}
	}
	if doc.Settings != nil && doc.Settings.Login != nil {
		l := loginSettingsOf(*doc.Settings.Login)
		*doc.Settings.Login = loginDocOf(loginsettings.Normalize(l))
	}
}

// configState is the current configuration and the IDs behind its natural keys.
type configState struct {
	doc        declarative.Document
	ids        map[string]map[string]uuid.UUID // section → key (declarative.Key.String) → ID
	names      map[string]string               // key of a device group or profile → its name
	groups     map[string]uuid.UUID            // device group name → ID
	profiles   map[string]pgstore.PermissionProfile
	userGroups map[string]uuid.UUID // slug → ID
	users      map[string]uuid.UUID // username → ID
}

// loadConfig reads the organization's configuration in document form.
func loadConfig(ctx context.Context, q *pgstore.Queries) (configState, error) {
	st := configState{ids: map[string]map[string]uuid.UUID{}, names: map[string]string{}, groups: map[string]uuid.UUID{},
		profiles: map[string]pgstore.PermissionProfile{}, userGroups: map[string]uuid.UUID{}, users: map[string]uuid.UUID{}}
	for _, s := range declarative.Sections() {
		st.ids[s] = map[string]uuid.UUID{}
	}
	doc := declarative.Document{APIVersion: declarative.APIVersion, Kind: declarative.Kind}

	login, err := q.GetLoginSettings(ctx)
	if err != nil {
		return st, fmt.Errorf("login settings: %w", err)
	}
	upd, err := LoadUpdateSettings(ctx, q)
	if err != nil {
		return st, fmt.Errorf("update settings: %w", err)
	}
	doc.Settings = &declarative.Settings{Login: loginDocOfRow(login), Updates: &declarative.UpdateSettings{
		SecurityDailyAt: upd.SecurityDailyAt, RegularSchedule: upd.RegularSchedule, RegularUpdatesEnabled: upd.RegularUpdatesEnabled,
		MaxRandomDelayMin: upd.MaxRandomDelayMin, StalenessWarningH: upd.StalenessWarningH, StalenessCriticalH: upd.StalenessCriticalH,
	}}

	groups, err := q.ListAllDeviceGroups(ctx)
	if err != nil {
		return st, fmt.Errorf("device groups: %w", err)
	}
	names := map[uuid.UUID]string{}
	dgs := make([]declarative.DeviceGroup, 0, len(groups))
	for _, g := range groups {
		names[g.ID], st.groups[g.Name] = g.Name, g.ID
		item := declarative.DeviceGroup{Name: g.Name, Description: g.Description}
		st.ids[declarative.SectionDeviceGroups][item.Key().String()] = g.ID
		st.names[item.Key().String()] = g.Name
		dgs = append(dgs, item)
	}
	doc.DeviceGroups = &dgs
	groupName := func(id uuid.NullUUID) *string {
		if !id.Valid {
			return nil
		}
		n := names[id.UUID]
		return &n
	}

	profiles, err := q.ListAllPermissionProfiles(ctx)
	if err != nil {
		return st, fmt.Errorf("permission profiles: %w", err)
	}
	pps := make([]declarative.PermissionProfile, 0, len(profiles))
	byID := map[uuid.UUID]string{}
	for _, p := range profiles {
		st.profiles[p.Name], byID[p.ID] = p, p.Name
		cmds := p.Commands
		if cmds == nil {
			cmds = []string{}
		}
		item := declarative.PermissionProfile{Name: p.Name, Class: p.Class, Commands: cmds, RequirePassword: p.RequirePassword,
			TimestampTimeoutMin: int(p.TimestampTimeoutMin), Lecture: p.Lecture}
		st.ids[declarative.SectionPermissionProfiles][item.Key().String()] = p.ID
		st.names[item.Key().String()] = p.Name
		pps = append(pps, item)
	}
	doc.PermissionProfiles = &pps

	files, err := q.ListAllManagedFiles(ctx)
	if err != nil {
		return st, fmt.Errorf("managed files: %w", err)
	}
	mfs := make([]declarative.ManagedFile, 0, len(files))
	for _, f := range files {
		item := declarative.ManagedFile{Path: f.Path, DeviceGroup: groupName(f.DeviceGroupID), Mode: f.Mode, Owner: f.Owner,
			Group: f.Grp, Content: f.Content}
		st.ids[declarative.SectionManagedFiles][item.Key().String()] = f.ID
		mfs = append(mfs, item)
	}
	doc.ManagedFiles = &mfs

	units, err := q.ListAllManagedUnits(ctx)
	if err != nil {
		return st, fmt.Errorf("managed units: %w", err)
	}
	mus := make([]declarative.ManagedUnit, 0, len(units))
	for _, u := range units {
		item := declarative.ManagedUnit{Unit: u.Unit, DeviceGroup: groupName(u.DeviceGroupID), Enabled: u.Enabled, Active: u.Active}
		st.ids[declarative.SectionManagedUnits][item.Key().String()] = u.ID
		mus = append(mus, item)
	}
	doc.ManagedUnits = &mus

	holds, err := q.ListAllPackageHolds(ctx)
	if err != nil {
		return st, fmt.Errorf("package holds: %w", err)
	}
	phs := make([]declarative.PackageHold, 0, len(holds))
	for _, h := range holds {
		item := declarative.PackageHold{Package: h.Package, Version: h.Version, DeviceGroup: groupName(h.DeviceGroupID), Reason: h.Reason}
		st.ids[declarative.SectionPackageHolds][item.Key().String()] = h.ID
		phs = append(phs, item)
	}
	doc.PackageHolds = &phs

	userGroups, err := q.ListAllUserGroups(ctx)
	if err != nil {
		return st, fmt.Errorf("user groups: %w", err)
	}
	slugs := map[uuid.UUID]string{}
	for _, g := range userGroups {
		st.userGroups[g.Slug], slugs[g.ID] = g.ID, g.Slug
	}
	users, err := q.ListAllAppUsers(ctx)
	if err != nil {
		return st, fmt.Errorf("users: %w", err)
	}
	usernames := map[uuid.UUID]string{}
	for _, u := range users {
		st.users[u.Username], usernames[u.ID] = u.ID, u.Username
	}
	assignments, err := q.ListAllProfileAssignments(ctx)
	if err != nil {
		return st, fmt.Errorf("profile assignments: %w", err)
	}
	pas := make([]declarative.ProfileAssignment, 0, len(assignments))
	for _, a := range assignments {
		subject := declarative.Subject{Type: a.SubjectType}
		switch a.SubjectType {
		case declarative.SubjectGroup:
			subject.Slug = slugs[a.SubjectID.UUID]
		case declarative.SubjectUser:
			subject.Username = usernames[a.SubjectID.UUID]
		}
		item := declarative.ProfileAssignment{Profile: byID[a.ProfileID], Subject: subject, DeviceGroup: groupName(a.DeviceGroupID)}
		st.ids[declarative.SectionProfileAssignments][item.Key().String()] = a.ID
		pas = append(pas, item)
	}
	doc.ProfileAssignments = &pas
	st.doc = doc
	return st, nil
}

func loginDocOfRow(r pgstore.OrganizationLoginSetting) *declarative.LoginSettings {
	var hours *int
	if r.RotateAfterRevealHours != nil {
		h := int(*r.RotateAfterRevealHours)
		hours = &h
	}
	return &declarative.LoginSettings{
		HelloEnabled: r.HelloEnabled, HelloPinMinLength: int(r.HelloPinMinLength), UserLockSessionAction: r.UserLockSessionAction,
		BreakGlassAccounts: nonNil(r.BreakGlassAccounts), SudoersDAllowlist: nonNil(r.SudoersDAllowlist), SudoLectureText: r.SudoLectureText,
		LocalAdminUsername: r.LocalAdminUsername, LocalAdminRotationDays: int(r.LocalAdminRotationDays),
		RotateAfterRevealHours: hours, NoticeText: r.NoticeText, BootPinMinLength: int(r.BootPinMinLength),
	}
}

func loginSettingsOf(l declarative.LoginSettings) loginsettings.Settings {
	return loginsettings.Settings{
		HelloEnabled: l.HelloEnabled, HelloPinMinLength: l.HelloPinMinLength, UserLockSessionAction: l.UserLockSessionAction,
		BreakGlassAccounts: l.BreakGlassAccounts, SudoersDAllowlist: l.SudoersDAllowlist, SudoLectureText: l.SudoLectureText,
		LocalAdminUsername: l.LocalAdminUsername, LocalAdminRotationDays: l.LocalAdminRotationDays,
		RotateAfterRevealHours: l.RotateAfterRevealHours, NoticeText: l.NoticeText, BootPinMinLength: l.BootPinMinLength,
	}
}

func loginDocOf(s loginsettings.Settings) declarative.LoginSettings {
	return declarative.LoginSettings{
		HelloEnabled: s.HelloEnabled, HelloPinMinLength: s.HelloPinMinLength, UserLockSessionAction: s.UserLockSessionAction,
		BreakGlassAccounts: nonNil(s.BreakGlassAccounts), SudoersDAllowlist: nonNil(s.SudoersDAllowlist), SudoLectureText: s.SudoLectureText,
		LocalAdminUsername: s.LocalAdminUsername, LocalAdminRotationDays: s.LocalAdminRotationDays,
		RotateAfterRevealHours: s.RotateAfterRevealHours, NoticeText: s.NoticeText, BootPinMinLength: s.BootPinMinLength,
	}
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
