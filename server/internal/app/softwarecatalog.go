package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the software catalog actions (plan M13a decision 11): organization administrators and operators manage the
// catalog and its assignments without a step-up; the package source an entry uses is the trust anchor, and that is
// what needs the step-up.
var (
	SpecSoftwareCatalogEntryCreate = ActionSpec{Code: audit.CodeSoftwareCatalogEntryCreated, AllowedRoles: RolesWrite}
	SpecSoftwareCatalogEntryUpdate = ActionSpec{Code: audit.CodeSoftwareCatalogEntryUpdated, AllowedRoles: RolesWrite}
	SpecSoftwareCatalogEntryDelete = ActionSpec{Code: audit.CodeSoftwareCatalogEntryDeleted, AllowedRoles: RolesWrite}
	SpecSoftwareAssignmentCreate   = ActionSpec{Code: audit.CodeSoftwareAssignmentCreated, AllowedRoles: RolesWrite}
	SpecSoftwareAssignmentUpdate   = ActionSpec{Code: audit.CodeSoftwareAssignmentUpdated, AllowedRoles: RolesWrite}
	SpecSoftwareAssignmentDelete   = ActionSpec{Code: audit.CodeSoftwareAssignmentDeleted, AllowedRoles: RolesWrite}
)

// CatalogEntry is a catalog entry as the API shows it; the icon stays in the database.
type CatalogEntry = pgstore.GetSoftwareCatalogEntryRow

// Assignment is a software assignment with the name of its catalog entry.
type Assignment = pgstore.GetSoftwareAssignmentRow

// SoftwareCatalog are the use cases of the organization's software catalog and the assignments of its entries
// (plan M13a decisions 7 to 11).
type SoftwareCatalog struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewSoftwareCatalog creates the use cases.
func NewSoftwareCatalog(runner *ActionRunner, org *db.OrgPool) *SoftwareCatalog {
	return &SoftwareCatalog{runner: runner, org: org}
}

// CatalogQuery selects a page of catalog entries; q matches name and description.
type CatalogQuery struct {
	Page     ListPage
	Category *string
	SourceID *uuid.UUID
}

// List returns one page of catalog entries.
func (c *SoftwareCatalog) List(ctx context.Context, query CatalogQuery) (Listed[CatalogEntry], error) {
	var out Listed[CatalogEntry]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountSoftwareCatalogEntries(ctx, pgstore.CountSoftwareCatalogEntriesParams{
			QPattern: query.Page.QPattern, Category: query.Category, SourceID: nullID(query.SourceID), CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count software catalog entries: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListSoftwareCatalogEntries(ctx, pgstore.ListSoftwareCatalogEntriesParams{
			QPattern: query.Page.QPattern, Category: query.Category, SourceID: nullID(query.SourceID),
			Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		for _, r := range rows {
			out.Items = append(out.Items, CatalogEntry(r))
		}
		return err
	})
	return out, err
}

// Get returns one catalog entry.
func (c *SoftwareCatalog) Get(ctx context.Context, id uuid.UUID) (CatalogEntry, error) {
	var out CatalogEntry
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetSoftwareCatalogEntry(ctx, id)
		return notFound(err)
	})
	return out, err
}

// Icon returns the entry's PNG icon; an entry without one is not found.
func (c *SoftwareCatalog) Icon(ctx context.Context, id uuid.UUID) ([]byte, error) {
	var out []byte
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return nil, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetSoftwareCatalogEntryIcon(ctx, id)
		return notFound(err)
	})
	return out, err
}

// EntryInput are the fields of a catalog entry. On update they replace the stored values.
type EntryInput struct {
	Name, Description, Category string
	SourceID                    *uuid.UUID
	Packages                    []software.PackageRef
}

// Create adds a catalog entry (audited: software_catalog_entry.created). A source that is not one of the
// organization's is not found.
func (c *SoftwareCatalog) Create(ctx context.Context, in EntryInput) (CatalogEntry, error) {
	var out CatalogEntry
	in.Name, in.Category = software.NormalizeName(in.Name), software.NormalizeCategory(in.Category)
	in.Packages = software.NormalizePackages(in.Packages)
	spec := SpecSoftwareCatalogEntryCreate
	spec.Params = map[string]any{
		"name": software.DisplayParam(in.Name, software.MaxNameLength), "category": software.DisplayParam(in.Category, software.MaxCategoryLength),
		"source_id": idParam(in.SourceID), "source_slug": nil, "package_count": len(in.Packages),
	}
	err := c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := software.ValidateEntry(in.Name, in.Description, in.Category, in.Packages); err != nil {
			return softwareEntryProblem(err)
		}
		slug, kind, err := entrySource(ctx, q, in.SourceID)
		if err != nil {
			return err
		}
		rec.SetParam("source_slug", slug)
		if err := software.ValidatePackages(kind, in.Packages); err != nil {
			return softwareEntryProblem(err)
		}
		packages, err := json.Marshal(in.Packages)
		if err != nil {
			return fmt.Errorf("encode package references: %w", err)
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		id := uuid.Must(uuid.NewV7())
		err = q.InsertSoftwareCatalogEntry(ctx, pgstore.InsertSoftwareCatalogEntryParams{
			ID: id, OrganizationID: org, Name: in.Name, Description: in.Description, Category: in.Category,
			SourceID: nullID(in.SourceID), Packages: packages, CreatedBy: uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil},
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("a catalog entry with this name exists")
		}
		// The source was deleted after the lookup.
		if db.IsForeignKeyViolation(err) {
			return problem.NotFound
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "software_catalog_entry", ID: id.String(), Display: in.Name})
		rec.StateChanged(statechange.ScopeOrg, org)
		out, err = q.GetSoftwareCatalogEntry(ctx, id)
		return err
	})
	return out, err
}

// Update replaces the name, description, category, source and package references of an entry (audited:
// software_catalog_entry.updated with the changed fields).
func (c *SoftwareCatalog) Update(ctx context.Context, id uuid.UUID, in EntryInput) (CatalogEntry, error) {
	var out CatalogEntry
	in.Name, in.Category = software.NormalizeName(in.Name), software.NormalizeCategory(in.Category)
	in.Packages = software.NormalizePackages(in.Packages)
	spec := SpecSoftwareCatalogEntryUpdate
	spec.Target = &audit.Target{Type: "software_catalog_entry", ID: id.String()}
	err := c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetSoftwareCatalogEntryForUpdate(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "software_catalog_entry", ID: id.String(), Display: old.Name})
		oldPackages, err := software.DecodePackages(old.Packages)
		if err != nil {
			return err
		}
		rec.SetParam("name", software.DisplayParam(in.Name, software.MaxNameLength))
		rec.SetParam("fields", entryFields(old, oldPackages, in))
		if err := software.ValidateEntry(in.Name, in.Description, in.Category, in.Packages); err != nil {
			return softwareEntryProblem(err)
		}
		intents, err := q.ListSoftwareAssignmentIntentsOfEntry(ctx, id)
		if err != nil {
			return err
		}
		for _, intent := range intents {
			if err := software.ValidateAssignmentTarget(intent, in.Packages); err != nil {
				return softwareAssignmentProblem(err)
			}
		}
		_, kind, err := entrySource(ctx, q, in.SourceID)
		if err != nil {
			return err
		}
		if err := software.ValidatePackages(kind, in.Packages); err != nil {
			return softwareEntryProblem(err)
		}
		packages, err := json.Marshal(in.Packages)
		if err != nil {
			return fmt.Errorf("encode package references: %w", err)
		}
		n, err := q.UpdateSoftwareCatalogEntry(ctx, pgstore.UpdateSoftwareCatalogEntryParams{
			ID: id, Name: in.Name, Description: in.Description, Category: in.Category, SourceID: nullID(in.SourceID),
			Packages: packages,
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("a catalog entry with this name exists")
		}
		if db.IsForeignKeyViolation(err) {
			return problem.NotFound
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		rec.StateChanged(statechange.ScopeOrg, old.OrganizationID)
		out, err = q.GetSoftwareCatalogEntry(ctx, id)
		return err
	})
	return out, err
}

// SetIcon sets the entry's icon (audited: software_catalog_entry.updated with the field icon). The icon is one PNG
// of at most software.MaxIconBytes and software.MaxIconDimension pixels in each direction.
func (c *SoftwareCatalog) SetIcon(ctx context.Context, id uuid.UUID, icon []byte) error {
	spec := SpecSoftwareCatalogEntryUpdate
	spec.Target = &audit.Target{Type: "software_catalog_entry", ID: id.String()}
	spec.Params = map[string]any{"fields": []string{"icon"}}
	return c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetSoftwareCatalogEntryForUpdate(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "software_catalog_entry", ID: id.String(), Display: old.Name})
		rec.SetParam("name", old.Name)
		if err := validateIcon(icon); err != nil {
			return err
		}
		n, err := q.SetSoftwareCatalogEntryIcon(ctx, pgstore.SetSoftwareCatalogEntryIconParams{ID: id, Icon: icon})
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		rec.StateChanged(statechange.ScopeOrg, old.OrganizationID)
		return nil
	})
}

// Delete removes an entry together with its assignments (audited: software_catalog_entry.deleted with the number of
// assignments removed); the devices stop managing the application.
func (c *SoftwareCatalog) Delete(ctx context.Context, id uuid.UUID) error {
	spec := SpecSoftwareCatalogEntryDelete
	spec.Target = &audit.Target{Type: "software_catalog_entry", ID: id.String()}
	return c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetSoftwareCatalogEntryForUpdate(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "software_catalog_entry", ID: id.String(), Display: old.Name})
		rec.SetParam("name", old.Name)
		// The entry is locked, so no assignment can be added between the count and the cascade.
		row, err := q.GetSoftwareCatalogEntry(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetParam("assignment_count", row.AssignmentCount)
		n, err := q.DeleteSoftwareCatalogEntry(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		rec.StateChanged(statechange.ScopeOrg, old.OrganizationID)
		return nil
	})
}

// SoftwareAssignmentQuery selects a page of assignments; q matches the entry's name. Target is one of the
// software.Target* kinds.
type SoftwareAssignmentQuery struct {
	Page           ListPage
	CatalogEntryID *uuid.UUID
	DeviceGroupID  *uuid.UUID
	UserID         *uuid.UUID
	UserGroupID    *uuid.UUID
	Target         *string
	Intent         *string
}

// ListAssignments returns one page of software assignments.
func (c *SoftwareCatalog) ListAssignments(ctx context.Context, query SoftwareAssignmentQuery) (Listed[Assignment], error) {
	var out Listed[Assignment]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountSoftwareAssignments(ctx, pgstore.CountSoftwareAssignmentsParams{
			QPattern: query.Page.QPattern, CatalogEntryID: nullID(query.CatalogEntryID), DeviceGroupID: nullID(query.DeviceGroupID),
			UserID: nullID(query.UserID), UserGroupID: nullID(query.UserGroupID), Target: query.Target,
			Intent: query.Intent, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count software assignments: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListSoftwareAssignments(ctx, pgstore.ListSoftwareAssignmentsParams{
			QPattern: query.Page.QPattern, CatalogEntryID: nullID(query.CatalogEntryID), DeviceGroupID: nullID(query.DeviceGroupID),
			UserID: nullID(query.UserID), UserGroupID: nullID(query.UserGroupID), Target: query.Target, Intent: query.Intent, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		for _, r := range rows {
			out.Items = append(out.Items, Assignment(r))
		}
		return err
	})
	return out, err
}

// GetAssignment returns one software assignment.
func (c *SoftwareCatalog) GetAssignment(ctx context.Context, id uuid.UUID) (Assignment, error) {
	var out Assignment
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetSoftwareAssignment(ctx, id)
		return notFound(err)
	})
	return out, err
}

// UserSoftwareQuery selects a page of the assignments that target a user; q matches the entry's name.
type UserSoftwareQuery struct {
	Page   ListPage
	Intent *string
}

// UserSoftware is an assignment that targets a user, directly or through a user group (UserGroupID).
type UserSoftware = pgstore.ListUserSoftwareRow

// UserSoftware returns one page of the assignments that target the user directly or through one of their user groups
// (plan M13b decision 6); a missing user or another organization's is not found.
func (c *SoftwareCatalog) UserSoftware(ctx context.Context, user uuid.UUID, query UserSoftwareQuery) (Listed[UserSoftware], error) {
	var out Listed[UserSoftware]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetAppUser(ctx, user); err != nil {
			return notFound(err)
		}
		id := uuid.NullUUID{UUID: user, Valid: true}
		n, err := q.CountUserSoftware(ctx, pgstore.CountUserSoftwareParams{
			UserID: id, QPattern: query.Page.QPattern, Intent: query.Intent, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count the software of user %s: %w", user, err)
		}
		out.Count = int(n)
		out.Items, err = q.ListUserSoftware(ctx, pgstore.ListUserSoftwareParams{
			UserID: id, QPattern: query.Page.QPattern, Intent: query.Intent, Sort: query.Page.Sort,
			SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list the software of user %s: %w", user, err)
		}
		return nil
	})
	return out, err
}

// AssignmentInput are the fields of an assignment. At most one of DeviceGroupID, UserID and UserGroupID names its
// target; none is the whole organization. UpdateRule is derived (software.DefaultUpdateRule) when empty. On update
// they replace the stored intent, update rule, version and reason; the entry and the target are fixed, and giving
// either is refused.
type AssignmentInput struct {
	CatalogEntryID *uuid.UUID
	DeviceGroupID  *uuid.UUID
	UserID         *uuid.UUID
	UserGroupID    *uuid.UUID
	Intent         string
	UpdateRule     string
	Version        *string
	Reason         string
}

// Bounds of request text in the audit params of an assignment: an intent or update rule is at most 9 characters.
const maxIntentParam = 16

// CreateAssignment assigns an entry to the organization, a device group, a user or a user group (audited:
// software_assignment.created). An entry, group or user that is not the organization's is not found; the compiler
// recomputes the devices.
func (c *SoftwareCatalog) CreateAssignment(ctx context.Context, in AssignmentInput) (Assignment, error) {
	var out Assignment
	if in.UpdateRule == "" {
		in.UpdateRule = software.DefaultUpdateRule(in.Intent, in.Version)
	}
	spec := SpecSoftwareAssignmentCreate
	spec.Params = assignmentParams(nil, in)
	spec.Params["app"] = nil
	err := c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := software.ValidateAssignment(in.Intent, in.UpdateRule, in.Version, in.Reason); err != nil {
			return softwareAssignmentProblem(err)
		}
		if _, err := software.Target(in.DeviceGroupID, in.UserID, in.UserGroupID); err != nil {
			return softwareAssignmentProblem(err)
		}
		if in.CatalogEntryID == nil {
			return problem.InvalidRequest.WithDetail("catalog_entry_id is required")
		}
		// Locked as Update locks it, so a concurrent package change cannot slip past the intent check of either side.
		entry, err := q.GetSoftwareCatalogEntryForUpdate(ctx, *in.CatalogEntryID)
		if err != nil {
			return notFound(err)
		}
		rec.SetParam("app", entry.Name)
		if err := entryAssignable(in.Intent, entry.Packages); err != nil {
			return err
		}
		group, err := assignmentTargetName(ctx, q, in.DeviceGroupID, in.UserID, in.UserGroupID)
		if err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		id := uuid.Must(uuid.NewV7())
		err = q.InsertSoftwareAssignment(ctx, pgstore.InsertSoftwareAssignmentParams{
			ID: id, OrganizationID: org, CatalogEntryID: entry.ID, DeviceGroupID: nullID(in.DeviceGroupID),
			UserID: nullID(in.UserID), UserGroupID: nullID(in.UserGroupID), Intent: in.Intent,
			UpdateRule: in.UpdateRule, Version: in.Version, Reason: in.Reason,
			CreatedBy: uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil},
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("this application is already assigned to this target")
		}
		// The entry or the target was deleted after the lookup.
		if db.IsForeignKeyViolation(err) {
			return problem.NotFound
		}
		if err != nil {
			return err
		}
		rec.SetTarget(assignmentTarget(id, entry.Name, group))
		rec.StateChanged(statechange.ScopeOrg, org)
		out, err = q.GetSoftwareAssignment(ctx, id)
		return err
	})
	return out, err
}

// UpdateAssignment replaces the intent, update rule, version and reason of an assignment (audited:
// software_assignment.updated with the old intent and version).
func (c *SoftwareCatalog) UpdateAssignment(ctx context.Context, id uuid.UUID, in AssignmentInput) (Assignment, error) {
	var out Assignment
	if in.UpdateRule == "" {
		in.UpdateRule = software.DefaultUpdateRule(in.Intent, in.Version)
	}
	spec := SpecSoftwareAssignmentUpdate
	spec.Target = &audit.Target{Type: "software_assignment", ID: id.String()}
	err := c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		pre, err := q.GetSoftwareAssignment(ctx, id)
		if err != nil {
			return notFound(err)
		}
		// The entry is locked first, as Update and Delete of the entry lock it before its assignments; the other
		// order could deadlock. The entry of an assignment never changes, so the unlocked read names the right one.
		entry, err := q.GetSoftwareCatalogEntryForUpdate(ctx, pre.CatalogEntryID)
		if err != nil {
			return notFound(err)
		}
		if _, err := q.GetSoftwareAssignmentForUpdate(ctx, id); err != nil {
			return notFound(err)
		}
		old, err := q.GetSoftwareAssignment(ctx, id)
		if err != nil {
			return notFound(err)
		}
		group, err := assignmentTargetName(ctx, q, groupPtr(old.DeviceGroupID), groupPtr(old.UserID), groupPtr(old.UserGroupID))
		if err != nil {
			return err
		}
		rec.SetTarget(assignmentTarget(id, old.AppName, group))
		for k, v := range assignmentParams(&old, AssignmentInput{
			CatalogEntryID: &old.CatalogEntryID, DeviceGroupID: groupPtr(old.DeviceGroupID), UserID: groupPtr(old.UserID),
			UserGroupID: groupPtr(old.UserGroupID), Intent: in.Intent, UpdateRule: in.UpdateRule, Version: in.Version,
			Reason: in.Reason,
		}) {
			rec.SetParam(k, v)
		}
		if in.CatalogEntryID != nil || in.DeviceGroupID != nil || in.UserID != nil || in.UserGroupID != nil {
			return problem.InvalidRequest.WithDetail("catalog_entry_id, device_group_id, user_id and user_group_id cannot be changed")
		}
		if err := software.ValidateAssignment(in.Intent, in.UpdateRule, in.Version, in.Reason); err != nil {
			return softwareAssignmentProblem(err)
		}
		if err := entryAssignable(in.Intent, entry.Packages); err != nil {
			return err
		}
		n, err := q.UpdateSoftwareAssignment(ctx, pgstore.UpdateSoftwareAssignmentParams{
			ID: id, Intent: in.Intent, UpdateRule: in.UpdateRule, Version: in.Version, Reason: in.Reason,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		rec.StateChanged(statechange.ScopeOrg, old.OrganizationID)
		out, err = q.GetSoftwareAssignment(ctx, id)
		return err
	})
	return out, err
}

// DeleteAssignment removes an assignment (audited: software_assignment.deleted); the devices stop enforcing it,
// installed software stays.
func (c *SoftwareCatalog) DeleteAssignment(ctx context.Context, id uuid.UUID) error {
	spec := SpecSoftwareAssignmentDelete
	spec.Target = &audit.Target{Type: "software_assignment", ID: id.String()}
	return c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if _, err := q.GetSoftwareAssignmentForUpdate(ctx, id); err != nil {
			return notFound(err)
		}
		old, err := q.GetSoftwareAssignment(ctx, id)
		if err != nil {
			return notFound(err)
		}
		group, err := assignmentTargetName(ctx, q, groupPtr(old.DeviceGroupID), groupPtr(old.UserID), groupPtr(old.UserGroupID))
		if err != nil {
			return err
		}
		rec.SetTarget(assignmentTarget(id, old.AppName, group))
		rec.SetParam("app", old.AppName)
		rec.SetParam("catalog_entry_id", old.CatalogEntryID.String())
		for k, v := range targetParams(groupPtr(old.DeviceGroupID), groupPtr(old.UserID), groupPtr(old.UserGroupID)) {
			rec.SetParam(k, v)
		}
		rec.SetParam("intent", old.Intent)
		n, err := q.DeleteSoftwareAssignment(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		rec.StateChanged(statechange.ScopeOrg, old.OrganizationID)
		return nil
	})
}

// entrySource returns the slug ("" for the distribution's own repositories) and the kind of the source an entry uses;
// a source of another organization or an unknown one is not found.
func entrySource(ctx context.Context, q *pgstore.Queries, source *uuid.UUID) (slug, kind string, err error) {
	if source == nil {
		return "", software.SourceKindAPT, nil
	}
	s, err := q.GetSoftwareSource(ctx, *source)
	if err != nil {
		return "", "", notFound(err)
	}
	return s.SoftwareSource.Slug, s.SoftwareSource.Kind, nil
}

// entryAssignable refuses an intent for an entry whose packages it must not touch (software.ValidateAssignmentTarget).
func entryAssignable(intent string, raw []byte) error {
	packages, err := software.DecodePackages(raw)
	if err != nil {
		return err
	}
	return softwareAssignmentProblem(software.ValidateAssignmentTarget(intent, packages))
}

// assignmentTargetName returns the name of an assignment's target: the device group's or the user group's name or
// the user's name ("" for the whole organization); a target of another organization or an unknown one is not found.
func assignmentTargetName(ctx context.Context, q *pgstore.Queries, deviceGroup, user, userGroup *uuid.UUID) (string, error) {
	switch {
	case deviceGroup != nil:
		g, err := q.GetDeviceGroup(ctx, *deviceGroup)
		if err != nil {
			return "", notFound(err)
		}
		return g.Name, nil
	case user != nil:
		u, err := q.GetAppUser(ctx, *user)
		if err != nil {
			return "", notFound(err)
		}
		return u.Username, nil
	case userGroup != nil:
		g, err := q.GetUserGroup(ctx, *userGroup)
		if err != nil {
			return "", notFound(err)
		}
		return g.Name, nil
	}
	return "", nil
}

// targetParams are the audit params that name an assignment's target (plan M13b §6.4); target is "" when more than
// one target ID is given, which the assignment rules refuse.
func targetParams(deviceGroup, user, userGroup *uuid.UUID) map[string]any {
	target, _ := software.Target(deviceGroup, user, userGroup)
	return map[string]any{
		"target": target, "device_group_id": idParam(deviceGroup), "user_id": idParam(user), "user_group_id": idParam(userGroup),
	}
}

func assignmentTarget(id uuid.UUID, app, group string) audit.Target {
	if group == "" {
		group = "organization"
	}
	return audit.Target{Type: "software_assignment", ID: id.String(), Display: app + " → " + group}
}

// assignmentParams are the audit params of an assignment as requested; old, when given, adds the stored intent and
// version and names the entry. Request text is bounded before it is validated: a refused request must not put
// arbitrary text into an immutable audit event.
func assignmentParams(old *Assignment, in AssignmentInput) map[string]any {
	params := map[string]any{
		"catalog_entry_id": idParam(in.CatalogEntryID),
		"intent":           software.DisplayParam(in.Intent, maxIntentParam), "update_rule": software.DisplayParam(in.UpdateRule, maxIntentParam),
		"version": nil, "reason": software.DisplayParam(in.Reason, software.MaxReasonLength),
	}
	maps.Copy(params, targetParams(in.DeviceGroupID, in.UserID, in.UserGroupID))
	if in.Version != nil {
		params["version"] = software.DisplayParam(*in.Version, software.MaxVersionLength)
	}
	if old != nil {
		params["app"] = old.AppName
		params["old_intent"] = old.Intent
		params["old_version"] = versionParam(old.Version)
	}
	return params
}

// entryFields names what a change of an entry changes.
func entryFields(old pgstore.GetSoftwareCatalogEntryForUpdateRow, oldPackages []software.PackageRef, in EntryInput) []string {
	fields := []string{}
	for _, f := range []struct {
		name    string
		changed bool
	}{
		{"name", in.Name != old.Name},
		{"description", in.Description != old.Description},
		{"category", in.Category != old.Category},
		{"source_id", nullID(in.SourceID) != old.SourceID},
		{"packages", !slices.Equal(in.Packages, oldPackages)},
	} {
		if f.changed {
			fields = append(fields, f.name)
		}
	}
	return fields
}

// validateIcon checks the icon with the catalog's rules: a larger or non-PNG body is invalid_request.
func validateIcon(icon []byte) error {
	return softwareRuleProblem(software.ValidateIcon(icon), software.ErrIcon)
}

// softwareEntryProblem and softwareAssignmentProblem map a validation error of the domain to invalid_request; the
// detail is the rule without the sentinel.
func softwareEntryProblem(err error) error {
	return softwareRuleProblem(err, software.ErrEntry)
}

func softwareAssignmentProblem(err error) error {
	return softwareRuleProblem(err, software.ErrAssignment)
}

func softwareRuleProblem(err, sentinel error) error {
	if errors.Is(err, sentinel) {
		return problem.InvalidRequest.WithDetail(strings.TrimPrefix(err.Error(), sentinel.Error()+": "))
	}
	return err
}
