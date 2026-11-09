package app

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// The software sections of the declarative configuration (plan M13c decisions 1–3): sources, catalog entries and
// assignments in document form, executed with the rules of SoftwareSources and SoftwareCatalog.

// loadSoftwareConfig reads the software sections into doc and st. groups, slugs and usernames name the device groups,
// user groups and users by ID.
func loadSoftwareConfig(ctx context.Context, q *pgstore.Queries, st *configState, doc *declarative.Document,
	groups, slugs, usernames map[uuid.UUID]string) error {
	sources, err := q.ListAllSoftwareSources(ctx)
	if err != nil {
		return fmt.Errorf("software sources: %w", err)
	}
	sourceSlugs := map[uuid.UUID]string{}
	srcs := make([]declarative.SoftwareSource, 0, len(sources))
	for _, s := range sources {
		item := declarative.SoftwareSource{Slug: s.Slug, Kind: s.Kind, Name: s.Name, URIs: nonNil(s.Uris),
			Suites: nonNil(s.Suites), Components: nonNil(s.Components), Architectures: nonNil(s.Architectures),
			SigningKey: s.SigningKey, Fingerprint: s.Fingerprint}
		st.ids[declarative.SectionSoftwareSources][item.Key().String()] = s.ID
		st.sources[s.Slug], sourceSlugs[s.ID] = s.ID, s.Slug
		srcs = append(srcs, item)
	}
	doc.SoftwareSources = &srcs

	entries, err := q.ListAllSoftwareCatalogEntries(ctx)
	if err != nil {
		return fmt.Errorf("software catalog: %w", err)
	}
	entryNames := map[uuid.UUID]string{}
	cat := make([]declarative.SoftwareCatalogEntry, 0, len(entries))
	for _, e := range entries {
		packages, err := software.DecodePackages(e.Packages)
		if err != nil {
			return fmt.Errorf("catalog entry %s: %w", e.ID, err)
		}
		item := declarative.SoftwareCatalogEntry{Name: e.Name, Description: e.Description, Category: e.Category,
			Packages: packages}
		if e.Approval != software.ApprovalNone {
			item.Approval = e.Approval
		}
		if e.SourceID.Valid {
			slug := sourceSlugs[e.SourceID.UUID]
			item.Source = &slug
		}
		st.ids[declarative.SectionSoftwareCatalog][item.Key().String()] = e.ID
		st.entries[e.Name], entryNames[e.ID] = e.ID, e.Name
		cat = append(cat, item)
	}
	doc.SoftwareCatalog = &cat

	assignments, err := q.ListAllSoftwareAssignments(ctx)
	if err != nil {
		return fmt.Errorf("software assignments: %w", err)
	}
	sas := make([]declarative.SoftwareAssignment, 0, len(assignments))
	for _, a := range assignments {
		target := declarative.SoftwareTarget{Type: software.TargetOrganization}
		switch {
		case a.DeviceGroupID.Valid:
			target = declarative.SoftwareTarget{Type: software.TargetDeviceGroup, Name: groups[a.DeviceGroupID.UUID]}
		case a.UserID.Valid:
			target = declarative.SoftwareTarget{Type: software.TargetUser, Username: usernames[a.UserID.UUID]}
		case a.UserGroupID.Valid:
			target = declarative.SoftwareTarget{Type: software.TargetUserGroup, Slug: slugs[a.UserGroupID.UUID]}
		}
		item := declarative.SoftwareAssignment{Entry: entryNames[a.CatalogEntryID], Target: target, Intent: a.Intent,
			UpdateRule: a.UpdateRule, Version: a.Version, Reason: a.Reason}
		st.ids[declarative.SectionSoftwareAssignments][item.Key().String()] = a.ID
		sas = append(sas, item)
	}
	doc.SoftwareAssignments = &sas
	return nil
}

// normalizeSoftware brings the software sections into the form the per-resource use cases store, so that a document
// written by hand shows no change against its export: trimmed names, the source key in its stored armor and the
// fingerprint without spaces, the scope of system Flatpak references, and the derived update rule.
func normalizeSoftware(doc *declarative.Document) {
	if doc.SoftwareSources != nil {
		for i, s := range *doc.SoftwareSources {
			s.Name = software.NormalizeName(s.Name)
			s.URIs, s.Suites, s.Components, s.Architectures = nonNil(s.URIs), nonNil(s.Suites), nonNil(s.Components), nonNil(s.Architectures)
			s.SigningKey, _ = software.CanonicalSigningKey(s.SigningKey)
			s.Fingerprint = software.NormalizeFingerprint(s.Fingerprint)
			(*doc.SoftwareSources)[i] = s
		}
	}
	if doc.SoftwareCatalog != nil {
		for i, e := range *doc.SoftwareCatalog {
			e.Name, e.Category = software.NormalizeName(e.Name), software.NormalizeCategory(e.Category)
			e.Packages = software.NormalizePackages(e.Packages)
			if e.Approval == software.ApprovalNone {
				e.Approval = ""
			}
			(*doc.SoftwareCatalog)[i] = e
		}
	}
	if doc.SoftwareAssignments != nil {
		for i, a := range *doc.SoftwareAssignments {
			if a.UpdateRule == "" {
				a.UpdateRule = software.DefaultUpdateRule(a.Intent, a.Version)
			}
			(*doc.SoftwareAssignments)[i] = a
		}
	}
}

// requireSourceStepUp is the rule of the source endpoints for a plan that changes software sources (plan M13c
// decision 2): an organization administrator with a fresh step-up, which an API token never has. A dry run checks the
// role only; its plan names the section in requires_step_up instead of refusing.
func (ex *configExec) requireSourceStepUp() error {
	if ex.planOnly {
		if ex.p.APITokenID != uuid.Nil {
			return nil
		}
		return ex.requireAdmin("change software sources")
	}
	return ex.requireAdminStepUp("may change software sources")
}

func (ex *configExec) softwareSource(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		id := ex.id(c)
		if _, err := ex.q.GetSoftwareSourceForUpdate(ctx, id); err != nil {
			return notFound(err)
		}
		used, err := ex.q.CountSoftwareCatalogEntriesBySource(ctx, uuid.NullUUID{UUID: id, Valid: true})
		if err != nil {
			return err
		}
		if used > 0 {
			return problem.InUse.WithDetail("a catalog entry uses this source; change or delete the entry first")
		}
		_, err = ex.q.DeleteSoftwareSource(ctx, id)
		return err
	}
	s := (*ex.desired.SoftwareSources)[ex.item(c)]
	in := software.SourceInput{Kind: s.Kind, Slug: s.Slug, Name: s.Name, URIs: s.URIs, Suites: s.Suites,
		Components: s.Components, Architectures: s.Architectures, SigningKey: s.SigningKey, Fingerprint: s.Fingerprint}
	key, err := software.ValidateSource(in)
	if err != nil {
		return softwareSourceProblem(err)
	}
	if c.Action == declarative.ActionCreate {
		var row pgstore.SoftwareSource
		row, err = ex.q.InsertSoftwareSource(ctx, pgstore.InsertSoftwareSourceParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, Kind: in.Kind, Slug: in.Slug, Name: in.Name,
			Uris: in.URIs, Suites: in.Suites, Components: in.Components, Architectures: in.Architectures,
			SigningKey: key.SigningKey, Fingerprint: key.Fingerprint, WeakKey: key.WeakKey,
			CreatedBy: uuid.NullUUID{UUID: ex.p.ID, Valid: ex.p.ID != uuid.Nil},
		})
		if err == nil {
			ex.st.sources[row.Slug] = row.ID
		}
	} else {
		old, gerr := ex.q.GetSoftwareSourceForUpdate(ctx, ex.id(c))
		if gerr != nil {
			return notFound(gerr)
		}
		if old.Kind != in.Kind {
			return problem.InvalidRequest.WithDetail("kind cannot be changed; delete the source and create it again")
		}
		_, err = ex.q.UpdateSoftwareSource(ctx, pgstore.UpdateSoftwareSourceParams{
			ID: old.ID, Name: in.Name, Uris: in.URIs, Suites: in.Suites, Components: in.Components,
			Architectures: in.Architectures, SigningKey: key.SigningKey, Fingerprint: key.Fingerprint, WeakKey: key.WeakKey,
		})
	}
	if db.IsUniqueViolation(err, "") {
		return problem.AlreadyExists.WithDetail("a software source with this slug or name exists")
	}
	return err
}

func (ex *configExec) softwareEntry(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		id := ex.id(c)
		if _, err := ex.q.GetSoftwareCatalogEntryForUpdate(ctx, id); err != nil {
			return notFound(err)
		}
		// guardEntryDeletions checked the configuration as read; an assignment added since then is refused here, under
		// the entry's lock, instead of going with the entry (ON DELETE CASCADE).
		row, err := ex.q.GetSoftwareCatalogEntry(ctx, id)
		if err != nil {
			return notFound(err)
		}
		if err := requireEntryUnassigned(ctx, ex.q, id, row.Name, row.AssignmentCount); err != nil {
			return err
		}
		_, err = ex.q.DeleteSoftwareCatalogEntry(ctx, id)
		return err
	}
	e := (*ex.desired.SoftwareCatalog)[ex.item(c)]
	if err := software.ValidateEntry(e.Name, e.Description, e.Category, e.Packages); err != nil {
		return softwareEntryProblem(err)
	}
	approval := software.ApprovalNone
	if e.Approval != "" {
		approval = e.Approval
	}
	if !software.ValidApproval(approval) {
		return problem.InvalidRequest.WithDetail("approval of catalog entry " + strconv.Quote(e.Name) + " must be none or required")
	}
	var source *uuid.UUID
	if e.Source != nil {
		id, ok := ex.st.sources[*e.Source]
		if !ok {
			return problem.InvalidRequest.WithDetail("software source " + strconv.Quote(*e.Source) + " does not exist")
		}
		source = &id
	}
	_, kind, err := entrySource(ctx, ex.q, source)
	if err != nil {
		return err
	}
	if err := software.ValidatePackages(kind, e.Packages); err != nil {
		return softwareEntryProblem(err)
	}
	packages, err := json.Marshal(e.Packages)
	if err != nil {
		return fmt.Errorf("encode package references: %w", err)
	}
	if c.Action == declarative.ActionCreate {
		id := uuid.Must(uuid.NewV7())
		err = ex.q.InsertSoftwareCatalogEntry(ctx, pgstore.InsertSoftwareCatalogEntryParams{
			ID: id, OrganizationID: ex.p.OrganizationID, Name: e.Name, Description: e.Description, Category: e.Category,
			SourceID: nullID(source), Packages: packages, Approval: approval,
			CreatedBy: uuid.NullUUID{UUID: ex.p.ID, Valid: ex.p.ID != uuid.Nil},
		})
		if err == nil {
			ex.st.entries[e.Name] = id
		}
	} else {
		id := ex.id(c)
		if _, err := ex.q.GetSoftwareCatalogEntryForUpdate(ctx, id); err != nil {
			return notFound(err)
		}
		var intents []string
		if intents, err = ex.q.ListSoftwareAssignmentIntentsOfEntry(ctx, id); err != nil {
			return err
		}
		for _, intent := range intents {
			if err := software.ValidateAssignmentTarget(intent, e.Packages); err != nil {
				return softwareAssignmentProblem(err)
			}
		}
		_, err = ex.q.UpdateSoftwareCatalogEntry(ctx, pgstore.UpdateSoftwareCatalogEntryParams{
			ID: id, Name: e.Name, Description: e.Description, Category: e.Category, SourceID: nullID(source), Packages: packages,
			Approval: approval,
		})
	}
	if db.IsUniqueViolation(err, "") {
		return problem.AlreadyExists.WithDetail("a catalog entry with this name exists")
	}
	return err
}

func (ex *configExec) softwareAssignment(ctx context.Context, c declarative.Change) error {
	if c.Action == declarative.ActionDelete {
		_, err := ex.q.DeleteSoftwareAssignment(ctx, ex.id(c))
		return err
	}
	a := (*ex.desired.SoftwareAssignments)[ex.item(c)]
	if err := software.ValidateAssignment(a.Intent, a.UpdateRule, a.Version, a.Reason); err != nil {
		return softwareAssignmentProblem(err)
	}
	entryID, ok := ex.st.entries[a.Entry]
	if !ok {
		return problem.InvalidRequest.WithDetail("catalog entry " + strconv.Quote(a.Entry) + " does not exist")
	}
	// Locked as SoftwareCatalog locks it, so a concurrent package change cannot slip past the intent check.
	entry, err := ex.q.GetSoftwareCatalogEntryForUpdate(ctx, entryID)
	if err != nil {
		return notFound(err)
	}
	if err := entryAssignable(a.Intent, entry.Packages); err != nil {
		return err
	}
	if c.Action == declarative.ActionUpdate {
		params := pgstore.UpdateSoftwareAssignmentParams{
			ID: ex.id(c), Intent: a.Intent, UpdateRule: a.UpdateRule, Version: a.Version, Reason: a.Reason,
		}
		// The document cannot carry urgent and an apply has no step-up, so an urgent assignment whose effect changes
		// loses the flag; otherwise an apply could repurpose it to run outside the windows (plan M13c decision 7).
		if repurposesAssignment(c) {
			params.Urgent = new(false)
		}
		_, err := ex.q.UpdateSoftwareAssignment(ctx, params)
		return err
	}
	var group, user, userGroup *uuid.UUID
	switch a.Target.Type {
	case software.TargetDeviceGroup:
		if group, err = ex.group(&a.Target.Name); err != nil {
			return err
		}
	case software.TargetUser:
		id, ok := ex.st.users[a.Target.Username]
		if !ok {
			return problem.InvalidRequest.WithDetail("unknown user " + strconv.Quote(a.Target.Username))
		}
		user = &id
	case software.TargetUserGroup:
		id, ok := ex.st.userGroups[a.Target.Slug]
		if !ok {
			return problem.InvalidRequest.WithDetail("unknown group " + strconv.Quote(a.Target.Slug))
		}
		userGroup = &id
	}
	err = ex.q.InsertSoftwareAssignment(ctx, pgstore.InsertSoftwareAssignmentParams{
		ID: uuid.Must(uuid.NewV7()), OrganizationID: ex.p.OrganizationID, CatalogEntryID: entryID,
		DeviceGroupID: nullID(group), UserID: nullID(user), UserGroupID: nullID(userGroup), Intent: a.Intent,
		UpdateRule: a.UpdateRule, Version: a.Version, Reason: a.Reason,
		CreatedBy: uuid.NullUUID{UUID: ex.p.ID, Valid: ex.p.ID != uuid.Nil},
	})
	if db.IsUniqueViolation(err, "") {
		return problem.AlreadyExists.WithDetail("this application is already assigned to this target")
	}
	return err
}

// repurposesAssignment reports whether an assignment update changes what the assignment does on a device, as opposed
// to a change of its reason alone.
func repurposesAssignment(c declarative.Change) bool {
	for _, f := range c.Fields {
		switch f.Name {
		case "intent", "update_rule", "version":
			return true
		}
	}
	return false
}

// guardEntryDeletions refuses a plan that deletes a catalog entry (a rename in a document is the deletion of the old
// name) while the configuration as read still has assignments of it, even when the plan deletes them too: their
// removal is an assignment change that rolls out in waves, and the entry may go only once none is left (plan M13c
// amendment 2026-11-09, A10-12). The refusal is 409 in_use and names the assignments by target. The revert of the open
// rollout's change set is the rollback itself and must always be possible (A10-13): there only the assignments the
// plan keeps count; the plan deletes the others before the entry, so the locked re-check sees none of them.
func (ex *configExec) guardEntryDeletions(plan declarative.Plan) error {
	if ex.st.doc.SoftwareAssignments == nil {
		return nil
	}
	deleted := map[string]bool{}
	if ex.endsRollout {
		for _, c := range plan.Changes {
			if c.Section == declarative.SectionSoftwareAssignments && c.Action == declarative.ActionDelete {
				deleted[c.Key] = true
			}
		}
	}
	for _, c := range plan.Changes {
		if c.Section != declarative.SectionSoftwareCatalog || c.Action != declarative.ActionDelete {
			continue
		}
		var name string
		var named []string
		for _, a := range *ex.st.doc.SoftwareAssignments {
			if ex.st.entries[a.Entry] == ex.id(c) && !deleted[a.Key().String()] {
				name = a.Entry
				named = append(named, assignmentTargetText(a.Target.Type, cmp.Or(a.Target.Name, a.Target.Username, a.Target.Slug)))
			}
		}
		if len(named) > 0 {
			// Sorted, the text orders by target type and name like the per-resource refusal.
			slices.Sort(named)
			return atPath(ex.path(c), entryInUse(name, len(named), named[:min(len(named), maxNamedAssignments)]))
		}
	}
	return nil
}
