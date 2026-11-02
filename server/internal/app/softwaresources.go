package app

import (
	"context"
	"errors"
	"fmt"
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

// Specs of the software source actions (plan M13a decision 4): a source is a root-equivalent trust anchor, so every
// change needs an organization administrator with a fresh step-up; API tokens never have one.
var (
	SpecSoftwareSourceCreate = ActionSpec{Code: audit.CodeSoftwareSourceCreated, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecSoftwareSourceUpdate = ActionSpec{Code: audit.CodeSoftwareSourceUpdated, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecSoftwareSourceDelete = ActionSpec{Code: audit.CodeSoftwareSourceDeleted, AllowedRoles: RolesAdmin, RequiresStepUp: true}
)

// SoftwareSources are the use cases of the organization's APT package sources (plan M13a decisions 1–6). The server
// never contacts a source.
type SoftwareSources struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewSoftwareSources creates the use cases.
func NewSoftwareSources(runner *ActionRunner, org *db.OrgPool) *SoftwareSources {
	return &SoftwareSources{runner: runner, org: org}
}

// List returns one page of sources; q matches name and slug.
func (s *SoftwareSources) List(ctx context.Context, page ListPage) (Listed[pgstore.SoftwareSource], error) {
	var out Listed[pgstore.SoftwareSource]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountSoftwareSources(ctx, pgstore.CountSoftwareSourcesParams{QPattern: page.QPattern, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count software sources: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListSoftwareSources(ctx, pgstore.ListSoftwareSourcesParams{
			QPattern: page.QPattern, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// Get returns one source with its signing key.
func (s *SoftwareSources) Get(ctx context.Context, id uuid.UUID) (pgstore.SoftwareSource, error) {
	var out pgstore.SoftwareSource
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetSoftwareSource(ctx, id)
		return notFound(err)
	})
	return out, err
}

// Create adds a source (audited: software_source.created). The typed fingerprint must equal the signing key's; the
// key policy is checked before the comparison, so a refused key answers invalid_request whatever was typed.
func (s *SoftwareSources) Create(ctx context.Context, in software.SourceInput) (pgstore.SoftwareSource, error) {
	var out pgstore.SoftwareSource
	in.Name = software.NormalizeName(in.Name)
	in.URIs, in.Suites, in.Components, in.Architectures = nonNil(in.URIs), nonNil(in.Suites), nonNil(in.Components), nonNil(in.Architectures)
	spec := SpecSoftwareSourceCreate
	spec.Params = map[string]any{
		"name": software.DisplayParam(in.Name, software.MaxNameLength), "slug": software.DisplayParam(in.Slug, maxSlugParam),
		"uris": displayParams(in.URIs, software.MaxURIs, software.MaxURILength), "suites": displayParams(in.Suites, software.MaxSuites, maxSuiteParam),
		"components":  displayParams(in.Components, software.MaxComponents, maxComponentParam),
		"fingerprint": software.DisplayParam(software.NormalizeFingerprint(in.Fingerprint), maxFingerprintParam),
	}
	err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		key, err := software.ValidateSource(in)
		if err != nil {
			return softwareSourceProblem(err)
		}
		rec.SetParam("fingerprint", key.Fingerprint)
		rec.SetParam("weak_key", key.WeakKey)
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		out, err = q.InsertSoftwareSource(ctx, pgstore.InsertSoftwareSourceParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Slug: in.Slug, Name: in.Name, Uris: in.URIs,
			Suites: in.Suites, Components: in.Components, Architectures: in.Architectures, SigningKey: key.SigningKey,
			Fingerprint: key.Fingerprint, WeakKey: key.WeakKey, CreatedBy: uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil},
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("a software source with this slug or name exists")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(sourceTarget(out))
		rec.StateChanged(statechange.ScopeOrg, org)
		return nil
	})
	return out, err
}

// SourceUpdate are the changes of a source; nil keeps the stored value. Slug is immutable and refused when given;
// SigningKey and Fingerprint only come together.
type SourceUpdate struct {
	Slug, Name                              *string
	URIs, Suites, Components, Architectures *[]string
	SigningKey, Fingerprint                 *string
}

// Update changes a source (audited: software_source.updated with the changed fields and the old and the new
// fingerprint). Every rule is checked on the merged state of the stored source and the change, so a change of the
// suites alone cannot leave a source that apt refuses.
func (s *SoftwareSources) Update(ctx context.Context, id uuid.UUID, in SourceUpdate) (pgstore.SoftwareSource, error) {
	var out pgstore.SoftwareSource
	spec := SpecSoftwareSourceUpdate
	spec.Target = &audit.Target{Type: "software_source", ID: id.String()}
	err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetSoftwareSourceForUpdate(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(sourceTarget(old))
		merged, fields := mergeSource(old, in)
		rec.SetParam("name", software.DisplayParam(merged.Name, software.MaxNameLength))
		rec.SetParam("slug", old.Slug)
		rec.SetParam("fields", fields)
		rec.SetParam("fingerprint", software.DisplayParam(software.NormalizeFingerprint(merged.Fingerprint), maxFingerprintParam))
		rec.SetParam("old_fingerprint", old.Fingerprint)
		switch {
		case in.Slug != nil:
			return problem.InvalidRequest.WithDetail("slug cannot be changed")
		case (in.SigningKey == nil) != (in.Fingerprint == nil):
			return problem.InvalidRequest.WithDetail("signing_key and fingerprint must be given together")
		}
		key, err := software.ValidateSource(merged)
		if err != nil {
			return softwareSourceProblem(err)
		}
		if key.SigningKey != old.SigningKey {
			rec.SetParam("fields", append(fields, "signing_key"))
		}
		rec.SetParam("fingerprint", key.Fingerprint)
		rec.SetParam("weak_key", key.WeakKey)
		out, err = q.UpdateSoftwareSource(ctx, pgstore.UpdateSoftwareSourceParams{
			ID: id, Name: merged.Name, Uris: merged.URIs, Suites: merged.Suites, Components: merged.Components,
			Architectures: merged.Architectures, SigningKey: key.SigningKey, Fingerprint: key.Fingerprint,
			WeakKey: key.WeakKey,
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("a software source with this name exists")
		}
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(sourceTarget(out))
		rec.StateChanged(statechange.ScopeOrg, out.OrganizationID)
		return nil
	})
	return out, err
}

// Delete removes a source (audited: software_source.deleted); the devices remove its source file and keyring.
func (s *SoftwareSources) Delete(ctx context.Context, id uuid.UUID) error {
	spec := SpecSoftwareSourceDelete
	spec.Target = &audit.Target{Type: "software_source", ID: id.String()}
	return s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetSoftwareSourceForUpdate(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(sourceTarget(old))
		rec.SetParam("name", old.Name)
		rec.SetParam("slug", old.Slug)
		rec.SetParam("fingerprint", old.Fingerprint)
		rec.SetParam("weak_key", old.WeakKey)
		n, err := q.DeleteSoftwareSource(ctx, id)
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

// mergeSource applies a change to a stored source and returns the result with the names of the fields whose value
// changed, except the signing key, which counts as changed only when its canonical form differs after validation.
// The stored fingerprint stands for the typed one when the key stays.
func mergeSource(old pgstore.SoftwareSource, in SourceUpdate) (software.SourceInput, []string) {
	m := software.SourceInput{
		Slug: old.Slug, Name: old.Name, URIs: old.Uris, Suites: old.Suites, Components: old.Components,
		Architectures: old.Architectures, SigningKey: old.SigningKey, Fingerprint: old.Fingerprint,
	}
	fields := []string{}
	if in.Name != nil && software.NormalizeName(*in.Name) != old.Name {
		m.Name = software.NormalizeName(*in.Name)
		fields = append(fields, "name")
	}
	for _, f := range []struct {
		name string
		in   *[]string
		dst  *[]string
	}{{"uris", in.URIs, &m.URIs}, {"suites", in.Suites, &m.Suites}, {"components", in.Components, &m.Components}, {"architectures", in.Architectures, &m.Architectures}} {
		if f.in != nil && !slices.Equal(*f.in, *f.dst) {
			*f.dst = nonNil(*f.in)
			fields = append(fields, f.name)
		}
	}
	if in.SigningKey != nil {
		m.SigningKey = *in.SigningKey
		if in.Fingerprint != nil {
			m.Fingerprint = *in.Fingerprint
		}
	}
	return m, fields
}

// Bounds of request text in the audit params beyond the domain's limits: the slug and suite patterns' maximum, a
// component's, and a typed fingerprint with its group separators.
const (
	maxSlugParam        = 41
	maxSuiteParam       = 64
	maxComponentParam   = 32
	maxFingerprintParam = 64
)

// displayParams bounds a list of request values for the audit params (software.DisplayParam per value); a longer list
// is cut to maxItems and ends in "…".
func displayParams(values []string, maxItems, maxRunes int) []string {
	out := make([]string, 0, min(len(values), maxItems+1))
	for i, v := range values {
		if i == maxItems {
			return append(out, "…")
		}
		out = append(out, software.DisplayParam(v, maxRunes))
	}
	return out
}

// softwareSourceProblem maps a validation error of the domain to its problem; the detail is the rule without the sentinel.
func softwareSourceProblem(err error) error {
	if errors.Is(err, software.ErrFingerprint) {
		return problem.FingerprintMismatch.WithDetail(strings.TrimPrefix(err.Error(), software.ErrFingerprint.Error()+": "))
	}
	if errors.Is(err, software.ErrSource) {
		return problem.InvalidRequest.WithDetail(strings.TrimPrefix(err.Error(), software.ErrSource.Error()+": "))
	}
	return err
}

func sourceTarget(s pgstore.SoftwareSource) audit.Target {
	return audit.Target{Type: "software_source", ID: s.ID.String(), Display: s.Name}
}
