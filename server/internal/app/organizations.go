package app

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/ports"
	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// Organizations are the platform use cases.
type Organizations struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	idp      ports.IdentityProvider
}

// NewOrganizations creates the use cases.
func NewOrganizations(runner *ActionRunner, platform *db.PlatformPool, idp ports.IdentityProvider) *Organizations {
	return &Organizations{runner: runner, platform: platform, idp: idp}
}

// SpecOrganizationCreate is the privileged action organization.created.
var SpecOrganizationCreate = ActionSpec{Code: audit.CodeOrganizationCreated, AllowedRoles: RolesPlatform}

// OrganizationPage is one page of organizations.
type OrganizationPage struct {
	Items      []pgstore.Organization
	NextCursor *string
}

// List returns one page, newest first.
func (o *Organizations) List(ctx context.Context, cursor *string, limit *int) (OrganizationPage, error) {
	if _, err := RequirePlatform(ctx); err != nil {
		return OrganizationPage{}, err
	}
	before, err := DecodeCursor(cursor)
	if err != nil {
		return OrganizationPage{}, err
	}
	n, err := PageLimit(limit)
	if err != nil {
		return OrganizationPage{}, err
	}
	var page OrganizationPage
	err = o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.ListOrganizations(ctx, pgstore.ListOrganizationsParams{Before: before, MaxRows: n + 1})
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

// Get returns one organization.
func (o *Organizations) Get(ctx context.Context, id uuid.UUID) (pgstore.Organization, error) {
	if _, err := RequirePlatform(ctx); err != nil {
		return pgstore.Organization{}, err
	}
	var org pgstore.Organization
	err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		org, err = q.GetOrganization(ctx, id)
		return notFound(err)
	})
	return org, err
}

// Create creates an organization and its Authentik groups (audited: organization.created). An organization in
// status provisioning_failed with the same slug is re-provisioned; reprovisioned reports that case.
func (o *Organizations) Create(ctx context.Context, slug, name string) (org pgstore.Organization, reprovisioned bool, err error) {
	slug = strings.TrimSpace(slug)
	name = strings.TrimSpace(name)
	spec := SpecOrganizationCreate
	spec.Params = map[string]any{"slug": slug, "name": name}
	err = o.runner.RunExternal(ctx, ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			if err := organization.ValidateSlug(slug); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := organization.ValidateName(name); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			existing, err := q.GetOrganizationBySlug(ctx, slug)
			switch {
			case err == nil && existing.Status == organization.StatusProvisioningFailed:
				reprovisioned = true
				org, err = q.UpdateOrganizationStatus(ctx, pgstore.UpdateOrganizationStatusParams{
					ID: existing.ID, Name: name, Status: organization.StatusProvisioning,
				})
				if err != nil {
					return err
				}
			case err == nil:
				return problem.SlugTaken.WithDetail("an organization with this slug exists")
			case db.IsNoRows(err):
				org, err = q.InsertOrganization(ctx, pgstore.InsertOrganizationParams{
					ID: uuid.Must(uuid.NewV7()), Slug: slug, Name: name, Status: organization.StatusProvisioning,
				})
				if db.IsUniqueViolation(err, "") {
					return problem.SlugTaken.WithDetail("an organization with this slug exists")
				}
				if err != nil {
					return err
				}
			default:
				return err
			}
			rec.SetOrganization(org.ID)
			rec.SetTarget(audit.Target{Type: "organization", ID: org.ID.String(), Display: org.Slug})
			rec.SetParam("reprovisioned", reprovisioned)
			return nil
		},
		func(ctx context.Context) error {
			_, err := o.idp.EnsureOrganization(ctx, slug)
			return err
		},
		func(ctx context.Context, q *pgstore.Queries, _ Recorder, externalErr error) error {
			status := organization.StatusActive
			if externalErr != nil {
				status = organization.StatusProvisioningFailed
			}
			var err error
			org, err = q.UpdateOrganizationStatus(ctx, pgstore.UpdateOrganizationStatusParams{ID: org.ID, Name: org.Name, Status: status})
			return err
		})
	return org, reprovisioned, err
}

// orgOf returns the organization of the principal.
func orgOf(ctx context.Context) (uuid.UUID, error) {
	p, ok := principal.From(ctx)
	if !ok || p.OrganizationID == uuid.Nil {
		return uuid.Nil, problem.NoOrganization
	}
	return p.OrganizationID, nil
}
