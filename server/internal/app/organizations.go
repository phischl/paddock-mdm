package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
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

// Specs of the privileged platform actions on organizations.
var (
	SpecOrganizationCreate     = ActionSpec{Code: audit.CodeOrganizationCreated, AllowedRoles: RolesPlatform}
	SpecOrganizationSetDomains = ActionSpec{Code: audit.CodeOrganizationDomainsChanged, AllowedRoles: RolesPlatform}
)

// List returns one page of organizations, optionally limited to statuses, and the capped number of matches
// (ADR 0018).
func (o *Organizations) List(ctx context.Context, page ListPage, statuses []string) (Listed[pgstore.Organization], error) {
	var out Listed[pgstore.Organization]
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountOrganizations(ctx, pgstore.CountOrganizationsParams{
			QPattern: page.QPattern, Statuses: statuses, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count organizations: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListOrganizations(ctx, pgstore.ListOrganizationsParams{
			QPattern: page.QPattern, Statuses: statuses, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list organizations: %w", err)
		}
		return nil
	})
	return out, err
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

// SetDomains replaces the domains of an organization (plan M3a decision 1, audited in the organization:
// organization.domains_changed). A domain of another organization is 409 domain_taken. The organization's devices
// are recompiled (the primary domain is part of the login resource).
func (o *Organizations) SetDomains(ctx context.Context, id uuid.UUID, domains []string) (pgstore.Organization, error) {
	spec := SpecOrganizationSetDomains
	spec.Target = &audit.Target{Type: "organization", ID: id.String()}
	normalized := make([]string, len(domains))
	for i, d := range domains {
		normalized[i] = strings.ToLower(strings.TrimSpace(d))
	}
	var out pgstore.Organization
	err := o.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.GetOrganization(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetOrganization(cur.ID)
		rec.SetTarget(audit.Target{Type: "organization", ID: cur.ID.String(), Display: cur.Slug})
		rec.SetParam("slug", cur.Slug)
		rec.SetParam("domains", normalized)
		rec.SetParam("old_domains", cur.Domains)
		if err := organization.ValidateDomains(normalized); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if err := q.LockOrganizationDomains(ctx); err != nil {
			return err
		}
		others, err := q.ListOrganizationsClaimingDomains(ctx, pgstore.ListOrganizationsClaimingDomainsParams{Domains: normalized, ID: id})
		if err != nil {
			return err
		}
		if len(others) > 0 {
			return problem.DomainTaken.WithDetail("a domain belongs to another organization")
		}
		if out, err = q.UpdateOrganizationDomains(ctx, pgstore.UpdateOrganizationDomainsParams{ID: id, Domains: normalized}); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, id)
		return nil
	})
	return out, err
}

// orgOf returns the organization of the principal.
func orgOf(ctx context.Context) (uuid.UUID, error) {
	p, ok := principal.From(ctx)
	if !ok || p.OrganizationID == uuid.Nil {
		return uuid.Nil, problem.NoOrganization
	}
	return p.OrganizationID, nil
}
