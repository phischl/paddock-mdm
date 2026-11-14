package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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

// ProvisioningBudget bounds the identity provider provisioning of one organization create: long enough for an
// Authentik under load including retries, well short of the server's write timeout of 120 s (PDK-351).
const ProvisioningBudget = 60 * time.Second

// Organizations are the platform use cases.
type Organizations struct {
	runner     *ActionRunner
	platform   *db.PlatformPool
	idp        ports.IdentityProvider
	uninstalls *Uninstalls
	// development allows a deletion without grace period (PADDOCK_ENV=development, plan M17 decision 2).
	development bool
	budget      time.Duration
	// deletionBudget bounds issuing and withdrawing the devices' uninstalls (DeletionRequestBudget).
	deletionBudget time.Duration
	now            func() time.Time
}

// NewOrganizations creates the use cases; uninstalls issues and withdraws the devices' uninstalls of a deletion
// request, development allows grace_days 0.
func NewOrganizations(runner *ActionRunner, platform *db.PlatformPool, idp ports.IdentityProvider, uninstalls *Uninstalls,
	development bool) *Organizations {
	return &Organizations{runner: runner, platform: platform, idp: idp, uninstalls: uninstalls, development: development,
		budget: ProvisioningBudget, deletionBudget: DeletionRequestBudget, now: time.Now}
}

// WithDeletionRequestBudget changes the budget of issuing and withdrawing the devices' uninstalls (tests).
func (o *Organizations) WithDeletionRequestBudget(d time.Duration) *Organizations {
	o.deletionBudget = d
	return o
}

// WithProvisioningBudget changes the provisioning budget (tests).
func (o *Organizations) WithProvisioningBudget(d time.Duration) *Organizations {
	o.budget = d
	return o
}

// Specs of the privileged platform actions on organizations.
var (
	SpecOrganizationCreate     = ActionSpec{Code: audit.CodeOrganizationCreated, AllowedRoles: RolesPlatform}
	SpecOrganizationSetDomains = ActionSpec{Code: audit.CodeOrganizationDomainsChanged, AllowedRoles: RolesPlatform}
	// SpecOrganizationDeletionRequest and SpecOrganizationDeletionCancel are recorded in the platform
	// pseudo-organization (plan M17 decision 19).
	SpecOrganizationDeletionRequest = ActionSpec{Code: audit.CodeOrganizationDeletionRequested, AllowedRoles: RolesPlatform,
		RequiresStepUp: true}
	SpecOrganizationDeletionCancel = ActionSpec{Code: audit.CodeOrganizationDeletionCancelled, AllowedRoles: RolesPlatform}
)

// DeletionRequestBudget bounds how long a deletion request issues the devices' uninstalls.
const DeletionRequestBudget = 2 * time.Minute

// DeletionRequestStale is how long after a deletion request without recorded uninstall counts a cancel is refused as
// still in progress: well beyond DeletionRequestBudget, so only a request whose process died is cancelled this way.
const DeletionRequestStale = 10 * time.Minute

// DeletionInput is a deletion request of a platform administrator (plan M17 §6).
type DeletionInput struct {
	ConfirmSlug string
	Reason      string
	GraceDays   int
}

// List returns one page of organizations, optionally limited to statuses, and the capped number of matches
// (ADR 0018).
func (o *Organizations) List(ctx context.Context, page ListPage, statuses []string) (Listed[pgstore.Organization], error) {
	var out Listed[pgstore.Organization]
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	if len(statuses) == 0 {
		statuses = organization.ListedByDefault()
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
			// Provisioning outlives a client that gave up (a closed dialog, a proxy timeout): a half-done provisioning
			// is not abandoned and its outcome is recorded. The budget bounds it instead.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.budget)
			defer cancel()
			_, err := o.idp.EnsureOrganization(ctx, slug)
			if err != nil && ctx.Err() != nil && !errors.Is(err, problem.UpstreamUnavailable) {
				return fmt.Errorf("%w: provisioning exceeded %s: %w", problem.UpstreamUnavailable, o.budget, err)
			}
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

// RequestDeletion starts the deletion of an organization (audited in the platform pseudo-organization:
// organization.deletion_requested, with a step-up; plan M17 decisions 1–3, ADR 0052 decisions 1 and 2). The first
// transaction checks the typed slug, the reason and the grace period and makes the deletion pending; the second issues
// the uninstall leave to every active device as the system; the third records the counts. When issuing fails, the
// pending deletion is withdrawn again, so a pending deletion always has its uninstalls.
func (o *Organizations) RequestDeletion(ctx context.Context, id uuid.UUID, in DeletionInput) (pgstore.Organization, error) {
	spec := SpecOrganizationDeletionRequest
	spec.Target = &audit.Target{Type: "organization", ID: id.String()}
	spec.Params = map[string]any{"reason": in.Reason, "grace_days": in.GraceDays}
	var out pgstore.Organization
	var issued, skipped int
	err := o.runner.RunExternal(ctx, ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, err := q.GetOrganization(ctx, id)
			if err != nil {
				return notFound(err)
			}
			rec.SetTarget(audit.Target{Type: "organization", ID: cur.ID.String(), Display: cur.Slug})
			rec.SetParam("slug", cur.Slug)
			if in.ConfirmSlug != cur.Slug {
				return problem.InvalidRequest.WithDetail("confirm_slug does not match the organization's slug")
			}
			if err := organization.ValidateDeletionReason(in.Reason); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := organization.ValidateGraceDays(in.GraceDays, o.development); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if !organization.Deletable(cur.Status) || cur.DeleteAfter != nil {
				return errNotDeletable(cur)
			}
			by := actorDisplay(ctx)
			out, err = q.RequestOrganizationDeletion(ctx, pgstore.RequestOrganizationDeletionParams{
				ID: id, RequestedBy: &by, Reason: &in.Reason, GraceDays: int32(in.GraceDays), //nolint:gosec // bounded to 0–90 above
			})
			if db.IsNoRows(err) {
				return problem.InvalidState.WithDetail("a deletion is already requested")
			}
			if err != nil {
				return err
			}
			rec.SetParam("delete_after", out.DeleteAfter.UTC().Format(time.RFC3339))
			return nil
		},
		func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, o.deletionBudget)
			defer cancel()
			var err error
			issued, skipped, err = o.uninstalls.requestForOffboarding(offboardingContext(ctx, id),
				out.DeleteAfter.Add(organization.OffboardedDeviceRetention))
			return err
		},
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
			if externalErr != nil {
				if _, err := q.CancelOrganizationDeletion(ctx, id); err != nil && !db.IsNoRows(err) {
					return err
				}
				return nil
			}
			// Set before the statement that can fail: a failure event still states how many devices were told to leave
			// (plan M17 amendment e point 13).
			rec.SetParam("uninstalls_issued", issued)
			rec.SetParam("uninstalls_skipped", skipped)
			row, err := q.SetOrganizationDeletionUninstalls(ctx, pgstore.SetOrganizationDeletionUninstallsParams{
				ID: id, RequestedAt: out.DeletionRequestedAt, Issued: int32(issued), Skipped: int32(skipped), //nolint:gosec // device counts
			})
			if db.IsNoRows(err) {
				return problem.InvalidState.WithDetail("the deletion was cancelled while its uninstalls were issued")
			}
			if err != nil {
				return err
			}
			out = row
			return nil
		})
	return out, err
}

// CancelDeletion cancels the pending deletion of an organization (audited in the platform pseudo-organization:
// organization.deletion_cancelled; plan M17 decision 4). It holds the organization row while it withdraws the
// offboarding uninstalls the devices have not received, so the worker cannot start the deletion meanwhile; the
// deletion columns are cleared last, so a failure leaves the deletion pending and the cancel can be repeated.
func (o *Organizations) CancelDeletion(ctx context.Context, id uuid.UUID) (pgstore.Organization, error) {
	spec := SpecOrganizationDeletionCancel
	spec.Target = &audit.Target{Type: "organization", ID: id.String()}
	var out pgstore.Organization
	err := o.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockOrganization(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "organization", ID: cur.ID.String(), Display: cur.Slug})
		rec.SetParam("slug", cur.Slug)
		if !organization.DeletionPending(cur.Status, cur.DeleteAfter) {
			return problem.InvalidState.WithDetail("no deletion is pending")
		}
		if cur.DeletionUninstallsIssued == nil && cur.DeletionRequestedAt != nil &&
			o.now().Sub(*cur.DeletionRequestedAt) < DeletionRequestStale {
			return problem.InvalidState.WithDetail("the deletion request is still issuing its uninstalls")
		}
		// On timeout the organization transaction rolls back and so does this one: the deletion stays pending.
		bounded, cancel := context.WithTimeout(ctx, o.deletionBudget)
		defer cancel()
		cancelled, err := o.uninstalls.cancelForOffboarding(offboardingContext(bounded, id))
		if err != nil {
			return err
		}
		rec.SetParam("uninstalls_cancelled", cancelled)
		out, err = q.CancelOrganizationDeletion(ctx, id)
		return err
	})
	return out, err
}

// errNotDeletable is the refusal of a deletion request for an organization whose state does not allow one.
func errNotDeletable(cur pgstore.Organization) error {
	if cur.DeleteAfter != nil && organization.Deletable(cur.Status) {
		return problem.InvalidState.WithDetail("a deletion is already requested")
	}
	return problem.InvalidState.WithDetail("an organization in status " + cur.Status + " cannot be deleted")
}

// offboardingContext is the organization context in which a deletion request and its cancel issue and withdraw the
// devices' uninstalls as the system (ADR 0052 decision 2). org is the organization the platform action loaded through
// the platform pool, never a value the caller supplies to the organization pool.
func offboardingContext(ctx context.Context, org uuid.UUID) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "organization-offboarding",
		OrganizationID: org})
}

// orgOf returns the organization of the principal.
func orgOf(ctx context.Context) (uuid.UUID, error) {
	p, ok := principal.From(ctx)
	if !ok || p.OrganizationID == uuid.Nil {
		return uuid.Nil, problem.NoOrganization
	}
	return p.OrganizationID, nil
}
