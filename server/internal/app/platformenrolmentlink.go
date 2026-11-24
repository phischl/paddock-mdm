package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// specPlatformEnrolmentLinkCLI is paddock-server admin enrolment-link (ADR 0053 decision 1).
var specPlatformEnrolmentLinkCLI = ActionSpec{Code: audit.CodePlatformEnrolmentLinkCreated, Actor: &adminActor}

// ErrNoPortalRole refuses a sign-in setup link on the host for an account that holds no portal role: it is a direct
// member neither of paddock.platform.admins nor of any organization's admins, operators or auditors group
// (organization.ResolveRole), or its role group belongs to no Paddock organization.
var ErrNoPortalRole = problem.InvalidState.WithDetail("the user holds no portal role: it is not a direct member of " +
	organization.PlatformAdminsGroup() + " or of an organization's admins, operators or auditors group, or that " +
	"group belongs to no organization in Paddock")

// ErrAmbiguousPortalRole refuses a sign-in setup link on the host for an account whose role assignment is ambiguous:
// it is a direct member of role groups of several organizations, or of several role groups of one organization. The
// portal sign-in denies such an account too (organization.ResolveRole, ADR 0045), so the operator must first remove
// the extra group memberships.
var ErrAmbiguousPortalRole = problem.InvalidState.WithDetail("the user's role assignment is ambiguous: it is a direct " +
	"member of role groups of several organizations, or of several role groups of one organization; remove the extra " +
	"group memberships in the identity provider so that it holds exactly one organization role, then run the command again")

// ErrPortalAccountOrganizationOffboarding refuses a sign-in setup link on the host for an account whose role group
// belongs to an organization that is being deleted or was deleted (PDK-1112): the offboarding ends the setup links of
// the organization's members, so a link issued meanwhile would outlive it.
var ErrPortalAccountOrganizationOffboarding = problem.InvalidState.WithDetail("the user's organization is being " +
	"deleted or was deleted; it gets no sign-in setup link")

// PasswordByLinkDirectory finds the account the operator named, tells whether its password belongs to an upstream
// source and marks the accounts whose sign-in setup link may set a password (authentik.Client).
type PasswordByLinkDirectory interface {
	// UserByUsername reads the user named exactly username with the names of its direct groups; found is false when
	// there is none.
	UserByUsername(ctx context.Context, username string) (u ports.IdentityUser, groups []string, found bool, err error)
	// HasSourceConnection reports whether the user pk is connected to an upstream source of the identity provider.
	HasSourceConnection(ctx context.Context, pk string) (bool, error)
	// SetUserAttribute sets the user attribute key to value; nil removes it.
	SetUserAttribute(ctx context.Context, pk, key string, value any) error
}

// PlatformEnrolmentLinks creates the sign-in setup links of administrator accounts on the host (ADR 0053 decision 1):
// platform administrators, which are managed in the identity provider directly, and organization accounts with a
// portal role that the operator created by hand there (plan M12h-2 amendment f addendum b).
type PlatformEnrolmentLinks struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	dir      ports.UserDirectory
	marks    PasswordByLinkDirectory
	now      func() time.Time
}

// NewPlatformEnrolmentLinks creates the use case.
func NewPlatformEnrolmentLinks(runner *ActionRunner, platform *db.PlatformPool, dir ports.UserDirectory,
	marks PasswordByLinkDirectory) *PlatformEnrolmentLinks {
	return &PlatformEnrolmentLinks{runner: runner, platform: platform, dir: dir, marks: marks, now: time.Now}
}

// CreateCLI creates a one-time sign-in setup link for the account username (audited: platform.enrolment_link_created
// with organization_id, passkey_only and previous_links_revoked in the platform pseudo-organization, actor
// paddock-server admin). Only an account with a portal role gets one (ErrNoPortalRole): a direct member of
// paddock.platform.admins or of one organization's admins, operators or auditors group, and only while active. Such
// an account reaching the host command was created by hand in the identity provider, so before issuing the link the
// account is marked with ports.AttrPasswordByLink and the link sets a password if the account has none; an account
// connected to an upstream source (SCIM included) loses any earlier mark and its link sets up only the passkey
// (EnrolmentLink.PasskeyOnly, plan M12h-2 amendment f addenda).
func (p *PlatformEnrolmentLinks) CreateCLI(ctx context.Context, username string) (EnrolmentLink, error) {
	username = strings.TrimSpace(username)
	spec := specPlatformEnrolmentLinkCLI
	spec.Params = map[string]any{"username": username}
	spec.Target = &audit.Target{Type: "platform_admin", Display: username}
	var out EnrolmentLink
	var revoked *int
	var passkeyOnly *bool
	var acct portalAccount
	err := p.runner.RunExternal(systemPlatform(ctx), ScopePlatform, spec,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil },
		func(ctx context.Context) error {
			var err error
			acct, err = p.portalAccount(ctx, username)
			if err != nil {
				return err
			}
			pk := acct.pk
			out, revoked, err = recoveryLinkOfActive(ctx, p.dir, pk, p.now, func(ctx context.Context) error {
				synced, err := p.marks.HasSourceConnection(ctx, pk)
				if err != nil {
					return err
				}
				// A connected account loses a mark left by an earlier host link, so its link really is passkey-only.
				var mark any
				if !synced {
					mark = true
				}
				if err := p.marks.SetUserAttribute(ctx, pk, ports.AttrPasswordByLink, mark); err != nil {
					return err
				}
				passkeyOnly = &synced
				return nil
			})
			out.PasskeyOnly = passkeyOnly != nil && *passkeyOnly
			return err
		},
		func(_ context.Context, _ *pgstore.Queries, rec Recorder, _ error) error {
			if acct.organization != uuid.Nil {
				// A param, not the event's organization: the operator acts on the host, outside any organization.
				rec.SetParam("organization_id", acct.organization.String())
				if !acct.platform {
					rec.SetTarget(audit.Target{Type: "user", Display: username})
				}
			}
			// Named passkey_only, not password_allowed: audit param keys never contain "password" (mustBeSafeParam).
			if passkeyOnly != nil {
				rec.SetParam("passkey_only", *passkeyOnly)
			}
			recordRevoked(rec, revoked)
			return nil
		})
	if err != nil {
		return EnrolmentLink{}, err
	}
	return out, nil
}

// portalAccount is the account a host link is for: its identity provider pk, whether it is a platform administrator,
// and the ID of its organization (uuid.Nil for a platform administrator without an organization role).
type portalAccount struct {
	pk           string
	platform     bool
	organization uuid.UUID
}

// portalAccount finds the account username and the portal role its direct groups grant, by the rule of the portal
// sign-in (organization.ResolveRole): an account the sign-in denies gets no link either, and neither does an account
// of an organization that is being deleted or was deleted (ErrPortalAccountOrganizationOffboarding, returned with the
// account so the event names its organization).
func (p *PlatformEnrolmentLinks) portalAccount(ctx context.Context, username string) (portalAccount, error) {
	if username == "" {
		return portalAccount{}, ErrNoPortalRole
	}
	u, groups, found, err := p.marks.UserByUsername(ctx, username)
	if err != nil {
		return portalAccount{}, err
	}
	if !found {
		return portalAccount{}, ErrNoPortalRole
	}
	role := organization.ResolveRole(groups)
	if role.Denied {
		if role.Reason == organization.DenialMultipleOrganizations || role.Reason == organization.DenialMultipleRoles {
			return portalAccount{}, ErrAmbiguousPortalRole
		}
		return portalAccount{}, ErrNoPortalRole
	}
	acct := portalAccount{pk: u.PK, platform: role.Platform}
	if role.Slug == "" {
		return acct, nil
	}
	err = p.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		o, err := q.GetOrganizationBySlug(ctx, role.Slug)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoPortalRole
		}
		if err != nil {
			return fmt.Errorf("organization %s: %w", role.Slug, err)
		}
		acct.organization = o.ID
		if organization.Offboarding(o.Status) {
			return ErrPortalAccountOrganizationOffboarding
		}
		return nil
	})
	if errors.Is(err, ErrPortalAccountOrganizationOffboarding) {
		return acct, err
	}
	if err != nil {
		return portalAccount{}, err
	}
	return acct, nil
}
