package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// specPlatformEnrolmentLinkCLI is paddock-server admin enrolment-link (ADR 0053 decision 1).
var specPlatformEnrolmentLinkCLI = ActionSpec{Code: audit.CodePlatformEnrolmentLinkCreated, Actor: &adminActor}

// ErrNotPlatformAdministrator refuses a sign-in setup link on the host for an account that is not a direct member of
// paddock.platform.admins: organization accounts get their links from an organization administrator in the portal.
var ErrNotPlatformAdministrator = problem.InvalidState.WithDetail("the user is not a direct member of " +
	organization.PlatformAdminsGroup())

// PasswordByLinkDirectory tells whether an account's password belongs to an upstream source and marks the accounts
// whose sign-in setup link may set a password (authentik.Client).
type PasswordByLinkDirectory interface {
	// HasSourceConnection reports whether the user pk is connected to an upstream source of the identity provider.
	HasSourceConnection(ctx context.Context, pk string) (bool, error)
	// SetUserAttribute sets the user attribute key to value; nil removes it.
	SetUserAttribute(ctx context.Context, pk, key string, value any) error
}

// PlatformEnrolmentLinks creates the sign-in setup links of platform administrator accounts on the host (ADR 0053
// decision 1). Platform administrators are managed in the identity provider directly, so no portal role creates them.
type PlatformEnrolmentLinks struct {
	runner *ActionRunner
	dir    ports.UserDirectory
	marks  PasswordByLinkDirectory
	now    func() time.Time
}

// NewPlatformEnrolmentLinks creates the use case.
func NewPlatformEnrolmentLinks(runner *ActionRunner, dir ports.UserDirectory, marks PasswordByLinkDirectory) *PlatformEnrolmentLinks {
	return &PlatformEnrolmentLinks{runner: runner, dir: dir, marks: marks, now: time.Now}
}

// CreateCLI creates a one-time sign-in setup link for the platform administrator username (audited:
// platform.enrolment_link_created with passkey_only and previous_links_revoked in the platform
// pseudo-organization, actor paddock-server admin). Only a direct member of paddock.platform.admins gets one
// (ErrNotPlatformAdministrator), and only while active. The operator creates platform administrators by hand in the
// identity provider, so before issuing the link the account is marked with ports.AttrPasswordByLink and the link sets
// a password if the account has none; an account connected to an upstream source loses any earlier mark and its link
// sets up only the passkey (EnrolmentLink.PasskeyOnly, plan M12h-2 amendment f addendum point 1).
func (p *PlatformEnrolmentLinks) CreateCLI(ctx context.Context, username string) (EnrolmentLink, error) {
	username = strings.TrimSpace(username)
	spec := specPlatformEnrolmentLinkCLI
	spec.Params = map[string]any{"username": username}
	spec.Target = &audit.Target{Type: "platform_admin", Display: username}
	var out EnrolmentLink
	var revoked *int
	var passkeyOnly *bool
	err := p.runner.RunExternal(systemPlatform(ctx), ScopePlatform, spec,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil },
		func(ctx context.Context) error {
			pk, err := p.platformAdministrator(ctx, username)
			if err != nil {
				return err
			}
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

// platformAdministrator returns the pk of the direct member username of paddock.platform.admins.
func (p *PlatformEnrolmentLinks) platformAdministrator(ctx context.Context, username string) (string, error) {
	group := organization.PlatformAdminsGroup()
	members, err := ListRoleGroups(ctx, p.dir, group).Members(group)
	if errors.Is(err, ports.ErrGroupNotFound) {
		return "", ErrNotPlatformAdministrator
	}
	if err != nil {
		return "", err
	}
	for _, m := range members {
		if username != "" && m.Username == username {
			return m.PK, nil
		}
	}
	return "", ErrNotPlatformAdministrator
}
