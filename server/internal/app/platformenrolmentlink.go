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

// PlatformEnrolmentLinks creates the sign-in setup links of platform administrator accounts on the host (ADR 0053
// decision 1). Platform administrators are managed in the identity provider directly, so no portal role creates them.
type PlatformEnrolmentLinks struct {
	runner *ActionRunner
	dir    ports.UserDirectory
	now    func() time.Time
}

// NewPlatformEnrolmentLinks creates the use case.
func NewPlatformEnrolmentLinks(runner *ActionRunner, dir ports.UserDirectory) *PlatformEnrolmentLinks {
	return &PlatformEnrolmentLinks{runner: runner, dir: dir, now: time.Now}
}

// CreateCLI creates a one-time sign-in setup link for the platform administrator username (audited:
// platform.enrolment_link_created in the platform pseudo-organization, actor paddock-server admin). Only a direct
// member of paddock.platform.admins gets one (ErrNotPlatformAdministrator), and only while active.
func (p *PlatformEnrolmentLinks) CreateCLI(ctx context.Context, username string) (EnrolmentLink, error) {
	username = strings.TrimSpace(username)
	spec := specPlatformEnrolmentLinkCLI
	spec.Params = map[string]any{"username": username}
	spec.Target = &audit.Target{Type: "platform_admin", Display: username}
	var out EnrolmentLink
	err := p.runner.RunExternal(systemPlatform(ctx), ScopePlatform, spec,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil },
		func(ctx context.Context) error {
			pk, err := p.platformAdministrator(ctx, username)
			if err != nil {
				return err
			}
			out, err = recoveryLinkOfActive(ctx, p.dir, pk, p.now)
			return err
		},
		func(context.Context, *pgstore.Queries, Recorder, error) error { return nil })
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
