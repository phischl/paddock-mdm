package app

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Accounts are the login and "me" use cases.
type Accounts struct {
	runner   *ActionRunner
	org      *db.OrgPool
	platform *db.PlatformPool
}

// NewAccounts creates the use cases.
func NewAccounts(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool) *Accounts {
	return &Accounts{runner: runner, org: org, platform: platform}
}

// LoginIdentity is what the verified ID token says about the user.
type LoginIdentity struct {
	Subject  string
	Username string // preferred_username
	Name     string
	IP       string
}

// LoginRole is the role resolved from the groups claim.
type LoginRole struct {
	Platform bool
	Slug     string
	Role     principal.Role
	Denied   bool
	Slugs    []string
}

// LoginResult is the outcome of a login.
type LoginResult struct {
	Principal principal.Principal
	Locale    string
}

// Denial reasons shown on /login-denied.
const (
	ReasonNotAuthorized = "not_authorized"
	ReasonLoginFailed   = "login_failed"
)

// ErrLoginDenied is returned when the user may not use the portal; the denial is already audited.
var ErrLoginDenied = problem.Forbidden.WithDetail(ReasonNotAuthorized)

// Login records admin.login and upserts the account (plan M0 §6.7). On denial it returns ErrLoginDenied.
func (a *Accounts) Login(ctx context.Context, id LoginIdentity, role LoginRole) (LoginResult, error) {
	if role.Denied {
		return LoginResult{}, a.recordDenied(ctx, id, role.Slugs)
	}
	if role.Platform {
		return a.loginPlatform(ctx, id)
	}
	orgID, err := a.org.ResolveSlug(ctx, role.Slug)
	if err != nil {
		return LoginResult{}, err
	}
	if orgID == uuid.Nil { // unknown or inactive organization
		return LoginResult{}, a.recordDenied(ctx, id, nil)
	}
	p := principal.Principal{
		Kind: principal.KindAdmin, Subject: id.Subject, Display: id.Username, Role: role.Role, OrganizationID: orgID, IP: id.IP,
	}
	// The account ID must be known before the principal is built: reuse the existing one or generate a new one.
	err = a.org.InOrg(principal.With(ctx, p), func(ctx context.Context, q *pgstore.Queries) error {
		acc, err := q.GetAdminAccountBySubject(ctx, id.Subject)
		switch {
		case err == nil:
			p.ID = acc.ID
		case db.IsNoRows(err):
			p.ID = uuid.Must(uuid.NewV7())
		default:
			return err
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	var locale string
	spec := ActionSpec{
		Code:   audit.CodeAdminLogin,
		Target: &audit.Target{Type: "admin_account", ID: p.ID.String(), Display: id.Username},
		Params: map[string]any{"role": string(role.Role), "organization_slug": role.Slug},
	}
	err = a.runner.RunTx(principal.With(ctx, p), ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		acc, err := q.UpsertAdminAccount(ctx, pgstore.UpsertAdminAccountParams{
			ID: p.ID, OrganizationID: orgID, AuthentikSub: id.Subject, Username: id.Username,
			DisplayName: displayName(id), Role: string(role.Role),
		})
		if err != nil {
			return err
		}
		if acc.ID != p.ID {
			return errors.New("app: account ID changed during login")
		}
		locale = acc.Locale
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Principal: p, Locale: locale}, nil
}

func (a *Accounts) loginPlatform(ctx context.Context, id LoginIdentity) (LoginResult, error) {
	p := principal.Principal{Kind: principal.KindPlatformAdmin, Subject: id.Subject, Display: id.Username, Role: principal.RolePlatform, IP: id.IP}
	err := a.platform.InPlatform(principal.With(ctx, p), func(ctx context.Context, q *pgstore.Queries) error {
		acc, err := q.GetPlatformAdminBySubject(ctx, id.Subject)
		switch {
		case err == nil:
			p.ID = acc.ID
		case db.IsNoRows(err):
			p.ID = uuid.Must(uuid.NewV7())
		default:
			return err
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	var locale string
	spec := ActionSpec{
		Code:   audit.CodeAdminLogin,
		Target: &audit.Target{Type: "platform_admin", ID: p.ID.String(), Display: id.Username},
		Params: map[string]any{"role": string(principal.RolePlatform)},
	}
	err = a.runner.RunTx(principal.With(ctx, p), ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		acc, err := q.UpsertPlatformAdmin(ctx, pgstore.UpsertPlatformAdminParams{
			ID: p.ID, AuthentikSub: id.Subject, Username: id.Username, DisplayName: displayName(id),
		})
		if err != nil {
			return err
		}
		locale = acc.Locale
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Principal: p, Locale: locale}, nil
}

// recordDenied audits a rejected login: in the organization when exactly one named organization resolves,
// otherwise in the platform pseudo-organization. The actor is anonymous with the preferred_username.
func (a *Accounts) recordDenied(ctx context.Context, id LoginIdentity, slugs []string) error {
	var resolved []uuid.UUID
	for _, s := range slugs {
		orgID, err := a.org.ResolveSlug(ctx, s)
		if err != nil {
			return err
		}
		if orgID != uuid.Nil {
			resolved = append(resolved, orgID)
		}
	}
	sys := principal.Principal{Kind: principal.KindSystem, IP: id.IP}
	scope := ScopePlatform
	if len(resolved) == 1 {
		sys.OrganizationID = resolved[0]
		scope = ScopeOrg
	}
	spec := ActionSpec{
		Code:   audit.CodeAdminLogin,
		Actor:  &audit.Actor{Type: audit.ActorAnonymous, Display: id.Username, IP: id.IP},
		Params: map[string]any{"reason": ReasonNotAuthorized},
	}
	err := a.runner.RunTx(principal.With(ctx, sys), scope, spec, func(context.Context, *pgstore.Queries, Recorder) error {
		return ErrLoginDenied
	})
	if errors.Is(err, problem.Forbidden) {
		return ErrLoginDenied
	}
	return err
}

// RecordLoginFailure audits a login that failed before the identity was known (state, code exchange, token).
func (a *Accounts) RecordLoginFailure(ctx context.Context, ip, reason string, cause error) {
	sys := principal.Principal{Kind: principal.KindSystem, IP: ip}
	spec := ActionSpec{
		Code:   audit.CodeAdminLogin,
		Actor:  &audit.Actor{Type: audit.ActorAnonymous, IP: ip},
		Params: map[string]any{"reason": reason},
	}
	_ = a.runner.RunTx(principal.With(ctx, sys), ScopePlatform, spec, func(context.Context, *pgstore.Queries, Recorder) error {
		return cause
	})
}

func displayName(id LoginIdentity) string {
	if id.Name != "" {
		return id.Name
	}
	return id.Username
}

// Me is the signed-in administrator.
type Me struct {
	ID           uuid.UUID
	Username     string
	DisplayName  string
	Role         principal.Role
	Organization *pgstore.Organization
	Locale       string
}

// GetMe returns the signed-in administrator.
func (a *Accounts) GetMe(ctx context.Context) (Me, error) {
	p, ok := principal.From(ctx)
	if !ok {
		return Me{}, problem.Unauthenticated
	}
	me := Me{ID: p.ID, Role: p.Role}
	if p.Kind == principal.KindPlatformAdmin {
		err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			acc, err := q.GetPlatformAdmin(ctx, p.ID)
			if err != nil {
				return notFound(err)
			}
			me.Username, me.DisplayName, me.Locale = acc.Username, acc.DisplayName, acc.Locale
			return nil
		})
		return me, unauthenticatedIfGone(err)
	}
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		acc, err := q.GetAdminAccount(ctx, p.ID)
		if err != nil {
			return notFound(err)
		}
		org, err := q.GetOrganization(ctx, p.OrganizationID)
		if err != nil {
			return notFound(err)
		}
		me.Username, me.DisplayName, me.Locale, me.Organization = acc.Username, acc.DisplayName, acc.Locale, &org
		return nil
	})
	return me, unauthenticatedIfGone(err)
}

// SupportedLocales are the catalogs of the portal (M0: English only).
var SupportedLocales = []string{"en"}

// UpdateLocale stores the administrator's locale.
func (a *Accounts) UpdateLocale(ctx context.Context, locale string) (Me, error) {
	p, ok := principal.From(ctx)
	if !ok {
		return Me{}, problem.Unauthenticated
	}
	supported := false
	for _, l := range SupportedLocales {
		supported = supported || l == locale
	}
	if !supported {
		return Me{}, problem.InvalidRequest.WithDetail("unsupported locale")
	}
	var err error
	if p.Kind == principal.KindPlatformAdmin {
		err = a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.UpdatePlatformAdminLocale(ctx, pgstore.UpdatePlatformAdminLocaleParams{ID: p.ID, Locale: locale})
			return notFound(err)
		})
	} else {
		err = a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.UpdateAdminAccountLocale(ctx, pgstore.UpdateAdminAccountLocaleParams{ID: p.ID, Locale: locale})
			return notFound(err)
		})
	}
	if err != nil {
		return Me{}, unauthenticatedIfGone(err)
	}
	return a.GetMe(ctx)
}

// unauthenticatedIfGone: a session whose account no longer exists is treated as signed out.
func unauthenticatedIfGone(err error) error {
	if errors.Is(err, problem.NotFound) {
		return problem.Unauthenticated
	}
	return err
}
