package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SessionRevoker ends every portal session of an account (sessions.Store).
type SessionRevoker interface {
	RevokeAccount(ctx context.Context, accountID uuid.UUID) (int, error)
}

// Accounts are the login and "me" use cases.
type Accounts struct {
	runner   *ActionRunner
	org      *db.OrgPool
	platform *db.PlatformPool
	sessions SessionRevoker
}

// NewAccounts creates the use cases.
func NewAccounts(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool, sessions SessionRevoker) *Accounts {
	return &Accounts{runner: runner, org: org, platform: platform, sessions: sessions}
}

// LoginIdentity is what the verified ID token says about the user.
type LoginIdentity struct {
	Subject  string
	Username string // preferred_username
	Name     string
	IP       string
	// OpenSession creates the server-side session of the login (sessions.Store). It runs inside the login's
	// transaction, after the account row (admin_account or platform_admin) is written and locked: a revocation of the
	// account locks the same row first (revokeAccount updates it; revokePlatformAdmin selects it FOR UPDATE, then
	// counts and ends the sessions), so it either waits for the login and also counts and ends the new session, or ran
	// before it and the login re-grants the role the groups claim carries now. An error fails the login and records it
	// as failed.
	OpenSession func(ctx context.Context, p principal.Principal) error
	// PreviousRole is the role of the session a switch ends (ADR 0045 decision 3); "" for a plain sign-in. It is
	// recorded as the admin.login param previous_role.
	PreviousRole principal.Role
	// Channel is principal.ChannelMCP when the login opens an MCP session and "" for the portal (ADR 0044 amendment
	// A2); it is recorded as the admin.login param channel.
	Channel principal.Channel
	// Renewal marks an MCP login that renews a session from a refreshed token pair (ADR 0044 amendment 2026-10-28);
	// it is recorded as the admin.login param renewal.
	Renewal bool
}

// ErrAmbiguousRole: Login was called with a LoginRole that names the platform role and an organization role.
var ErrAmbiguousRole = errors.New("app: login role names more than one role")

// LoginRole is the role resolved from the groups claim.
type LoginRole struct {
	Platform bool
	Slug     string
	Role     principal.Role
	Denied   bool
	Slugs    []string
	// DenialReason is the organization.DenialReason of a denied role; it becomes the audit param denial_reason.
	DenialReason string
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
	ReasonMFARequired   = "mfa_required" // the ID token carried no second factor (amr without "mfa")
	// ReasonMCPLoginRequired: an MCP renewal without a live login binding of its sub and auth_time (ADR 0044
	// amendment 2026-10-28).
	ReasonMCPLoginRequired = "mcp_login_required"
	// ReasonTokenReplayed: an MCP session call with an ID token that was presented before (ADR 0044 amendment
	// 2026-10-28).
	ReasonTokenReplayed = "token_replayed"
	// ReasonKeyStoreSealed: the session keys are not loaded because OpenBao was sealed or unreachable at the start.
	ReasonKeyStoreSealed = "key_store_sealed"
)

// ErrLoginDenied is returned when the user may not use the portal; the denial is already audited.
var ErrLoginDenied = problem.Forbidden.WithDetail(ReasonNotAuthorized)

// DenialOrganizationInactive is the denial reason of a role in an unknown or inactive organization.
const DenialOrganizationInactive = "organization_inactive"

// ErrOrganizationInactive is returned when the role's organization is unknown or not active; the denial is already
// audited.
var ErrOrganizationInactive = problem.Forbidden.WithDetail(DenialOrganizationInactive)

// Login records admin.login and upserts the account (plan M0 §6.7). On denial it returns ErrLoginDenied.
func (a *Accounts) Login(ctx context.Context, id LoginIdentity, role LoginRole) (LoginResult, error) {
	if role.Denied {
		return LoginResult{}, a.recordDenied(ctx, id, role.Slugs, role.DenialReason)
	}
	if role.Platform && role.Slug != "" {
		return LoginResult{}, ErrAmbiguousRole
	}
	if role.Platform {
		return a.loginPlatform(ctx, id)
	}
	orgID, err := a.org.ResolveSlug(ctx, role.Slug)
	if err != nil {
		return LoginResult{}, err
	}
	if orgID == uuid.Nil { // unknown or inactive organization
		if err := a.recordDenied(ctx, id, nil, DenialOrganizationInactive); !errors.Is(err, ErrLoginDenied) {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrOrganizationInactive
	}
	p := principal.Principal{
		Kind: principal.KindAdmin, Subject: id.Subject, Display: id.Username, Role: role.Role, OrganizationID: orgID, IP: id.IP,
		Channel: id.Channel,
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
		Params: id.loginParams(map[string]any{"role": string(role.Role), "organization_slug": role.Slug}),
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
		return id.openSession(ctx, p)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Principal: p, Locale: locale}, nil
}

func (a *Accounts) loginPlatform(ctx context.Context, id LoginIdentity) (LoginResult, error) {
	p := principal.Principal{Kind: principal.KindPlatformAdmin, Subject: id.Subject, Display: id.Username, Role: principal.RolePlatform, IP: id.IP,
		Channel: id.Channel}
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
		Params: id.loginParams(map[string]any{"role": string(principal.RolePlatform)}),
	}
	err = a.runner.RunTx(principal.With(ctx, p), ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		acc, err := q.UpsertPlatformAdmin(ctx, pgstore.UpsertPlatformAdminParams{
			ID: p.ID, AuthentikSub: id.Subject, Username: id.Username, DisplayName: displayName(id),
		})
		if err != nil {
			return err
		}
		locale = acc.Locale
		return id.openSession(ctx, p)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Principal: p, Locale: locale}, nil
}

// loginParams adds the channel to the params of a successful admin.login, renewal when it renews an MCP session, and
// previous_role when the login is a role switch.
func (id LoginIdentity) loginParams(params map[string]any) map[string]any {
	params["channel"] = id.channel()
	if id.Renewal {
		params["renewal"] = true
	}
	if id.PreviousRole != "" {
		params["previous_role"] = string(id.PreviousRole)
	}
	return params
}

// channel is the admin.login param channel: portal unless the login opens an MCP session.
func (id LoginIdentity) channel() string {
	if id.Channel == "" {
		return "portal"
	}
	return string(id.Channel)
}

func (id LoginIdentity) openSession(ctx context.Context, p principal.Principal) error {
	if id.OpenSession == nil {
		return nil
	}
	if err := id.OpenSession(ctx, p); err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	return nil
}

// recordDenied audits a rejected login: in the organization when exactly one named organization resolves,
// otherwise in the platform pseudo-organization. The actor is anonymous with the preferred_username.
func (a *Accounts) recordDenied(ctx context.Context, id LoginIdentity, slugs []string, denialReason string) error {
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
	// The channel makes a refused MCP login an event of source mcp.
	sys := principal.Principal{Kind: principal.KindSystem, IP: id.IP, Channel: id.Channel}
	scope := ScopePlatform
	if len(resolved) == 1 {
		sys.OrganizationID = resolved[0]
		scope = ScopeOrg
	}
	spec := ActionSpec{
		Code:   audit.CodeAdminLogin,
		Actor:  &audit.Actor{Type: audit.ActorAnonymous, Display: id.Username, IP: id.IP},
		Params: map[string]any{"reason": ReasonNotAuthorized, "denial_reason": denialReason, "channel": id.channel()},
	}
	err := a.runner.RunTx(principal.With(ctx, sys), scope, spec, func(context.Context, *pgstore.Queries, Recorder) error {
		return ErrLoginDenied
	})
	if errors.Is(err, problem.Forbidden) {
		return ErrLoginDenied
	}
	return err
}

// RecordLoginFailure audits a login that failed before a role was resolved (state, code exchange, token, missing
// second factor). A non-empty username becomes the anonymous actor's display; channel is the login's channel ("" for
// the portal).
func (a *Accounts) RecordLoginFailure(ctx context.Context, ip, username, reason string, channel principal.Channel, cause error) {
	sys := principal.Principal{Kind: principal.KindSystem, IP: ip, Channel: channel}
	spec := ActionSpec{
		Code:   audit.CodeAdminLogin,
		Actor:  &audit.Actor{Type: audit.ActorAnonymous, Display: username, IP: ip},
		Params: map[string]any{"reason": reason, "channel": LoginIdentity{Channel: channel}.channel()},
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
	// Theme is the portal theme preference: system, light or dark (plan M7c decision 1).
	Theme string
	// APIToken is the token of a request made with an API token (nil for sessions, plan M6c decision 10).
	APIToken *MeAPIToken
}

// MeAPIToken is the API token a request authenticated with.
type MeAPIToken struct {
	ID        uuid.UUID
	Name      string
	ExpiresAt time.Time
}

// GetMe returns the signed-in administrator.
func (a *Accounts) GetMe(ctx context.Context) (Me, error) {
	p, ok := principal.From(ctx)
	if !ok {
		return Me{}, problem.Unauthenticated
	}
	me := Me{ID: p.ID, Role: p.Role}
	if p.APITokenID != uuid.Nil {
		return a.tokenMe(ctx, p)
	}
	if p.Kind == principal.KindPlatformAdmin {
		err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			acc, err := q.GetPlatformAdmin(ctx, p.ID)
			if err != nil {
				return notFound(err)
			}
			me.Username, me.DisplayName, me.Locale, me.Theme = acc.Username, acc.DisplayName, acc.Locale, acc.Theme
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
		me.Username, me.DisplayName, me.Locale, me.Theme, me.Organization = acc.Username, acc.DisplayName, acc.Locale, acc.Theme, &org
		return nil
	})
	return me, unauthenticatedIfGone(err)
}

// tokenMe answers GET /api/v1/me for a request made with an API token from the token, not from the account of the
// administrator who created it.
func (a *Accounts) tokenMe(ctx context.Context, p principal.Principal) (Me, error) {
	me := Me{ID: p.APITokenID, Username: p.APITokenName, DisplayName: p.APITokenName, Role: p.Role, Locale: "en", Theme: ThemeSystem}
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		tok, err := q.GetApiToken(ctx, p.APITokenID)
		if err != nil {
			return notFound(err)
		}
		org, err := q.GetOrganization(ctx, p.OrganizationID)
		if err != nil {
			return notFound(err)
		}
		me.Organization = &org
		me.APIToken = &MeAPIToken{ID: tok.ID, Name: tok.Name, ExpiresAt: tok.ExpiresAt}
		return nil
	})
	return me, unauthenticatedIfGone(err)
}

// SupportedLocales are the catalogs of the portal (plan M6b decision 2: English and German).
var SupportedLocales = []string{"en", "de"}

// ThemeSystem is the default theme preference: the portal follows prefers-color-scheme.
const ThemeSystem = "system"

// SupportedThemes are the portal theme preferences (plan M7c decision 1).
var SupportedThemes = []string{ThemeSystem, "light", "dark"}

// AccountSettings is a patch of the account settings; a nil field is left unchanged.
type AccountSettings struct {
	Locale *string
	Theme  *string
}

// ErrEmptySettings: a settings patch without any field.
var ErrEmptySettings = problem.InvalidRequest.WithDetail("no setting to update")

// ValidateAccountSettings checks a settings patch: at least one field, every present field a supported value.
func ValidateAccountSettings(s AccountSettings) error {
	if s.Locale == nil && s.Theme == nil {
		return ErrEmptySettings
	}
	if s.Locale != nil && !contains(SupportedLocales, *s.Locale) {
		return problem.InvalidRequest.WithDetail("unsupported locale")
	}
	if s.Theme != nil && !contains(SupportedThemes, *s.Theme) {
		return problem.InvalidRequest.WithDetail("unsupported theme")
	}
	return nil
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// UpdateSettings stores the administrator's locale and theme preference; not a privileged action (no audit).
func (a *Accounts) UpdateSettings(ctx context.Context, s AccountSettings) (Me, error) {
	p, ok := principal.From(ctx)
	if !ok {
		return Me{}, problem.Unauthenticated
	}
	if p.APITokenID != uuid.Nil {
		return Me{}, problem.Forbidden.WithDetail("an API token has no account settings")
	}
	if err := ValidateAccountSettings(s); err != nil {
		return Me{}, err
	}
	var err error
	if p.Kind == principal.KindPlatformAdmin {
		err = a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.UpdatePlatformAdminSettings(ctx, pgstore.UpdatePlatformAdminSettingsParams{ID: p.ID, Locale: s.Locale, Theme: s.Theme})
			return notFound(err)
		})
	} else {
		err = a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.UpdateAdminAccountSettings(ctx, pgstore.UpdateAdminAccountSettingsParams{ID: p.ID, Locale: s.Locale, Theme: s.Theme})
			return notFound(err)
		})
	}
	if err != nil {
		return Me{}, unauthenticatedIfGone(err)
	}
	return a.GetMe(ctx)
}

// AccountState is what the api re-reads from the account row of an MCP session on every request (plan M14 §3.3
// item 14).
type AccountState struct {
	Role            principal.Role
	Disabled        bool
	MCPWriteEnabled bool
}

// AccountState reads the role, the deactivation and the MCP write opt-in of p's own account row: admin_account in p's
// organization, platform_admin in the platform pool, whose role is always platform_admin. A missing row is
// problem.Unauthenticated.
func (a *Accounts) AccountState(ctx context.Context, p principal.Principal) (AccountState, error) {
	ctx = principal.With(ctx, p)
	var st AccountState
	if p.Kind == principal.KindPlatformAdmin {
		err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			write, err := q.GetPlatformAdminState(ctx, p.ID)
			if err != nil {
				return notFound(err)
			}
			st = AccountState{Role: principal.RolePlatform, MCPWriteEnabled: write}
			return nil
		})
		return st, unauthenticatedIfGone(err)
	}
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetAdminAccountState(ctx, p.ID)
		if err != nil {
			return notFound(err)
		}
		st = AccountState{Role: principal.Role(row.Role), Disabled: row.Disabled, MCPWriteEnabled: row.McpWriteEnabled}
		return nil
	})
	return st, unauthenticatedIfGone(err)
}

// unauthenticatedIfGone: a session whose account no longer exists is treated as signed out.
func unauthenticatedIfGone(err error) error {
	if errors.Is(err, problem.NotFound) {
		return problem.Unauthenticated
	}
	return err
}

// OrganizationID resolves the slug of a role group to its active organization (uuid.Nil: unknown or inactive).
func (a *Accounts) OrganizationID(ctx context.Context, slug string) (uuid.UUID, error) {
	return a.org.ResolveSlug(ctx, slug)
}

// Reasons of admin.sessions_revoked (plan M8s decision 17).
const (
	RevokeReasonStepUpRoleMismatch = "step_up_role_mismatch"
	RevokeReasonRoleChanged        = "role_changed"
	RevokeReasonDeactivated        = "deactivated"
	RevokeReasonRemoved            = "removed"
)

// stepUpCheckActor is the actor of a revocation at the step-up: the api's own check, not the administrator.
var stepUpCheckActor = audit.Actor{Type: audit.ActorSystem, Display: "step-up role check"}

// StepUpMismatch records admin.sessions_revoked (reason step_up_role_mismatch, actor system, target the account),
// writes the resolved role to admin_account.role when res names the same organization, sets disabled_at = now()
// when res grants no role in it, and revokes every session of the account (ADR 0034 decision 5).
func (a *Accounts) StepUpMismatch(ctx context.Context, accountID, orgID uuid.UUID, res organization.RoleResolution) error {
	var newRole principal.Role
	if active, ok := res.Active(organization.ChoiceOrganization); ok {
		resolved, err := a.org.ResolveSlug(ctx, active.Slug)
		if err != nil {
			return err
		}
		if resolved == orgID {
			newRole = active.Role
		}
	}
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: stepUpCheckActor.Display, OrganizationID: orgID})
	spec := ActionSpec{
		Code:   audit.CodeAdminSessionsRevoked,
		Actor:  &stepUpCheckActor,
		Target: &audit.Target{Type: "admin_account", ID: accountID.String()},
	}
	return a.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		return revokeAccount(ctx, q, rec, a.sessions, accountID, RevokeReasonStepUpRoleMismatch, newRole)
	})
}

// revokeAccount gives the account newRole, or disables it when newRole is empty, revokes every session of it and sets
// the params of admin.sessions_revoked.
func revokeAccount(ctx context.Context, q *pgstore.Queries, rec Recorder, store SessionRevoker, accountID uuid.UUID,
	reason string, newRole principal.Role) error {
	acc, err := q.GetAdminAccount(ctx, accountID)
	if err != nil {
		return fmt.Errorf("account: %w", err)
	}
	rec.SetTarget(audit.Target{Type: "admin_account", ID: accountID.String(), Display: acc.Username})
	if newRole == "" {
		err = q.DisableAdminAccount(ctx, accountID)
	} else {
		err = q.SetAdminAccountRole(ctx, pgstore.SetAdminAccountRoleParams{ID: accountID, Role: string(newRole)})
	}
	if err != nil {
		return fmt.Errorf("update account: %w", err)
	}
	n, err := store.RevokeAccount(ctx, accountID)
	if err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	oldRole := acc.Role
	if string(newRole) == oldRole {
		oldRole, newRole = "", ""
	}
	rec.SetParam("reason", reason)
	rec.SetParam("sessions", n)
	rec.SetParam("old_role", oldRole)
	rec.SetParam("new_role", string(newRole))
	return nil
}
