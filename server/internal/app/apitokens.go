package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/apitoken"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// APITokens are the API token use cases (plan M6c §3.1).
type APITokens struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewAPITokens creates the use cases.
func NewAPITokens(runner *ActionRunner, org *db.OrgPool) *APITokens {
	return &APITokens{runner: runner, org: org, now: time.Now}
}

// Specs of the privileged API token actions. Creation requires a step-up: a token is a long-lived credential that
// bypasses MFA at every later use (plan M6c decision 4).
var (
	SpecAPITokenCreate = ActionSpec{Code: audit.CodeAPITokenCreated, AllowedRoles: RolesWrite, RequiresStepUp: true}
	SpecAPITokenRevoke = ActionSpec{Code: audit.CodeAPITokenRevoked, AllowedRoles: RolesWrite}
)

// APITokenQuery selects one page of API tokens.
type APITokenQuery struct {
	Page     ListPage
	Statuses []string // active, expired, revoked; nil: all
}

// List returns one page of API tokens.
func (a *APITokens) List(ctx context.Context, query APITokenQuery) (Listed[pgstore.ApiTokenListed], error) {
	var out Listed[pgstore.ApiTokenListed]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	statuses := query.Statuses
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountApiTokens(ctx, pgstore.CountApiTokensParams{QPattern: query.Page.QPattern, Statuses: statuses, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count api tokens: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListApiTokens(ctx, pgstore.ListApiTokensParams{
			QPattern: query.Page.QPattern, Statuses: statuses, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list api tokens: %w", err)
		}
		return nil
	})
	return out, err
}

// Get returns one API token; missing and foreign tokens are both not_found.
func (a *APITokens) Get(ctx context.Context, id uuid.UUID) (pgstore.ApiTokenListed, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.ApiTokenListed{}, err
	}
	var tok pgstore.ApiTokenListed
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		tok, err = q.GetApiToken(ctx, id)
		return notFound(err)
	})
	return tok, err
}

// APITokenInput are the fields of a new API token.
type APITokenInput struct {
	Name      string
	Role      principal.Role
	ExpiresAt time.Time
}

// CreatedAPIToken is the result of Create. Secret is shown once and never stored.
type CreatedAPIToken struct {
	Token  pgstore.ApiTokenListed
	Secret string
}

// Create creates an API token (audited: api_token.created; the secret is never recorded).
func (a *APITokens) Create(ctx context.Context, in APITokenInput) (CreatedAPIToken, error) {
	var out CreatedAPIToken
	spec := SpecAPITokenCreate
	spec.Params = map[string]any{"name": in.Name, "role": string(in.Role), "expires_at": in.ExpiresAt.UTC().Format(time.RFC3339)}
	err := a.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		if !apitoken.RoleAllowed(p.Role, in.Role) {
			return problem.Forbidden.WithDetail(apitoken.ErrRoleAboveCeiling.Error())
		}
		if err := apitoken.ValidateName(in.Name); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if err := apitoken.ValidateExpiry(a.now(), in.ExpiresAt); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		secret, hash, prefix, err := apitoken.Generate()
		if err != nil {
			return err
		}
		id, err := q.InsertApiToken(ctx, pgstore.InsertApiTokenParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: p.OrganizationID, Name: in.Name, Role: string(in.Role),
			SecretSha256: hash, Prefix: prefix, CreatedBy: p.ID, ExpiresAt: in.ExpiresAt,
		})
		if db.IsUniqueViolation(err, "api_token_org_name_live_idx") {
			return problem.NameTaken.WithDetail("an active or expired API token with this name exists")
		}
		if err != nil {
			return err
		}
		if out.Token, err = q.GetApiToken(ctx, id); err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "api_token", ID: id.String(), Display: in.Name})
		rec.SetParam("prefix", prefix)
		out.Secret = secret
		return nil
	})
	return out, err
}

// Revoke revokes an API token (audited: api_token.revoked). An organization administrator revokes any token of the
// organization, an operator only the tokens it created; a request made with an API token may not revoke.
func (a *APITokens) Revoke(ctx context.Context, id uuid.UUID) (pgstore.ApiTokenListed, error) {
	var tok pgstore.ApiTokenListed
	spec := SpecAPITokenRevoke
	spec.Target = &audit.Target{Type: "api_token", ID: id.String()}
	err := a.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		if p.APITokenID != uuid.Nil {
			return problem.Forbidden.WithDetail("an API token cannot revoke API tokens")
		}
		var err error
		if tok, err = q.GetApiToken(ctx, id); err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "api_token", ID: id.String(), Display: tok.Name})
		rec.SetParam("name", tok.Name)
		rec.SetParam("role", tok.Role)
		rec.SetParam("created_by", tok.CreatedBy.String())
		if p.Role == principal.RoleOrgOperator && tok.CreatedBy != p.ID {
			return problem.Forbidden.WithDetail("operators revoke only the API tokens they created")
		}
		n, err := q.RevokeApiToken(ctx, pgstore.RevokeApiTokenParams{ID: id, By: uuid.NullUUID{UUID: p.ID, Valid: true}})
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.InvalidState.WithDetail("the API token is already revoked")
		}
		tok, err = q.GetApiToken(ctx, id)
		return err
	})
	return tok, err
}

// APITokenAuthResult is the outcome of an API token authentication (label of paddock_api_token_auth_total).
type APITokenAuthResult string

// Results of Authenticate.
const (
	APITokenOK      APITokenAuthResult = "ok"
	APITokenUnknown APITokenAuthResult = "unknown"
	APITokenRevoked APITokenAuthResult = "revoked"
	APITokenExpired APITokenAuthResult = "expired"
)

// Authenticate turns an API token secret into the request principal (plan M6c decisions 7 and 9). A malformed or
// unknown secret is refused without an audit event; a revoked or expired token is refused with exactly one
// api_token.use_denied event in its organization. Every refusal returns problem.Unauthenticated.
func (a *APITokens) Authenticate(ctx context.Context, secret, ip string) (principal.Principal, APITokenAuthResult, error) {
	hash, ok := apitoken.Hash(secret)
	if !ok {
		return principal.Principal{}, APITokenUnknown, problem.Unauthenticated
	}
	row, found, err := a.org.LookupAPIToken(ctx, hash)
	if err != nil {
		return principal.Principal{}, "", fmt.Errorf("look up api token: %w", err)
	}
	if !found {
		return principal.Principal{}, APITokenUnknown, problem.Unauthenticated
	}
	switch {
	case row.Revoked:
		return principal.Principal{}, APITokenRevoked, a.refuse(ctx, row, ip, APITokenRevoked)
	case !row.ExpiresAt.After(a.now()):
		return principal.Principal{}, APITokenExpired, a.refuse(ctx, row, ip, APITokenExpired)
	}
	return principal.Principal{
		Kind: principal.KindAdmin, ID: row.CreatedBy, Display: row.Name + " (api token)", Role: principal.Role(row.Role),
		OrganizationID: row.OrganizationID, IP: ip, APITokenID: row.ID, APITokenName: row.Name,
	}, APITokenOK, nil
}

// refuse records the refused use of a revoked or expired token and returns the error for the client.
func (a *APITokens) refuse(ctx context.Context, row pgstore.LookupApiTokenRow, ip string, reason APITokenAuthResult) error {
	sys := principal.Principal{Kind: principal.KindSystem, OrganizationID: row.OrganizationID, IP: ip}
	spec := ActionSpec{
		Code:   audit.CodeAPITokenUseDenied,
		Actor:  &audit.Actor{Type: audit.ActorAnonymous, Display: row.Name, IP: ip},
		Target: &audit.Target{Type: "api_token", ID: row.ID.String(), Display: row.Name},
		Params: map[string]any{"name": row.Name, "reason": string(reason)},
	}
	err := a.runner.RunTxRefusal(principal.With(ctx, sys), ScopeOrg, spec, problem.Forbidden,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil })
	if err != nil && !errors.Is(err, problem.Forbidden) {
		slog.ErrorContext(ctx, "recording the refused api token use failed", "token_id", row.ID, "error", err)
	}
	return problem.Unauthenticated.WithDetail("api token " + string(reason))
}
