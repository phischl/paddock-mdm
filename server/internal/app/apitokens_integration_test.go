package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/apitoken"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// tokenHarness is the harness of the API token tests: an organization with administrators of every role.
type tokenHarness struct {
	harness
	tokens *app.APITokens
	corr   string // correlation ID of every action of the test, also in subtests
}

func newTokenHarness(t *testing.T) tokenHarness {
	t.Helper()
	h := newHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return tokenHarness{harness: h, tokens: app.NewAPITokens(h.runner, pool), corr: "corr-" + t.Name()}
}

// account inserts an administrator of the organization and returns its principal, stepped up when steppedUp.
func (h tokenHarness) account(t *testing.T, role principal.Role, steppedUp bool) principal.Principal {
	t.Helper()
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(),
		Display: string(role) + " admin", Role: role, OrganizationID: h.org, IP: "192.0.2.1"}
	if steppedUp {
		p.StepUpAt = time.Now()
	}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, $4, $4, $5)`, p.ID, p.OrganizationID, p.Subject, p.Display, string(role)); err != nil {
		t.Fatal(err)
	}
	return p
}

func (h tokenHarness) create(t *testing.T, creator principal.Principal, name string, role principal.Role) app.CreatedAPIToken {
	t.Helper()
	created, err := h.tokens.Create(principal.With(context.Background(), creator),
		app.APITokenInput{Name: name, Role: role, ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

// during returns code:outcome:error_code of the actions recorded while fn ran.
func (h tokenHarness) during(t *testing.T, fn func()) []string {
	t.Helper()
	before := len(h.actions(t))
	fn()
	return h.actions(t)[before:]
}

// actions returns code:outcome:error_code of every action recorded with the harness' correlation ID.
func (h tokenHarness) actions(t *testing.T) []string {
	t.Helper()
	rows, err := h.super.Query(context.Background(),
		"SELECT code || ':' || coalesce(outcome, status) || ':' || coalesce(error_code, '') FROM action WHERE correlation_id = $1 ORDER BY started_at, id",
		h.corr)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (h tokenHarness) lastUsed(t *testing.T, id uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := h.super.QueryRow(context.Background(), "SELECT last_used_at FROM api_token WHERE id = $1", id).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// TestM6cTablesFailClosed: without an organization context the api role reads no API token and no change set at
// all — the query fails instead of returning rows (CLAUDE.md, organization isolation).
func TestM6cTablesFailClosed(t *testing.T) {
	conn, err := pgx.Connect(context.Background(), pgtest.SharedPaddock(t).API)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, table := range []string{"api_token", "api_token_listed", "change_set"} {
		var n int
		if err := conn.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err == nil {
			t.Errorf("%s readable without paddock.org_id (%d rows)", table, n)
		}
	}
}

func TestAPITokenCreateAndAuthenticate(t *testing.T) {
	h := newTokenHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, true)
	created := h.create(t, admin, "ci deploy", principal.RoleOrgOperator)
	ev := expectOne(t, h.harness, audit.OutcomeSuccess, "")
	if ev.Code != audit.CodeAPITokenCreated || ev.Params["name"] != "ci deploy" || ev.Params["role"] != "org_operator" ||
		ev.Params["prefix"] != created.Secret[:12] || ev.Target == nil || ev.Target.ID != created.Token.ID.String() {
		t.Fatalf("event %+v", ev)
	}
	for k, v := range ev.Params {
		if s, ok := v.(string); ok && s == created.Secret {
			t.Fatalf("param %s carries the secret", k)
		}
	}
	if created.Token.Status != "active" || created.Token.CreatedByDisplay != admin.Display || created.Token.LastUsedAt != nil {
		t.Fatalf("token %+v", created.Token)
	}

	p, result, err := h.tokens.Authenticate(context.Background(), created.Secret, "198.51.100.7")
	if err != nil || result != app.APITokenOK {
		t.Fatalf("Authenticate = %v, %v", result, err)
	}
	want := principal.Principal{Kind: principal.KindAdmin, ID: admin.ID, Display: "ci deploy (api token)", Role: principal.RoleOrgOperator,
		OrganizationID: h.org, IP: "198.51.100.7", APITokenID: created.Token.ID, APITokenName: "ci deploy"}
	if p != want {
		t.Fatalf("principal %+v, want %+v", p, want)
	}

	// last_used_at is touched at most once per 60 s.
	first := h.lastUsed(t, created.Token.ID)
	if first == nil {
		t.Fatal("last_used_at not set by the first use")
	}
	if _, _, err := h.tokens.Authenticate(context.Background(), created.Secret, ""); err != nil {
		t.Fatal(err)
	}
	if again := h.lastUsed(t, created.Token.ID); again == nil || !again.Equal(*first) {
		t.Fatalf("last_used_at changed within 60 s: %v → %v", first, again)
	}
	if _, err := h.super.Exec(context.Background(), "UPDATE api_token SET last_used_at = now() - interval '61 seconds' WHERE id = $1", created.Token.ID); err != nil {
		t.Fatal(err)
	}
	old := h.lastUsed(t, created.Token.ID)
	if _, _, err := h.tokens.Authenticate(context.Background(), created.Secret, ""); err != nil {
		t.Fatal(err)
	}
	if later := h.lastUsed(t, created.Token.ID); later == nil || !later.After(*old) {
		t.Fatalf("last_used_at not refreshed after 60 s: %v → %v", old, later)
	}

	// Actions with the token are attributed to it.
	ctx := principal.With(context.Background(), p)
	if err := h.runner.RunTx(ctx, app.ScopeOrg, createSpec, createGroup("by token "+uuid.NewString()[:8])); err != nil {
		t.Fatal(err)
	}
	_, events := h.recorded(t, "corr-"+t.Name())
	last := events[len(events)-1]
	if last.Actor.Type != audit.ActorAPIToken || last.Actor.ID != created.Token.ID.String() || last.Actor.Display != "ci deploy" ||
		last.Source != audit.SourceAPI {
		t.Fatalf("actor %+v source %s", last.Actor, last.Source)
	}
}

func TestAPITokenAuthenticateRefusals(t *testing.T) {
	h := newTokenHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, true)

	t.Run("unknown and malformed secrets are not recorded", func(t *testing.T) {
		unknown, _, _, err := apitoken.Generate()
		if err != nil {
			t.Fatal(err)
		}
		got := h.during(t, func() {
			for _, s := range []string{"", "pdk_short", "Bearer x", unknown} {
				_, result, err := h.tokens.Authenticate(context.Background(), s, "")
				if !errors.Is(err, problem.Unauthenticated) || result != app.APITokenUnknown {
					t.Errorf("%q: %v, %v", s, result, err)
				}
			}
		})
		if len(got) != 0 {
			t.Fatalf("actions %v, want none", got)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		created := h.create(t, admin, "revoked "+uuid.NewString()[:8], principal.RoleOrgAuditor)
		if _, err := h.tokens.Revoke(principal.With(context.Background(), admin), created.Token.ID); err != nil {
			t.Fatal(err)
		}
		got := h.during(t, func() {
			_, result, err := h.tokens.Authenticate(context.Background(), created.Secret, "198.51.100.8")
			if !errors.Is(err, problem.Unauthenticated) || result != app.APITokenRevoked {
				t.Fatalf("Authenticate = %v, %v", result, err)
			}
		})
		if len(got) != 1 || got[0] != "api_token.use_denied:denied:forbidden" {
			t.Fatalf("actions %v", got)
		}
		_, events := h.recorded(t, h.corr)
		ev := events[len(events)-1]
		if ev.Actor.Type != audit.ActorAnonymous || ev.Actor.Display != created.Token.Name || ev.Params["reason"] != "revoked" ||
			ev.OrganizationID != h.org {
			t.Fatalf("event %+v", ev)
		}
	})
	t.Run("expired", func(t *testing.T) {
		created := h.create(t, admin, "expired "+uuid.NewString()[:8], principal.RoleOrgAuditor)
		if _, err := h.super.Exec(context.Background(), "UPDATE api_token SET expires_at = now() - interval '1 second' WHERE id = $1", created.Token.ID); err != nil {
			t.Fatal(err)
		}
		got := h.during(t, func() {
			_, result, err := h.tokens.Authenticate(context.Background(), created.Secret, "")
			if !errors.Is(err, problem.Unauthenticated) || result != app.APITokenExpired {
				t.Fatalf("Authenticate = %v, %v", result, err)
			}
		})
		if len(got) != 1 || got[0] != "api_token.use_denied:denied:forbidden" {
			t.Fatalf("actions %v", got)
		}
		if tok, err := h.tokens.Get(principal.With(context.Background(), admin), created.Token.ID); err != nil || tok.Status != "expired" {
			t.Fatalf("Get = %+v, %v", tok, err)
		}
	})
	t.Run("inactive organization", func(t *testing.T) {
		created := h.create(t, admin, "suspended "+uuid.NewString()[:8], principal.RoleOrgAuditor)
		if _, err := h.super.Exec(context.Background(), "UPDATE organization SET status = 'provisioning' WHERE id = $1", h.org); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = h.super.Exec(context.Background(), "UPDATE organization SET status = 'active' WHERE id = $1", h.org)
		})
		if _, result, err := h.tokens.Authenticate(context.Background(), created.Secret, ""); !errors.Is(err, problem.Unauthenticated) || result != app.APITokenUnknown {
			t.Fatalf("Authenticate = %v, %v", result, err)
		}
	})
}

func TestAPITokenCreateRules(t *testing.T) {
	h := newTokenHarness(t)
	in := func(name string, role principal.Role, d time.Duration) app.APITokenInput {
		return app.APITokenInput{Name: name, Role: role, ExpiresAt: time.Now().Add(d)}
	}
	admin := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	auditor := h.account(t, principal.RoleOrgAuditor, true)
	h.create(t, admin, "taken", principal.RoleOrgAuditor)
	writer := h.create(t, admin, "writer", principal.RoleOrgAdmin)
	token, _, err := h.tokens.Authenticate(context.Background(), writer.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		p    principal.Principal
		in   app.APITokenInput
		want string // action outcome:error_code
	}{
		"admin creates an admin token":   {admin, in("a "+uuid.NewString()[:8], principal.RoleOrgAdmin, time.Hour+time.Minute), "success:"},
		"operator creates an auditor":    {operator, in("o "+uuid.NewString()[:8], principal.RoleOrgAuditor, 24*time.Hour), "success:"},
		"operator above its role":        {operator, in("o "+uuid.NewString()[:8], principal.RoleOrgAdmin, 24*time.Hour), "denied:forbidden"},
		"auditor":                        {auditor, in("x "+uuid.NewString()[:8], principal.RoleOrgAuditor, 24*time.Hour), "denied:forbidden"},
		"without step-up":                {h.account(t, principal.RoleOrgAdmin, false), in("n "+uuid.NewString()[:8], principal.RoleOrgAuditor, 24*time.Hour), "denied:step_up_required"},
		"token cannot create tokens":     {token, in("t "+uuid.NewString()[:8], principal.RoleOrgAuditor, 24*time.Hour), "denied:step_up_required"},
		"expiry below one hour":          {admin, in("e "+uuid.NewString()[:8], principal.RoleOrgAuditor, 30*time.Minute), "failure:invalid_request"},
		"expiry above 365 days":          {admin, in("e "+uuid.NewString()[:8], principal.RoleOrgAuditor, 366*24*time.Hour), "failure:invalid_request"},
		"invalid name":                   {admin, in("-bad", principal.RoleOrgAuditor, 24*time.Hour), "failure:invalid_request"},
		"name of a token that is active": {admin, in("taken", principal.RoleOrgAuditor, 24*time.Hour), "failure:name_taken"},
	} {
		t.Run(name, func(t *testing.T) {
			got := h.during(t, func() {
				_, err := h.tokens.Create(principal.With(context.Background(), c.p), c.in)
				if (c.want == "success:") != (err == nil) {
					t.Errorf("Create = %v, want %s", err, c.want)
				}
			})
			if len(got) != 1 || got[0] != "api_token.created:"+c.want {
				t.Fatalf("actions %v, want [api_token.created:%s]", got, c.want)
			}
		})
	}
}

func TestAPITokenRevokeRules(t *testing.T) {
	h := newTokenHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	byAdmin := h.create(t, admin, "by admin", principal.RoleOrgAuditor)
	byOperator := h.create(t, operator, "by operator", principal.RoleOrgAuditor)
	token, _, err := h.tokens.Authenticate(context.Background(), byAdmin.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	revoke := func(t *testing.T, p principal.Principal, id uuid.UUID, want string) {
		t.Helper()
		got := h.during(t, func() {
			_, err := h.tokens.Revoke(principal.With(context.Background(), p), id)
			if (want == "success:") != (err == nil) {
				t.Errorf("Revoke = %v, want %s", err, want)
			}
		})
		if len(got) != 1 || got[0] != "api_token.revoked:"+want {
			t.Fatalf("actions %v, want [api_token.revoked:%s]", got, want)
		}
	}
	revoke(t, token, byOperator.Token.ID, "denied:forbidden")
	revoke(t, operator, byAdmin.Token.ID, "denied:forbidden")
	revoke(t, operator, uuid.Must(uuid.NewV7()), "failure:not_found")
	revoke(t, operator, byOperator.Token.ID, "success:")
	revoke(t, operator, byOperator.Token.ID, "failure:invalid_state")
	revoke(t, admin, byAdmin.Token.ID, "success:")
	tok, err := h.tokens.Get(principal.With(context.Background(), admin), byAdmin.Token.ID)
	if err != nil || tok.Status != "revoked" || tok.RevokedAt == nil || tok.RevokedBy.UUID != admin.ID {
		t.Fatalf("Get = %+v, %v", tok, err)
	}
	// The name of a revoked token is free again.
	h.create(t, admin, "by admin", principal.RoleOrgAuditor)
}
