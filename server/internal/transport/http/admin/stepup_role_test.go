package admin_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// TestStepUpRoleMismatch covers plan M8s decision 20: a step-up whose groups grant the session's role is accepted;
// groups that grant another role or another organization refuse it, update or disable the account, end every session
// of it and record admin.sessions_revoked once; a platform session with organization groups is only refused.
func TestStepUpRoleMismatch(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slug := func(org uuid.UUID) string {
		var s string
		if err := e.super.QueryRow(ctx, "SELECT slug FROM organization WHERE id = $1", org).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	acme, globex := slug(e.acme), slug(e.globex)
	// account creates an org admin of acme with one more session besides the step-up's.
	account := func() principal.Principal {
		p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(),
			Display: "alice@acme.test", Role: principal.RoleOrgAdmin, OrganizationID: e.acme}
		if _, err := e.super.Exec(ctx, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
			VALUES ($1, $2, $3, $4, $4, 'org_admin')`, p.ID, p.OrganizationID, p.Subject, p.Display); err != nil {
			t.Fatal(err)
		}
		e.cookie(p)
		return p
	}
	stepUp := func(p principal.Principal, groups []string) string {
		t.Helper()
		w := newStepUpWorldFor(t, 0, p, e.accounts)
		res := w.stepUp(map[string]any{"sub": p.Subject, "auth_time": time.Now().Unix() - 5, "amr": []string{"pwd", "mfa"},
			"jti": uuid.NewString(), "groups": groups})
		if res.Code != http.StatusFound {
			t.Fatalf("callback: %d", res.Code)
		}
		return res.Header().Get("Location")
	}
	sessionsOf := func(id uuid.UUID) int {
		e.sessions.mu.Lock()
		defer e.sessions.mu.Unlock()
		n := 0
		for _, rec := range e.sessions.records {
			if rec.AccountID == id {
				n++
			}
		}
		return n
	}
	state := func(id uuid.UUID) (role string, disabled bool) {
		if err := e.super.QueryRow(ctx, "SELECT role, disabled_at IS NOT NULL FROM admin_account WHERE id = $1", id).Scan(&role, &disabled); err != nil {
			t.Fatal(err)
		}
		return role, disabled
	}
	revoked := func(id uuid.UUID) []string {
		rows, err := e.super.Query(ctx, `SELECT outcome || ' ' || (actor->>'type') || ' ' || (params->>'reason') || ' ' ||
			(params->>'sessions') || ' [' || (params->>'old_role') || '] [' || (params->>'new_role') || ']' FROM action
			WHERE code = 'admin.sessions_revoked' AND target->>'id' = $1`, id.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}

	t.Run("groups that grant the session's role", func(t *testing.T) {
		p := account()
		if loc := stepUp(p, []string{organization.RoleGroup(acme, organization.GroupAdmins)}); loc != "/devices/x" {
			t.Fatalf("step-up: %s", loc)
		}
		if role, disabled := state(p.ID); role != "org_admin" || disabled || sessionsOf(p.ID) != 1 || len(revoked(p.ID)) != 0 {
			t.Fatalf("account changed: %s disabled %v", role, disabled)
		}
	})
	t.Run("another role", func(t *testing.T) {
		p := account()
		if loc := stepUp(p, []string{organization.RoleGroup(acme, organization.GroupAuditors)}); loc != "/devices/x?stepup=failed" {
			t.Fatalf("step-up: %s", loc)
		}
		if role, disabled := state(p.ID); role != "org_auditor" || disabled || sessionsOf(p.ID) != 0 {
			t.Fatalf("account %s disabled %v, %d sessions", role, disabled, sessionsOf(p.ID))
		}
		if ev := revoked(p.ID); len(ev) != 1 || ev[0] != "success system step_up_role_mismatch 1 [org_admin] [org_auditor]" {
			t.Fatalf("events %v", ev)
		}
	})
	t.Run("another organization", func(t *testing.T) {
		p := account()
		if loc := stepUp(p, []string{organization.RoleGroup(globex, organization.GroupAdmins)}); loc != "/devices/x?stepup=failed" {
			t.Fatalf("step-up: %s", loc)
		}
		if role, disabled := state(p.ID); role != "org_admin" || !disabled || sessionsOf(p.ID) != 0 {
			t.Fatalf("account %s disabled %v, %d sessions", role, disabled, sessionsOf(p.ID))
		}
		if ev := revoked(p.ID); len(ev) != 1 || ev[0] != "success system step_up_role_mismatch 1 [org_admin] []" {
			t.Fatalf("events %v", ev)
		}
	})
	t.Run("no groups", func(t *testing.T) {
		p := account()
		if loc := stepUp(p, nil); loc != "/devices/x?stepup=failed" {
			t.Fatalf("step-up: %s", loc)
		}
		if role, disabled := state(p.ID); role != "org_admin" || disabled || sessionsOf(p.ID) != 1 || len(revoked(p.ID)) != 0 {
			t.Fatalf("account changed: %s disabled %v", role, disabled)
		}
	})
	t.Run("platform session with organization groups", func(t *testing.T) {
		p := principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(),
			Display: "alice@acme.test", Role: principal.RolePlatform}
		e.cookie(p)
		loc := stepUp(p, []string{organization.RoleGroup(acme, organization.GroupAdmins)})
		if loc != "/devices/x?stepup=failed" || sessionsOf(p.ID) != 1 || len(revoked(p.ID)) != 0 {
			t.Fatalf("step-up: %s, %d sessions", loc, sessionsOf(p.ID))
		}
	})
}
