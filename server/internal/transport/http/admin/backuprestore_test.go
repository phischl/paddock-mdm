package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

const restorePlans = "/api/platform/v1/backup/restore-plans"

func newRestoreEnv(t *testing.T) *env {
	t.Helper()
	platform, err := db.NewPlatformPool(context.Background(), pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	e := newEnvWith(t, func(d *admin.Deps) {
		d.BackupTargets = app.NewBackupTargets(d.Runner, platform, &countingWrap{}, backupset.Policy{})
		d.BackupRestorePlans = app.NewBackupRestorePlans(d.Runner, platform)
	})
	reset := func() {
		if _, err := e.super.Exec(context.Background(), `DELETE FROM backup_run; DELETE FROM backup_target_status;
			DELETE FROM backup_restore_plan; DELETE FROM backup_target`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)
	return e
}

// succeeded inserts a successful local run of every kind, finished at.
func (e *env) succeeded(at time.Time, kinds ...string) {
	e.t.Helper()
	for _, k := range kinds {
		if _, err := e.super.Exec(context.Background(), `INSERT INTO backup_run (id, kind, state, outcome, started_at,
			finished_at) VALUES ($1, $2, 'finished', 'succeeded', $3, $3)`, uuid.Must(uuid.NewV7()), k, at); err != nil {
			e.t.Fatal(err)
		}
	}
}

// TestBackupRestorePlanEndpoints (PDK-735 AC 1, 2, 4): the typed word, the step-up, the one open plan, the source
// check, cancel, the list contract and the organization roles.
func TestBackupRestorePlanEndpoints(t *testing.T) {
	e := newRestoreEnv(t)
	root := e.platformSession()
	su := e.steppedUp(root, time.Now())
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	e.succeeded(at.Add(-time.Hour), "postgres", "authentik", "openbao")
	body := map[string]any{"kind": "point_in_time", "at": at, "components": []string{"postgres", "openbao"},
		"confirmation": "restore"}

	r := e.do(call{method: "POST", path: restorePlans, cookie: su, body: map[string]any{"kind": "point_in_time", "at": at,
		"components": []string{"postgres"}, "confirmation": "Restore"}})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("without the typed word: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_planned:failure:invalid_request")

	r = e.do(call{method: "POST", path: restorePlans, cookie: root, body: body})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_planned:denied:step_up_required")

	r = e.do(call{method: "POST", path: restorePlans, cookie: su, body: map[string]any{"kind": "components",
		"components": []string{"fleet"}, "confirmation": "restore"}})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" || !strings.Contains(string(r.body), "fleet") {
		t.Fatalf("component without a success: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_planned:failure:invalid_state")

	r = e.do(call{method: "POST", path: restorePlans, cookie: su, body: body})
	if r.status != http.StatusCreated {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_planned:success:")
	var plan adminapi.BackupRestorePlan
	r.decode(t, &plan)
	if plan.State != "approved" || plan.HostCommand != "./paddock restore --plan "+plan.Id.String() ||
		plan.ExpiresAt == nil || plan.ExpiresAt.Sub(plan.CreatedAt).Round(time.Second) != 24*time.Hour ||
		plan.Source != "repo" || plan.SourceTargetId != nil || plan.At == nil || !plan.At.Equal(at) ||
		len(plan.Components) != 2 || r.header.Get("Location") != restorePlans+"/"+plan.Id.String() {
		t.Fatalf("created %+v", plan)
	}

	r = e.do(call{method: "POST", path: restorePlans, cookie: su, body: body})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("second plan: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_planned:failure:invalid_state")

	r = e.do(call{method: "GET", path: restorePlans + "?state=approved&sort=-state&q=root", cookie: root})
	var page adminapi.BackupRestorePlanPage
	r.decode(t, &page)
	if r.status != http.StatusOK || page.Total != 1 || page.Items[0].Id != plan.Id || page.Sort != "-state" {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: restorePlans + "/" + plan.Id.String(), cookie: root})
	if r.status != http.StatusOK {
		t.Fatalf("get: %d %s", r.status, r.body)
	}

	cancel := restorePlans + "/" + plan.Id.String() + "/cancel"
	r = e.do(call{method: "POST", path: cancel, cookie: root})
	e.expectEvent(r, "platform.restore_cancelled:denied:step_up_required")
	r = e.do(call{method: "POST", path: cancel, cookie: su})
	r.decode(t, &plan)
	if r.status != http.StatusOK || plan.State != "expired" {
		t.Fatalf("cancel: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_cancelled:success:")
	r = e.do(call{method: "POST", path: cancel, cookie: su})
	if r.status != http.StatusConflict {
		t.Fatalf("cancel twice: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_cancelled:failure:invalid_state")
	r = e.do(call{method: "POST", path: restorePlans + "/" + uuid.NewString() + "/cancel", cookie: su})
	if r.status != http.StatusNotFound {
		t.Fatalf("cancel unknown: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.restore_cancelled:failure:not_found")

	for _, role := range []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		org := e.steppedUp(e.session(e.acme, role), time.Now())
		for _, c := range []call{
			{method: "GET", path: restorePlans, cookie: org},
			{method: "GET", path: restorePlans + "/" + plan.Id.String(), cookie: org},
			{method: "POST", path: restorePlans, cookie: org, body: body},
			{method: "POST", path: cancel, cookie: org},
		} {
			if r := e.do(c); r.status != http.StatusForbidden {
				t.Errorf("%s %s %s: %d %s", role, c.method, c.path, r.status, r.body)
			}
		}
	}
}
