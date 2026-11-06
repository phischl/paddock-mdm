package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type restoreWorld struct {
	backupWorld
	plans   *app.BackupRestorePlans
	reports *app.RestoreReports
}

func newRestoreWorld(t *testing.T) restoreWorld {
	t.Helper()
	w := newBackupWorld(t)
	ctx := context.Background()
	platformPool, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platformPool.Close)
	// The host's reports run as paddock_backup, the role that holds the UPDATE grant on backup_restore_plan.
	backupPool, err := db.NewBackupPool(ctx, pgtest.SharedPaddock(t).Backup, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backupPool.Close)
	corr := "corr-" + t.Name()
	runner := app.NewActionRunner(nil, nil, func(context.Context) string { return corr }, app.WithPlatformScope(backupPool.InBackup))
	return restoreWorld{backupWorld: w, plans: app.NewBackupRestorePlans(w.runner, platformPool),
		reports: app.NewRestoreReports(runner, backupPool.InBackup)}
}

// run inserts a finished run of kind; targets is the run's mirror result.
func (w restoreWorld) run(t *testing.T, kind, outcome string, finished time.Time, targets string) {
	t.Helper()
	if _, err := w.super.Exec(context.Background(), `INSERT INTO backup_run (id, kind, state, outcome, started_at, finished_at,
		targets) VALUES ($1, $2, 'finished', $3, $4, $4, $5::jsonb)`, uuid.Must(uuid.NewV7()), kind, outcome, finished,
		targets); err != nil {
		t.Fatal(err)
	}
}

// restoreEvents returns code:outcome:error_code and the params of the restore events of the test, in order.
func (w restoreWorld) restoreEvents(t *testing.T) ([]string, []string) {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT code || ':' || coalesce(outcome, status) || ':' ||
		coalesce(error_code, ''), params::text FROM action WHERE code LIKE 'platform.restore_%' AND correlation_id = $1
		ORDER BY started_at, id`, "corr-"+t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var evs, params []string
	for rows.Next() {
		var ev, p string
		if err := rows.Scan(&ev, &p); err != nil {
			t.Fatal(err)
		}
		evs, params = append(evs, ev), append(params, p)
	}
	return evs, params
}

func (w restoreWorld) state(t *testing.T, id uuid.UUID) (string, *string) {
	t.Helper()
	var state string
	var detail *string
	if err := w.super.QueryRow(context.Background(), `SELECT state, outcome_detail FROM backup_restore_plan WHERE id = $1`,
		id).Scan(&state, &detail); err != nil {
		t.Fatal(err)
	}
	return state, detail
}

func isProblem(err error, code string) bool {
	return err != nil && problem.From(err).Code == code
}

// TestRestorePlanCreate (plan M15 decision 25): the typed word, the kinds and components, the source check per kind
// and target, the one open plan and the expiry.
func TestRestorePlanCreate(t *testing.T) {
	w := newRestoreWorld(t)
	ctx := steppedPlatform()
	now := time.Now().UTC().Truncate(time.Second)
	t0 := now.Add(-48 * time.Hour)
	w.run(t, "postgres", "succeeded", t0, `[]`)
	w.run(t, "authentik", "succeeded", t0, `[]`)
	w.run(t, "openbao", "failed", t0, `[]`)
	w.run(t, "openbao", "succeeded", now.Add(-time.Hour), `[]`)
	at := now.Add(-24 * time.Hour)

	for _, tc := range []struct {
		name string
		in   app.PlanInput
		code string
	}{
		{"no typed word", app.PlanInput{Kind: "components", Components: []string{"postgres"}}, "invalid_request"},
		{"wrong word", app.PlanInput{Kind: "components", Components: []string{"postgres"}, Confirmation: "RESTORE"}, "invalid_request"},
		{"unknown kind", app.PlanInput{Kind: "fresh_install", Components: []string{"postgres"}, Confirmation: "restore"}, "invalid_request"},
		{"point without at", app.PlanInput{Kind: "point_in_time", Components: []string{"postgres"}, Confirmation: "restore"}, "invalid_request"},
		{"future", app.PlanInput{Kind: "point_in_time", At: new(now.Add(time.Hour)), Components: []string{"postgres"}, Confirmation: "restore"}, "invalid_request"},
		{"components with at", app.PlanInput{Kind: "components", At: &at, Components: []string{"postgres"}, Confirmation: "restore"}, "invalid_request"},
		{"no component", app.PlanInput{Kind: "components", Confirmation: "restore"}, "invalid_request"},
		{"repository alone", app.PlanInput{Kind: "components", Components: []string{"backup-repo"}, Confirmation: "restore"}, "invalid_request"},
		{"unknown target", app.PlanInput{Kind: "components", SourceTargetID: new(uuid.New()), Components: []string{"postgres"}, Confirmation: "restore"}, "invalid_request"},
		{"openbao only failed before at", app.PlanInput{Kind: "point_in_time", At: &at, Components: []string{"postgres", "openbao"}, Confirmation: "restore"}, "invalid_state"},
		{"no fleet", app.PlanInput{Kind: "components", Components: []string{"fleet"}, Confirmation: "restore"}, "invalid_state"},
	} {
		if _, err := w.plans.Create(ctx, tc.in); !isProblem(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	_, err := w.plans.Create(ctx, app.PlanInput{Kind: "point_in_time", At: &at, Components: []string{"openbao"}, Confirmation: "restore"})
	if !isProblem(err, "invalid_state") || !strings.Contains(problem.From(err).Detail, "openbao") {
		t.Errorf("missing kind not named: %v", err)
	}

	plan, err := w.plans.Create(ctx, app.PlanInput{Kind: "point_in_time", At: &at,
		Components: []string{"openbao", "postgres", "postgres"}, Confirmation: "restore"})
	if err == nil {
		t.Fatalf("openbao has no success before at, got %+v", plan)
	}
	plan, err = w.plans.Create(ctx, app.PlanInput{Kind: "point_in_time", At: &at, Components: []string{"postgres", "postgres"},
		Confirmation: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != "approved" || plan.Source != "repo" || strings.Join(plan.Components, ",") != "postgres" ||
		plan.ExpiresAt.Sub(plan.CreatedAt).Round(time.Minute) != 24*time.Hour || plan.CreatedBy != "root" {
		t.Fatalf("plan %+v", plan)
	}
	if _, err := w.plans.Create(ctx, app.PlanInput{Kind: "components", Components: []string{"openbao"}, Confirmation: "restore"}); !isProblem(err, "invalid_state") {
		t.Fatalf("second open plan: %v", err)
	}

	// An approved plan past its expiry reads as expired and no longer blocks a new plan.
	if _, err := w.super.Exec(context.Background(), `UPDATE backup_restore_plan SET expires_at = now() - interval '1 second'
		WHERE id = $1`, plan.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := w.plans.Get(ctx, plan.ID); err != nil || got.State != "expired" {
		t.Fatalf("lapsed plan reads %+v %v", got, err)
	}
	if list, err := w.plans.List(ctx, app.RestorePlanQuery{Page: app.ListPage{Sort: "-created_at", Limit: 10},
		States: []string{"expired"}}); err != nil || list.Count != 1 {
		t.Fatalf("list expired: %+v %v", list, err)
	}
	if _, err := w.plans.Cancel(ctx, plan.ID); !isProblem(err, "invalid_state") {
		t.Fatalf("cancel lapsed: %v", err)
	}
	second, err := w.plans.Create(ctx, app.PlanInput{Kind: "components", Components: []string{"openbao"}, Confirmation: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := w.state(t, plan.ID); s != "expired" {
		t.Errorf("lapsed plan stored as %s", s)
	}
	if _, err := w.plans.Cancel(ctx, second.ID); err != nil {
		t.Fatal(err)
	}

	// A target serves a kind that reached it at or before at, through a run or through its mirror state.
	target, err := w.targets.Create(ctx, s3Input("offsite"))
	if err != nil {
		t.Fatal(err)
	}
	w.run(t, "fleet", "succeeded", t0, `[{"target_id":"`+target.ID.String()+`","ok":false}]`)
	fleetOnTarget := app.PlanInput{Kind: "components", SourceTargetID: &target.ID, Components: []string{"fleet"}, Confirmation: "restore"}
	if _, err := w.plans.Create(ctx, fleetOnTarget); !isProblem(err, "invalid_state") {
		t.Fatalf("fleet never reached the target: %v", err)
	}
	if _, err := w.super.Exec(context.Background(), `INSERT INTO backup_target_status (target_id, kind, last_success_at)
		VALUES ($1, 'fleet', $2)`, target.ID, t0); err != nil {
		t.Fatal(err)
	}
	onTarget, err := w.plans.Create(ctx, fleetOnTarget)
	if err != nil || onTarget.Source != "target" || *onTarget.SourceTargetID != target.ID || *onTarget.SourceTargetName != "offsite" {
		t.Fatalf("plan from target %+v %v", onTarget, err)
	}

	evs, params := w.restoreEvents(t)
	if len(evs) != 20 || evs[len(evs)-1] != "platform.restore_planned:success:" {
		t.Fatalf("events %v", evs)
	}
	if !strings.Contains(params[len(params)-1], target.ID.String()) || !strings.Contains(params[len(params)-1], `"source": "target"`) {
		t.Errorf("params %s", params[len(params)-1])
	}
}

// TestRestorePlanCreateRefusals: organization roles and a missing step-up are refused before any check.
func TestRestorePlanCreateRefusals(t *testing.T) {
	w := newRestoreWorld(t)
	in := app.PlanInput{Kind: "components", Components: []string{"postgres"}, Confirmation: "restore"}
	if _, err := w.plans.Create(platformCtx(), in); !errors.Is(err, problem.StepUpRequired) {
		t.Errorf("without step-up: %v", err)
	}
	if _, err := w.plans.Create(adminCtx(uuid.Must(uuid.NewV7()), principal.RoleOrgAdmin, "alice"), in); !errors.Is(err, problem.Forbidden) {
		t.Errorf("organization admin: %v", err)
	}
	if _, err := w.plans.List(adminCtx(uuid.Must(uuid.NewV7()), principal.RoleOrgAdmin, "alice"), app.RestorePlanQuery{}); !errors.Is(err, problem.Forbidden) {
		t.Errorf("organization admin list: %v", err)
	}
	evs, _ := w.restoreEvents(t)
	if strings.Join(evs, " ") != "platform.restore_planned:denied:step_up_required platform.restore_planned:denied:forbidden" {
		t.Errorf("events %v", evs)
	}
}

// TestRestoreReports (plan M15 decisions 23–24): the host starts an approved plan and finishes it through the backup
// role; an expired plan is refused; a restored database without the plan row records it again; a restore without a
// plan is a fresh_install row.
func TestRestoreReports(t *testing.T) {
	w := newRestoreWorld(t)
	ctx := steppedPlatform()
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	w.run(t, "openbao", "succeeded", at.Add(-time.Hour), `[]`)
	plan, err := w.plans.Create(ctx, app.PlanInput{Kind: "point_in_time", At: &at, Components: []string{"openbao"}, Confirmation: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	report := func(outcome string, id *uuid.UUID) app.RestoreReport {
		return app.RestoreReport{Outcome: outcome, Operator: "alice", Source: "repo", Components: []string{"openbao"}, PlanID: id, At: &at}
	}
	host := context.Background()

	if p, err := w.reports.Plan(app.OperatorContext(host, "host"), plan.ID); err != nil || p.State != "approved" {
		t.Fatalf("host read %+v %v", p, err)
	}
	if _, err := w.reports.Report(host, report("completed", nil)); err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	if _, err := w.reports.Report(host, report("running", nil)); !isProblem(err, "invalid_request") {
		t.Errorf("running without a plan: %v", err)
	}
	if _, err := w.reports.Report(host, app.RestoreReport{Outcome: "running", Operator: "alice; rm", Source: "repo",
		Components: []string{"openbao"}, PlanID: &plan.ID}); !isProblem(err, "invalid_request") {
		t.Errorf("operator not a login name: %v", err)
	}
	started, err := w.reports.Report(host, report("running", &plan.ID))
	if err != nil || started.State != "running" || started.StartedAt == nil {
		t.Fatalf("running: %+v %v", started, err)
	}
	if _, err := w.reports.Report(host, report("running", &plan.ID)); !errors.Is(err, app.ErrRestorePlanNotExecutable) ||
		!isProblem(err, "invalid_state") {
		t.Errorf("running twice: %v", err)
	}
	unknown := uuid.Must(uuid.NewV7())
	if _, err := w.reports.Report(host, report("running", &unknown)); !errors.Is(err, app.ErrRestorePlanNotExecutable) ||
		!isProblem(err, "not_found") {
		t.Errorf("running an unknown plan: %v", err)
	}
	done, err := w.reports.Report(host, report("completed", &plan.ID))
	if err != nil || done.State != "completed" || done.FinishedAt == nil {
		t.Fatalf("completed: %+v %v", done, err)
	}
	if _, err := w.reports.Report(host, report("failed", &plan.ID)); !isProblem(err, "invalid_state") {
		t.Errorf("failed after completed: %v", err)
	}

	// A plan the restored database no longer holds is recorded again under its ID, with the failed step.
	lost := uuid.Must(uuid.NewV7())
	failed := report("failed", &lost)
	failed.Component, failed.Detail = "fleet", "the step fleet failed"
	if _, err := w.reports.Report(host, failed); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if s, d := w.state(t, lost); s != "failed" || d == nil || *d != "fleet: the step fleet failed" {
		t.Errorf("lost plan recorded as %s %v", s, d)
	}

	// An expired plan is refused by the host.
	expired, err := w.plans.Create(ctx, app.PlanInput{Kind: "components", Components: []string{"openbao"}, Confirmation: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(context.Background(), `UPDATE backup_restore_plan SET expires_at = now() WHERE id = $1`, expired.ID); err != nil {
		t.Fatal(err)
	}
	if p, err := w.reports.Plan(host, expired.ID); err != nil || p.State != "expired" {
		t.Errorf("host reads %+v %v", p, err)
	}
	if _, err := w.reports.Report(host, report("running", &expired.ID)); !errors.Is(err, app.ErrRestorePlanNotExecutable) {
		t.Errorf("running an expired plan: %v", err)
	}

	// A plan whose target was deleted keeps source target without a target and is refused, never run from the
	// local repository.
	target, err := w.targets.Create(ctx, s3Input("offsite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(context.Background(), `INSERT INTO backup_target_status (target_id, kind, last_success_at)
		VALUES ($1, 'openbao', $2)`, target.ID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	orphan, err := w.plans.Create(ctx, app.PlanInput{Kind: "components", SourceTargetID: &target.ID,
		Components: []string{"openbao"}, Confirmation: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.targets.Delete(ctx, target.ID); err != nil {
		t.Fatal(err)
	}
	if p, err := w.reports.Plan(host, orphan.ID); err != nil || p.Source != "target" || p.SourceTargetID != nil {
		t.Errorf("host reads %+v %v", p, err)
	}
	if _, err := w.reports.Report(host, report("running", &orphan.ID)); !errors.Is(err, app.ErrRestorePlanNotExecutable) {
		t.Errorf("running a plan without its target: %v", err)
	}
	if s, _ := w.state(t, orphan.ID); s != "approved" {
		t.Errorf("plan without its target stored as %s", s)
	}

	// Every running report is one platform.restore_started event, the refused ones included.
	evs, params := w.restoreEvents(t)
	want := []string{"platform.restore_planned:success:", "platform.restore_completed:success:",
		"platform.restore_started:failure:invalid_request", "platform.restore_started:failure:invalid_request",
		"platform.restore_started:success:", "platform.restore_started:failure:invalid_state",
		"platform.restore_started:failure:not_found",
		"platform.restore_completed:success:", "platform.restore_failed:failure:invalid_state",
		"platform.restore_failed:failure:internal", "platform.restore_planned:success:",
		"platform.restore_started:failure:invalid_state", "platform.restore_planned:success:",
		"platform.restore_started:failure:invalid_state"}
	if strings.Join(evs, " ") != strings.Join(want, " ") {
		t.Fatalf("events %v, want %v", evs, want)
	}
	if !strings.Contains(params[4], plan.ID.String()) || !strings.Contains(params[4], `"source": "repo"`) ||
		!strings.Contains(params[4], `"components": ["openbao"]`) || strings.Contains(params[4], "source_target_id") {
		t.Errorf("start params %s", params[4])
	}
	if !strings.Contains(params[13], orphan.ID.String()) || !strings.Contains(params[13], `"source": "target"`) {
		t.Errorf("refused start params %s", params[13])
	}
	var kinds []string
	if err := w.super.QueryRow(context.Background(), `SELECT array_agg(kind ORDER BY kind) FROM backup_restore_plan
		WHERE kind = 'fresh_install'`).Scan(&kinds); err != nil || len(kinds) != 1 {
		t.Errorf("fresh install rows %v %v", kinds, err)
	}
	if !strings.Contains(params[1], `"plan_id": ""`) || !strings.Contains(params[7], plan.ID.String()) ||
		!strings.Contains(params[7], `"duration_s"`) || !strings.Contains(params[7], `"components": ["openbao"]`) {
		t.Errorf("report params %s / %s", params[1], params[7])
	}
	var actor string
	if err := w.super.QueryRow(context.Background(), `SELECT actor->>'type' || ':' || (actor->>'display') FROM action
		WHERE code = 'platform.restore_completed' AND correlation_id = $1 LIMIT 1`, "corr-"+t.Name()).Scan(&actor); err != nil || actor != "system:alice" {
		t.Errorf("actor %s %v", actor, err)
	}
	var starters []string
	if err := w.super.QueryRow(context.Background(), `SELECT array_agg(actor->>'display' ORDER BY started_at, id) FROM action
		WHERE code = 'platform.restore_started' AND correlation_id = $1`, "corr-"+t.Name()).Scan(&starters); err != nil ||
		strings.Join(starters, " ") != "alice host alice alice alice alice alice" {
		t.Errorf("start actors %v %v", starters, err)
	}
}

// TestRestorePlanAbandon (PDK-832): a running plan whose host never reported its end blocks every new plan until a
// platform administrator abandons it with a step-up and the typed word; the host's later reports are refused and
// audited.
func TestRestorePlanAbandon(t *testing.T) {
	w := newRestoreWorld(t)
	ctx := steppedPlatform()
	w.run(t, "openbao", "succeeded", time.Now().Add(-time.Hour), `[]`)
	in := app.PlanInput{Kind: "components", Components: []string{"openbao"}, Confirmation: "restore"}
	plan, err := w.plans.Create(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.plans.Abandon(ctx, plan.ID, "abandon"); !isProblem(err, "invalid_state") {
		t.Fatalf("abandon an approved plan: %v", err)
	}
	host := context.Background()
	report := func(outcome string) app.RestoreReport {
		return app.RestoreReport{Outcome: outcome, Operator: "alice", Source: "repo", Components: []string{"openbao"}, PlanID: &plan.ID}
	}
	if _, err := w.reports.Report(host, report("running")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.plans.Create(ctx, in); !isProblem(err, "invalid_state") {
		t.Fatalf("new plan while one is running: %v", err)
	}

	if _, err := w.plans.Abandon(platformCtx(), plan.ID, "abandon"); !errors.Is(err, problem.StepUpRequired) {
		t.Errorf("without step-up: %v", err)
	}
	if _, err := w.plans.Abandon(adminCtx(uuid.Must(uuid.NewV7()), principal.RoleOrgAdmin, "alice"), plan.ID, "abandon"); !errors.Is(err, problem.Forbidden) {
		t.Errorf("organization admin: %v", err)
	}
	if _, err := w.plans.Abandon(ctx, plan.ID, "Abandon"); !isProblem(err, "invalid_request") {
		t.Errorf("without the typed word: %v", err)
	}
	if _, err := w.plans.Abandon(ctx, uuid.Must(uuid.NewV7()), "abandon"); !isProblem(err, "not_found") {
		t.Errorf("unknown plan: %v", err)
	}
	if s, _ := w.state(t, plan.ID); s != "running" {
		t.Fatalf("refused abandons changed the plan to %s", s)
	}

	abandoned, err := w.plans.Abandon(ctx, plan.ID, "abandon")
	if err != nil || abandoned.State != "abandoned" || abandoned.FinishedAt == nil || abandoned.OutcomeDetail == nil ||
		*abandoned.OutcomeDetail != "abandoned by root" {
		t.Fatalf("abandon: %+v %v", abandoned, err)
	}
	if _, err := w.plans.Abandon(ctx, plan.ID, "abandon"); !isProblem(err, "invalid_state") {
		t.Errorf("abandon twice: %v", err)
	}

	for _, outcome := range []string{"completed", "failed"} {
		if _, err := w.reports.Report(host, report(outcome)); !isProblem(err, "invalid_state") ||
			!strings.Contains(problem.From(err).Detail, "abandoned") {
			t.Errorf("host reports %s after the abandon: %v", outcome, err)
		}
	}
	if _, err := w.reports.Report(host, report("running")); !errors.Is(err, app.ErrRestorePlanNotExecutable) {
		t.Errorf("host restarts the abandoned plan: %v", err)
	}
	if s, d := w.state(t, plan.ID); s != "abandoned" || d == nil || *d != "abandoned by root" {
		t.Errorf("host reports changed the abandoned plan to %s %v", s, d)
	}

	next, err := w.plans.Create(ctx, in)
	if err != nil {
		t.Fatalf("new plan after the abandon: %v", err)
	}
	if _, err := w.plans.Cancel(ctx, next.ID); err != nil {
		t.Fatal(err)
	}

	evs, params := w.restoreEvents(t)
	want := []string{"platform.restore_planned:success:", "platform.restore_abandoned:failure:invalid_state",
		"platform.restore_started:success:", "platform.restore_planned:failure:invalid_state",
		"platform.restore_abandoned:denied:step_up_required", "platform.restore_abandoned:denied:forbidden",
		"platform.restore_abandoned:failure:invalid_request", "platform.restore_abandoned:failure:not_found",
		"platform.restore_abandoned:success:", "platform.restore_abandoned:failure:invalid_state",
		"platform.restore_completed:failure:invalid_state", "platform.restore_failed:failure:invalid_state",
		"platform.restore_started:failure:invalid_state", "platform.restore_planned:success:",
		"platform.restore_cancelled:success:"}
	if strings.Join(evs, " ") != strings.Join(want, " ") {
		t.Fatalf("events %v, want %v", evs, want)
	}
	if !strings.Contains(params[8], plan.ID.String()) || !strings.Contains(params[8], `"kind": "components"`) ||
		!strings.Contains(params[8], `"components": ["openbao"]`) {
		t.Errorf("abandon params %s", params[8])
	}
	// Refused attempts name the plan they were about, the typed-word refusal before the plan is even read included.
	for i := 4; i <= 6; i++ {
		if !strings.Contains(params[i], `"plan_id": "`+plan.ID.String()+`"`) {
			t.Errorf("refused abandon %s params %s", evs[i], params[i])
		}
	}
	var target string
	if err := w.super.QueryRow(context.Background(), `SELECT coalesce(target::text, '') FROM action
		WHERE code = 'platform.restore_abandoned' AND error_code = 'invalid_request' AND correlation_id = $1`,
		"corr-"+t.Name()).Scan(&target); err != nil || !strings.Contains(target, plan.ID.String()) {
		t.Errorf("typed-word refusal target %q %v", target, err)
	}
}

// TestRestoreHostFailureNotAbandon proves a host failure report cannot pass for an administrator's abandon (PDK-832
// review 1): a failed step named abandoned leaves the plan failed, and the next report is refused as finished.
func TestRestoreHostFailureNotAbandon(t *testing.T) {
	w := newRestoreWorld(t)
	ctx := steppedPlatform()
	w.run(t, "openbao", "succeeded", time.Now().Add(-time.Hour), `[]`)
	plan, err := w.plans.Create(ctx, app.PlanInput{Kind: "components", Components: []string{"openbao"}, Confirmation: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	host := context.Background()
	report := func(outcome string) app.RestoreReport {
		return app.RestoreReport{Outcome: outcome, Operator: "alice", Source: "repo", Components: []string{"openbao"}, PlanID: &plan.ID}
	}
	if _, err := w.reports.Report(host, report("running")); err != nil {
		t.Fatal(err)
	}
	failed := report("failed")
	failed.Component, failed.Detail = "abandoned", "by root"
	if _, err := w.reports.Report(host, failed); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if s, _ := w.state(t, plan.ID); s != "failed" {
		t.Fatalf("host failure recorded as %s", s)
	}
	_, err = w.reports.Report(host, report("completed"))
	if !isProblem(err, "invalid_state") || strings.Contains(problem.From(err).Detail, "abandon") {
		t.Errorf("report after the host failure: %v", err)
	}
}
