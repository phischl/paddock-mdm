package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// deletionWorld is an organization with devices whose deletion a platform administrator requests (plan M17 §8.2).
type deletionWorld struct {
	uninstallWorld
	orgs     *app.Organizations
	devOrgs  *app.Organizations
	slug     string
	platform *db.PlatformPool
}

func newDeletionWorld(t *testing.T) deletionWorld {
	t.Helper()
	w := newUninstallWorld(t)
	env := pgtest.SharedPaddock(t)
	platform, err := db.NewPlatformPool(context.Background(), env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	// Every call records under its own request ID, so the events of one attempt can be counted.
	runner := app.NewActionRunner(w.api, platform, httpx.RequestID)
	uninstalls := app.NewUninstalls(runner, w.api, w.cache)
	d := deletionWorld{uninstallWorld: w, platform: platform,
		orgs:    app.NewOrganizations(runner, platform, nil, uninstalls, false),
		devOrgs: app.NewOrganizations(runner, platform, nil, uninstalls, true)}
	if err := w.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", w.org).Scan(&d.slug); err != nil {
		t.Fatal(err)
	}
	return d
}

// root is a platform administrator, stepped up now when stepUp is set; the context carries a fresh request ID.
func (d deletionWorld) root(stepUp bool) context.Context {
	p := principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Display: "root", Role: principal.RolePlatform,
		IP: "192.0.2.9"}
	if stepUp {
		p.StepUpAt = time.Now()
	}
	return httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())
}

func (d deletionWorld) input(grace int) app.DeletionInput {
	return app.DeletionInput{ConfirmSlug: d.slug, Reason: "contract ended", GraceDays: grace}
}

// attempt returns the single audit event recorded for the request of ctx and fails unless there is exactly one.
func (d deletionWorld) attempt(t *testing.T, ctx context.Context) audit.Event {
	t.Helper()
	rows, err := d.super.Query(context.Background(), "SELECT payload FROM outbox WHERE payload->>'correlation_id' = $1 AND payload ? 'code' ORDER BY id",
		httpx.RequestID(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []audit.Event
	for rows.Next() {
		var raw []byte
		var ev audit.Event
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	if len(events) != 1 {
		t.Fatalf("events of the attempt: %+v, want exactly one", events)
	}
	return events[0]
}

func expectAttempt(t *testing.T, ev audit.Event, code audit.Code, outcome audit.Outcome, errorCode string, org uuid.UUID) {
	t.Helper()
	if ev.Code != code || ev.Outcome != outcome || ev.ErrorCode != errorCode || ev.OrganizationID != org {
		t.Fatalf("event %s %s %q in %s, want %s %s %q in %s", ev.Code, ev.Outcome, ev.ErrorCode, ev.OrganizationID, code,
			outcome, errorCode, org)
	}
}

// TestOrganizationDeletionRequest (plan M17 decisions 1–3): a stepped-up platform administrator requests the deletion;
// every active device without an open uninstall or Lock receives uninstall leave as the system, valid until
// delete_after plus 365 days, without a per-device event; the request is recorded once in the platform
// pseudo-organization with the counts, which the organization keeps.
func TestOrganizationDeletionRequest(t *testing.T) {
	d := newDeletionWorld(t)
	second, _ := d.newDevice(t, d.org, "active")
	locked, _ := d.newDevice(t, d.org, "active")
	retired, _ := d.newDevice(t, d.org, "retired")
	d.exec(t, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by)
		VALUES ($1, $2, $3, 'lock', 'issued', $4)`, uuid.Must(uuid.NewV7()), d.org, locked, uuid.Must(uuid.NewV7()))
	other := d.otherOrg(t)
	foreign, _ := d.newDevice(t, other, "active")

	ctx := d.root(true)
	org, err := d.orgs.RequestDeletion(ctx, d.org, d.input(30))
	if err != nil {
		t.Fatal(err)
	}
	if org.Status != organization.StatusActive || org.DeleteAfter == nil || org.DeletionRequestedAt == nil ||
		org.DeletionUninstallsIssued == nil || *org.DeletionUninstallsIssued != 2 || *org.DeletionUninstallsSkipped != 1 ||
		*org.DeletionRequestedBy != "root" || *org.DeletionReason != "contract ended" {
		t.Fatalf("organization after the request: %+v", org)
	}
	if got := org.DeleteAfter.Sub(*org.DeletionRequestedAt); got != 30*24*time.Hour {
		t.Fatalf("grace period %s", got)
	}
	ev := d.attempt(t, ctx)
	expectAttempt(t, ev, audit.CodeOrganizationDeletionRequested, audit.OutcomeSuccess, "", audit.PlatformOrganizationID)
	if ev.Target == nil || ev.Target.ID != d.org.String() || ev.Params["slug"] != d.slug || ev.Params["reason"] != "contract ended" ||
		ev.Params["grace_days"] != float64(30) || ev.Params["uninstalls_issued"] != float64(2) ||
		ev.Params["uninstalls_skipped"] != float64(1) || ev.Params["delete_after"] != org.DeleteAfter.UTC().Format(time.RFC3339) ||
		!ev.Actor.StepUp {
		t.Fatalf("event %+v", ev)
	}

	want := org.DeleteAfter.Add(organization.OffboardedDeviceRetention)
	for _, dev := range []uuid.UUID{d.device, second} {
		var mode, reason, typ, cmdMode string
		var issuedBy *uuid.UUID
		var expires time.Time
		err := d.super.QueryRow(context.Background(), `SELECT d.uninstall_mode, d.uninstall_reason, c.type, c.params->>'mode',
			c.issued_by, c.expires_at FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
			WHERE d.id = $1 AND c.status = 'pending'`, dev).Scan(&mode, &reason, &typ, &cmdMode, &issuedBy, &expires)
		if err != nil {
			t.Fatalf("device %s: %v", dev, err)
		}
		if mode != "leave" || reason != "organization_offboarding" || typ != "uninstall" || cmdMode != "leave" || issuedBy != nil ||
			!expires.Equal(want) {
			t.Fatalf("device %s: mode %s reason %s type %s params mode %s issued_by %v expires %s (want %s)", dev, mode, reason,
				typ, cmdMode, issuedBy, expires, want)
		}
	}
	for _, dev := range []uuid.UUID{locked, retired, foreign} {
		if n := d.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1", dev); n != 0 {
			t.Fatalf("device %s got %d commands", dev, n)
		}
	}
	if n := d.count(t, "SELECT count(*) FROM outbox WHERE payload->>'code' = 'device.uninstall_requested' AND organization_id = $1", d.org); n != 0 {
		t.Fatalf("%d per-device uninstall events", n)
	}

	// A second request conflicts and is recorded once as well.
	again := d.root(true)
	_, err = d.orgs.RequestDeletion(again, d.org, d.input(30))
	expectUninstallProblem(t, err, "invalid_state", 409, "a deletion is already requested")
	expectAttempt(t, d.attempt(t, again), audit.CodeOrganizationDeletionRequested, audit.OutcomeFailure, "invalid_state",
		audit.PlatformOrganizationID)
}

// TestOrganizationDeletionRequestRefusals (plan M17 §8.2): the typed slug, the reason, the grace period, the step-up,
// the platform role, the organization's existence and state are checked, and each refused attempt is recorded once.
func TestOrganizationDeletionRequestRefusals(t *testing.T) {
	d := newDeletionWorld(t)
	long := strings.Repeat("r", 501)
	for name, tc := range map[string]struct {
		in  app.DeletionInput
		dev bool
	}{
		"wrong slug":              {in: app.DeletionInput{ConfirmSlug: d.slug + "x", Reason: "ok", GraceDays: 30}},
		"reason of 1":             {in: app.DeletionInput{ConfirmSlug: d.slug, Reason: "r", GraceDays: 30}},
		"reason of 501":           {in: app.DeletionInput{ConfirmSlug: d.slug, Reason: long, GraceDays: 30}},
		"grace 6":                 {in: d.input(6)},
		"grace 91":                {in: d.input(91)},
		"grace 0 in production":   {in: d.input(0)},
		"grace 91 in development": {in: d.input(91), dev: true},
	} {
		orgs := d.orgs
		if tc.dev {
			orgs = d.devOrgs
		}
		ctx := d.root(true)
		_, err := orgs.RequestDeletion(ctx, d.org, tc.in)
		if p := problem.From(err); p.Code != "invalid_request" || p.Status != 400 {
			t.Fatalf("%s: %v", name, err)
		}
		expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationDeletionRequested, audit.OutcomeFailure, "invalid_request",
			audit.PlatformOrganizationID)
	}

	noStepUp := d.root(false)
	if _, err := d.orgs.RequestDeletion(noStepUp, d.org, d.input(30)); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("without a step-up: %v", err)
	}
	expectAttempt(t, d.attempt(t, noStepUp), audit.CodeOrganizationDeletionRequested, audit.OutcomeDenied, "step_up_required",
		audit.PlatformOrganizationID)

	orgAdmin := d.as(d.org, principal.RoleOrgAdmin, true)
	if _, err := d.orgs.RequestDeletion(orgAdmin, d.org, d.input(30)); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("organization administrator: %v", err)
	}
	expectAttempt(t, d.attempt(t, orgAdmin), audit.CodeOrganizationDeletionRequested, audit.OutcomeDenied, "forbidden", d.org)

	unknown := d.root(true)
	if _, err := d.orgs.RequestDeletion(unknown, uuid.Must(uuid.NewV7()), d.input(30)); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown organization: %v", err)
	}
	expectAttempt(t, d.attempt(t, unknown), audit.CodeOrganizationDeletionRequested, audit.OutcomeFailure, "not_found",
		audit.PlatformOrganizationID)

	for _, status := range []string{"provisioning", "suspended", "deleting", "deleted"} {
		org := d.otherOrg(t)
		var slug string
		if err := d.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", org).Scan(&slug); err != nil {
			t.Fatal(err)
		}
		d.exec(t, `UPDATE organization SET status = $2, deleted_at = CASE WHEN $2 = 'deleted' THEN now() END,
			deletion_requested_at = CASE WHEN $2 IN ('deleting', 'deleted') THEN now() END,
			delete_after = CASE WHEN $2 IN ('deleting', 'deleted') THEN now() END WHERE id = $1`, org, status)
		ctx := d.root(true)
		_, err := d.orgs.RequestDeletion(ctx, org, app.DeletionInput{ConfirmSlug: slug, Reason: "ok", GraceDays: 30})
		if p := problem.From(err); p.Code != "invalid_state" || p.Status != 409 {
			t.Fatalf("status %s: %v", status, err)
		}
		expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationDeletionRequested, audit.OutcomeFailure, "invalid_state",
			audit.PlatformOrganizationID)
	}

	if n := d.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1", d.device); n != 0 {
		t.Fatalf("a refused request issued %d commands", n)
	}
	if n := d.count(t, "SELECT count(*) FROM organization WHERE id = $1 AND delete_after IS NOT NULL", d.org); n != 0 {
		t.Fatal("a refused request left a pending deletion")
	}

	// Development stacks may delete at once.
	ctx := d.root(true)
	org, err := d.devOrgs.RequestDeletion(ctx, d.org, d.input(0))
	if err != nil || org.DeleteAfter == nil || !org.DeleteAfter.Equal(*org.DeletionRequestedAt) {
		t.Fatalf("grace 0 in development: %+v %v", org, err)
	}
}

// TestOrganizationDeletionRequestIssueFailure: when issuing the uninstalls fails, no command stays and the deletion is
// withdrawn, so a pending deletion always has its uninstalls; the attempt is recorded once as failure.
func TestOrganizationDeletionRequestIssueFailure(t *testing.T) {
	d := newDeletionWorld(t)
	fn := "fail_offboarding_" + strings.ReplaceAll(d.device.String(), "-", "")
	d.exec(t, `CREATE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		  IF NEW.device_id = '`+d.device.String()+`' THEN RAISE EXCEPTION 'injected insert failure'; END IF;
		  RETURN NEW;
		END $$`)
	d.exec(t, `CREATE TRIGGER `+fn+` BEFORE INSERT ON device_command FOR EACH ROW EXECUTE FUNCTION `+fn+`()`)
	t.Cleanup(func() {
		_, _ = d.super.Exec(context.Background(), "DROP TRIGGER "+fn+" ON device_command; DROP FUNCTION "+fn+"()")
	})
	second, _ := d.newDevice(t, d.org, "active")

	ctx := d.root(true)
	if _, err := d.orgs.RequestDeletion(ctx, d.org, d.input(30)); err == nil {
		t.Fatal("the request succeeded")
	}
	expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationDeletionRequested, audit.OutcomeFailure, "internal",
		audit.PlatformOrganizationID)
	if n := d.count(t, "SELECT count(*) FROM device_command WHERE device_id = ANY($1)", []uuid.UUID{d.device, second}); n != 0 {
		t.Fatalf("%d commands stayed", n)
	}
	if n := d.count(t, `SELECT count(*) FROM organization WHERE id = $1 AND deletion_requested_at IS NULL AND delete_after IS NULL
		AND deletion_uninstalls_issued IS NULL`, d.org); n != 1 {
		t.Fatal("the deletion stayed pending")
	}
}

// TestOrganizationDeletionCancel (plan M17 decision 4): the cancel withdraws the offboarding uninstalls the devices have
// not received, keeps a delivered one and an uninstall an organization administrator requested, clears the deletion
// with its counts and is recorded once; without a pending deletion it conflicts.
func TestOrganizationDeletionCancel(t *testing.T) {
	d := newDeletionWorld(t)
	delivered, _ := d.newDevice(t, d.org, "active")
	own, ownHost := d.newDevice(t, d.org, "active")

	notPending := d.root(false)
	_, err := d.orgs.CancelDeletion(notPending, d.org)
	expectUninstallProblem(t, err, "invalid_state", 409, "no deletion is pending")
	expectAttempt(t, d.attempt(t, notPending), audit.CodeOrganizationDeletionCancelled, audit.OutcomeFailure, "invalid_state",
		audit.PlatformOrganizationID)

	if _, err := d.uninstalls.Request(d.as(d.org, principal.RoleOrgAdmin, true), own,
		app.UninstallInput{Mode: "reset", ConfirmHostname: ownHost, Reason: "returned"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.orgs.RequestDeletion(d.root(true), d.org, d.input(30)); err != nil {
		t.Fatal(err)
	}
	d.exec(t, `UPDATE device_command SET status = 'delivered', delivered_at = now()
		WHERE id = (SELECT uninstall_command_id FROM device WHERE id = $1)`, delivered)

	orgAdmin := d.as(d.org, principal.RoleOrgAdmin, false)
	if _, err := d.orgs.CancelDeletion(orgAdmin, d.org); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("organization administrator: %v", err)
	}
	expectAttempt(t, d.attempt(t, orgAdmin), audit.CodeOrganizationDeletionCancelled, audit.OutcomeDenied, "forbidden", d.org)
	unknown := d.root(false)
	if _, err := d.orgs.CancelDeletion(unknown, uuid.Must(uuid.NewV7())); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown organization: %v", err)
	}
	expectAttempt(t, d.attempt(t, unknown), audit.CodeOrganizationDeletionCancelled, audit.OutcomeFailure, "not_found",
		audit.PlatformOrganizationID)

	// The organization administrator cannot withdraw an offboarding uninstall per device (plan M17 amendment e point 8);
	// the refused attempt is recorded.
	_, err = d.uninstalls.Cancel(d.as(d.org, principal.RoleOrgAdmin, true), d.device)
	expectUninstallProblem(t, err, "invalid_state", 409,
		"the uninstall belongs to the organization's deletion; only cancelling the deletion withdraws it")
	if params, outcome := d.event(t, "device.uninstall_cancelled"); outcome != "failure" || params["hostname"] == nil {
		t.Fatalf("refused per-device cancel: %s %v", outcome, params)
	}

	var pendingCmd uuid.UUID
	if err := d.super.QueryRow(context.Background(), "SELECT uninstall_command_id FROM device WHERE id = $1", d.device).Scan(&pendingCmd); err != nil {
		t.Fatal(err)
	}
	ctx := d.root(false)
	org, err := d.orgs.CancelDeletion(ctx, d.org)
	if err != nil {
		t.Fatal(err)
	}
	if org.DeleteAfter != nil || org.DeletionRequestedAt != nil || org.DeletionUninstallsIssued != nil || org.DeletionReason != nil {
		t.Fatalf("organization after the cancel: %+v", org)
	}
	ev := d.attempt(t, ctx)
	expectAttempt(t, ev, audit.CodeOrganizationDeletionCancelled, audit.OutcomeSuccess, "", audit.PlatformOrganizationID)
	if ev.Params["slug"] != d.slug || ev.Params["uninstalls_cancelled"] != float64(1) {
		t.Fatalf("event params %v", ev.Params)
	}
	if n := d.count(t, `SELECT count(*) FROM device d JOIN device_command c ON c.id = $2
		WHERE d.id = $1 AND d.uninstall_requested_at IS NULL AND d.uninstall_reason IS NULL AND c.status = 'cancelled'`, d.device, pendingCmd); n != 1 {
		t.Fatal("the undelivered offboarding uninstall was not withdrawn")
	}
	if !containsID(d.cache.deleted, pendingCmd) {
		t.Fatal("the withdrawn command stayed in the device cache")
	}
	if n := d.count(t, `SELECT count(*) FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
		WHERE d.id = $1 AND d.uninstall_reason = 'organization_offboarding' AND c.status = 'delivered'`, delivered); n != 1 {
		t.Fatal("the delivered offboarding uninstall was withdrawn")
	}
	if n := d.count(t, `SELECT count(*) FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
		WHERE d.id = $1 AND d.uninstall_mode = 'reset' AND d.uninstall_reason IS NULL AND c.status = 'pending'`, own); n != 1 {
		t.Fatal("the administrator's own uninstall was withdrawn")
	}
	if n := d.count(t, `SELECT count(*) FROM outbox WHERE payload->>'code' = 'device.uninstall_cancelled'
		AND payload->>'outcome' = 'success' AND organization_id = $1`, d.org); n != 0 {
		t.Fatalf("%d per-device cancel events", n)
	}

	// The administrator's own uninstall stays cancellable per device.
	if _, err := d.uninstalls.Cancel(d.as(d.org, principal.RoleOrgAdmin, false), own); err != nil {
		t.Fatalf("own uninstall: %v", err)
	}

	again := d.root(false)
	_, err = d.orgs.CancelDeletion(again, d.org)
	expectUninstallProblem(t, err, "invalid_state", 409, "no deletion is pending")
	expectAttempt(t, d.attempt(t, again), audit.CodeOrganizationDeletionCancelled, audit.OutcomeFailure, "invalid_state",
		audit.PlatformOrganizationID)
}

// TestOrganizationDeletionCancelWhileIssuing: a request whose uninstall counts are not recorded yet is still issuing,
// so a cancel conflicts and cannot leave uninstalls behind; once the request is stale (its process died) the cancel
// works.
func TestOrganizationDeletionCancelWhileIssuing(t *testing.T) {
	d := newDeletionWorld(t)
	d.exec(t, `UPDATE organization SET deletion_requested_at = now(), deletion_requested_by = 'root', deletion_reason = 'r1',
		delete_after = now() + interval '30 days' WHERE id = $1`, d.org)
	ctx := d.root(false)
	_, err := d.orgs.CancelDeletion(ctx, d.org)
	expectUninstallProblem(t, err, "invalid_state", 409, "the deletion request is still issuing its uninstalls")
	expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationDeletionCancelled, audit.OutcomeFailure, "invalid_state",
		audit.PlatformOrganizationID)

	d.exec(t, "UPDATE organization SET deletion_requested_at = now() - interval '11 minutes' WHERE id = $1", d.org)
	if _, err := d.orgs.CancelDeletion(d.root(false), d.org); err != nil {
		t.Fatalf("stale request: %v", err)
	}
}

func containsID(ids []uuid.UUID, id uuid.UUID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// injectOrganizationUpdateFailure makes every update of org that records uninstall counts raise.
func (d deletionWorld) injectOrganizationUpdateFailure(t *testing.T, org uuid.UUID) {
	t.Helper()
	fn := "fail_counts_" + strings.ReplaceAll(org.String(), "-", "")
	d.exec(t, `CREATE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		  IF NEW.id = '`+org.String()+`' AND NEW.deletion_uninstalls_issued IS NOT NULL THEN
		    RAISE EXCEPTION 'injected finalize failure';
		  END IF;
		  RETURN NEW;
		END $$`)
	d.exec(t, `CREATE TRIGGER `+fn+` BEFORE UPDATE ON organization FOR EACH ROW EXECUTE FUNCTION `+fn+`()`)
	t.Cleanup(func() {
		_, _ = d.super.Exec(context.Background(), "DROP TRIGGER "+fn+" ON organization; DROP FUNCTION "+fn+"()")
	})
}

// TestOrganizationDeletionFinalizeFailure (plan M17 amendment e point 13): when recording the counts fails after the
// uninstalls went out, the failure event still states how many devices were told to leave; the deletion stays pending
// without counts, so the worker never starts it and only a stale cancel ends it.
func TestOrganizationDeletionFinalizeFailure(t *testing.T) {
	d := newDeletionWorld(t)
	locked, _ := d.newDevice(t, d.org, "active")
	d.exec(t, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by)
		VALUES ($1, $2, $3, 'lock', 'issued', $4)`, uuid.Must(uuid.NewV7()), d.org, locked, uuid.Must(uuid.NewV7()))
	d.injectOrganizationUpdateFailure(t, d.org)

	ctx := d.root(true)
	if _, err := d.orgs.RequestDeletion(ctx, d.org, d.input(30)); err == nil {
		t.Fatal("the request succeeded")
	}
	ev := d.attempt(t, ctx)
	expectAttempt(t, ev, audit.CodeOrganizationDeletionRequested, audit.OutcomeFailure, "internal", audit.PlatformOrganizationID)
	if ev.Params["uninstalls_issued"] != float64(1) || ev.Params["uninstalls_skipped"] != float64(1) {
		t.Fatalf("failure event params %v", ev.Params)
	}
	if n := d.count(t, `SELECT count(*) FROM organization WHERE id = $1 AND delete_after IS NOT NULL
		AND deletion_uninstalls_issued IS NULL`, d.org); n != 1 {
		t.Fatal("the deletion is not pending without counts")
	}
	if n := d.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_reason = 'organization_offboarding'", d.device); n != 1 {
		t.Fatal("the issued uninstall is gone")
	}
}

// blockingClaimCache is the device cache of a cancel whose budget runs out: a result claim waits for the deadline.
type blockingClaimCache struct{ *fakeUninstallCache }

func (c blockingClaimCache) ClaimResult(ctx context.Context, _, _ uuid.UUID, _ string) (uuid.UUID, string, error) {
	<-ctx.Done()
	return uuid.Nil, "", ctx.Err()
}

// TestOrganizationDeletionCancelBudget (plan M17 amendment e point 6): a cancel that exceeds its budget rolls back;
// the deletion and the uninstalls stay, and the attempt is recorded as failure.
func TestOrganizationDeletionCancelBudget(t *testing.T) {
	d := newDeletionWorld(t)
	if _, err := d.orgs.RequestDeletion(d.root(true), d.org, d.input(30)); err != nil {
		t.Fatal(err)
	}
	runner := app.NewActionRunner(d.api, d.platform, httpx.RequestID)
	slow := app.NewOrganizations(runner, d.platform, nil, app.NewUninstalls(runner, d.api, blockingClaimCache{d.cache}), false).
		WithDeletionRequestBudget(200 * time.Millisecond)
	ctx := d.root(false)
	if _, err := slow.CancelDeletion(ctx, d.org); err == nil {
		t.Fatal("the cancel succeeded")
	}
	expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationDeletionCancelled, audit.OutcomeFailure, "internal",
		audit.PlatformOrganizationID)
	if n := d.count(t, `SELECT count(*) FROM organization WHERE id = $1 AND delete_after IS NOT NULL
		AND deletion_uninstalls_issued = 1`, d.org); n != 1 {
		t.Fatal("the deletion did not stay pending")
	}
	if n := d.count(t, `SELECT count(*) FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
		WHERE d.id = $1 AND d.uninstall_reason = 'organization_offboarding' AND c.status = 'pending'`, d.device); n != 1 {
		t.Fatal("the uninstall did not stay")
	}
}

// TestOrganizationDeletionTenThousandDevices (plan M17 amendment e point 7): request and cancel for 10 000 active
// devices end to end. Targets on the development host: request ≤ 5 s, cancel ≤ 20 s; the test asserts loose ceilings.
func TestOrganizationDeletionTenThousandDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 10 000 devices")
	}
	d := newDeletionWorld(t)
	d.exec(t, `INSERT INTO device (id, organization_id, hostname, state)
		SELECT uuidv7(), $1, 'bulk-' || g, 'active' FROM generate_series(1, 9999) g`, d.org)

	start := time.Now()
	org, err := d.orgs.RequestDeletion(d.root(true), d.org, d.input(30))
	request := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if *org.DeletionUninstallsIssued != 10000 || *org.DeletionUninstallsSkipped != 0 {
		t.Fatalf("counts %d/%d", *org.DeletionUninstallsIssued, *org.DeletionUninstallsSkipped)
	}
	start = time.Now()
	ctx := d.root(false)
	if _, err := d.orgs.CancelDeletion(ctx, d.org); err != nil {
		t.Fatal(err)
	}
	cancel := time.Since(start)
	if ev := d.attempt(t, ctx); ev.Params["uninstalls_cancelled"] != float64(10000) {
		t.Fatalf("cancelled %v", ev.Params["uninstalls_cancelled"])
	}
	t.Logf("10 000 devices: request %s (target 5 s), cancel %s (target 20 s)", request, cancel)
	if request > 30*time.Second || cancel > 60*time.Second {
		t.Fatalf("request %s (ceiling 30 s), cancel %s (ceiling 60 s)", request, cancel)
	}
}
