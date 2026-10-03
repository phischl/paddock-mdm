package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
)

var commitTrigger sync.Once

type harness struct {
	runner *app.ActionRunner
	super  *pgx.Conn
	org    uuid.UUID
}

func newHarness(t *testing.T) harness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	commitTrigger.Do(func() {
		// Injected commit failure: a deferred constraint trigger raises at COMMIT for a magic group name.
		conn, err := pgx.Connect(context.Background(), env.Super)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(context.Background()) }()
		_, err = conn.Exec(context.Background(), `
			CREATE FUNCTION fail_on_commit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  IF NEW.name = 'fail-on-commit' THEN RAISE EXCEPTION 'injected commit failure'; END IF;
			  RETURN NULL;
			END $$;
			CREATE CONSTRAINT TRIGGER fail_on_commit AFTER INSERT ON device_group
			  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_on_commit();`)
		if err != nil {
			t.Fatal(err)
		}
	})
	ctx := context.Background()
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	platformPool, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platformPool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })

	h := harness{
		runner: app.NewActionRunner(orgPool, platformPool, func(context.Context) string { return "corr-" + t.Name() }),
		super:  super,
		org:    uuid.Must(uuid.NewV7()),
	}
	_, err = super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Test', 'active')",
		h.org, "t"+h.org.String()[24:])
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h harness) admin(role principal.Role) context.Context {
	return principal.With(context.Background(), principal.Principal{
		Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: role, OrganizationID: h.org, IP: "192.0.2.1",
	})
}

type actionRow struct {
	org       uuid.UUID
	code      string
	status    string
	outcome   *string
	errorCode *string
}

// recorded returns the action rows and outbox payloads written for one correlation ID.
func (h harness) recorded(t *testing.T, correlation string) ([]actionRow, []audit.Event) {
	t.Helper()
	ctx := context.Background()
	rows, err := h.super.Query(ctx, "SELECT organization_id, code, status, outcome, error_code FROM action WHERE correlation_id = $1", correlation)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (actionRow, error) {
		var a actionRow
		err := r.Scan(&a.org, &a.code, &a.status, &a.outcome, &a.errorCode)
		return a, err
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = h.super.Query(ctx, "SELECT payload FROM outbox WHERE payload->>'correlation_id' = $1", correlation)
	if err != nil {
		t.Fatal(err)
	}
	events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (audit.Event, error) {
		var raw []byte
		var ev audit.Event
		if err := r.Scan(&raw); err != nil {
			return ev, err
		}
		return ev, json.Unmarshal(raw, &ev)
	})
	if err != nil {
		t.Fatal(err)
	}
	return actions, events
}

func expectOne(t *testing.T, h harness, outcome audit.Outcome, errorCode string) audit.Event {
	t.Helper()
	actions, events := h.recorded(t, "corr-"+t.Name())
	if len(actions) != 1 || len(events) != 1 {
		t.Fatalf("want exactly one action and one outbox event, got %d actions, %d events", len(actions), len(events))
	}
	a, ev := actions[0], events[0]
	if a.status != "finished" || a.outcome == nil || *a.outcome != string(outcome) {
		t.Fatalf("action = %+v, want finished/%s", a, outcome)
	}
	if ev.Outcome != outcome || ev.ErrorCode != errorCode || ev.Schema != audit.Schema {
		t.Fatalf("event outcome %s/%q, want %s/%q", ev.Outcome, ev.ErrorCode, outcome, errorCode)
	}
	if !ev.RecordedAt.IsZero() {
		t.Fatal("outbox payload must not carry recorded_at")
	}
	return ev
}

func createGroup(name string) func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
	return func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
		p, _ := principal.From(ctx)
		g, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.Must(uuid.NewV7()), OrganizationID: p.OrganizationID, Name: name})
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: g.ID.String(), Display: g.Name})
		return nil
	}
}

var createSpec = app.ActionSpec{
	Code:         audit.CodeDeviceGroupCreated,
	AllowedRoles: []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator},
	Params:       map[string]any{"name": "g"},
}

func TestRunTxSuccess(t *testing.T) {
	h := newHarness(t)
	if err := h.runner.RunTx(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, createSpec, createGroup("ok")); err != nil {
		t.Fatal(err)
	}
	ev := expectOne(t, h, audit.OutcomeSuccess, "")
	if ev.OrganizationID != h.org || ev.Code != audit.CodeDeviceGroupCreated || ev.Target == nil || ev.Target.Display != "ok" ||
		ev.Actor.Type != audit.ActorAdmin || ev.Actor.IP != "192.0.2.1" || ev.Source != audit.SourcePortal {
		t.Fatalf("unexpected event %+v", ev)
	}
}

func TestRunTxFnError(t *testing.T) {
	h := newHarness(t)
	err := h.runner.RunTx(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, createSpec,
		func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
			if err := createGroup("rolled-back")(ctx, q, rec); err != nil {
				return err
			}
			return problem.NameTaken
		})
	if !errors.Is(err, problem.NameTaken) {
		t.Fatalf("RunTx = %v, want name_taken", err)
	}
	expectOne(t, h, audit.OutcomeFailure, "name_taken")
	var n int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM device_group WHERE name = 'rolled-back'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("the use case's change was not rolled back (%d rows, %v)", n, err)
	}
}

func TestRunTxCommitError(t *testing.T) {
	h := newHarness(t)
	err := h.runner.RunTx(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, createSpec, createGroup("fail-on-commit"))
	if err == nil {
		t.Fatal("RunTx succeeded despite the injected commit failure")
	}
	expectOne(t, h, audit.OutcomeFailure, "internal")
}

func TestRunTxDenied(t *testing.T) {
	h := newHarness(t)
	called := false
	err := h.runner.RunTx(h.admin(principal.RoleOrgAuditor), app.ScopeOrg, createSpec,
		func(context.Context, *pgstore.Queries, app.Recorder) error { called = true; return nil })
	if !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("RunTx = %v, want forbidden", err)
	}
	if called {
		t.Fatal("fn ran for a denied principal")
	}
	expectOne(t, h, audit.OutcomeDenied, "forbidden")
}

func TestRunTxNoOrganizationIsRecordedInPlatform(t *testing.T) {
	h := newHarness(t)
	ctx := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Role: principal.RolePlatform})
	err := h.runner.RunTx(ctx, app.ScopeOrg, createSpec, createGroup("x"))
	if !errors.Is(err, problem.NoOrganization) {
		t.Fatalf("RunTx = %v, want no_organization", err)
	}
	ev := expectOne(t, h, audit.OutcomeDenied, "no_organization")
	if ev.OrganizationID != audit.PlatformOrganizationID {
		t.Fatalf("denial recorded in %s, want the platform pseudo-organization", ev.OrganizationID)
	}
}

func TestRunTxUnauthenticatedIsNotAudited(t *testing.T) {
	h := newHarness(t)
	err := h.runner.RunTx(context.Background(), app.ScopeOrg, createSpec, createGroup("x"))
	if !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("RunTx = %v, want unauthenticated", err)
	}
	actions, events := h.recorded(t, "corr-"+t.Name())
	if len(actions)+len(events) != 0 {
		t.Fatal("an unauthenticated request was audited")
	}
}

func platformCtx() context.Context {
	return principal.With(context.Background(), principal.Principal{
		Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Display: "root", Role: principal.RolePlatform,
	})
}

func TestRunExternalFailure(t *testing.T) {
	h := newHarness(t)
	orgID := uuid.Must(uuid.NewV7())
	slug := "ext" + orgID.String()[24:]
	spec := app.ActionSpec{Code: audit.CodeOrganizationCreated, AllowedRoles: []principal.Role{principal.RolePlatform},
		Params: map[string]any{"slug": slug}}
	err := h.runner.RunExternal(platformCtx(), app.ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
			rec.SetOrganization(orgID)
			_, err := q.InsertOrganization(ctx, pgstore.InsertOrganizationParams{ID: orgID, Slug: slug, Name: slug, Status: "provisioning"})
			return err
		},
		func(context.Context) error { return problem.UpstreamUnavailable },
		func(ctx context.Context, q *pgstore.Queries, rec app.Recorder, externalErr error) error {
			status := "active"
			if externalErr != nil {
				status = "provisioning_failed"
			}
			_, err := q.UpdateOrganizationStatus(ctx, pgstore.UpdateOrganizationStatusParams{ID: orgID, Name: slug, Status: status})
			return err
		})
	if !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("RunExternal = %v, want upstream_unavailable", err)
	}
	ev := expectOne(t, h, audit.OutcomeFailure, "upstream_unavailable")
	if ev.OrganizationID != orgID || ev.Source != audit.SourcePlatform {
		t.Fatalf("event organization %s source %s, want %s/platform", ev.OrganizationID, ev.Source, orgID)
	}
	var status string
	if err := h.super.QueryRow(context.Background(), "SELECT status FROM organization WHERE id = $1", orgID).Scan(&status); err != nil || status != "provisioning_failed" {
		t.Fatalf("organization status %q (%v), want provisioning_failed", status, err)
	}
}

func TestRunExternalSuccess(t *testing.T) {
	h := newHarness(t)
	orgID := uuid.Must(uuid.NewV7())
	spec := app.ActionSpec{Code: audit.CodeOrganizationCreated, AllowedRoles: []principal.Role{principal.RolePlatform}}
	external := false
	err := h.runner.RunExternal(platformCtx(), app.ScopePlatform, spec,
		func(_ context.Context, _ *pgstore.Queries, rec app.Recorder) error {
			rec.SetOrganization(orgID)
			return nil
		},
		func(context.Context) error { external = true; return nil },
		func(context.Context, *pgstore.Queries, app.Recorder, error) error { return nil })
	if err != nil || !external {
		t.Fatalf("RunExternal = %v, external called %v", err, external)
	}
	expectOne(t, h, audit.OutcomeSuccess, "")
}

func TestRunExternalPrepareError(t *testing.T) {
	h := newHarness(t)
	spec := app.ActionSpec{Code: audit.CodeOrganizationCreated}
	external := false
	err := h.runner.RunExternal(platformCtx(), app.ScopePlatform, spec,
		func(context.Context, *pgstore.Queries, app.Recorder) error { return problem.SlugTaken },
		func(context.Context) error { external = true; return nil },
		func(context.Context, *pgstore.Queries, app.Recorder, error) error { return nil })
	if !errors.Is(err, problem.SlugTaken) || external {
		t.Fatalf("RunExternal = %v (external called %v), want slug_taken without external call", err, external)
	}
	expectOne(t, h, audit.OutcomeFailure, "slug_taken")
}

func TestRunExternalDenied(t *testing.T) {
	h := newHarness(t)
	spec := app.ActionSpec{Code: audit.CodeOrganizationCreated, AllowedRoles: []principal.Role{principal.RolePlatform}}
	err := h.runner.RunExternal(h.admin(principal.RoleOrgAdmin), app.ScopePlatform, spec,
		func(context.Context, *pgstore.Queries, app.Recorder) error { t.Fatal("prepare ran"); return nil },
		func(context.Context) error { t.Fatal("external ran"); return nil },
		func(context.Context, *pgstore.Queries, app.Recorder, error) error { return nil })
	if !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("RunExternal = %v, want forbidden", err)
	}
	if ev := expectOne(t, h, audit.OutcomeDenied, "forbidden"); ev.OrganizationID != h.org {
		t.Fatalf("denied platform action recorded in %s, want the caller's organization %s", ev.OrganizationID, h.org)
	}
}
