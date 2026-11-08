package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/buildinfo"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/migrate"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type fakeSeal struct{ st bao.SealStatus }

func (f fakeSeal) SealStatus(context.Context) (bao.SealStatus, error) { return f.st, nil }

type fakeSessionCounter map[uuid.UUID]int

func (f fakeSessionCounter) CountAccount(_ context.Context, id uuid.UUID) (int, error) {
	return f[id], nil
}

func itemOf(t *testing.T, r app.UpgradeCheckReport, name string) app.UpgradeCheckItem {
	t.Helper()
	for _, i := range r.Items {
		if i.Name == name {
			return i
		}
	}
	t.Fatalf("no item %s in %+v", name, r.Items)
	return app.UpgradeCheckItem{}
}

// TestUpgradeCheckReport (plan M16 decision 4): the report of a seeded installation counts the active devices of
// every organization, lists those whose agent is a release older than the window (development versions and other
// states are not judged), fails above 1 % or 5 devices, refuses a database ahead of the binary, warns on a running
// agent rollout, passes a database that predates the goose_db_version grant, and answers only platform administrators and
// the CLI. It runs on its own database: the counts cover
// the whole installation.
func TestUpgradeCheckReport(t *testing.T) {
	env := pgtest.StartPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	pool := func(dsn string) *db.OrgPool {
		p, err := db.NewOrgPool(ctx, dsn, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)

	device := func(org uuid.UUID, hostname, state string, version *string) {
		t.Helper()
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, $4)", id, org, hostname, state)
		if version != nil {
			exec("INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, $3)", id, org, *version)
		}
	}
	ptr := func(s string) *string { return &s }
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, org := range []uuid.UUID{a, b} {
		exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'U', 'active')", org, "u"+org.String()[24:])
	}
	target := buildinfo.Current()
	for i := range 3 {
		device(a, "a-current-"+string(rune('0'+i)), "active", ptr(target))
	}
	device(a, "a-window", "active", ptr(buildinfo.Window(target)[0]))
	device(a, "a-dev", "active", ptr("0.0.0-dev"))
	device(a, "a-silent", "active", nil)
	device(a, "a-old", "active", ptr("0.0.1"))
	device(a, "a-retired", "retired", ptr("0.0.1"))
	device(b, "b-old-1", "active", ptr("0.1.0-alpha.1"))
	device(b, "b-old-2", "active", ptr("0.1.0-alpha.1"))

	admin := uuid.Must(uuid.NewV7())
	exec("INSERT INTO platform_admin (id, authentik_sub, username, display_name) VALUES ($1, $2, 'root', 'root')", admin, uuid.NewString())
	binary, err := migrate.LatestPaddock()
	if err != nil {
		t.Fatal(err)
	}
	seal := fakeSeal{bao.SealStatus{Reachable: true, Initialized: true, Sealed: true}}
	api := app.NewUpgradeCheck(pool(env.API), platform, seal, fakeSessionCounter{admin: 2}, binary)
	cli := app.NewUpgradeCheck(pool(env.Worker), platform, nil, nil, binary)
	root := principal.With(ctx, principal.Principal{Kind: principal.KindPlatformAdmin, ID: admin, Role: principal.RolePlatform})

	r, err := api.Report(root, target)
	if err != nil {
		t.Fatal(err)
	}
	if r.TargetVersion != target || !slices.Equal(r.Window, buildinfo.Window(target)) || r.Failed() {
		t.Fatalf("report %+v", r)
	}
	names := make([]string, len(r.Items))
	for i, it := range r.Items {
		names[i] = it.Name
	}
	if want := []string{"migrations", "agents", "backups", "openbao", "pending", "sessions"}; !slices.Equal(names, want) {
		t.Fatalf("items %v, want %v", names, want)
	}
	if it := itemOf(t, r, app.CheckAgents); it.Status != app.CheckWarn || !strings.HasPrefix(it.Detail, "3 of 9 active devices") {
		t.Errorf("agents %+v", it)
	}
	var listed []string
	for _, o := range r.AgentsOutside {
		listed = append(listed, o.Hostname+"="+o.AgentVersion)
	}
	slices.Sort(listed)
	if want := []string{"a-old=0.0.1", "b-old-1=0.1.0-alpha.1", "b-old-2=0.1.0-alpha.1"}; !slices.Equal(listed, want) {
		t.Errorf("agents outside %v, want %v", listed, want)
	}
	if it := itemOf(t, r, app.CheckMigrations); it.Status != app.CheckPass || !strings.Contains(it.Detail, "as this release expects") {
		t.Errorf("migrations %+v", it)
	}
	if it := itemOf(t, r, app.CheckBackups); it.Status != app.CheckInfo || !strings.HasPrefix(it.Detail, "n/a") {
		t.Errorf("backups %+v", it)
	}
	if it := itemOf(t, r, app.CheckOpenBao); it.Status != app.CheckInfo || it.Detail != "OpenBao sealed; automatic unseal disabled" {
		t.Errorf("openbao %+v", it)
	}
	if it := itemOf(t, r, app.CheckPending); it.Status != app.CheckPass {
		t.Errorf("pending %+v", it)
	}
	if it := itemOf(t, r, app.CheckSessions); it.Detail != "1 platform administrators signed in" {
		t.Errorf("sessions %+v", it)
	}

	// Above 5 devices outside (and above 1 %): FAIL. A running agent rollout: WARN. The CLI sees the same.
	for i := range 3 {
		device(b, "b-old-more-"+string(rune('0'+i)), "active", ptr("0.1.0-alpha.1"))
	}
	exec("INSERT INTO agent_release (version, status, created_by, published_at) VALUES ('0.1.0-alpha.7', 'published', 't', now())")
	exec("INSERT INTO agent_rollout (version, status, started_by) VALUES ('0.1.0-alpha.7', 'running', 't')")
	r, err = cli.ReportCLI(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if it := itemOf(t, r, app.CheckAgents); it.Status != app.CheckFail || !strings.HasPrefix(it.Detail, "6 of 12 active devices") || !r.Failed() {
		t.Errorf("agents %+v", it)
	}
	if it := itemOf(t, r, app.CheckPending); it.Status != app.CheckWarn || !strings.Contains(it.Detail, "0.1.0-alpha.7") {
		t.Errorf("pending %+v", it)
	}
	if it := itemOf(t, r, app.CheckOpenBao); it.Detail != "seal state n/a; automatic unseal disabled" {
		t.Errorf("openbao without a client %+v", it)
	}
	if it := itemOf(t, r, app.CheckSessions); !strings.HasPrefix(it.Detail, "n/a") {
		t.Errorf("sessions without a store %+v", it)
	}

	// A database ahead of the binary is a downgrade.
	exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)", binary+1)
	r, err = cli.ReportCLI(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if it := itemOf(t, r, app.CheckMigrations); it.Status != app.CheckFail {
		t.Errorf("migrations with the database ahead: %+v", it)
	}

	// A database from before migration 00102 does not let the platform role read goose_db_version: it is behind the
	// binary, and the rest of the report still runs.
	exec("REVOKE SELECT ON goose_db_version FROM paddock_platform")
	for name, check := range map[string]func() (app.UpgradeCheckReport, error){
		"api": func() (app.UpgradeCheckReport, error) { return api.Report(root, target) },
		"cli": func() (app.UpgradeCheckReport, error) { return cli.ReportCLI(ctx, target) },
	} {
		r, err := check()
		if err != nil {
			t.Fatalf("%s without the goose_db_version grant: %v", name, err)
		}
		if it := itemOf(t, r, app.CheckMigrations); it.Status != app.CheckPass || !strings.Contains(it.Detail, "predates") {
			t.Errorf("%s migrations without the goose_db_version grant: %+v", name, it)
		}
		if len(r.Items) != 6 {
			t.Errorf("%s items %+v", name, r.Items)
		}
	}

	if _, err := api.Report(root, "0.0.0-unknown"); !errors.Is(err, app.ErrUnknownTargetVersion) {
		t.Errorf("unknown target: %v", err)
	}
	orgAdmin := principal.With(ctx, principal.Principal{Kind: principal.KindAdmin, Role: principal.RoleOrgAdmin, OrganizationID: a, ID: uuid.Must(uuid.NewV7())})
	if _, err := api.Report(orgAdmin, target); !errors.Is(err, problem.Forbidden) {
		t.Errorf("organization administrator: %v", err)
	}
}
