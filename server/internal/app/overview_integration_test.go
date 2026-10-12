package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// overviewAgent is what the overview reads about the agent in one organization's scope.
type overviewAgent struct {
	latest  string
	rollout []pgstore.RunningAgentRolloutRow
	updates pgstore.OverviewUpdatesRow
}

// TestOverviewAgentRelease (PDK-051, plan M7c decision 26 amendment 2026-10-12): the API role reads the latest
// published release and the running rollout in organization scope through paddock_latest_published_agent_version
// and paddock_running_agent_rollout; the worker and platform roles may not call them. The agent buckets of
// OverviewUpdates compare by SemVer precedence, partition the active devices of the asking organization while a
// current release exists, and never count another organization's devices. Everything runs in one transaction that is
// rolled back, so the releases of other tests stay untouched.
func TestOverviewAgentRelease(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	tx, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	org := func() uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", id, "o"+id.String()[24:])
		return id
	}
	device := func(org uuid.UUID, state string, version *string) {
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', $3)", id, org, state)
		exec("INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, $3)", id, org, version)
	}
	v := func(s string) *string { return &s }
	acme, globex := org(), org()
	// acme: two on the current release (one differs only in build metadata), one older, one that is no semantic
	// version, one newer, one without agent version, one without a status row; a retired device is not counted.
	for _, version := range []*string{v("500.0.0"), v("500.0.0+build.7"), v("499.9.9"), v("not-a-version"), v("500.2.0"), nil} {
		device(acme, "active", version)
	}
	exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", uuid.Must(uuid.NewV7()), acme)
	device(acme, "retired", v("1.0.0"))
	device(globex, "active", v("499.0.0"))

	read := func(role string, asking uuid.UUID) (overviewAgent, error) {
		t.Helper()
		var out overviewAgent
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sp.Rollback(ctx) }()
		if _, err := sp.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", asking.String()); err != nil {
			t.Fatal(err)
		}
		q := pgstore.New(sp)
		if out.latest, err = q.LatestPublishedAgentVersion(ctx); err != nil {
			return out, err
		}
		if out.rollout, err = q.RunningAgentRollout(ctx); err != nil {
			return out, err
		}
		out.updates, err = q.OverviewUpdates(ctx)
		return out, err
	}
	api := func(asking uuid.UUID) overviewAgent {
		t.Helper()
		out, err := read("paddock_api", asking)
		if err != nil {
			t.Fatalf("api role: %v", err)
		}
		return out
	}

	// Without any published release or rollout: no latest, no rollout, and only unknown counts.
	exec("UPDATE agent_rollout SET status = 'halted' WHERE status IN ('running', 'completed')")
	exec("UPDATE agent_release SET status = 'draft' WHERE status = 'published'")
	if got := api(acme); got.latest != "" || len(got.rollout) != 0 ||
		got.updates.AgentOnCurrent != 0 || got.updates.AgentOutdated != 0 || got.updates.AgentAhead != 0 || got.updates.AgentUnknown != 2 {
		t.Fatalf("without releases: %+v", got)
	}

	// 500.10.0 is the newest published release by precedence (lexically below 500.2.0); 600.0.0 is only a draft.
	// 500.0.0 completed its rollout, 500.2.0 runs in its second of four waves at 10 %.
	for version, status := range map[string]string{"500.0.0": "published", "500.2.0": "published", "500.10.0": "published", "600.0.0": "draft"} {
		exec("INSERT INTO agent_release (version, status, created_by, published_at) VALUES ($1, $2, 't', now()) ON CONFLICT (version) DO UPDATE SET status = EXCLUDED.status", version, status)
	}
	exec(`INSERT INTO agent_rollout (version, status, started_by, updated_at) VALUES ('500.0.0', 'completed', 't', '2300-01-01T00:00:00Z')
		ON CONFLICT (version) DO UPDATE SET status = 'completed', updated_at = EXCLUDED.updated_at`)
	exec(`INSERT INTO agent_rollout (version, status, started_by, waves, current_wave_index) VALUES ('500.2.0', 'running', 't', '{1,10,50,100}', 1)
		ON CONFLICT (version) DO UPDATE SET status = 'running', waves = EXCLUDED.waves, current_wave_index = EXCLUDED.current_wave_index`)

	got := api(acme)
	if got.latest != "500.10.0" {
		t.Errorf("latest published %q, want 500.10.0", got.latest)
	}
	if len(got.rollout) != 1 || got.rollout[0] != (pgstore.RunningAgentRolloutRow{Version: "500.2.0", Wave: 2, Waves: 4, Percent: 10}) {
		t.Errorf("running rollout %+v, want 500.2.0 wave 2 of 4 at 10 %%", got.rollout)
	}
	u := got.updates
	if u.AgentOnCurrent != 2 || u.AgentOutdated != 2 || u.AgentAhead != 1 || u.AgentUnknown != 2 {
		t.Errorf("acme agent buckets: on %d, outdated %d, ahead %d, unknown %d; want 2, 2, 1, 2", u.AgentOnCurrent, u.AgentOutdated, u.AgentAhead, u.AgentUnknown)
	}
	var active int32
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM device WHERE organization_id = $1 AND state = 'active'", acme).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if sum := u.AgentOnCurrent + u.AgentOutdated + u.AgentAhead + u.AgentUnknown; sum != active {
		t.Errorf("agent buckets add up to %d, active devices %d", sum, active)
	}
	var attentionOutdated int32
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM attention_condition a JOIN device d ON d.id = a.device_id WHERE d.organization_id = $1 AND a.kind = 'agent_outdated'", acme).Scan(&attentionOutdated); err != nil {
		t.Fatal(err)
	}
	if u.AgentOutdated != attentionOutdated {
		t.Errorf("outdated %d, agent_outdated conditions %d", u.AgentOutdated, attentionOutdated)
	}

	// Another organization reads the same platform values but only its own devices.
	other := api(globex)
	if other.latest != "500.10.0" || len(other.rollout) != 1 {
		t.Errorf("globex latest %q, rollout %+v", other.latest, other.rollout)
	}
	if o := other.updates; o.AgentOnCurrent != 0 || o.AgentOutdated != 1 || o.AgentAhead != 0 || o.AgentUnknown != 0 {
		t.Errorf("globex agent buckets %+v, want outdated 1 only", o)
	}

	// Only the API role may call the functions.
	for _, role := range []string{"paddock_worker", "paddock_platform"} {
		for _, fn := range []string{"paddock_latest_published_agent_version()", "paddock_running_agent_rollout()"} {
			sp, err := tx.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sp.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
				t.Fatal(err)
			}
			_, err = sp.Exec(ctx, "SELECT * FROM "+fn)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Errorf("%s calls %s: %v, want permission denied (42501)", role, fn, err)
			}
			_ = sp.Rollback(ctx)
		}
	}

	// Once no rollout runs, rollout is empty.
	exec("UPDATE agent_rollout SET status = 'halted' WHERE version = '500.2.0'")
	if got := api(acme); len(got.rollout) != 0 {
		t.Errorf("rollout after halt %+v", got.rollout)
	}
}
