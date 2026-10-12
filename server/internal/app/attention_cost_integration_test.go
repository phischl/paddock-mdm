package app_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestAttentionCurrentKeyOnce (PDK-027, migration 00042): the attention list, its counts and the overview evaluate
// the current release (paddock_current_agent_version, a SECURITY DEFINER lookup) a fixed number of times per query,
// not once per active device; at 10 000 devices the per-device lookup cost about 0.5 s per query
// (docs/operations/capacity.md). The calls are counted with the transaction's function statistics, so the test pins
// the behaviour, not a plan's text. Everything runs in one transaction that is rolled back.
func TestAttentionCurrentKeyOnce(t *testing.T) {
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
	exec("SET LOCAL track_functions = 'all'")
	org := uuid.Must(uuid.NewV7())
	exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", org, "o"+org.String()[24:])
	versions := []string{"500.0.0", "499.9.9", "500.2.0", "not-a-version"}
	devices := 0
	addDevices := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			id := uuid.Must(uuid.NewV7())
			exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", id, org)
			exec("INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, $3)", id, org, versions[devices%len(versions)])
			devices++
		}
	}
	exec("INSERT INTO agent_release (version, status, created_by, published_at) VALUES ('500.0.0', 'published', 't', now()) ON CONFLICT (version) DO UPDATE SET status = 'published'")
	exec(`INSERT INTO agent_rollout (version, status, started_by, updated_at) VALUES ('500.0.0', 'completed', 't', '2300-01-01T00:00:00Z')
		ON CONFLICT (version) DO UPDATE SET status = 'completed', updated_at = EXCLUDED.updated_at`)

	outdated := []string{"agent_outdated"}
	queries := map[string]func(q *pgstore.Queries) (int64, error){
		"ListAttention": func(q *pgstore.Queries) (int64, error) {
			rows, err := q.ListAttention(ctx, pgstore.ListAttentionParams{Sort: "-since", MaxRows: 100})
			return int64(len(rows)), err
		},
		"ListAttention agent_outdated": func(q *pgstore.Queries) (int64, error) {
			rows, err := q.ListAttention(ctx, pgstore.ListAttentionParams{Kinds: outdated, Sort: "-since", MaxRows: 100})
			return int64(len(rows)), err
		},
		"CountAttention": func(q *pgstore.Queries) (int64, error) {
			return q.CountAttention(ctx, pgstore.CountAttentionParams{CountLimit: 10001})
		},
		"ListAttentionDevices": func(q *pgstore.Queries) (int64, error) {
			rows, err := q.ListAttentionDevices(ctx, pgstore.ListAttentionDevicesParams{Sort: "-severity", MaxRows: 100})
			return int64(len(rows)), err
		},
		"ListAttentionDevices agent_outdated": func(q *pgstore.Queries) (int64, error) {
			rows, err := q.ListAttentionDevices(ctx, pgstore.ListAttentionDevicesParams{Kinds: outdated, Sort: "-severity", MaxRows: 100})
			return int64(len(rows)), err
		},
		"CountAttentionDevices": func(q *pgstore.Queries) (int64, error) {
			return q.CountAttentionDevices(ctx, pgstore.CountAttentionDevicesParams{CountLimit: 10001})
		},
		"OverviewAttention": func(q *pgstore.Queries) (int64, error) {
			r, err := q.OverviewAttention(ctx)
			return int64(r.Conditions), err
		},
		"OverviewUpdates": func(q *pgstore.Queries) (int64, error) {
			r, err := q.OverviewUpdates(ctx)
			return int64(r.AgentOutdated), err
		},
	}
	calls := func() int64 {
		t.Helper()
		var n int64
		if err := tx.QueryRow(ctx, "SELECT coalesce(pg_stat_get_xact_function_calls('paddock_current_agent_version()'::regprocedure), 0)").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// measure runs every query as the API role and returns how often each called paddock_current_agent_version.
	measure := func() map[string]int64 {
		t.Helper()
		out := map[string]int64{}
		for name, run := range queries {
			before := calls()
			sp, err := tx.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sp.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
				t.Fatal(err)
			}
			if _, err := sp.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
				t.Fatal(err)
			}
			n, err := run(pgstore.New(sp))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			_ = sp.Rollback(ctx)
			// Half of the devices are outdated (older or no semantic version); every query sees at least those.
			if n < int64(devices/2) {
				t.Errorf("%s: %d rows or conditions, want at least %d", name, n, devices/2)
			}
			out[name] = calls() - before
		}
		return out
	}
	// A query may name the current key more than once (each a single evaluation), so the test pins that the number
	// of calls does not grow with the fleet rather than an exact count.
	addDevices(8)
	small := measure()
	addDevices(32)
	for name, got := range measure() {
		if got != small[name] || got >= 8 {
			t.Errorf("%s: paddock_current_agent_version called %d times for 8 devices, %d times for %d devices; want a constant below 8",
				name, small[name], got, devices)
		}
	}
}
