package app_test

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestAttentionCurrentKeyOnce (PDK-027, migration 00042): the attention list, its counts and the overview evaluate
// the current release (paddock_current_agent_version, a SECURITY DEFINER lookup) a fixed number of times per query,
// not once per active device; at 10 000 devices the per-device lookup cost about 0.5 s per query
// (docs/operations/capacity.md). Since migration 00044 (PDK-090, ADR 0028) the same holds for the version key
// (paddock_version_key): the devices' keys are the stored column device_status.agent_version_key, computed at insert,
// so a query only computes the current release's key. The calls are counted with the transaction's function
// statistics, so the test pins the behaviour, not a plan's text. Everything runs in one transaction that is rolled
// back.
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
	functions := []string{"paddock_current_agent_version()", "paddock_version_key(text)"}
	calls := func() [2]int64 {
		t.Helper()
		var n [2]int64
		for i, fn := range functions {
			if err := tx.QueryRow(ctx, "SELECT coalesce(pg_stat_get_xact_function_calls($1::text::regprocedure), 0)", fn).Scan(&n[i]); err != nil {
				t.Fatal(err)
			}
		}
		return n
	}
	// measure runs every query as the API role and returns how often each called the functions.
	measure := func() map[string][2]int64 {
		t.Helper()
		out := map[string][2]int64{}
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
			after := calls()
			out[name] = [2]int64{after[0] - before[0], after[1] - before[1]}
		}
		return out
	}
	// A query may name the current key more than once (each a single evaluation), so the test pins that the number
	// of calls does not grow with the fleet rather than an exact count.
	addDevices(8)
	small := measure()
	addDevices(32)
	for name, got := range measure() {
		for i, fn := range functions {
			if small[name][i] < 1 || got[i] != small[name][i] || got[i] >= 8 {
				t.Errorf("%s: %s called %d times for 8 devices, %d times for %d devices; want a constant from 1 to 7",
					name, fn, small[name][i], got[i], devices)
			}
		}
	}
}

// TestAttentionDevicesGenericPlan (PDK-094): the device view of the attention list and its count read the view
// attention_condition once and keep their optional filters (q, kinds, device_id) out of it. pgx reuses prepared
// statements, so after five executions PostgreSQL may run a generic plan; with a filter such as
// "$1 IS NULL OR hostname ILIKE $1" pushed into the view's branches, that plan expects almost no rows and probes the
// view's tables once per device (list and count about 300 ms at 10 000 stale devices, capacity.md). The test pins
// the plan property, not timings: in the generic plan, device_alert (the view's alert branch) is scanned by exactly
// one node, and no node that scans a table refers to a query parameter.
func TestAttentionDevicesGenericPlan(t *testing.T) {
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
	org := uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", org, "o"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
		t.Fatal(err)
	}
	rec := &sqlRecorder{Tx: tx}
	q := pgstore.New(rec)
	if _, err := q.ListAttentionDevices(ctx, pgstore.ListAttentionDevicesParams{Kinds: []string{"agent_outdated"}, Sort: "-severity", MaxRows: 25}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CountAttentionDevices(ctx, pgstore.CountAttentionDevicesParams{CountLimit: 10001}); err != nil {
		t.Fatal(err)
	}
	if len(rec.sql) != 2 {
		t.Fatalf("recorded %d statements, want 2", len(rec.sql))
	}
	param := regexp.MustCompile(`\$\d`)
	for i, name := range []string{"ListAttentionDevices", "CountAttentionDevices"} {
		var plan []struct {
			Plan map[string]any `json:"Plan"`
		}
		// The simple query protocol, because the extended one would bind the statement's parameters.
		res, err := tx.Conn().PgConn().Exec(ctx, "EXPLAIN (GENERIC_PLAN, FORMAT JSON) "+rec.sql[i]).ReadAll()
		if err != nil {
			t.Fatalf("%s: explain: %v", name, err)
		}
		if err := json.Unmarshal(res[0].Rows[0][0], &plan); err != nil {
			t.Fatalf("%s: explain: %v", name, err)
		}
		alertScans := 0
		var walk func(node map[string]any)
		walk = func(node map[string]any) {
			if rel, ok := node["Relation Name"].(string); ok {
				if rel == "device_alert" {
					alertScans++
				}
				for key, v := range node {
					if s, ok := v.(string); ok && param.MatchString(s) {
						t.Errorf("%s: %s on %s has a parameter in %s: %s", name, node["Node Type"], rel, key, s)
					}
				}
			}
			children, _ := node["Plans"].([]any)
			for _, c := range children {
				if child, ok := c.(map[string]any); ok {
					walk(child)
				}
			}
		}
		walk(plan[0].Plan)
		if alertScans != 1 {
			t.Errorf("%s: device_alert scanned by %d plan nodes, want 1 (attention_condition read once)", name, alertScans)
		}
	}
}

// sqlRecorder is a pgstore.DBTX that records the statements of the queries it runs.
type sqlRecorder struct {
	pgx.Tx
	sql []string
}

func (r *sqlRecorder) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	r.sql = append(r.sql, sql)
	return r.Tx.Query(ctx, sql, args...)
}

func (r *sqlRecorder) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	r.sql = append(r.sql, sql)
	return r.Tx.QueryRow(ctx, sql, args...)
}
