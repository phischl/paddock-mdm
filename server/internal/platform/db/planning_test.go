package db_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// TestPoolQueryExecModes: the pools that open organization transactions plan every execution
// (pgx.QueryExecModeCacheDescribe) and run without JIT; every other pool, and the health and lock pools, keep pgx's
// statement cache and the server's JIT setting (ADR 0055 decisions 1, 2 and 6). A statement-cache view of an
// organization pool runs a listed statement as a named, cached one, still without JIT, while its parent keeps running
// it unnamed; Close of the view leaves the parent open (ADR 0055 amendment 2 decisions 8 and 12). The test covers the pool types of
// this package as of PDK-1079 (org, notifier, platform, relay, unsealer, backup, audit reader and writer); a new type
// needs an entry here and in connPools (export_test.go), which panics on a type it does not know.
func TestPoolQueryExecModes(t *testing.T) {
	env, audit := sharedPaddock(t), sharedAudit(t)
	f := newFixture(t)
	ctx := context.Background()
	opts := db.Options{MaxConns: 1, HealthConn: true, LockConns: 1}
	open := map[string]func() (any, error){
		"org":      func() (any, error) { return db.NewOrgPool(ctx, env.API, opts) },
		"notifier": func() (any, error) { return db.NewNotifierPool(ctx, env.Notifier, opts) },
		"platform": func() (any, error) { return db.NewPlatformPool(ctx, env.Platform, opts) },
		"relay":    func() (any, error) { return db.NewRelayPool(ctx, env.Relay, opts) },
		// pgtest has no unsealer role; the pool connects lazily and runs no statement here.
		"unsealer":     func() (any, error) { return db.NewUnsealerPool(ctx, env.Platform, opts) },
		"backup":       func() (any, error) { return db.NewBackupPool(ctx, env.Backup, opts) },
		"audit reader": func() (any, error) { return db.NewAuditReader(ctx, audit.Reader, opts) },
		"audit writer": func() (any, error) { return db.NewAuditWriterPool(ctx, audit.Writer, opts) },
	}
	for name, openPool := range open {
		p, err := openPool()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Cleanup(p.(interface{ Close() }).Close)
		want := pgx.QueryExecModeCacheStatement
		if name == "org" || name == "notifier" {
			want = pgx.QueryExecModeCacheDescribe
		}
		modes := db.QueryExecModes(p)
		if modes["query"] != want {
			t.Errorf("%s pool: query mode %s, want %s", name, modes["query"], want)
		}
		if modes["health"] != pgx.QueryExecModeCacheStatement {
			t.Errorf("%s pool: health mode %s, want %s", name, modes["health"], pgx.QueryExecModeCacheStatement)
		}
		if name == "platform" && modes["locks"] != pgx.QueryExecModeCacheStatement {
			t.Errorf("platform pool: lock mode %s, want %s", modes["locks"], pgx.QueryExecModeCacheStatement)
		}
		for pool, jit := range db.RuntimeParams(p, "jit") {
			wantJIT := ""
			if pool == "query" && (name == "org" || name == "notifier") {
				wantJIT = "off"
			}
			if jit != wantJIT {
				t.Errorf("%s pool, %s connections: jit %q, want %q (empty: the server's default)", name, pool, jit, wantJIT)
			}
		}
		var org *db.OrgPool
		switch v := p.(type) {
		case *db.OrgPool:
			org = v
		case *db.NotifierPool:
			org = &v.OrgPool
		}
		if org != nil {
			var jit string
			if err := db.InOrgTx(org, orgCtx(f.orgA), func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, "SHOW jit").Scan(&jit)
			}); err != nil {
				t.Fatal(err)
			}
			if jit != "off" {
				t.Errorf("SHOW jit on a %s pool connection: %s, want off", name, jit)
			}
		}
	}

	t.Run("statement-cache view", func(t *testing.T) {
		parent, err := db.NewOrgPool(ctx, env.Worker, db.Options{MaxConns: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(parent.Close)
		view := parent.WithStatementCache()
		if mode := db.QueryExecModes(view)["query"]; mode != pgx.QueryExecModeCacheDescribe {
			t.Errorf("view: pool mode %s, want %s (only the listed statements run cached)", mode, pgx.QueryExecModeCacheDescribe)
		}
		// DeleteDeviceEventDropped is listed and deletes nothing for a random device; GetDevice is not listed.
		probe := func(p *db.OrgPool) {
			t.Helper()
			err := p.InOrg(orgCtx(f.orgA), func(ctx context.Context, q *pgstore.Queries) error {
				if err := q.DeleteDeviceEventDropped(ctx, uuid.New()); err != nil {
					return err
				}
				if _, err := q.GetDevice(ctx, uuid.New()); !db.IsNoRows(err) {
					return err
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		probe(parent)
		if got := preparedStatements(t, parent, f.orgA, "-- name: DeleteDeviceEventDropped %"); len(got) != 0 {
			t.Errorf("parent pool: DeleteDeviceEventDropped prepared as %v, want unnamed (CacheDescribe)", got)
		}
		probe(view)
		if got := preparedStatements(t, parent, f.orgA, "-- name: DeleteDeviceEventDropped %"); len(got) != 1 {
			t.Errorf("view: DeleteDeviceEventDropped prepared as %v, want one named, cached statement", got)
		}
		if got := preparedStatements(t, parent, f.orgA, "-- name: GetDevice %"); len(got) != 0 {
			t.Errorf("view: unlisted GetDevice prepared as %v, want unnamed (planned per execution)", got)
		}
		var jit string
		if err := db.InOrgTx(view, orgCtx(f.orgA), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SHOW jit").Scan(&jit)
		}); err != nil {
			t.Fatal(err)
		}
		if jit != "off" {
			t.Errorf("SHOW jit on a view connection: %s, want off", jit)
		}
		view.Close()
		probe(parent)
	})
}

// preparedStatements returns the names of the prepared statements of p's connection whose SQL text is LIKE pattern.
func preparedStatements(t *testing.T, p *db.OrgPool, org uuid.UUID, pattern string) []string {
	t.Helper()
	var names []string
	err := db.InOrgTx(p, orgCtx(org), func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), "SELECT name FROM pg_prepared_statements WHERE statement LIKE $1", pattern)
		if err != nil {
			return err
		}
		names, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

const (
	planSmallDevices = 5
	planLargeDevices = 70000
	planEventsPerDev = 10
	// planBound is the time bound of one execution in the large organization (ADR 0055 decision 5).
	planBound = time.Second
)

// planOrgs seeds a small organization and one of planLargeDevices devices, each device with status, a bundle and
// planEventsPerDev seen events, set-based like the devstack's; it returns both organizations and a device of each.
// The rows are removed again in Cleanup: the package's tests share one database.
func planOrgs(t *testing.T) (small, large, smallDevice, largeDevice uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	super, err := pgx.Connect(ctx, sharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	small, large = uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	orgs := []uuid.UUID{small, large}
	t.Cleanup(func() {
		// The settings rows come from the organization insert triggers (migrations 00007, 00074, 00130).
		for _, table := range []string{"device_event_seen", "bundle", "device_status", "device",
			"organization_login_settings", "organization_privacy_settings", "organization_patch_sla"} {
			if _, err := super.Exec(ctx, "DELETE FROM "+table+" WHERE organization_id = ANY($1)", orgs); err != nil {
				t.Errorf("remove the seeded %s rows: %v", table, err)
			}
		}
		if _, err := super.Exec(ctx, "DELETE FROM organization WHERE id = ANY($1)", orgs); err != nil {
			t.Errorf("remove the seeded organizations: %v", err)
		}
		if _, err := super.Exec(ctx, "ANALYZE device; ANALYZE device_status; ANALYZE bundle; ANALYZE device_event_seen"); err != nil {
			t.Errorf("analyze after removing the seed: %v", err)
		}
	})
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $3, $3, 'active'), ($2, $4, $4, 'active')",
			[]any{small, large, "plan-s-" + small.String()[24:], "plan-l-" + large.String()[24:]}},
		{"INSERT INTO device (id, organization_id, hostname, state, bundle_seq) SELECT gen_random_uuid(), $1, 'plan-' || i, 'active', 1 " +
			"FROM generate_series(1, $2::int) i", []any{small, planSmallDevices}},
		{"INSERT INTO device (id, organization_id, hostname, state, bundle_seq) SELECT gen_random_uuid(), $1, 'plan-' || i, 'active', 1 " +
			"FROM generate_series(1, $2::int) i", []any{large, planLargeDevices}},
		{"INSERT INTO device_status (device_id, organization_id, schema_versions, agent_version, last_contact_at, applied_bundle_version) " +
			"SELECT id, organization_id, '{1,2}', '1.0.0', now(), 1 FROM device WHERE organization_id = ANY($1)", []any{orgs}},
		{"INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key, schema_version, created_at) " +
			"SELECT id, 1, organization_id, sha256(id::text::bytea), sha256(id::text::bytea), 'k', 2, now() - interval '2 hours' " +
			"FROM device WHERE organization_id = ANY($1)", []any{orgs}},
		{"INSERT INTO device_event_seen (device_id, event_seq, organization_id, received_at) " +
			"SELECT d.id, s, d.organization_id, now() - interval '1 day' FROM device d, generate_series(1, $2::int) s " +
			"WHERE d.organization_id = ANY($1)", []any{orgs, planEventsPerDev}},
	} {
		if _, err := super.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("seed: %s: %v", stmt.sql, err)
		}
	}
	// VACUUM, not only ANALYZE: the first read of freshly inserted rows sets their hint bits and took seconds, which
	// a long-lived organization's rows do not cost.
	for _, table := range []string{"device", "device_status", "bundle", "device_event_seen"} {
		if _, err := super.Exec(ctx, "VACUUM ANALYZE "+table); err != nil {
			t.Fatalf("vacuum %s: %v", table, err)
		}
	}
	for org, dev := range map[uuid.UUID]*uuid.UUID{small: &smallDevice, large: &largeDevice} {
		if err := super.QueryRow(ctx, "SELECT id FROM device WHERE organization_id = $1 LIMIT 1", org).Scan(dev); err != nil {
			t.Fatal(err)
		}
	}
	return small, large, smallDevice, largeDevice
}

// TestOrganizationPoolPlansPerExecution is the regression test of PDK-1079 (ADR 0055 decision 5): on one pooled
// connection, each query that was catastrophic with a plan built for a small organization runs six times in a small
// organization and then once in an organization of 70 000 devices, and that run stays within 1 s. Afterwards no
// statement of the connection holds a generic plan, and a parameterless statement run six times in the small
// organization is planned for the large one when it runs there. Every device has a status row, so the attention
// view's plan in the large organization costs more than PostgreSQL's JIT thresholds: the pools run as in production,
// and the 1 s bound also proves that organization pools do not JIT-compile (ADR 0055 decision 7).
func TestOrganizationPoolPlansPerExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 70 000 devices")
	}
	small, large, smallDevice, largeDevice := planOrgs(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, sharedPaddock(t).Worker, db.Options{ApplicationName: "paddock-test-plan", MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
	// ListDevicesWithOutdatedSchema is the compiler's; the worker role has no right on bundle.
	compilerPool, err := db.NewOrgPool(ctx, sharedPaddock(t).Compiler, db.Options{ApplicationName: "paddock-test-plan", MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(compilerPool.Close)
	if err := compilerPool.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
	device := map[uuid.UUID]uuid.UUID{small: smallDevice, large: largeDevice}
	queries := []struct {
		name string
		pool *db.OrgPool
		run  func(ctx context.Context, q *pgstore.Queries, device uuid.UUID) error
	}{
		{"CountAttention", pool, func(ctx context.Context, q *pgstore.Queries, _ uuid.UUID) error {
			_, err := q.CountAttention(ctx, pgstore.CountAttentionParams{CountLimit: 10001})
			return err
		}},
		{"ListAttention", pool, func(ctx context.Context, q *pgstore.Queries, _ uuid.UUID) error {
			_, err := q.ListAttention(ctx, pgstore.ListAttentionParams{Sort: "since", MaxRows: 50})
			return err
		}},
		{"ListAttentionConditionKeys", pool, func(ctx context.Context, q *pgstore.Queries, _ uuid.UUID) error {
			_, err := q.ListAttentionConditionKeys(ctx)
			return err
		}},
		{"ListDevicesWithOutdatedSchema", compilerPool, func(ctx context.Context, q *pgstore.Queries, _ uuid.UUID) error {
			_, err := q.ListDevicesWithOutdatedSchema(ctx)
			return err
		}},
		{"ListConfigRolloutDevices", pool, func(ctx context.Context, q *pgstore.Queries, _ uuid.UUID) error {
			_, err := q.ListConfigRolloutDevices(ctx, nil)
			return err
		}},
		{"MaxDeviceEventSeenBefore", pool, func(ctx context.Context, q *pgstore.Queries, d uuid.UUID) error {
			_, err := q.MaxDeviceEventSeenBefore(ctx, pgstore.MaxDeviceEventSeenBeforeParams{DeviceID: d, Before: time.Now()})
			return err
		}},
		{"ListDeviceEventSeenAbove", pool, func(ctx context.Context, q *pgstore.Queries, d uuid.UUID) error {
			_, err := q.ListDeviceEventSeenAbove(ctx, pgstore.ListDeviceEventSeenAboveParams{DeviceID: d, Above: planEventsPerDev - 1})
			return err
		}},
	}
	for _, query := range queries {
		t.Run(query.name, func(t *testing.T) {
			timed := func(org uuid.UUID) time.Duration {
				// A plan built for the small organization ran for minutes here; the deadline keeps a failure short.
				runCtx, cancel := context.WithTimeout(orgCtx(org), 30*time.Second)
				defer cancel()
				var elapsed time.Duration
				err := query.pool.InOrg(runCtx, func(ctx context.Context, q *pgstore.Queries) error {
					start := time.Now()
					err := query.run(ctx, q, device[org])
					elapsed = time.Since(start)
					return err
				})
				if err != nil {
					t.Fatalf("%s after %s: %v", query.name, elapsed, err)
				}
				return elapsed
			}
			for range 6 {
				timed(small)
			}
			if elapsed := timed(large); elapsed > planBound {
				t.Fatalf("%s in the large organization after six runs in the small one: %s, want at most %s",
					query.name, elapsed, planBound)
			} else {
				t.Logf("%s in the large organization: %s", query.name, elapsed)
			}
		})
	}

	t.Run("no generic plan cached", func(t *testing.T) {
		for _, p := range []*db.OrgPool{pool, compilerPool} {
			noGenericPlan(t, p, large)
		}
	})

	t.Run("parameterless statement re-planned", func(t *testing.T) {
		const query = "SELECT id FROM device WHERE state = 'active'"
		estimate := func(tx pgx.Tx, stmt string) float64 {
			var plan []struct {
				Plan struct {
					Rows float64 `json:"Plan Rows"`
				} `json:"Plan"`
			}
			var raw []byte
			if err := tx.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+stmt).Scan(&raw); err != nil {
				t.Fatalf("EXPLAIN %s: %v", stmt, err)
			}
			if err := json.Unmarshal(raw, &plan); err != nil || len(plan) != 1 {
				t.Fatalf("EXPLAIN %s: %s %v", stmt, raw, err)
			}
			return plan[0].Plan.Rows
		}
		// Query, not Exec: pgx sends an Exec without arguments over the simple protocol, which prepares nothing.
		run := func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, query)
			if err != nil {
				return err
			}
			rows.Close()
			return rows.Err()
		}
		var smallRows float64
		for range 6 {
			if err := db.InOrgTx(pool, orgCtx(small), func(tx pgx.Tx) error {
				smallRows = estimate(tx, query)
				return run(tx)
			}); err != nil {
				t.Fatal(err)
			}
		}
		err := db.InOrgTx(pool, orgCtx(large), func(tx pgx.Tx) error {
			if err := run(tx); err != nil {
				return err
			}
			largeRows := estimate(tx, query)
			if largeRows < 100*smallRows {
				t.Fatalf("the plan does not depend on the organization: %.0f rows estimated in the large one, %.0f in the small one",
					largeRows, smallRows)
			}
			rows, err := tx.Query(ctx, "SELECT name FROM pg_prepared_statements WHERE statement = $1", query)
			if err != nil {
				return err
			}
			names, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			for _, name := range names {
				if cached := estimate(tx, "EXECUTE "+pgx.Identifier{name}.Sanitize()); cached != largeRows {
					t.Errorf("after six runs in the small organization the statement runs a plan estimated for %.0f rows "+
						"in the large organization, planned afresh %.0f", cached, largeRows)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// noGenericPlan fails t if p's connection holds a generic plan for a pgstore statement.
func noGenericPlan(t *testing.T, p *db.OrgPool, org uuid.UUID) {
	t.Helper()
	err := db.InOrgTx(p, orgCtx(org), func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(),
			"SELECT statement FROM pg_prepared_statements WHERE generic_plans > 0 AND statement LIKE '-- name: %'")
		if err != nil {
			return err
		}
		statements, err := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, s := range statements {
			t.Errorf("the connection holds a generic plan for %s", strings.SplitN(s, "\n", 2)[0])
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
