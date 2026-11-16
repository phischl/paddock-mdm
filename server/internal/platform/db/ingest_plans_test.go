package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// ingestBufferBound is the most shared buffers one execution of a listed statement may touch in the large organization
// (ADR 0055 amendment 2 decision 12); a device-keyed lookup needs a few, a scan of the organization tens of thousands.
const ingestBufferBound = 100

// ingestPlanCase runs one query in organization org for device.
type ingestPlanCase struct {
	name string
	run  func(ctx context.Context, q *pgstore.Queries, org, device uuid.UUID) error
}

// ingestPlanCases are the allow-listed queries of the statement-cache view that read, update, upsert or delete, plus
// ListDeviceEventSeenAbove and CountDeviceEventSeenInRanges of the event-gap round, which runs per execution but whose
// device-keyed lookups migration 00158 made safe in every mode (ADR 0055 amendment 2026-11-16 (3) decision 12). TestIngestStatementAllowList makes every listed name
// that is not a plain INSERT … VALUES have a case here.
func ingestPlanCases() []ingestPlanCase {
	now := time.Now()
	return []ingestPlanCase{
		{"UpsertDeviceStatus", func(ctx context.Context, q *pgstore.Queries, org, d uuid.UUID) error {
			return q.UpsertDeviceStatus(ctx, pgstore.UpsertDeviceStatusParams{
				DeviceID: d, OrganizationID: org, LastContactAt: &now, Health: json.RawMessage(`{}`),
				SchemaVersions: []int32{1, 2}, Arch: "amd64", ComponentsOutdated: []string{},
			})
		}},
		{"SetDeviceLoginState", func(ctx context.Context, q *pgstore.Queries, org, d uuid.UUID) error {
			return q.SetDeviceLoginState(ctx, pgstore.SetDeviceLoginStateParams{
				DeviceID: d, OrganizationID: org, Area: "login", State: json.RawMessage(`{"occurred_at":"2026-11-15T00:00:00Z"}`),
			})
		}},
		{"UpsertDeviceUserSeen", func(ctx context.Context, q *pgstore.Queries, org, d uuid.UUID) error {
			return q.UpsertDeviceUserSeen(ctx, pgstore.UpsertDeviceUserSeenParams{
				OrganizationID: org, DeviceID: d, Username: "plan", LastSeenAt: now,
			})
		}},
		{"MaxDeviceEventSeenBefore", func(ctx context.Context, q *pgstore.Queries, _, d uuid.UUID) error {
			_, err := q.MaxDeviceEventSeenBefore(ctx, pgstore.MaxDeviceEventSeenBeforeParams{DeviceID: d, Before: now})
			return err
		}},
		{"DeleteDeviceEventSeenBefore", func(ctx context.Context, q *pgstore.Queries, _, d uuid.UUID) error {
			_, err := q.DeleteDeviceEventSeenBefore(ctx, pgstore.DeleteDeviceEventSeenBeforeParams{DeviceID: d, Before: now})
			return err
		}},
		{"DeleteDeviceEventDropped", func(ctx context.Context, q *pgstore.Queries, _, d uuid.UUID) error {
			return q.DeleteDeviceEventDropped(ctx, d)
		}},
		{"ListDeviceEventSeenAbove", func(ctx context.Context, q *pgstore.Queries, _, d uuid.UUID) error {
			_, err := q.ListDeviceEventSeenAbove(ctx, pgstore.ListDeviceEventSeenAboveParams{DeviceID: d, Above: planEventsPerDev - 1})
			return err
		}},
		{"CountDeviceEventSeenInRanges", func(ctx context.Context, q *pgstore.Queries, _, d uuid.UUID) error {
			_, err := q.CountDeviceEventSeenInRanges(ctx, pgstore.CountDeviceEventSeenInRangesParams{
				DeviceID: d, FromSeqs: []int64{1, 5}, ToSeqs: []int64{3, planEventsPerDev},
			})
			return err
		}},
	}
}

// errRecorded ends a pgstore call on a statementRecorder after it recorded the statement.
var errRecorded = errors.New("statement recorded")

// statementRecorder is a pgstore.DBTX that records the SQL and arguments of a call instead of running it.
type statementRecorder struct {
	sql  string
	args []any
}

func (r *statementRecorder) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	r.sql, r.args = sql, args
	return pgconn.CommandTag{}, nil
}

func (r *statementRecorder) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	r.sql, r.args = sql, args
	return nil, errRecorded
}

func (r *statementRecorder) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	r.sql, r.args = sql, args
	return recordedRow{}
}

type recordedRow struct{}

func (recordedRow) Scan(...any) error { return errRecorded }

// errRollback ends a transaction of the test so that its writes are rolled back.
var errRollback = errors.New("roll back")

// TestIngestViewGenericPlans is the plan test of the statement-cache view (ADR 0055 amendment 2 decision 12): on one
// connection with plan_cache_mode = force_generic_plan, every case of ingestPlanCases runs six times in a small
// organization as a named, cached statement, and its cached plan then executes in an organization of 70 000 devices
// touching at most ingestBufferBound shared buffers. The listed queries run through the view; the two event-gap
// queries, which the view does not list, are cached explicitly. Writes are rolled back.
func TestIngestViewGenericPlans(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 70 000 devices")
	}
	withoutAutovacuum(t, "device", "device_status", "bundle", "device_event_seen", "device_event_gap", "device_event_dropped")
	small, large, smallDevice, largeDevice := planOrgs(t)
	seedEventGaps(t, small, large)
	analyzeWithoutOrg(t, small)
	ctx := context.Background()
	dsn, err := url.Parse(sharedPaddock(t).Worker)
	if err != nil {
		t.Fatal(err)
	}
	params := dsn.Query()
	params.Set("plan_cache_mode", "force_generic_plan")
	params.Set("jit", "off")
	dsn.RawQuery = params.Encode()
	parent, err := db.NewOrgPool(ctx, dsn.String(), db.Options{ApplicationName: "paddock-test-ingest-plan", MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parent.Close)
	if err := parent.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
	view := parent.WithStatementCache()
	device := map[uuid.UUID]uuid.UUID{small: smallDevice, large: largeDevice}

	for _, c := range ingestPlanCases() {
		t.Run(c.name, func(t *testing.T) {
			listed := db.IngestStatementCached(c.name)
			record := func(org uuid.UUID) statementRecorder {
				var r statementRecorder
				if err := c.run(ctx, pgstore.New(&r), org, device[org]); err != nil && !errors.Is(err, errRecorded) {
					t.Fatal(err)
				}
				if db.StatementName(r.sql) != c.name {
					t.Fatalf("recorded %q, want the statement %s", r.sql, c.name)
				}
				return r
			}
			for range 6 {
				var err error
				if listed {
					err = view.InOrg(orgCtx(small), func(ctx context.Context, q *pgstore.Queries) error {
						if err := c.run(ctx, q, small, smallDevice); err != nil && !db.IsNoRows(err) {
							return err
						}
						return errRollback
					})
				} else {
					r := record(small)
					err = db.InOrgTx(view, orgCtx(small), func(tx pgx.Tx) error {
						rows, err := tx.Query(ctx, r.sql, append([]any{pgx.QueryExecModeCacheStatement}, r.args...)...)
						if err != nil {
							return err
						}
						rows.Close()
						if err := rows.Err(); err != nil {
							return err
						}
						return errRollback
					})
				}
				if !errors.Is(err, errRollback) {
					t.Fatalf("%s in the small organization: %v", c.name, err)
				}
			}
			r := record(large)
			var buffers int64
			err := db.InOrgTx(view, orgCtx(large), func(tx pgx.Tx) error {
				buffers = explainCached(t, tx, r)
				return errRollback
			})
			if !errors.Is(err, errRollback) {
				t.Fatal(err)
			}
			t.Logf("%s in the large organization: %d shared buffers", c.name, buffers)
			if buffers > ingestBufferBound {
				t.Errorf("%s: the plan cached in the small organization touched %d shared buffers in the large one, want at most %d",
					c.name, buffers, ingestBufferBound)
			}
		})
	}
}

// explainCached runs EXPLAIN (ANALYZE, BUFFERS) of the named, cached statement of r on tx's connection with r's
// arguments and returns the shared buffers its execution hit or read. It fails t if the statement is not cached on the
// connection or holds no generic plan.
func explainCached(t *testing.T, tx pgx.Tx, r statementRecorder) int64 {
	t.Helper()
	ctx := context.Background()
	var name string
	var types []string
	var generic int64
	err := tx.QueryRow(ctx, "SELECT name, parameter_types::text[], generic_plans FROM pg_prepared_statements WHERE statement = $1",
		r.sql).Scan(&name, &types, &generic)
	if err != nil {
		t.Fatalf("%s is not a cached statement of the connection: %v", db.StatementName(r.sql), err)
	}
	if generic == 0 {
		t.Fatalf("%s holds no generic plan", db.StatementName(r.sql))
	}
	if len(types) != len(r.args) {
		t.Fatalf("%s: %d parameter types, %d arguments", name, len(types), len(r.args))
	}
	// EXECUTE takes its arguments as expressions, not as bind parameters: each one becomes a typed literal.
	literals := make([]string, len(r.args))
	for i, arg := range r.args {
		var literal string
		if err := tx.QueryRow(ctx, "SELECT quote_nullable(($1::"+types[i]+")::text)", arg).Scan(&literal); err != nil {
			t.Fatalf("%s: argument %d: %v", name, i+1, err)
		}
		literals[i] = literal + "::" + types[i]
	}
	var raw []byte
	err = tx.QueryRow(ctx, fmt.Sprintf("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE %s(%s)",
		pgx.Identifier{name}.Sanitize(), strings.Join(literals, ", "))).Scan(&raw)
	if err != nil {
		t.Fatalf("EXPLAIN EXECUTE %s: %v", db.StatementName(r.sql), err)
	}
	var plan []struct {
		Plan struct {
			Hit  int64 `json:"Shared Hit Blocks"`
			Read int64 `json:"Shared Read Blocks"`
		} `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plan); err != nil || len(plan) != 1 {
		t.Fatalf("EXPLAIN EXECUTE %s: %s %v", db.StatementName(r.sql), raw, err)
	}
	return plan[0].Plan.Hit + plan[0].Plan.Read
}

// seedEventGaps gives every device of both organizations an open event gap and a dropped range, set-based, so a plan
// that reads an organization's rows of device_event_gap or device_event_dropped reads tens of thousands of them. The
// rows are removed in Cleanup, before planOrgs removes the devices.
func seedEventGaps(t *testing.T, orgs ...uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	super, err := pgx.Connect(ctx, sharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"device_event_gap", "device_event_dropped", "device_user_seen"} {
			if _, err := super.Exec(ctx, "DELETE FROM "+table+" WHERE organization_id = ANY($1)", orgs); err != nil {
				t.Errorf("remove the seeded %s rows: %v", table, err)
			}
		}
		if _, err := super.Exec(ctx, "ANALYZE device_event_gap; ANALYZE device_event_dropped"); err != nil {
			t.Errorf("analyze after removing the seed: %v", err)
		}
		_ = super.Close(ctx)
	})
	for _, sql := range []string{
		"INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at, first_seen_last_seq) " +
			"SELECT gen_random_uuid(), organization_id, id, 11, 12, now(), 13 FROM device WHERE organization_id = ANY($1)",
		"INSERT INTO device_event_dropped (device_id, from_seq, to_seq, organization_id) " +
			"SELECT id, 20, 21, organization_id FROM device WHERE organization_id = ANY($1)",
	} {
		if _, err := super.Exec(ctx, sql, orgs); err != nil {
			t.Fatalf("seed: %s: %v", sql, err)
		}
	}
	for _, table := range []string{"device_event_gap", "device_event_dropped"} {
		if _, err := super.Exec(ctx, "VACUUM ANALYZE "+table); err != nil {
			t.Fatalf("vacuum %s: %v", table, err)
		}
	}
}

// withoutAutovacuum turns autovacuum off for tables until t ends and resets the setting in Cleanup, so the shared
// database's other tests keep the default. An autovacuum ANALYZE after the seed would overwrite the statistics that
// analyzeWithoutOrg pins, and its invalidation of a table would rebuild the cached plan at EXECUTE, whose catalog
// reads count as shared buffers. The PDK-1079d diagnostic disproved autovacuum as the only source of that rebuild
// (UpsertDeviceStatus still failed with it off); see analyzeWithoutOrg's DISCARD TEMP for the confirmed one.
func withoutAutovacuum(t *testing.T, tables ...string) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, sharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, tb := range tables {
			if _, err := c.Exec(ctx, "ALTER TABLE "+pgx.Identifier{tb}.Sanitize()+" RESET (autovacuum_enabled)"); err != nil {
				t.Errorf("reset autovacuum on %s: %v", tb, err)
			}
		}
		_ = c.Close(ctx)
	})
	for _, tb := range tables {
		if _, err := c.Exec(ctx, "ALTER TABLE "+pgx.Identifier{tb}.Sanitize()+" SET (autovacuum_enabled = false)"); err != nil {
			t.Fatalf("turn off autovacuum on %s: %v", tb, err)
		}
	}
}

// analyzeWithoutOrg analyzes every base table of schema public with an organization_id column without the rows of
// organization org, so their statistics are those of an ANALYZE sample that missed a small organization: its
// organization_id estimate drops to one row, and planning in it prices an index led by organization_id below a
// primary-key or device-key lookup. A sample of 30 000 rows misses an organization of 5 devices in about 6 % of the
// ANALYZE runs and nearly always one of 1 device, so the test pins this worst case instead of depending on the sample
// (CI run 43793534819; ADR 0055 amendment 2026-11-16 (3) decision 12).
func analyzeWithoutOrg(t *testing.T, org uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, sharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	rows, err := c.Query(ctx, "SELECT c.table_name::text FROM information_schema.columns c "+
		"JOIN information_schema.tables t USING (table_schema, table_name) "+
		"WHERE c.table_schema = 'public' AND c.column_name = 'organization_id' AND t.table_type = 'BASE TABLE' "+
		"ORDER BY c.table_name")
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(tables) == 0 {
		t.Fatalf("tables with organization_id: %v (%d found)", err, len(tables))
	}
	// replica skips the foreign-key triggers, so the rows leave and return without touching their references.
	if _, err := c.Exec(ctx, "SET session_replication_role = replica"); err != nil {
		t.Fatal(err)
	}
	kept := func(i int) string { return "kept_" + strconv.Itoa(i) }
	for i, tb := range tables {
		for _, s := range []string{
			"CREATE TEMP TABLE " + kept(i) + " AS SELECT * FROM " + pgx.Identifier{tb}.Sanitize() + " WHERE organization_id = $1",
			"DELETE FROM " + pgx.Identifier{tb}.Sanitize() + " WHERE organization_id = $1",
		} {
			if _, err := c.Exec(ctx, s, org); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
		}
	}
	for _, tb := range tables {
		if _, err := c.Exec(ctx, "ANALYZE "+pgx.Identifier{tb}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	for i := len(tables) - 1; i >= 0; i-- {
		tb := tables[i]
		var cols string
		var always bool
		if err := c.QueryRow(ctx, "SELECT string_agg(quote_ident(column_name), ','), coalesce(bool_or(identity_generation = 'ALWAYS'), false) "+
			"FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND is_generated = 'NEVER'",
			tb).Scan(&cols, &always); err != nil {
			t.Fatal(err)
		}
		override := ""
		if always {
			override = " OVERRIDING SYSTEM VALUE"
		}
		if _, err := c.Exec(ctx, "INSERT INTO "+pgx.Identifier{tb}.Sanitize()+" ("+cols+")"+override+
			" SELECT "+cols+" FROM "+kept(i)); err != nil {
			t.Fatalf("restore %s: %v", tb, err)
		}
	}
	// A session drops its temporary tables after the client has gone, concurrently with the test that follows; their
	// catalog invalidations can overflow the shared invalidation queue and reset every backend's caches, so the plan
	// cached in the small organization is rebuilt at EXECUTE in the large one, and the rebuild's catalog reads count as
	// shared buffers. PDK-1079d diagnostic: UpsertDeviceStatus touched 105 buffers in exactly the 5 of 10 runs whose
	// plan was rebuilt and 12 in the others, with the same plan and no scan; with the drop done here, 10 of 10 runs
	// rebuilt no plan and stayed at 15.
	if _, err := c.Exec(ctx, "DISCARD TEMP"); err != nil {
		t.Fatal(err)
	}
}
