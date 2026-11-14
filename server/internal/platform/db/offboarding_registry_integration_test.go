package db_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// offboardingKept lists the tables with organization_id that the offboarding keeps on purpose: offboarded_device
// rows outlive the organization's data so that offboarded devices still uninstall (plan M17 decision 15, ADR 0052
// decisions 2 and 5).
var offboardingKept = map[string]bool{"offboarded_device": true}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// offboardingRegistryProblems checks plan M17 decision 8 on the schema q sees: every table in schema public with a
// column organization_id is registered in offboarding_table unless it is kept, every registered table exists and has
// organization_id, and for every foreign key into a registered table the referencing table is registered with a
// lower delete_order (paddock_offboard_delete_batch deletes in ascending delete_order).
func offboardingRegistryProblems(ctx context.Context, t *testing.T, q querier) []string {
	t.Helper()
	collect := func(sql string, scan func(pgx.Rows) error) {
		rows, err := q.Query(ctx, sql)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := scan(rows); err != nil {
				t.Fatal(err)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	orgTables := map[string]bool{}
	collect(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
		  AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'organization_id'
		              AND NOT a.attisdropped)`, func(r pgx.Rows) error {
		var name string
		err := r.Scan(&name)
		orgTables[name] = true
		return err
	})
	order := map[string]int32{}
	collect(`SELECT table_name, delete_order FROM offboarding_table`, func(r pgx.Rows) error {
		var name string
		var o int32
		err := r.Scan(&name, &o)
		order[name] = o
		return err
	})
	type fk struct{ from, to string }
	var fks []fk
	collect(`SELECT src.relname, dst.relname FROM pg_constraint con
		JOIN pg_class src ON src.oid = con.conrelid JOIN pg_class dst ON dst.oid = con.confrelid
		JOIN pg_namespace n ON n.oid = src.relnamespace
		WHERE con.contype = 'f' AND n.nspname = 'public' AND con.conrelid <> con.confrelid`, func(r pgx.Rows) error {
		var f fk
		err := r.Scan(&f.from, &f.to)
		fks = append(fks, f)
		return err
	})

	var problems []string
	for name := range orgTables {
		_, registered := order[name]
		switch {
		case offboardingKept[name] && registered:
			problems = append(problems, name+": kept by the offboarding but registered in offboarding_table")
		case !offboardingKept[name] && !registered:
			problems = append(problems, name+": has organization_id but is not registered in offboarding_table")
		}
	}
	for name := range order {
		if !orgTables[name] {
			problems = append(problems, name+": registered in offboarding_table but no table with organization_id")
		}
	}
	for _, f := range fks {
		to, toRegistered := order[f.to]
		if !toRegistered {
			continue
		}
		from, fromRegistered := order[f.from]
		switch {
		case !fromRegistered:
			problems = append(problems, fmt.Sprintf("%s: references registered %s but is not registered", f.from, f.to))
		case from >= to:
			problems = append(problems, fmt.Sprintf("%s (delete_order %d) references %s (delete_order %d): "+
				"the referencing table needs the lower delete_order", f.from, from, f.to, to))
		}
	}
	slices.Sort(problems)
	return slices.Compact(problems)
}

// TestOffboardingRegistry enforces plan M17 decision 8 on the migrated schema: a new table with organization_id that
// is not registered, or registered after a table it references, fails here.
func TestOffboardingRegistry(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var registered int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM offboarding_table").Scan(&registered); err != nil {
		t.Fatal(err)
	}
	if registered < 73 {
		t.Fatalf("offboarding_table has %d rows, want at least the 73 organization tables of migration 00126", registered)
	}
	if problems := offboardingRegistryProblems(ctx, t, conn); len(problems) > 0 {
		t.Fatalf("offboarding registry:\n  %s", strings.Join(problems, "\n  "))
	}

	t.Run("detects a missing table and a wrong order", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, stmt := range []string{
			"CREATE TABLE zz_offboarding_probe (organization_id uuid NOT NULL)",
			// device_status references device, so it must be deleted first.
			"UPDATE offboarding_table SET delete_order = 99999 WHERE table_name = 'device_status'",
		} {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
		got := strings.Join(offboardingRegistryProblems(ctx, t, tx), "\n")
		for _, want := range []string{
			"zz_offboarding_probe: has organization_id but is not registered",
			"device_status (delete_order 99999) references device",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("problems %q lack %q", got, want)
			}
		}
	})
}
