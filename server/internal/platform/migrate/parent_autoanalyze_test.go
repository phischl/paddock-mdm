package migrate_test

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestParentAutoanalyzeSettings (PDK-1096 AC1, ADR 0055 amendment 2026-11-16 (4) decision 17): on the migrated schema
// the parent tables device, app_user and user_group, and no other table, carry the earlier autoanalyze trigger of
// migration 00160.
func TestParentAutoanalyzeSettings(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	db, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()

	rows, err := db.Query(ctx, `SELECT c.relname, coalesce(c.reloptions, '{}') FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		AND EXISTS (SELECT 1 FROM unnest(c.reloptions) o WHERE o LIKE 'autovacuum_analyze_%')
		ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for rows.Next() {
		var name string
		var options []string
		if err := rows.Scan(&name, &options); err != nil {
			t.Fatal(err)
		}
		got[name] = options
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := []string{"app_user", "device", "user_group"}
	for _, table := range want {
		options, ok := got[table]
		if !ok {
			t.Errorf("table %s has no autovacuum_analyze reloptions", table)
			continue
		}
		for _, option := range []string{"autovacuum_analyze_scale_factor=0.01", "autovacuum_analyze_threshold=50"} {
			if !slices.Contains(options, option) {
				t.Errorf("table %s reloptions %v lack %s", table, options, option)
			}
		}
	}
	for table, options := range got {
		if !slices.Contains(want, table) {
			t.Errorf("table %s carries autovacuum_analyze reloptions %v outside the three parent tables", table, options)
		}
	}
}
