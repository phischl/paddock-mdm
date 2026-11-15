package migrate_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// The organization index migrations of plan M17 amendment 2026-11-16 q point 1: 00139 to 00157, one per table;
// 00140 builds admin_account_org_idx.
const (
	adminAccountIndexVersion = 140
	lastOrgIndexVersion      = 157
)

// TestOrganizationIndexRerun (amendment q points 1 and 9): a concurrent build that failed leaves an INVALID index and no
// recorded version; goose then runs the file again, outside a transaction, and its drop and build leave exactly one
// valid index. Running the file a further time changes nothing.
func TestOrganizationIndexRerun(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	name := "paddock_orgidx_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := super.Exec(ctx, "CREATE DATABASE "+name+" OWNER paddock_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = super.Close(context.Background())
	})

	provider := paddockProvider(t, withDatabase(t, env.Owner, name))
	if _, err := provider.UpTo(ctx, adminAccountIndexVersion-1); err != nil {
		t.Fatal(err)
	}
	db, err := pgx.Connect(ctx, withDatabase(t, env.Super, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })

	// A failed concurrent build: a unique build over two rows of one organization fails at validation and leaves the
	// index behind, INVALID, under the name the migration uses.
	org := uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Index', 'active')", []any{org, "ix" + org.String()[24:]}},
		{`INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
			VALUES (gen_random_uuid(), $1, 'sub-a', 'a', 'A', 'org_admin'), (gen_random_uuid(), $1, 'sub-b', 'b', 'B', 'org_admin')`, []any{org}},
	} {
		if _, err := db.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
	_, err = db.Exec(ctx, "CREATE UNIQUE INDEX CONCURRENTLY admin_account_org_idx ON admin_account (organization_id)")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("simulated build: %v, want a unique violation", err)
	}
	type index struct {
		valid, unique bool
	}
	indexes := func() []index {
		t.Helper()
		rows, err := db.Query(ctx, `SELECT i.indisvalid, i.indisunique FROM pg_index i
			JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'admin_account_org_idx'`)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (index, error) {
			var x index
			err := r.Scan(&x.valid, &x.unique)
			return x, err
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := indexes(); len(got) != 1 || got[0].valid {
		t.Fatalf("after the failed build: %+v, want one INVALID leftover", got)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != adminAccountIndexVersion-1 {
		t.Fatalf("recorded version %d, %v; want %d: a failed build records nothing", v, err, adminAccountIndexVersion-1)
	}

	if _, err := provider.UpTo(ctx, lastOrgIndexVersion); err != nil {
		t.Fatalf("re-run after the failed build: %v", err)
	}
	want := []index{{valid: true, unique: false}}
	if got := indexes(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("after the re-run: %+v, want exactly one valid, non-unique index", got)
	}

	if _, err := db.Exec(ctx, "DELETE FROM goose_db_version WHERE version_id = $1", adminAccountIndexVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ApplyVersion(ctx, adminAccountIndexVersion, true); err != nil {
		t.Fatalf("second run of the file: %v", err)
	}
	if got := indexes(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("after the second run: %+v, want exactly one valid, non-unique index", got)
	}
}
