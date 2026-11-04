package auditwriter_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestPreviousReleaseAuditInsert runs the audit writer's insert statement of every release in pkg/compat/testdata (ADR
// 0047 decision 2) on the current audit schema, as the writer role: a migration that adds a required column or revokes
// a grant would break a writer of the previous release, which runs against the migrated database during an upgrade.
// The check-in, event and command fixtures of the same directories are verified in pkg/compat, which must not import
// the server.
func TestPreviousReleaseAuditInsert(t *testing.T) {
	root, err := pgtest.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "pkg", "compat", "testdata", "*", "audit-insert.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no audit-insert.sql fixtures below pkg/compat/testdata")
	}
	env := pgtest.SharedAudit(t)
	for _, file := range files {
		t.Run(filepath.Base(filepath.Dir(file)), func(t *testing.T) {
			stmt, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			conn, err := pgx.Connect(ctx, env.Writer)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close(ctx) }()
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()

			now := time.Now().UTC().Truncate(time.Microsecond)
			if _, err := tx.Exec(ctx, "SELECT audit_ensure_partition($1::date)", time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)); err != nil {
				t.Fatal(err)
			}
			// The argument list is the one of the current insert statement; a release whose insert takes other parameters
			// needs its argument shape stored with the fixture before this test can run it.
			args := []any{
				uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now, now, "device_group.created", "success", "portal",
				[]byte(`{"type":"user","id":"fixture"}`), []byte(`{"type":"device_group","id":"fixture"}`),
				[]byte(`{}`), "compat-fixture", "audit/fixture", int64(1),
			}
			var got uuid.UUID
			if err := tx.QueryRow(ctx, string(stmt), args...).Scan(&got); err != nil {
				t.Fatalf("the previous release's insert on the current schema: %v", err)
			}
			if got != args[0] {
				t.Fatalf("returned event %s, inserted %s", got, args[0])
			}
		})
	}
}
