package migrate_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

const offboardingProgressVersion = 159

// TestOffboardingProgressMigration (PDK-1087 AC9, plan M17 amendment 2026-11-16 s points 1.2 and 3): migration 00159
// adds the step cursor and the recorded failure codes, and counts the stored code of a deletion that is running as
// recorded, so the upgrade does not record its organization.deletion_step_failed a second time; every other
// organization starts with none.
func TestOffboardingProgressMigration(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	name := "paddock_offboarding_progress_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := super.Exec(ctx, "CREATE DATABASE "+name+" OWNER paddock_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = super.Close(context.Background())
	})

	provider := paddockProvider(t, withDatabase(t, env.Owner, name))
	if _, err := provider.UpTo(ctx, offboardingProgressVersion-1); err != nil {
		t.Fatal(err)
	}
	db, err := pgx.Connect(ctx, withDatabase(t, env.Super, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	failing, clean, active := uuid.New(), uuid.New(), uuid.New()
	for _, o := range []struct {
		id   uuid.UUID
		slug string
	}{{failing, "fail"}, {clean, "clean"}, {active, "active"}} {
		if _, err := db.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", o.id, "op-"+o.slug); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []struct {
		id   uuid.UUID
		code any
	}{{failing, "object_store_unavailable"}, {clean, nil}} {
		if _, err := db.Exec(ctx, `UPDATE organization SET status = 'deleting', deletion_requested_at = now(),
			deletion_requested_by = 'platform admin', deletion_reason = 'contract ended', delete_after = now(),
			deletion_uninstalls_issued = 0, deletion_uninstalls_skipped = 0, offboarding_step = 'objects',
			offboarding_error_code = $2 WHERE id = $1`, o.id, o.code); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := provider.UpTo(ctx, offboardingProgressVersion); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		id       uuid.UUID
		recorded []string
	}{{failing, []string{"object_store_unavailable"}}, {clean, []string{}}, {active, []string{}}} {
		var recorded []string
		var cursor *string
		if err := db.QueryRow(ctx, "SELECT offboarding_failures_recorded, offboarding_cursor FROM organization WHERE id = $1",
			want.id).Scan(&recorded, &cursor); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(recorded, want.recorded) || cursor != nil {
			t.Fatalf("organization %s after the migration: recorded %v, cursor %v; want %v and NULL", want.id, recorded, cursor, want.recorded)
		}
	}
}
