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

const softwareTargetsVersion = 113

// TestSoftwareTargetsMigration: migration 00113 applies on a schema with an existing source, assignment and status
// row (plan M13b decision 3); the source becomes apt, the status row a system row without a user. Afterwards the
// unique key refuses a second assignment of an entry to the same target, the organization (all targets NULL)
// included, an assignment takes at most one target, available takes no version, and a Flatpak source has exactly
// one URI and no suites.
func TestSoftwareTargetsMigration(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	name := "paddock_swtargets_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := super.Exec(ctx, "CREATE DATABASE "+name+" OWNER paddock_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = super.Close(context.Background())
	})

	provider := paddockProvider(t, withDatabase(t, env.Owner, name))
	if _, err := provider.UpTo(ctx, softwareTargetsVersion-1); err != nil {
		t.Fatal(err)
	}
	db, err := pgx.Connect(ctx, withDatabase(t, env.Super, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	exec := func(t *testing.T, stmt string, args ...any) error {
		t.Helper()
		_, err := db.Exec(ctx, stmt, args...)
		return err
	}
	org, device, source, entry, user, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, x := range []struct {
		stmt string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, 'swt', 'O', 'active')", []any{org}},
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", []any{device, org}},
		{"INSERT INTO app_user (id, organization_id, username, source) VALUES ($1, $2, 'alice@example.org', 'local')", []any{user, org}},
		{"INSERT INTO user_group (id, organization_id, slug, name, source) VALUES ($1, $2, 'devs', 'Devs', 'local')", []any{group, org}},
		{`INSERT INTO software_source (id, organization_id, slug, name, uris, suites, components, signing_key, fingerprint)
			VALUES ($1, $2, 'vendor', 'Vendor', '{https://apt.example.org}', '{stable}', '{main}', 'k', $3)`,
			[]any{source, org, strings.Repeat("A", 40)}},
		{`INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages)
			VALUES ($1, $2, 'App', $3, '[{"distribution":"ubuntu","release":"*","architecture":"*","package":"app"}]')`,
			[]any{entry, org, source}},
		{`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, intent) VALUES ($1, $2, $3, 'required')`,
			[]any{uuid.New(), org, entry}},
		{`INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, reported_at)
			VALUES ($1, $2, $3, 'app', 'required', 'installed', now())`, []any{device, org, entry}},
	} {
		if err := exec(t, x.stmt, x.args...); err != nil {
			t.Fatalf("%s: %v", x.stmt, err)
		}
	}

	if _, err := provider.UpTo(ctx, softwareTargetsVersion); err != nil {
		t.Fatal(err)
	}
	var kind, scope, username string
	if err := db.QueryRow(ctx, "SELECT kind FROM software_source WHERE id = $1", source).Scan(&kind); err != nil || kind != "apt" {
		t.Fatalf("existing source kind %q (%v), want apt", kind, err)
	}
	if err := db.QueryRow(ctx, "SELECT scope, username FROM device_software_status WHERE device_id = $1", device).
		Scan(&scope, &username); err != nil || scope != "system" || username != "" {
		t.Fatalf("existing status row scope %q username %q (%v), want system and empty", scope, username, err)
	}

	insertAssignment := `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, device_group_id, user_id,
		user_group_id, intent, version) VALUES (gen_random_uuid(), $1, $2, NULL, $3, $4, $5, $6)`
	ok := func(name, stmt string, args ...any) {
		t.Run(name, func(t *testing.T) {
			if err := exec(t, stmt, args...); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	refused := func(name, code, stmt string, args ...any) {
		t.Run(name, func(t *testing.T) {
			err := exec(t, stmt, args...)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != code {
				t.Fatalf("err %v, want SQLSTATE %s", err, code)
			}
		})
	}
	const unique, check = "23505", "23514"
	noUser, noGroup, noVersion := uuid.NullUUID{}, uuid.NullUUID{}, (*string)(nil)
	userID, groupID := uuid.NullUUID{UUID: user, Valid: true}, uuid.NullUUID{UUID: group, Valid: true}
	version := "1.0"
	refused("second organization assignment", unique, insertAssignment, org, entry, noUser, noGroup, "hold", noVersion)
	ok("user target", insertAssignment, org, entry, userID, noGroup, "available", noVersion)
	refused("second user assignment", unique, insertAssignment, org, entry, userID, noGroup, "required", noVersion)
	ok("user group target", insertAssignment, org, entry, noUser, groupID, "forbid", noVersion)
	refused("two targets", check, insertAssignment, org, entry, userID, groupID, "required", noVersion)
	refused("available with a version", check, `INSERT INTO software_assignment (id, organization_id, catalog_entry_id,
		user_id, intent, version) VALUES (gen_random_uuid(), $1, $2, NULL, 'available', $3)`, org, entry, &version)
	insertSource := `INSERT INTO software_source (id, organization_id, slug, name, kind, uris, suites, components,
		signing_key, fingerprint) VALUES (gen_random_uuid(), $1, $2, $2, 'flatpak', $3, $4, '{}', 'k', $5)`
	fp := strings.Repeat("B", 40)
	ok("flatpak source", insertSource, org, "flathub", []string{"https://dl.flathub.org/repo/"}, []string{}, fp)
	refused("flatpak source with two URIs", check, insertSource, org, "two",
		[]string{"https://a.example.org/", "https://b.example.org/"}, []string{}, fp)
	refused("flatpak source with a suite", check, insertSource, org, "suite", []string{"https://a.example.org/"},
		[]string{"stable"}, fp)
	refused("apt source without suites", check, `INSERT INTO software_source (id, organization_id, slug, name, uris,
		suites, signing_key, fingerprint) VALUES (gen_random_uuid(), $1, 'nosuite', 'nosuite', '{https://a.example.org}',
		'{}', 'k', $2)`, org, fp)
	ok("user status row next to the system row", `INSERT INTO device_software_status (device_id, organization_id,
		catalog_entry_id, package, intent, state, scope, username, reported_at)
		VALUES ($1, $2, $3, 'app', 'available', 'installed', 'user', 'alice@example.org', now())`, device, org, entry)

	t.Run("deleting the user removes its assignment", func(t *testing.T) {
		if err := exec(t, "DELETE FROM app_user WHERE id = $1", user); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM software_assignment WHERE user_id = $1", user).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%d assignments of the deleted user (%v)", n, err)
		}
	})
}
