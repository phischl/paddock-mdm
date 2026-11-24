package migrate_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

const inventoryHostBindingVersion = 163

// TestMigration00163ReservesRetiredHosts (ADR 0057, review round 3): a device retired before migration 00163 has its
// stored host reserved with reason retired afterwards; an active device's stored host is not reserved.
func TestMigration00163ReservesRetiredHosts(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	name := "paddock_bindings_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := super.Exec(ctx, "CREATE DATABASE "+name+" OWNER paddock_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = super.Close(context.Background())
	})
	provider := paddockProvider(t, withDatabase(t, env.Owner, name))
	if _, err := provider.UpTo(ctx, inventoryHostBindingVersion-1); err != nil {
		t.Fatal(err)
	}
	db, err := pgx.Connect(ctx, withDatabase(t, env.Super, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	org, retired, active := uuid.New(), uuid.New(), uuid.New()
	for _, stmt := range []string{
		`INSERT INTO organization (id, slug, name, status) SELECT $1, 'm163', 'M', 'active' WHERE $2::uuid <> $3::uuid`,
		`INSERT INTO device (id, organization_id, hostname, state) VALUES ($2, $1, 'r', 'retired'), ($3, $1, 'a', 'active')`,
		`INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($2, $1, '501'), ($3, $1, '502')`,
	} {
		if _, err := db.Exec(ctx, stmt, org, retired, active); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provider.UpTo(ctx, inventoryHostBindingVersion); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.QueryRow(ctx, `SELECT string_agg(device_id::text || ' ' || host_id || ' ' || reason, ',')
		FROM device_inventory_left_host`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != retired.String()+" 501 retired" {
		t.Fatalf("reservations %q, want only the retired device's host", got)
	}
}
