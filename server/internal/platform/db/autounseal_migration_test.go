package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestAutoUnsealMigration: migration 00050 runs without the role paddock_unsealer (the test cluster has none) and
// leaves exactly one row in state disabled; the platform role may read and update it, but the row cannot be enabled
// without an acknowledgement (plan M8u decision 2).
func TestAutoUnsealMigration(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	var exists bool
	if err := super.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_unsealer')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("the test cluster must not have the role paddock_unsealer: the migration's conditional grant is under test")
	}

	platform, err := pgx.Connect(ctx, env.Platform)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = platform.Close(ctx) }()
	var n int
	var state string
	if err := platform.QueryRow(ctx, "SELECT count(*), min(state) FROM openbao_auto_unseal").Scan(&n, &state); err != nil {
		t.Fatal(err)
	}
	if n != 1 || state != "disabled" {
		t.Fatalf("openbao_auto_unseal: %d rows, state %q; want 1 row disabled", n, state)
	}
	if _, err := platform.Exec(ctx, "UPDATE openbao_auto_unseal SET state = 'enabled' WHERE id = 1"); err == nil {
		t.Fatal("enabling without an acknowledgement succeeded; want a check violation")
	}
	if _, err := platform.Exec(ctx, "INSERT INTO openbao_auto_unseal (id, state) VALUES (2, 'disabled')"); err == nil {
		t.Fatal("a second row was inserted; want a refusal")
	}
}
