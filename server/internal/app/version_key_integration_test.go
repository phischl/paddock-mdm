package app_test

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// staleVersionKeys lists every stored version key that differs from what paddock_version_key computes now, as
// "<table>:<version>". PostgreSQL does not recompute a stored generated column when the function it calls is replaced,
// so this is what a migration changing the function leaves behind unless it recomputes both columns (ADR 0028).
func staleVersionKeys(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT 'agent_release:' || version FROM agent_release WHERE version_key IS DISTINCT FROM paddock_version_key(version)
		UNION ALL
		SELECT 'device_status:' || coalesce(agent_version, '<null>') FROM device_status
		WHERE agent_version_key IS DISTINCT FROM paddock_version_key(agent_version)`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// TestStoredVersionKeysAreCurrent (PDK-092): after all migrations every stored key equals paddock_version_key of its
// version, for semantic, pre-release, unparsable and missing versions, and the check catches a stale key.
func TestStoredVersionKeysAreCurrent(t *testing.T) {
	h := newReleaseHarness(t, true)
	ctx := context.Background()
	major := strconv.FormatInt(time.Now().UnixNano()%9000000+1000000, 10)
	stale := major + ".1.0"
	for _, v := range []string{stale, major + ".2.0-rc.1"} {
		if _, err := h.releases.Create(platformAdmin(), v); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []any{stale, major + ".2.0-rc.1", "unknown-" + major, nil} {
		org, dev := h.device(t)
		if _, err := h.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, $3)", dev, org, v); err != nil {
			t.Fatal(err)
		}
	}

	if got, err := staleVersionKeys(ctx, h.super); err != nil || len(got) != 0 {
		t.Fatalf("stale keys after all migrations: %v, %v", got, err)
	}

	tx, err := h.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A copy of the current function lets the replacement differ for one version only. CREATE OR REPLACE keeps the
	// function's OID, which both generated columns are bound to, as a migration changing the key format would.
	var copyDef string
	if err := tx.QueryRow(ctx, "SELECT replace(pg_get_functiondef('paddock_version_key(text)'::regprocedure), "+
		"'paddock_version_key(', 'paddock_version_key_before(')").Scan(&copyDef); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		copyDef,
		"CREATE OR REPLACE FUNCTION paddock_version_key(v text) RETURNS text LANGUAGE sql IMMUTABLE AS " +
			"$$ SELECT CASE WHEN v = '" + stale + "' THEN 'changed' ELSE paddock_version_key_before(v) END $$",
	} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	got, err := staleVersionKeys(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"agent_release:" + stale, "device_status:" + stale}; !slices.Equal(got, want) {
		t.Errorf("stale keys after the function changed: %v, want %v", got, want)
	}
	// The no-op UPDATE of ADR 0028's amendment recomputes the keys; limited to the seeded version so the transaction
	// locks no rows of tests running in parallel.
	for _, stmt := range []string{
		"UPDATE agent_release SET version = version WHERE version = $1",
		"UPDATE device_status SET agent_version = agent_version WHERE agent_version = $1",
	} {
		if _, err := tx.Exec(ctx, stmt, stale); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := staleVersionKeys(ctx, tx); err != nil || len(got) != 0 {
		t.Errorf("stale keys after the no-op update: %v, %v", got, err)
	}
}
