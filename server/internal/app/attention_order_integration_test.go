package app_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestAttentionDevicesConditionOrder (PDK-103): a device's conditions come back in the same order on every request.
// agent_outdated and disk_not_compliant share rank 1 and the same since (the device's last contact), so the order
// by rank and since alone ties and the result depended on the plan. The test runs the query repeatedly under every
// plan cache mode; pgx reuses the prepared statement, so the automatic mode switches to a generic plan after five
// executions. Everything runs in one transaction that is rolled back.
func TestAttentionDevicesConditionOrder(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	tx, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	org := uuid.Must(uuid.NewV7())
	device := uuid.Must(uuid.NewV7())
	contact := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", org, "o"+org.String()[24:])
	exec("INSERT INTO agent_release (version, status, created_by, published_at) VALUES ('500.0.0', 'published', 't', now()) ON CONFLICT (version) DO UPDATE SET status = 'published'")
	exec(`INSERT INTO agent_rollout (version, status, started_by, updated_at) VALUES ('500.0.0', 'completed', 't', '2300-01-01T00:00:00Z')
		ON CONFLICT (version) DO UPDATE SET status = 'completed', updated_at = EXCLUDED.updated_at`)
	exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", device, org)
	exec(`INSERT INTO device_status (device_id, organization_id, agent_version, last_contact_at, health)
		VALUES ($1, $2, '499.9.9', $3, '{"disk": {"state": "not_compliant"}}')`, device, org, contact)
	exec("SET LOCAL ROLE paddock_api")
	exec("SELECT set_config('paddock.org_id', $1, true)", org.String())

	want := []string{"agent_outdated", "disk_not_compliant"}
	q := pgstore.New(tx)
	for _, mode := range []string{"auto", "force_generic_plan", "force_custom_plan"} {
		exec("SELECT set_config('plan_cache_mode', $1, true)", mode)
		for run := 0; run < 8; run++ {
			rows, err := q.ListAttentionDevices(ctx, pgstore.ListAttentionDevicesParams{Sort: "-severity", MaxRows: 25})
			if err != nil {
				t.Fatalf("%s run %d: %v", mode, run, err)
			}
			if len(rows) != 1 {
				t.Fatalf("%s run %d: %d devices, want 1", mode, run, len(rows))
			}
			var conditions []struct {
				Kind  string    `json:"kind"`
				Since time.Time `json:"since"`
			}
			if err := json.Unmarshal(rows[0].Conditions, &conditions); err != nil {
				t.Fatalf("%s run %d: %v", mode, run, err)
			}
			got := make([]string, 0, len(conditions))
			for _, c := range conditions {
				if !c.Since.Equal(contact) {
					t.Fatalf("%s run %d: %s since %s, want %s (the tie the test needs)", mode, run, c.Kind, c.Since, contact)
				}
				got = append(got, c.Kind)
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s run %d: conditions %v, want %v", mode, run, got, want)
			}
		}
	}
}
