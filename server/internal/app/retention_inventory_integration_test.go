package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// emptyOrganization creates an organization without devices; its privacy settings are the defaults (30 days, here
// seconds).
func (w retentionWorld) emptyOrganization(t *testing.T) uuid.UUID {
	t.Helper()
	org := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'R', 'active')",
		org, "i"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	return org
}

// inventoried creates a device of org in state since changed with the inventory the sync stores: the Fleet host ref
// (none for ""), software packages, findings and policy results.
func (w retentionWorld) inventoried(t *testing.T, org uuid.UUID, state string, changed time.Time, ref string, software, findings, policies int) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	dev := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(ctx, `INSERT INTO device (id, organization_id, hostname, state, state_changed_at)
		VALUES ($1, $2, $3, $4, $5)`, dev, org, "inv-"+dev.String()[24:], state, changed); err != nil {
		t.Fatal(err)
	}
	if ref != "" {
		if _, err := w.super.Exec(ctx, `INSERT INTO device_inventory_ref (device_id, organization_id, external_id)
			VALUES ($1, $2, $3)`, dev, org, ref); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []struct {
		sql string
		n   int
	}{
		{`INSERT INTO installed_software (device_id, organization_id, name, version, source)
		  SELECT $1, $2, 'pkg' || g, '1.0', 'deb_packages' FROM generate_series(1, $3::int) g`, software},
		{`INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version)
		  SELECT $1, $2, 'CVE-2099-' || g, 'pkg1', '1.0' FROM generate_series(1, $3::int) g`, findings},
		{`INSERT INTO inventory_policy_result (device_id, organization_id, policy_key, passing, updated_at)
		  SELECT $1, $2, 'policy' || g, true, now() FROM generate_series(1, $3::int) g`, policies},
	} {
		if _, err := w.super.Exec(ctx, stmt.sql, dev, org, stmt.n); err != nil {
			t.Fatal(err)
		}
	}
	return dev
}

// inventoryRows counts a device's rows in the four inventory tables.
func (w retentionWorld) inventoryRows(t *testing.T, dev uuid.UUID) int {
	t.Helper()
	return countRows(t, w.super, `SELECT (SELECT count(*) FROM device_inventory_ref WHERE device_id = $1)
		+ (SELECT count(*) FROM installed_software WHERE device_id = $1)
		+ (SELECT count(*) FROM vulnerability_finding WHERE device_id = $1)
		+ (SELECT count(*) FROM inventory_policy_result WHERE device_id = $1)`, dev)
}

type inventoryPurgedEvent struct {
	outcome, errorCode, target string
	params                     map[string]any
}

// inventoryPurgedEvents returns org's finished device.inventory_purged events, oldest first.
func (w retentionWorld) inventoryPurgedEvents(t *testing.T, org uuid.UUID) []inventoryPurgedEvent {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT outcome, coalesce(error_code, ''), target->>'id', params
		FROM action WHERE organization_id = $1 AND code = 'device.inventory_purged' AND status = 'finished'
		ORDER BY started_at, id`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []inventoryPurgedEvent
	for rows.Next() {
		var ev inventoryPurgedEvent
		var params []byte
		if err := rows.Scan(&ev.outcome, &ev.errorCode, &ev.target, &params); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(params, &ev.params); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRetentionPurgeRetiredInventory (plan M10 decision 16, gate R2's unit): a device retired longer than
// retired_inventory_days loses its four tables' rows and its Fleet host with one device.inventory_purged success event;
// a device of re-enrolled hardware keeps the Fleet host its active successor uses; a device without a host is purged
// without a Fleet call; a device retired inside the period and active, quarantined, pending and rejected devices are
// never touched. A second pass finds nothing and records nothing.
func TestRetentionPurgeRetiredInventory(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	old := now.Add(-400 * time.Second)
	retired := w.inventoried(t, org, "retired", old, "11", 3, 2, 1)
	reEnrolled := w.inventoried(t, org, "retired", old.Add(time.Second), "12", 1, 0, 0)
	successor := w.inventoried(t, org, "active", old, "12", 1, 0, 0)
	hostless := w.inventoried(t, org, "retired", old.Add(2*time.Second), "", 2, 0, 0)
	recent := w.inventoried(t, org, "retired", now.Add(-10*time.Second), "13", 1, 0, 0)
	untouched := []uuid.UUID{successor, recent}
	for i, state := range []string{"active", "quarantined", "pending", "rejected"} {
		untouched = append(untouched, w.inventoried(t, org, state, old, "2"+string(rune('0'+i)), 1, 1, 1))
	}

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now)
	if err != nil || n != 7+2+2 {
		t.Fatalf("purged %d rows (%v), want 11", n, err)
	}
	for _, dev := range []uuid.UUID{retired, reEnrolled, hostless} {
		if left := w.inventoryRows(t, dev); left != 0 {
			t.Fatalf("device %s keeps %d inventory rows", dev, left)
		}
	}
	for _, dev := range untouched {
		if left := w.inventoryRows(t, dev); left == 0 {
			t.Fatalf("device %s lost its inventory", dev)
		}
	}
	if !slices.Equal(w.fleet.deleted, []ports.HostRef{"11"}) {
		t.Fatalf("Fleet hosts deleted %v, want [11]", w.fleet.deleted)
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 3 {
		t.Fatalf("%d events, want 3: %+v", len(events), events)
	}
	want := []struct {
		dev                         uuid.UUID
		software, findings, results float64
		hostDeleted                 bool
	}{{retired, 3, 2, 1, true}, {reEnrolled, 1, 0, 0, false}, {hostless, 2, 0, 0, false}}
	for i, ev := range events {
		p := ev.params
		if ev.outcome != "success" || ev.target != want[i].dev.String() || p["software"] != want[i].software ||
			p["findings"] != want[i].findings || p["policy_results"] != want[i].results ||
			p["fleet_host_deleted"] != want[i].hostDeleted || p["hostname"] != "inv-"+want[i].dev.String()[24:] {
			t.Fatalf("event %d: %+v", i, ev)
		}
	}
	if at, err := time.Parse(time.RFC3339, events[0].params["retired_at"].(string)); err != nil || at.Sub(old).Abs() > time.Millisecond {
		t.Fatalf("retired_at %v (%v), want %v", events[0].params["retired_at"], err, old)
	}

	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("second pass %d (%v), want 0", n, err)
	}
	if events := w.inventoryPurgedEvents(t, org); len(events) != 3 {
		t.Fatalf("%d events after a pass without retired inventory, want 3", len(events))
	}
}

// TestRetentionPurgeRetiredInventorySettings: the period is the organization's retired_inventory_days.
func TestRetentionPurgeRetiredInventorySettings(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	if _, err := w.super.Exec(context.Background(),
		"UPDATE organization_privacy_settings SET retired_inventory_days = 200 WHERE organization_id = $1", org); err != nil {
		t.Fatal(err)
	}
	kept := w.inventoried(t, org, "retired", now.Add(-100*time.Second), "31", 1, 0, 0)
	purged := w.inventoried(t, org, "retired", now.Add(-300*time.Second), "32", 1, 0, 0)
	if _, err := w.retention.PurgeRetiredInventory(systemCtx(org), now); err != nil {
		t.Fatal(err)
	}
	if w.inventoryRows(t, kept) != 2 || w.inventoryRows(t, purged) != 0 {
		t.Fatalf("rows left: inside the period %d, outside %d", w.inventoryRows(t, kept), w.inventoryRows(t, purged))
	}
}

// TestRetentionPurgeRetiredInventoryFleetUnavailable (plan M10 decision 16): when Fleet fails, the event is failure
// with upstream_unavailable, no Paddock row is deleted and the pass ends; the next pass retries the device first.
func TestRetentionPurgeRetiredInventoryFleetUnavailable(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	first := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "41", 2, 1, 0)
	second := w.inventoried(t, org, "retired", now.Add(-399*time.Second), "42", 1, 0, 0)
	w.fleet.err = errors.New("fleet: HTTP 503: unavailable")

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now)
	if !errors.Is(err, problem.UpstreamUnavailable) || n != 0 {
		t.Fatalf("purged %d (%v), want upstream_unavailable and nothing", n, err)
	}
	if w.inventoryRows(t, first) != 4 || w.inventoryRows(t, second) != 2 {
		t.Fatal("Paddock rows deleted although Fleet failed")
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 1 || events[0].outcome != "failure" || events[0].errorCode != "upstream_unavailable" ||
		events[0].target != first.String() || events[0].params["fleet_host_deleted"] != false || events[0].params["software"] != float64(2) {
		t.Fatalf("events %+v, want one failure of the first device", events)
	}

	w.fleet.err = nil
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now); err != nil || n != 4+2 {
		t.Fatalf("retry purged %d (%v), want 6", n, err)
	}
	events = w.inventoryPurgedEvents(t, org)
	if len(events) != 3 || events[1].outcome != "success" || events[1].target != first.String() ||
		events[1].params["fleet_host_deleted"] != true || events[2].target != second.String() {
		t.Fatalf("events after the retry %+v", events)
	}
}

// TestRetentionPurgeRetiredInventoryLimits (plan M10 decision 16, amendment 2026-10-30): one pass purges at most 100
// devices; a pass whose budget has elapsed stops after the device it finished.
func TestRetentionPurgeRetiredInventoryLimits(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	if _, err := w.super.Exec(context.Background(), `
		WITH d AS (
		  INSERT INTO device (id, organization_id, hostname, state, state_changed_at)
		  SELECT gen_random_uuid(), $1, 'bulk' || g, 'retired', $2::timestamptz + g * interval '1 ms' FROM generate_series(1, 102) g
		  RETURNING id, organization_id)
		INSERT INTO installed_software (device_id, organization_id, name, version, source)
		SELECT id, organization_id, 'bash', '5.2', 'deb_packages' FROM d`, org, now.Add(-400*time.Second)); err != nil {
		t.Fatal(err)
	}
	left := func() int {
		return countRows(t, w.super, "SELECT count(*) FROM installed_software WHERE organization_id = $1", org)
	}
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now); err != nil || n != 100 || left() != 2 {
		t.Fatalf("first pass purged %d (%v), %d left; want 100 and 2", n, err, left())
	}
	w.retention.SetBudget(0)
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now); err != nil || n != 1 || left() != 1 {
		t.Fatalf("pass without budget purged %d (%v), %d left; want 1 and 1", n, err, left())
	}
	if events := w.inventoryPurgedEvents(t, org); len(events) != 101 {
		t.Fatalf("%d events, want 101", len(events))
	}
	if len(w.fleet.deleted) != 0 {
		t.Fatalf("Fleet called for devices without a host: %v", w.fleet.deleted)
	}
}

// TestRetentionPurgeRetiredInventorySystemOnly: only the worker's system principal may purge.
func TestRetentionPurgeRetiredInventorySystemOnly(t *testing.T) {
	w := newRetentionWorld(t)
	org := w.emptyOrganization(t)
	dev := w.inventoried(t, org, "retired", time.Now().Add(-400*time.Second), "51", 1, 0, 0)
	admin := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAdmin, OrganizationID: org})
	if _, err := w.retention.PurgeRetiredInventory(admin, time.Now()); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("admin purge: %v, want unauthenticated", err)
	}
	if w.inventoryRows(t, dev) != 2 || len(w.fleet.deleted) != 0 {
		t.Fatal("an admin purged the inventory")
	}
}
