package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
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

// hardware sets a device's hardware UUID.
func (w retentionWorld) hardware(t *testing.T, dev uuid.UUID, hw string) {
	t.Helper()
	if _, err := w.super.Exec(context.Background(), "UPDATE device SET hardware_uuid = $2 WHERE id = $1", dev, hw); err != nil {
		t.Fatal(err)
	}
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

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	if err != nil || n != 3 {
		t.Fatalf("purged %d devices (%v), want 3", n, err)
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
		use                         any
	}{{retired, 3, 2, 1, true, "none"}, {reEnrolled, 1, 0, 0, false, "ref"}, {hostless, 2, 0, 0, false, nil}}
	for i, ev := range events {
		p := ev.params
		if ev.outcome != "success" || ev.target != want[i].dev.String() || p["software"] != want[i].software ||
			p["findings"] != want[i].findings || p["policy_results"] != want[i].results ||
			p["fleet_host_deleted"] != want[i].hostDeleted || p["fleet_host_in_use"] != want[i].use || p["hostname"] != "inv-"+want[i].dev.String()[24:] {
			t.Fatalf("event %d: %+v", i, ev)
		}
	}
	if at, err := time.Parse(time.RFC3339, events[0].params["retired_at"].(string)); err != nil || at.Sub(old).Abs() > time.Millisecond {
		t.Fatalf("retired_at %v (%v), want %v", events[0].params["retired_at"], err, old)
	}

	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 0 {
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
	if _, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil {
		t.Fatal(err)
	}
	if w.inventoryRows(t, kept) != 2 || w.inventoryRows(t, purged) != 0 {
		t.Fatalf("rows left: inside the period %d, outside %d", w.inventoryRows(t, kept), w.inventoryRows(t, purged))
	}
}

// TestRetentionPurgeRetiredInventoryFleetUnavailable (plan M10 decision 16, amendment 2026-10-30): when Fleet fails,
// every device's event is failure with upstream_unavailable, no Paddock row is deleted and the pass ends partial with
// the failed devices counted; the next pass retries the devices.
func TestRetentionPurgeRetiredInventoryFleetUnavailable(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	first := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "41", 2, 1, 0)
	second := w.inventoried(t, org, "retired", now.Add(-399*time.Second), "42", 1, 0, 0)
	w.fleet.err = errors.New("fleet: HTTP 503: unavailable")

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	if !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "2 of 2 devices failed") || n != 0 {
		t.Fatalf("purged %d (%v), want upstream_unavailable, 2 of 2 failed and nothing", n, err)
	}
	if w.inventoryRows(t, first) != 4 || w.inventoryRows(t, second) != 2 {
		t.Fatal("Paddock rows deleted although Fleet failed")
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 2 || events[0].outcome != "failure" || events[0].errorCode != "upstream_unavailable" ||
		events[0].target != first.String() || events[0].params["fleet_host_deleted"] != false || events[0].params["software"] != float64(2) ||
		events[1].outcome != "failure" || events[1].target != second.String() {
		t.Fatalf("events %+v, want one failure per device", events)
	}

	w.fleet.err = nil
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 2 {
		t.Fatalf("retry purged %d devices (%v), want 2", n, err)
	}
	events = w.inventoryPurgedEvents(t, org)
	if len(events) != 4 || events[2].outcome != "success" || events[2].target != first.String() ||
		events[2].params["fleet_host_deleted"] != true || events[3].target != second.String() {
		t.Fatalf("events after the retry %+v", events)
	}
}

// TestRetentionPurgeRetiredInventoryPoisonDevice (plan M10 amendment 2026-10-30): a device whose host Fleet keeps
// refusing fails alone; the devices after it are purged in the same pass.
func TestRetentionPurgeRetiredInventoryPoisonDevice(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	poison := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "71", 1, 0, 0)
	next := w.inventoried(t, org, "retired", now.Add(-399*time.Second), "72", 1, 0, 0)
	w.fleet.failing = "71"

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	if err == nil || !strings.Contains(err.Error(), "1 of 2 devices failed") || n != 1 {
		t.Fatalf("purged %d (%v), want 1 and 1 of 2 failed", n, err)
	}
	if w.inventoryRows(t, poison) != 2 || w.inventoryRows(t, next) != 0 {
		t.Fatalf("rows left: refused %d, next %d; want 2 and 0", w.inventoryRows(t, poison), w.inventoryRows(t, next))
	}
	if !slices.Equal(w.fleet.deleted, []ports.HostRef{"72"}) {
		t.Fatalf("Fleet hosts deleted %v, want [72]", w.fleet.deleted)
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 2 || events[0].outcome != "failure" || events[0].target != poison.String() ||
		events[1].outcome != "success" || events[1].target != next.String() {
		t.Fatalf("events %+v, want a failure of the refused device and a success of the next", events)
	}
}

// TestRetentionPurgeRetiredInventoryHostInUse (plan M10 amendments 2026-10-30): one Fleet serves every organization.
// When another organization's device references the host ('ref'), the host stays and the retired device's Paddock
// rows go. When an active, quarantined or pending device of the same hardware has no reference yet ('hardware'), in
// the same or another organization, the host and the retired device's host reference stay and its other rows go.
// Otherwise ('none') the host is deleted, also when a device of the same hardware has its own, different reference.
func TestRetentionPurgeRetiredInventoryHostInUse(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	orgA, orgB := w.emptyOrganization(t), w.emptyOrganization(t)
	old := now.Add(-400 * time.Second)
	crossRef := w.inventoried(t, orgA, "retired", old, "81", 1, 0, 0)
	foreign := w.inventoried(t, orgB, "active", old, "81", 1, 0, 0)
	sameOrgHW := w.inventoried(t, orgA, "retired", old.Add(time.Second), "82", 1, 0, 0)
	w.hardware(t, sameOrgHW, "AAAA-82")
	w.hardware(t, w.inventoried(t, orgA, "active", now, "", 0, 0, 0), "aaaa-82")
	crossOrgHW := w.inventoried(t, orgA, "retired", old.Add(2*time.Second), "83", 1, 0, 0)
	w.hardware(t, crossOrgHW, "bbbb-83")
	w.hardware(t, w.inventoried(t, orgB, "quarantined", now, "", 0, 0, 0), "bbbb-83")
	alone := w.inventoried(t, orgA, "retired", old.Add(3*time.Second), "84", 1, 0, 0)
	w.hardware(t, alone, "cccc-84")
	w.hardware(t, w.inventoried(t, orgB, "retired", now, "", 0, 0, 0), "cccc-84")
	pendingHW := w.inventoried(t, orgA, "retired", old.Add(4*time.Second), "85", 1, 0, 0)
	w.hardware(t, pendingHW, "dddd-85")
	w.hardware(t, w.inventoried(t, orgB, "pending", now, "", 0, 0, 0), "dddd-85")
	ownRef := w.inventoried(t, orgA, "retired", old.Add(5*time.Second), "86", 1, 0, 0)
	w.hardware(t, ownRef, "eeee-86")
	w.hardware(t, w.inventoried(t, orgB, "active", now, "87", 0, 0, 0), "eeee-86")

	n, err := w.retention.PurgeRetiredInventory(systemCtx(orgA), now, app.NewRetentionRound())
	if err != nil || n != 6 {
		t.Fatalf("purged %d devices (%v), want 6", n, err)
	}
	if !slices.Equal(w.fleet.deleted, []ports.HostRef{"84", "86"}) {
		t.Fatalf("Fleet hosts deleted %v, want [84 86]", w.fleet.deleted)
	}
	want := []struct {
		dev     uuid.UUID
		rowsAft int
		use     string
	}{{crossRef, 0, "ref"}, {sameOrgHW, 1, "hardware"}, {crossOrgHW, 1, "hardware"}, {alone, 0, "none"},
		{pendingHW, 1, "hardware"}, {ownRef, 0, "none"}}
	events := w.inventoryPurgedEvents(t, orgA)
	if len(events) != len(want) {
		t.Fatalf("%d events, want %d", len(events), len(want))
	}
	for i, ev := range events {
		if left := w.inventoryRows(t, want[i].dev); left != want[i].rowsAft {
			t.Fatalf("device %d keeps %d inventory rows, want %d", i, left, want[i].rowsAft)
		}
		if ev.outcome != "success" || ev.target != want[i].dev.String() || ev.params["software"] != float64(1) ||
			ev.params["fleet_host_in_use"] != want[i].use || ev.params["fleet_host_deleted"] != (want[i].use == "none") {
			t.Fatalf("event %d: %+v", i, ev)
		}
	}
	if w.inventoryRows(t, foreign) != 2 {
		t.Fatal("the other organization's device lost its inventory")
	}
	if events := w.inventoryPurgedEvents(t, orgB); len(events) != 0 {
		t.Fatalf("the other organization got %d events", len(events))
	}
}

// TestRetentionPurgeRetiredInventoryHardwareRetried (plan M10 amendments 2026-10-30): a device kept for 'hardware'
// is listed and checked again in every pass; once the device of the same hardware has its own, different reference
// or is gone (rejected), the retired device's host is deleted and its reference goes.
func TestRetentionPurgeRetiredInventoryHardwareRetried(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	old := now.Add(-400 * time.Second)
	synced := w.inventoried(t, org, "retired", old, "61", 2, 0, 0)
	w.hardware(t, synced, "abcd-61")
	successor := w.inventoried(t, org, "active", now, "", 0, 0, 0)
	w.hardware(t, successor, "abcd-61")
	gone := w.inventoried(t, org, "retired", old.Add(time.Second), "63", 1, 0, 0)
	w.hardware(t, gone, "abcd-63")
	pending := w.inventoried(t, org, "pending", now, "", 0, 0, 0)
	w.hardware(t, pending, "abcd-63")

	for pass := 1; pass <= 2; pass++ {
		if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 2 {
			t.Fatalf("pass %d purged %d devices (%v), want 2", pass, n, err)
		}
		if w.fleet.calls != 0 || w.inventoryRows(t, synced) != 1 || w.inventoryRows(t, gone) != 1 {
			t.Fatalf("pass %d: %d Fleet calls, rows left %d and %d; want 0, 1 and 1", pass, w.fleet.calls,
				w.inventoryRows(t, synced), w.inventoryRows(t, gone))
		}
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 4 || events[0].params["software"] != float64(2) || events[2].params["software"] != float64(0) {
		t.Fatalf("events %+v, want two per device", events)
	}
	for i, ev := range events {
		if ev.outcome != "success" || ev.params["fleet_host_in_use"] != "hardware" || ev.params["fleet_host_deleted"] != false {
			t.Fatalf("event %d: %+v", i, ev)
		}
	}

	if _, err := w.super.Exec(context.Background(), `INSERT INTO device_inventory_ref (device_id, organization_id, external_id)
		VALUES ($1, $2, '62')`, successor, org); err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(context.Background(), "UPDATE device SET state = 'rejected' WHERE id = $1", pending); err != nil {
		t.Fatal(err)
	}
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 2 {
		t.Fatalf("pass 3 purged %d devices (%v), want 2", n, err)
	}
	if !slices.Equal(w.fleet.deleted, []ports.HostRef{"61", "63"}) || w.inventoryRows(t, synced) != 0 || w.inventoryRows(t, gone) != 0 {
		t.Fatalf("Fleet hosts deleted %v, rows left %d and %d; want [61 63], 0 and 0", w.fleet.deleted,
			w.inventoryRows(t, synced), w.inventoryRows(t, gone))
	}
	events = w.inventoryPurgedEvents(t, org)
	if len(events) != 6 || events[4].params["fleet_host_in_use"] != "none" || events[4].params["fleet_host_deleted"] != true ||
		events[5].params["fleet_host_in_use"] != "none" {
		t.Fatalf("events after the successors changed %+v", events[4:])
	}
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 0 {
		t.Fatalf("pass 4 purged %d devices (%v), want 0", n, err)
	}
}

// TestRetentionPurgeRetiredInventoryHostCheckFails (plan M10 amendment 2026-10-30): when the check for the host's other
// devices fails, the pass fails closed for that device: no Fleet call, no Paddock row deleted, one failure event.
func TestRetentionPurgeRetiredInventoryHostCheckFails(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	dev := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "91", 2, 1, 0)
	w.retention.SetHostUsers(func(context.Context, uuid.UUID, string) (string, error) {
		return "", errors.New("platform pool unavailable")
	})

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	if err == nil || n != 0 {
		t.Fatalf("purged %d (%v), want a failure and nothing", n, err)
	}
	if len(w.fleet.deleted) != 0 || w.inventoryRows(t, dev) != 4 {
		t.Fatalf("deleted although the check failed: hosts %v, %d rows left", w.fleet.deleted, w.inventoryRows(t, dev))
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 1 || events[0].outcome != "failure" || events[0].target != dev.String() ||
		events[0].params["fleet_host_deleted"] != false {
		t.Fatalf("events %+v, want one failure", events)
	}
}

// TestRetentionPurgeRetiredInventoryChangedAfterList (plan M10 decision 16): a listed device that was reactivated, or
// reactivated and retired again, before its row lock is refused under the lock with one failure event each; neither
// its Paddock rows nor its Fleet host are deleted.
func TestRetentionPurgeRetiredInventoryChangedAfterList(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	first := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "95", 1, 0, 0)
	reRetired := w.inventoried(t, org, "retired", now.Add(-399*time.Second), "96", 2, 1, 0)
	reactivated := w.inventoried(t, org, "retired", now.Add(-398*time.Second), "97", 1, 0, 0)
	w.retention.SetHostUsers(func(ctx context.Context, _ uuid.UUID, _ string) (string, error) {
		if _, err := w.super.Exec(ctx, "UPDATE device SET state_changed_at = $2 WHERE id = $1", reRetired, now); err != nil {
			return "", err
		}
		if _, err := w.super.Exec(ctx, "UPDATE device SET state = 'active', state_changed_at = $2 WHERE id = $1", reactivated, now); err != nil {
			return "", err
		}
		return "none", nil
	})

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	if err == nil || !strings.Contains(err.Error(), "2 of 3 devices failed") || n != 1 {
		t.Fatalf("purged %d (%v), want 1 and 2 of 3 failed", n, err)
	}
	if !slices.Equal(w.fleet.deleted, []ports.HostRef{"95"}) {
		t.Fatalf("Fleet hosts deleted %v, want only [95]", w.fleet.deleted)
	}
	if w.inventoryRows(t, first) != 0 || w.inventoryRows(t, reRetired) != 4 || w.inventoryRows(t, reactivated) != 2 {
		t.Fatalf("rows left: first %d, retired again %d, reactivated %d; want 0, 4 and 2",
			w.inventoryRows(t, first), w.inventoryRows(t, reRetired), w.inventoryRows(t, reactivated))
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 3 || events[0].outcome != "success" ||
		events[1].outcome != "failure" || events[1].target != reRetired.String() || events[1].params["fleet_host_deleted"] != false ||
		events[2].outcome != "failure" || events[2].target != reactivated.String() || events[2].errorCode != events[1].errorCode {
		t.Fatalf("events %+v, want a success and one failure per changed device", events)
	}
}

// TestRetentionPurgeRetiredInventoryLimits (plan M10 decision 16, amendment 2026-10-30): a pass whose budget has
// elapsed stops after the device it finished; otherwise it pages on past the first 100 devices until none is left.
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
	w.retention.SetBudget(0)
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 1 || left() != 101 {
		t.Fatalf("pass without budget purged %d (%v), %d left; want 1 and 101", n, err, left())
	}
	w.retention.SetBudget(time.Hour)
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 101 || left() != 0 {
		t.Fatalf("pass purged %d (%v), %d left; want 101 and 0", n, err, left())
	}
	if events := w.inventoryPurgedEvents(t, org); len(events) != 102 {
		t.Fatalf("%d events, want 102", len(events))
	}
	if len(w.fleet.deleted) != 0 {
		t.Fatalf("Fleet called for devices without a host: %v", w.fleet.deleted)
	}
}

// TestRetentionPurgeRetiredInventoryPagesPastFailures (plan M10 amendment 2026-10-30): devices that keep failing fill
// more than one page, and the pass pages on to the devices behind them within the same pass.
func TestRetentionPurgeRetiredInventoryPagesPastFailures(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	var failing []uuid.UUID
	for i := range 3 {
		failing = append(failing, w.inventoried(t, org, "retired", now.Add(time.Duration(i-400)*time.Second), "f"+string(rune('1'+i)), 1, 0, 0))
	}
	behind := []uuid.UUID{
		w.inventoried(t, org, "retired", now.Add(-390*time.Second), "g1", 1, 0, 0),
		w.inventoried(t, org, "retired", now.Add(-389*time.Second), "g2", 1, 0, 0),
	}
	w.retention.SetPage(2)
	w.retention.SetHostUsers(func(_ context.Context, _ uuid.UUID, host string) (string, error) {
		if strings.HasPrefix(host, "f") {
			return "", errors.New("check refused")
		}
		return "none", nil
	})

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	if err == nil || !strings.Contains(err.Error(), "3 of 5 devices failed") || n != 2 {
		t.Fatalf("purged %d (%v), want 2 and 3 of 5 failed", n, err)
	}
	if !slices.Equal(w.fleet.deleted, []ports.HostRef{"g1", "g2"}) {
		t.Fatalf("Fleet hosts deleted %v, want [g1 g2]", w.fleet.deleted)
	}
	for _, dev := range failing {
		if w.inventoryRows(t, dev) != 2 {
			t.Fatalf("failing device %s lost rows", dev)
		}
	}
	for _, dev := range behind {
		if w.inventoryRows(t, dev) != 0 {
			t.Fatalf("device %s behind the failing ones keeps rows", dev)
		}
	}
}

// retiredInventorySkips returns org's retention.purged events of store retired_inventory as outcome/error code.
func (w retentionWorld) retiredInventorySkips(t *testing.T, org uuid.UUID) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT outcome || '/' || coalesce(error_code, '') FROM action
		WHERE organization_id = $1 AND code = 'retention.purged' AND params->>'store' = 'retired_inventory'
		  AND status = 'finished' ORDER BY started_at, id`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRetentionPurgeRetiredInventoryFleetBreaker (plan M10 amendment 2026-10-30): after three consecutive Fleet
// failures in a round, the round's remaining devices and later organizations make no Fleet call and keep their rows;
// each skipped organization gets one retention.purged failure (upstream_unavailable) instead of one event per device,
// and an organization without due devices gets none. The next round starts with Fleet again.
func TestRetentionPurgeRetiredInventoryFleetBreaker(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	orgA, orgB, orgC := w.emptyOrganization(t), w.emptyOrganization(t), w.emptyOrganization(t)
	var devsA, devsB []uuid.UUID
	for i := range 5 {
		devsA = append(devsA, w.inventoried(t, orgA, "retired", now.Add(time.Duration(i-400)*time.Second), "b"+string(rune('1'+i)), 1, 0, 0))
	}
	for i := range 2 {
		devsB = append(devsB, w.inventoried(t, orgB, "retired", now.Add(time.Duration(i-400)*time.Second), "c"+string(rune('1'+i)), 1, 0, 0))
	}
	w.fleet.err = errors.New("fleet: HTTP 503: unavailable")
	round := app.NewRetentionRound()

	n, err := w.retention.PurgeRetiredInventory(systemCtx(orgA), now, round)
	if !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "3 of 3 devices failed") || n != 0 {
		t.Fatalf("organization A purged %d (%v), want upstream_unavailable and 3 of 3 failed", n, err)
	}
	if w.fleet.calls != 3 {
		t.Fatalf("%d Fleet calls, want 3", w.fleet.calls)
	}
	if events := w.inventoryPurgedEvents(t, orgA); len(events) != 3 {
		t.Fatalf("organization A has %d device events, want 3", len(events))
	}
	if skips := w.retiredInventorySkips(t, orgA); !slices.Equal(skips, []string{"failure/upstream_unavailable"}) {
		t.Fatalf("organization A skip events %v", skips)
	}
	for _, dev := range devsA {
		if w.inventoryRows(t, dev) != 2 {
			t.Fatalf("device %s lost rows although Fleet failed", dev)
		}
	}

	n, err = w.retention.PurgeRetiredInventory(systemCtx(orgB), now, round)
	if !errors.Is(err, problem.UpstreamUnavailable) || n != 0 {
		t.Fatalf("organization B purged %d (%v), want upstream_unavailable", n, err)
	}
	if w.fleet.calls != 3 || len(w.inventoryPurgedEvents(t, orgB)) != 0 || w.inventoryRows(t, devsB[0]) != 2 {
		t.Fatalf("organization B: %d Fleet calls, %d device events, %d rows", w.fleet.calls,
			len(w.inventoryPurgedEvents(t, orgB)), w.inventoryRows(t, devsB[0]))
	}
	if skips := w.retiredInventorySkips(t, orgB); !slices.Equal(skips, []string{"failure/upstream_unavailable"}) {
		t.Fatalf("organization B skip events %v", skips)
	}
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(orgC), now, round); err != nil || n != 0 ||
		len(w.retiredInventorySkips(t, orgC)) != 0 {
		t.Fatalf("organization C without due devices: %d (%v), skips %v", n, err, w.retiredInventorySkips(t, orgC))
	}

	w.fleet.err = nil
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(orgB), now, app.NewRetentionRound()); err != nil || n != 2 {
		t.Fatalf("next round purged %d devices of organization B (%v), want 2", n, err)
	}
}

// TestRetentionPurgeRetiredInventorySystemOnly: only the worker's system principal may purge.
func TestRetentionPurgeRetiredInventorySystemOnly(t *testing.T) {
	w := newRetentionWorld(t)
	org := w.emptyOrganization(t)
	dev := w.inventoried(t, org, "retired", time.Now().Add(-400*time.Second), "51", 1, 0, 0)
	admin := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAdmin, OrganizationID: org})
	if _, err := w.retention.PurgeRetiredInventory(admin, time.Now(), app.NewRetentionRound()); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("admin purge: %v, want unauthenticated", err)
	}
	if w.inventoryRows(t, dev) != 2 || len(w.fleet.deleted) != 0 {
		t.Fatal("an admin purged the inventory")
	}
}
