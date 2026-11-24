package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// hostID is a numeric host ID no other test uses.
func hostID() string { return fmt.Sprint(rand.Int64N(1e15) + 1) }

func (h inventoryHarness) left(t *testing.T, dev uuid.UUID) []string {
	t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT host_id || ' ' || reason || ' ' || (removed_at IS NULL)::text
		FROM device_inventory_left_host WHERE device_id = $1 ORDER BY host_id`, dev)
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
	return out
}

// TestStoreHostRecordsReplacedHost (review round 2): changing the stored host reserves the previous one; storing the
// same host again reserves nothing; returning to a reserved host releases it.
func TestStoreHostRecordsReplacedHost(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	a, b := ports.HostRef(hostID()), ports.HostRef(hostID())
	store := func(ref ports.HostRef) {
		t.Helper()
		if err := h.sync.StoreHost(systemCtx(org), dev, ref, ports.HostInventory{}); err != nil {
			t.Fatal(err)
		}
	}
	store(a)
	store(a)
	if got := h.left(t, dev); len(got) != 0 {
		t.Fatalf("same host: %v", got)
	}
	store(b)
	if got := h.left(t, dev); !slices.Equal(got, []string{string(a) + " replaced true"}) {
		t.Fatalf("replaced: %v", got)
	}
	store(a)
	if got := h.left(t, dev); !slices.Equal(got, []string{string(b) + " replaced true"}) {
		t.Fatalf("returned to a: %v", got)
	}
}

// TestRemoveLeftInventoryHost (review round 2): one action per attempt with its params; a deleted host ends the
// reservation, a refused one is retried later, an unavailable inventory system keeps it; a host another device uses is
// released without an action.
func TestRemoveLeftInventoryHost(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	other, foreign := h.device(t, uuid.Nil, uuid.NewString(), "active")
	ctx := context.Background()
	reserve := func(device, o uuid.UUID) inventory.LeftHost {
		t.Helper()
		l := inventory.LeftHost{DeviceID: device, OrganizationID: o, Host: ports.HostRef(hostID()), Reason: inventory.LeftRelisted,
			Hostname: "h", LeftAt: time.Now().UTC().Truncate(time.Microsecond)}
		if _, err := h.super.Exec(ctx, `INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
			VALUES ($1, $2, $3, $4, $5)`, device, o, string(l.Host), l.Reason, l.LeftAt); err != nil {
			t.Fatal(err)
		}
		return l
	}
	actions := func(host ports.HostRef) []map[string]any {
		t.Helper()
		rows, err := h.super.Query(ctx, `SELECT outcome, params FROM action WHERE code = 'device.inventory_host_removed'
			AND params ->> 'fleet_host' = $1`, string(host))
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var outcome string
			var raw []byte
			var p map[string]any
			if err := rows.Scan(&outcome, &raw); err != nil || json.Unmarshal(raw, &p) != nil {
				t.Fatal(err)
			}
			p["outcome"] = outcome
			out = append(out, p)
		}
		return out
	}
	admin := &fakeInventoryAdmin{failing: map[ports.HostRef]error{}}

	ok := reserve(dev, org)
	if got, err := h.sync.RemoveLeftInventoryHost(systemCtx(org), ok, admin); err != nil || got != app.LeftHostRemoved {
		t.Fatalf("removed: %v %v", got, err)
	}
	want := map[string]any{"hostname": "h", "fleet_host": string(ok.Host), "reason": "relisted", "fleet_host_deleted": true,
		"left_at": audit.Timestamp(ok.LeftAt).Format(time.RFC3339Nano), "outcome": "success"}
	if got := actions(ok.Host); len(got) != 1 || !maps.Equal(got[0], want) {
		t.Fatalf("actions %v, want %v", got, want)
	}
	if n := h.count(t, "SELECT count(*) FROM device_inventory_left_host WHERE host_id = $1 AND removed_at IS NOT NULL", string(ok.Host)); n != 1 {
		t.Fatal("not marked removed")
	}

	refused := reserve(dev, org)
	admin.failing[refused.Host] = fleetRefused(refused.Host)
	if _, err := h.sync.RemoveLeftInventoryHost(systemCtx(org), refused, admin); err == nil {
		t.Fatal("refused: no error")
	}
	if n := h.count(t, `SELECT count(*) FROM device_inventory_left_host WHERE host_id = $1 AND attempted_at IS NOT NULL
		AND removed_at IS NULL`, string(refused.Host)); n != 1 || len(actions(refused.Host)) != 1 || actions(refused.Host)[0]["outcome"] != "failure" {
		t.Fatalf("refused: %v", actions(refused.Host))
	}

	down := reserve(dev, org)
	admin.failing[down.Host] = fleetDown()
	if _, err := h.sync.RemoveLeftInventoryHost(systemCtx(org), down, admin); err == nil {
		t.Fatal("unavailable: no error")
	}
	if n := h.count(t, `SELECT count(*) FROM device_inventory_left_host WHERE host_id = $1 AND attempted_at IS NULL
		AND removed_at IS NULL`, string(down.Host)); n != 1 {
		t.Fatal("unavailable: the reservation changed")
	}

	used := reserve(dev, org)
	if _, err := h.super.Exec(ctx, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
		foreign, other, string(used.Host)); err != nil {
		t.Fatal(err)
	}
	calls := admin.calls
	if got, err := h.sync.RemoveLeftInventoryHost(systemCtx(org), used, admin); err != nil || got != app.LeftHostInUse {
		t.Fatalf("in use: %v %v", got, err)
	}
	if admin.calls != calls || len(actions(used.Host)) != 0 || len(h.left(t, dev)) != 3 {
		t.Fatalf("in use: %d calls, actions %v, rows %v", admin.calls-calls, actions(used.Host), h.left(t, dev))
	}
}

// TestFleetHostInUseCoversBindingsAndReservations (review round 2): another device's binding and open reservation use
// a host, in another organization and for a retired device too; a removed reservation does not.
func TestFleetHostInUseCoversBindingsAndReservations(t *testing.T) {
	w := newOffboardWorld(t)
	sys := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem})
	asking, _ := w.newDevice(t, w.org, "retired")
	for _, c := range []struct {
		name, sql string
		retired   bool
	}{
		{"binding", "INSERT INTO device_fleet_binding (device_id, organization_id, host_id) VALUES ($1, $2, $3)", false},
		{"reservation", `INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
			VALUES ($1, $2, $3, 'replaced', now())`, false},
		{"retired device's reservation", `INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason,
			left_at) VALUES ($1, $2, $3, 'replaced', now())`, true},
	} {
		host := hostID()
		holder, _ := w.newDevice(t, w.other, "active")
		if c.retired {
			w.exec(t, "UPDATE device SET state = 'retired' WHERE id = $1", holder)
		}
		w.exec(t, c.sql, holder, w.other, host)
		if got, err := w.platform.FleetHostInUse(sys, asking, host); err != nil || got != db.FleetHostUsedByRef {
			t.Fatalf("%s: FleetHostInUse = %q %v", c.name, got, err)
		}
		if got, err := w.platform.FleetHostInUseOutside(sys, w.org, host); err != nil || got != db.FleetHostUsedByRef {
			t.Fatalf("%s: FleetHostInUseOutside = %q %v", c.name, got, err)
		}
		w.exec(t, "DELETE FROM device_fleet_binding WHERE device_id = $1", holder)
		w.exec(t, "UPDATE device_inventory_left_host SET removed_at = now() WHERE device_id = $1", holder)
		if got, err := w.platform.FleetHostInUse(sys, asking, host); err != nil || got != db.FleetHostUnused {
			t.Fatalf("%s removed: FleetHostInUse = %q %v", c.name, got, err)
		}
		if got, err := w.platform.FleetHostInUseOutside(sys, w.org, host); err != nil || got != db.FleetHostUnused {
			t.Fatalf("%s removed: FleetHostInUseOutside = %q %v", c.name, got, err)
		}
	}
}

// TestOffboardingDeletesReservedHosts (review round 2): the organization deletion's Fleet step deletes the
// organization's reserved hosts and keeps one that another organization stores.
func TestOffboardingDeletesReservedHosts(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	own, shared := hostID(), hostID()
	for _, h := range []string{own, shared} {
		w.exec(t, `INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
			VALUES ($1, $2, $3, 'replaced', now())`, w.device, w.org, h)
		w.fleet.hosts[h] = true
	}
	storer, _ := w.newDevice(t, w.other, "active")
	w.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
		storer, w.other, shared)
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepObjects)
	if w.fleet.hosts[own] || !slices.Contains(w.fleet.deleted, own) {
		t.Fatalf("the reserved host was not deleted: %v", w.fleet.deleted)
	}
	if !w.fleet.hosts[shared] || slices.Contains(w.fleet.deleted, shared) {
		t.Fatalf("a host another organization stores was deleted: %v", w.fleet.deleted)
	}
}

// TestRetireReservesStoredHost (review round 3, retired, regression): both retirement paths reserve the device's
// stored host with reason retired in the retirement's transaction; a device without a stored host gets none, and a
// refused retirement reserves nothing.
func TestRetireReservesStoredHost(t *testing.T) {
	w := newUninstallWorld(t)
	reserved := func(dev uuid.UUID) string {
		t.Helper()
		var got *string
		_ = w.super.QueryRow(context.Background(), `SELECT string_agg(host_id || ' ' || reason, ',') FROM device_inventory_left_host
			WHERE device_id = $1`, dev).Scan(&got)
		if got == nil {
			return ""
		}
		return *got
	}
	byAdmin := w.device
	byReport, _ := w.newDevice(t, w.org, "active")
	hostless, _ := w.newDevice(t, w.org, "active")
	hostA, hostB := hostID(), hostID()
	w.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $3, $4), ($2, $3, $5)",
		byAdmin, byReport, w.org, hostA, hostB)
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	if _, err := w.devices.Retire(admin, byAdmin); err != nil {
		t.Fatal(err)
	}
	w.exec(t, "UPDATE device SET uninstalled_at = now() WHERE id = $1", byReport)
	if retired, err := w.reports.RetireUninstalled(systemCtx(w.org), byReport); err != nil || !retired {
		t.Fatalf("retire uninstalled: %v %v", retired, err)
	}
	if _, err := w.devices.Retire(admin, hostless); err != nil {
		t.Fatal(err)
	}
	if reserved(byAdmin) != hostA+" retired" || reserved(byReport) != hostB+" retired" || reserved(hostless) != "" {
		t.Fatalf("admin %q, report %q, hostless %q", reserved(byAdmin), reserved(byReport), reserved(hostless))
	}
	w.exec(t, "DELETE FROM device_inventory_left_host WHERE device_id = $1", byAdmin)
	if _, err := w.devices.Retire(admin, byAdmin); err == nil {
		t.Fatal("a retired device was retired again")
	}
	if got := reserved(byAdmin); got != "" {
		t.Fatalf("a refused retirement reserved %q", got)
	}
}

// TestRetentionPurgeAfterRetiredHostRemoved (review round 3, retired): after the inventory round removed a retired
// device's host from Fleet, the inventory purge finds it deleted and removes Paddock's copy as before.
func TestRetentionPurgeAfterRetiredHostRemoved(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(worker, platform, httpx.RequestID)
	org := w.emptyOrganization(t)
	host := hostID()
	dev := w.inventoried(t, org, "active", time.Now(), host, 2, 1, 1)
	if _, err := w.super.Exec(ctx, "UPDATE device SET uninstalled_at = now() WHERE id = $1", dev); err != nil {
		t.Fatal(err)
	}
	if retired, err := app.NewDeviceReports(runner, worker).RetireUninstalled(systemCtx(org), dev); err != nil || !retired {
		t.Fatalf("retire: %v %v", retired, err)
	}
	sync := app.NewInventorySync(runner, worker, platform)
	left, err := sync.InventoryLeftHosts(systemCtx(uuid.Nil))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(left, func(l inventory.LeftHost) bool { return l.DeviceID == dev })
	if i < 0 || left[i].Reason != inventory.LeftRetired || !left[i].OrgActive {
		t.Fatalf("no reservation for the retired device: %+v", left)
	}
	if got, err := sync.RemoveLeftInventoryHost(systemCtx(org), left[i], w.fleet); err != nil || got != app.LeftHostRemoved {
		t.Fatalf("removal: %v %v", got, err)
	}
	if _, err := w.super.Exec(ctx, "UPDATE device SET state_changed_at = now() - interval '400 seconds' WHERE id = $1", dev); err != nil {
		t.Fatal(err)
	}
	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), time.Now().UTC(), app.NewRetentionRound()); err != nil || n != 1 {
		t.Fatalf("purged %d (%v)", n, err)
	}
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 1 || events[0].params["fleet_host_deleted"] != true || w.inventoryRows(t, dev) != 0 {
		t.Fatalf("purge events %+v, rows %d", events, w.inventoryRows(t, dev))
	}
}

// TestAPIRoleReadsOnlyReservationKeys (review round 3): the API role reads only the key columns of its own
// organization's reservations.
func TestAPIRoleReadsOnlyReservationKeys(t *testing.T) {
	w := newUninstallWorld(t)
	other, _ := w.newDevice(t, w.org, "active")
	foreignOrg := uuid.Must(uuid.NewV7())
	w.exec(t, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'F', 'active')", foreignOrg, "f"+foreignOrg.String()[24:])
	foreign, _ := w.newDevice(t, foreignOrg, "active")
	for _, d := range [][2]uuid.UUID{{other, w.org}, {foreign, foreignOrg}} {
		w.exec(t, `INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
			VALUES ($1, $2, $3, 'replaced', now())`, d[0], d[1], hostID())
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).API)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", w.org.String()); err != nil {
		t.Fatal(err)
	}
	var devices []uuid.UUID
	rows, err := tx.Query(ctx, "SELECT device_id FROM device_inventory_left_host")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var d uuid.UUID
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		devices = append(devices, d)
	}
	rows.Close()
	if !slices.Equal(devices, []uuid.UUID{other}) {
		t.Fatalf("the API role sees %v, want only its organization's %s", devices, other)
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT s"); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := tx.QueryRow(ctx, "SELECT reason FROM device_inventory_left_host").Scan(&reason); err == nil ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the API role reads another column: %v", err)
	}

}
