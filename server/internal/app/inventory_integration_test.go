package app_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type inventoryHarness struct {
	sync  *app.InventorySync
	super *pgx.Conn
}

func newInventoryHarness(t *testing.T) inventoryHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	runner := app.NewActionRunner(worker, platform, httpx.RequestID)
	return inventoryHarness{sync: app.NewInventorySync(runner, worker, platform), super: super}
}

// device inserts an active device with a hardware UUID into org (a new organization if org is uuid.Nil).
func (h inventoryHarness) device(t *testing.T, org uuid.UUID, hardwareUUID, state string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if org == uuid.Nil {
		org = uuid.Must(uuid.NewV7())
		if _, err := h.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'I', 'active')", org, "i"+org.String()[24:]); err != nil {
			t.Fatal(err)
		}
	}
	dev := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'h', $3, $4)",
		dev, org, state, hardwareUUID); err != nil {
		t.Fatal(err)
	}
	return org, dev
}

func (h inventoryHarness) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestMapHosts (plan M5a decision 6): a hardware UUID maps case-insensitively to its one active or quarantined
// device; a UUID of two such devices (also in different organizations) and a retired device's UUID map to nothing.
func TestMapHosts(t *testing.T) {
	h := newInventoryHarness(t)
	one, ambiguous, retired := strings.ToUpper(uuid.NewString()), uuid.NewString(), uuid.NewString()
	org, dev := h.device(t, uuid.Nil, one, "active")
	h.device(t, uuid.Nil, ambiguous, "active")
	h.device(t, uuid.Nil, ambiguous, "quarantined")
	h.device(t, org, retired, "retired")
	h.device(t, org, retired+"x", "pending")
	got, err := h.sync.MapHosts(systemCtx(uuid.Nil), []string{strings.ToLower(one), ambiguous, retired, uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[strings.ToLower(one)] != (app.MappedDevice{DeviceID: dev, OrganizationID: org}) {
		t.Fatalf("mapped %+v", got)
	}
}

func score(f float64) *float64 { return &f }

// TestStoreHostReplacesTheInventory: the inventory of a device is stored under its organization and replaced on the
// next round (removed packages, findings and policies are deleted); duplicates from the inventory system are stored
// once; the api of another organization reads none of it (RLS).
func TestStoreHostReplacesTheInventory(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	seen := time.Now().UTC().Truncate(time.Second)
	inv := ports.HostInventory{OSVersion: "Ubuntu 24.04.5 LTS", AgentVersion: "1.61.0", LastSeenAt: &seen,
		Software: []ports.SoftwarePackage{
			{Name: "openssl", Version: "3.0.13-0ubuntu3", Source: "deb_packages", Vulnerabilities: []ports.Vulnerability{
				{CVE: "cve-2024-0001", CVSSScore: score(9.8), FixedVersion: "3.0.13-0ubuntu3.1"}, {CVE: "CVE-2024-0002"}}},
			{Name: "openssl", Version: "3.0.13-0ubuntu3", Source: "deb_packages"},
			{Name: "curl", Version: "8.5.0-2ubuntu10", Source: "deb_packages"},
		},
		Policies: []ports.PolicyResult{{Key: "paddock_agent_running", Passing: true}, {Key: "disk_encrypted"}},
	}
	if err := h.sync.StoreHost(systemCtx(org), dev, "17", inv); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM installed_software WHERE device_id = $1", dev); n != 2 {
		t.Fatalf("%d packages, want 2", n)
	}
	var severity, fixed *string
	var cvss *float64
	if err := h.super.QueryRow(context.Background(), `SELECT severity, cvss_score::float8, fixed_version FROM vulnerability_finding
		WHERE device_id = $1 AND cve = 'CVE-2024-0001'`, dev).Scan(&severity, &cvss, &fixed); err != nil ||
		severity == nil || *severity != "critical" || cvss == nil || *cvss != 9.8 || fixed == nil || *fixed != "3.0.13-0ubuntu3.1" {
		t.Fatalf("finding %v %v %v, %v", severity, cvss, fixed, err)
	}
	if n := h.count(t, `SELECT count(*) FROM vulnerability_finding WHERE device_id = $1 AND cve = 'CVE-2024-0002'
		AND severity IS NULL AND cvss_score IS NULL AND fixed_version IS NULL`, dev); n != 1 {
		t.Fatal("the finding without score is not stored with unknown values")
	}
	if n := h.count(t, "SELECT count(*) FROM device_inventory_ref WHERE device_id = $1 AND external_id = '17' AND fleetd_version = '1.61.0'", dev); n != 1 {
		t.Fatal("no inventory reference")
	}

	other, _ := h.device(t, uuid.Nil, uuid.NewString(), "active")
	for _, table := range []string{"device_inventory_ref", "installed_software", "vulnerability_finding", "inventory_policy_result"} {
		if n := h.apiCount(t, other, table); n != 0 {
			t.Errorf("%s: another organization reads %d rows", table, n)
		}
		if n := h.apiCount(t, org, table); n == 0 {
			t.Errorf("%s: the device's organization reads nothing", table)
		}
	}

	inv.Software = inv.Software[2:]
	inv.Policies = inv.Policies[:1]
	if err := h.sync.StoreHost(systemCtx(org), dev, "17", inv); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{"installed_software": 1, "vulnerability_finding": 0, "inventory_policy_result": 1} {
		if n := h.count(t, "SELECT count(*) FROM "+table+" WHERE device_id = $1", dev); n != want {
			t.Errorf("%s: %d rows, want %d", table, n, want)
		}
	}

}

// apiCount counts the rows of table that role paddock_api sees in org's context.
func (h inventoryHarness) apiCount(t *testing.T, org uuid.UUID, table string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := h.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var n int
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestReportAgentNotRunning (plan M5a decision 8): a failing agent-running policy of a device without check-in for 15
// minutes is reported once as device.tamper_agent_not_running; a device that checked in recently is not; passing
// again ends the failure, and a new failure is reported again.
func TestReportAgentNotRunning(t *testing.T) {
	h := newInventoryHarness(t)
	org, silent := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, recent := h.device(t, org, uuid.NewString(), "active")
	now := time.Now().UTC()
	ctx := context.Background()
	for dev, contact := range map[uuid.UUID]time.Time{silent: now.Add(-20 * time.Minute), recent: now.Add(-2 * time.Minute)} {
		if _, err := h.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)", dev, org, contact); err != nil {
			t.Fatal(err)
		}
	}
	fail := ports.HostInventory{Policies: []ports.PolicyResult{{Key: "paddock_agent_running"}}}
	for _, dev := range []uuid.UUID{silent, recent} {
		if err := h.sync.StoreHost(systemCtx(org), dev, "1", fail); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		got, err := h.sync.ReportAgentNotRunning(systemCtx(org), now)
		if err != nil {
			t.Fatal(err)
		}
		if n := h.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.tamper_agent_not_running'", org); n != 1 {
			t.Fatalf("%d events after %v, want 1 for the silent device", n, got)
		}
	}
	pass := ports.HostInventory{Policies: []ports.PolicyResult{{Key: "paddock_agent_running", Passing: true}}}
	if err := h.sync.StoreHost(systemCtx(org), silent, "1", pass); err != nil {
		t.Fatal(err)
	}
	if err := h.sync.StoreHost(systemCtx(org), silent, "1", fail); err != nil {
		t.Fatal(err)
	}
	got, err := h.sync.ReportAgentNotRunning(systemCtx(org), now)
	if err != nil || !slices.Equal(got, []uuid.UUID{silent}) {
		t.Fatalf("second failure %v, %v", got, err)
	}
}
