package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
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
	// Both reports count against the device's open tamper finding, written with each event (plan M9 decision 31).
	var occurrences int
	var lastEvent, latest uuid.UUID
	if err := h.super.QueryRow(ctx, `SELECT occurrences, last_event_id FROM finding
		WHERE device_id = $1 AND kind = 'tamper' AND code = 'device.tamper_agent_not_running' AND closed_at IS NULL`, silent).Scan(&occurrences, &lastEvent); err != nil {
		t.Fatal(err)
	}
	if err := h.super.QueryRow(ctx, `SELECT id FROM action WHERE target ->> 'id' = $1 AND code = 'device.tamper_agent_not_running'
		ORDER BY started_at DESC LIMIT 1`, silent.String()).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if occurrences != 2 || lastEvent != latest {
		t.Fatalf("finding: %d occurrences, last event %s; want 2 and %s", occurrences, lastEvent, latest)
	}
}

// binaryResult stores a host whose agent binary policy passes or fails and which evaluated its policies at evaluated.
func (h inventoryHarness) binaryResult(t *testing.T, org, dev uuid.UUID, passing bool, evaluated time.Time) {
	t.Helper()
	inv := ports.HostInventory{PolicyUpdatedAt: &evaluated, Policies: []ports.PolicyResult{{Key: "paddock_agent_binary_known", Passing: passing}}}
	if err := h.sync.StoreHost(systemCtx(org), dev, "1", inv); err != nil {
		t.Fatal(err)
	}
}

// TestReportAgentBinaryUnknown (plan M5a amendment 2026-11-16, A3): a failing agent binary policy evaluated at or
// after the gate is reported once as device.tamper_agent_binary_changed with exactly its four params, marks the result
// and opens a tamper finding without subject in the event's transaction. An evaluation before the gate, a passing
// result, a retired device and another organization's device are not reported; passing again ends the failure.
func TestReportAgentBinaryUnknown(t *testing.T) {
	h := newInventoryHarness(t)
	ctx := context.Background()
	gate := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	org, failing := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, stale := h.device(t, org, uuid.NewString(), "active")
	_, passing := h.device(t, org, uuid.NewString(), "active")
	_, retired := h.device(t, org, uuid.NewString(), "retired")
	other, foreign := h.device(t, uuid.Nil, uuid.NewString(), "active")
	if _, err := h.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, '1.4.0')", failing, org); err != nil {
		t.Fatal(err)
	}
	evaluated := gate.Add(3 * time.Minute)
	h.binaryResult(t, org, failing, false, evaluated)
	h.binaryResult(t, org, stale, false, gate.Add(-time.Second))
	h.binaryResult(t, org, passing, true, evaluated)
	h.binaryResult(t, org, retired, false, evaluated)
	h.binaryResult(t, other, foreign, false, evaluated)

	for range 2 {
		got, err := h.sync.ReportAgentBinaryUnknown(systemCtx(org), time.Now(), gate, 3)
		if err != nil {
			t.Fatal(err)
		}
		if n := h.count(t, "SELECT count(*) FROM action WHERE code = 'device.tamper_agent_binary_changed' AND organization_id = $1", org); n != 1 {
			t.Fatalf("%d events after %v, want 1 for the failing device", n, got)
		}
	}
	var raw []byte
	var eventID uuid.UUID
	if err := h.super.QueryRow(ctx, `SELECT id, params FROM action WHERE code = 'device.tamper_agent_binary_changed' AND target ->> 'id' = $1`,
		failing.String()).Scan(&eventID, &raw); err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(raw, &params); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"policy": "paddock_agent_binary_known", "evaluated_at": audit.Timestamp(evaluated).Format(time.RFC3339Nano),
		"agent_version": "1.4.0", "known_hashes": float64(3)}
	if !maps.Equal(params, want) {
		t.Fatalf("params %v, want %v", params, want)
	}
	if n := h.count(t, `SELECT count(*) FROM inventory_policy_result WHERE device_id = $1 AND policy_key = 'paddock_agent_binary_known'
		AND alerted_at IS NOT NULL`, failing); n != 1 {
		t.Fatal("the result is not marked as reported")
	}
	if n := h.count(t, `SELECT count(*) FROM finding WHERE device_id = $1 AND kind = 'tamper' AND code = 'device.tamper_agent_binary_changed'
		AND subject = '' AND last_event_id = $2 AND closed_at IS NULL`, failing, eventID); n != 1 {
		t.Fatalf("%d open tamper findings for the event", n)
	}
	for _, dev := range []uuid.UUID{stale, passing, retired, foreign} {
		if n := h.count(t, "SELECT count(*) FROM action WHERE code = 'device.tamper_agent_binary_changed' AND target ->> 'id' = $1", dev.String()); n != 0 {
			t.Fatalf("device %s reported %d times", dev, n)
		}
	}
	got, err := h.sync.ReportAgentBinaryUnknown(systemCtx(other), time.Now(), gate, 3)
	if err != nil || !slices.Equal(got, []uuid.UUID{foreign}) {
		t.Fatalf("organization B in its own context: %v, %v", got, err)
	}

	h.binaryResult(t, org, failing, true, evaluated.Add(time.Minute))
	if n := h.count(t, "SELECT count(*) FROM inventory_policy_result WHERE device_id = $1 AND alerted_at IS NOT NULL", failing); n != 0 {
		t.Fatal("a passing result keeps alerted_at")
	}
	if got, err := h.sync.ReportAgentBinaryUnknown(systemCtx(org), time.Now(), gate, 3); err != nil || len(got) != 0 {
		t.Fatalf("a passing result reported: %v, %v", got, err)
	}
	h.binaryResult(t, org, failing, false, evaluated.Add(2*time.Minute))
	if got, err := h.sync.ReportAgentBinaryUnknown(systemCtx(org), time.Now(), gate, 3); err != nil || !slices.Equal(got, []uuid.UUID{failing}) {
		t.Fatalf("second failure %v, %v", got, err)
	}
}

// TestStoreHostKeepsReportedUnansweredPolicy (plan M5a amendment 2026-11-16, review round 1, A7): a reported result
// whose policy the host has not answered since Fleet reset it keeps its row and mark; an unreported one and one Fleet
// no longer lists are deleted; an unanswered policy never creates a row.
func TestStoreHostKeepsReportedUnansweredPolicy(t *testing.T) {
	h := newInventoryHarness(t)
	ctx := context.Background()
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	failing := ports.HostInventory{Policies: []ports.PolicyResult{{Key: "paddock_agent_binary_known"}, {Key: "paddock_agent_running"}, {Key: "dropped"}}}
	if err := h.sync.StoreHost(systemCtx(org), dev, "1", failing); err != nil {
		t.Fatal(err)
	}
	alerted := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, err := h.super.Exec(ctx, `UPDATE inventory_policy_result SET alerted_at = $2
		WHERE device_id = $1 AND policy_key IN ('paddock_agent_binary_known', 'dropped')`, dev, alerted); err != nil {
		t.Fatal(err)
	}
	unanswered := ports.HostInventory{UnansweredPolicies: []string{"paddock_agent_binary_known", "paddock_agent_running", "never_stored"}}
	if err := h.sync.StoreHost(systemCtx(org), dev, "1", unanswered); err != nil {
		t.Fatal(err)
	}
	rows, err := h.super.Query(ctx, "SELECT policy_key, passing, alerted_at FROM inventory_policy_result WHERE device_id = $1", dev)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		key     string
		passing bool
		alerted *time.Time
	}
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.key, &x.passing, &x.alerted)
		return x, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].key != "paddock_agent_binary_known" || got[0].passing || got[0].alerted == nil || !got[0].alerted.Equal(alerted) {
		t.Fatalf("stored results %+v, want only the reported unanswered failure unchanged", got)
	}
	// Fleet no longer lists the policy and reports no unanswered one (a nil list): the reported row goes too.
	if err := h.sync.StoreHost(systemCtx(org), dev, "1", ports.HostInventory{}); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM inventory_policy_result WHERE device_id = $1", dev); n != 0 {
		t.Fatalf("%d results kept for a policy Fleet no longer lists, want 0", n)
	}
}

// TestReportAgentNotRunningKeepsMarkWhileUnanswered (plan M5a amendment 2026-11-16, review round 1, A7): a reported
// stop whose policy is unanswered for one sync and then fails again, with no check-in in between, is not reported a
// second time.
func TestReportAgentNotRunningKeepsMarkWhileUnanswered(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	now := time.Now().UTC()
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)",
		dev, org, now.Add(-20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	fail := ports.HostInventory{Policies: []ports.PolicyResult{{Key: "paddock_agent_running"}}}
	for _, inv := range []ports.HostInventory{fail, {UnansweredPolicies: []string{"paddock_agent_running"}}, fail} {
		if err := h.sync.StoreHost(systemCtx(org), dev, "1", inv); err != nil {
			t.Fatal(err)
		}
		if _, err := h.sync.ReportAgentNotRunning(systemCtx(org), now); err != nil {
			t.Fatal(err)
		}
	}
	if n := h.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.tamper_agent_not_running'", org); n != 1 {
		t.Fatalf("%d events for one stop, want 1", n)
	}
}

// agentRunning stores a host whose agent-running policy passes or fails and which evaluated its policies at evaluated
// (nil: the inventory system reports no time).
func (h inventoryHarness) agentRunning(t *testing.T, org, dev uuid.UUID, passing bool, evaluated *time.Time) {
	t.Helper()
	inv := ports.HostInventory{PolicyUpdatedAt: evaluated, Policies: []ports.PolicyResult{{Key: "paddock_agent_running", Passing: passing}}}
	if err := h.sync.StoreHost(systemCtx(org), dev, "1", inv); err != nil {
		t.Fatal(err)
	}
}

// failingSince reads the stored failing_since of the device's agent-running result.
func (h inventoryHarness) failingSince(t *testing.T, dev uuid.UUID) *time.Time {
	t.Helper()
	var since *time.Time
	if err := h.super.QueryRow(context.Background(), `SELECT failing_since FROM inventory_policy_result
		WHERE device_id = $1 AND policy_key = 'paddock_agent_running'`, dev).Scan(&since); err != nil {
		t.Fatal(err)
	}
	return since
}

// TestStoreHostFailingSince (plan M5a amendment 2026-11-16 b, D3): the first failing evaluation sets failing_since to
// the host's evaluation time, later failing evaluations keep it, a pass clears it, a failure without evaluation time
// leaves it unset, and a failing row without it (as before the migration) takes the time of its next failing sync.
func TestStoreHostFailingSince(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, legacy := h.device(t, org, uuid.NewString(), "active")
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	at := func(d time.Duration) *time.Time { v := t0.Add(d); return &v }
	steps := []struct {
		name    string
		passing bool
		eval    *time.Time
		want    *time.Time
	}{
		{"first failure", false, at(0), at(0)},
		{"failing again", false, at(10 * time.Minute), at(0)},
		{"passing", true, at(20 * time.Minute), nil},
		{"failing without time", false, nil, nil},
		{"failing with time after a failure without", false, at(30 * time.Minute), at(30 * time.Minute)},
	}
	for _, s := range steps {
		h.agentRunning(t, org, dev, s.passing, s.eval)
		if got := h.failingSince(t, dev); !equalTime(got, s.want) {
			t.Fatalf("%s: failing_since %v, want %v", s.name, got, s.want)
		}
	}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO inventory_policy_result (device_id, organization_id, policy_key, passing, updated_at)
		VALUES ($1, $2, 'paddock_agent_running', false, now())`, legacy, org); err != nil {
		t.Fatal(err)
	}
	h.agentRunning(t, org, legacy, false, at(40*time.Minute))
	if got := h.failingSince(t, legacy); !equalTime(got, at(40*time.Minute)) {
		t.Fatalf("a failing row without failing_since: %v after a failing sync, want %v", got, at(40*time.Minute))
	}
}

func equalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// TestReportAgentNotRunningWhileCheckingIn (plan M5a decision 8 as amended 2026-11-16 b, D2): a device that keeps
// checking in is reported once its agent-running policy failed in evaluations at least 15 minutes apart in the
// inventory system's clock, with failing_since and evaluated_at; one evaluation, evaluations less than 15 minutes
// apart, a pass in between, unknown evaluation times, a retired device and another organization's device are not.
func TestReportAgentNotRunningWhileCheckingIn(t *testing.T) {
	h := newInventoryHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	t0 := now.Add(-2 * time.Hour).Truncate(time.Microsecond)
	at := func(d time.Duration) *time.Time { v := t0.Add(d); return &v }
	org, impostor := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, oneEval := h.device(t, org, uuid.NewString(), "active")
	_, short := h.device(t, org, uuid.NewString(), "active")
	_, restart := h.device(t, org, uuid.NewString(), "active")
	_, noTime := h.device(t, org, uuid.NewString(), "active")
	_, retired := h.device(t, org, uuid.NewString(), "retired")
	other, foreign := h.device(t, uuid.Nil, uuid.NewString(), "active")
	contact := now.Add(-2 * time.Minute).Truncate(time.Microsecond)
	for dev, o := range map[uuid.UUID]uuid.UUID{impostor: org, oneEval: org, short: org, restart: org, noTime: org, retired: org, foreign: other} {
		if _, err := h.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)", dev, o, contact); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []struct {
		org uuid.UUID
		dev uuid.UUID
	}{{org, impostor}, {org, retired}, {other, foreign}} {
		h.agentRunning(t, d.org, d.dev, false, at(0))
		h.agentRunning(t, d.org, d.dev, false, at(15*time.Minute))
	}
	h.agentRunning(t, org, oneEval, false, at(0))
	h.agentRunning(t, org, short, false, at(0))
	h.agentRunning(t, org, short, false, at(15*time.Minute-time.Second))
	h.agentRunning(t, org, restart, false, at(0))
	h.agentRunning(t, org, restart, true, at(10*time.Minute))
	h.agentRunning(t, org, restart, false, at(20*time.Minute))
	h.agentRunning(t, org, restart, false, at(30*time.Minute))
	h.agentRunning(t, org, noTime, false, nil)
	h.agentRunning(t, org, noTime, false, nil)

	events := func(dev uuid.UUID) int {
		return h.count(t, "SELECT count(*) FROM action WHERE code = 'device.tamper_agent_not_running' AND target ->> 'id' = $1", dev.String())
	}
	for i, want := range [][]uuid.UUID{{impostor}, nil} {
		got, err := h.sync.ReportAgentNotRunning(systemCtx(org), now)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("call %d: reported %v, %v; want %v", i+1, got, err, want)
		}
		if events(impostor) != 1 {
			t.Fatalf("impostor: %d events, want 1", events(impostor))
		}
	}
	for name, dev := range map[string]uuid.UUID{"oneEval": oneEval, "short": short, "restart": restart, "noTime": noTime, "retired": retired, "foreign": foreign} {
		if n := events(dev); n != 0 {
			t.Fatalf("%s: %d events, want 0", name, n)
		}
	}
	var raw []byte
	var eventID uuid.UUID
	if err := h.super.QueryRow(ctx, `SELECT id, params FROM action WHERE code = 'device.tamper_agent_not_running' AND target ->> 'id' = $1`,
		impostor.String()).Scan(&eventID, &raw); err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(raw, &params); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"policy": "paddock_agent_running", "last_contact_at": audit.Timestamp(contact).Format(time.RFC3339Nano),
		"failing_since": audit.Timestamp(*at(0)).Format(time.RFC3339Nano), "evaluated_at": audit.Timestamp(*at(15 * time.Minute)).Format(time.RFC3339Nano)}
	if !maps.Equal(params, want) {
		t.Fatalf("params %v, want %v", params, want)
	}
	if n := h.count(t, `SELECT count(*) FROM finding WHERE device_id = $1 AND kind = 'tamper' AND code = 'device.tamper_agent_not_running'
		AND last_event_id = $2 AND closed_at IS NULL`, impostor, eventID); n != 1 {
		t.Fatalf("%d open tamper findings for the event", n)
	}

	h.agentRunning(t, org, short, false, at(15*time.Minute))
	h.agentRunning(t, org, restart, false, at(35*time.Minute))
	got, err := h.sync.ReportAgentNotRunning(systemCtx(org), now)
	slices.SortFunc(got, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	wantDevs := []uuid.UUID{short, restart}
	slices.SortFunc(wantDevs, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	if err != nil || !slices.Equal(got, wantDevs) {
		t.Fatalf("after 15 minutes of failing evaluations: reported %v, %v; want %v", got, err, wantDevs)
	}
	if got, err := h.sync.ReportAgentNotRunning(systemCtx(other), now); err != nil || !slices.Equal(got, []uuid.UUID{foreign}) {
		t.Fatalf("organization B in its own context: %v, %v", got, err)
	}
	if n := h.count(t, "SELECT count(*) FROM action WHERE code = 'device.tamper_agent_not_running' AND organization_id = $1 AND target ->> 'id' = $2",
		org, foreign.String()); n != 0 {
		t.Fatalf("organization B's device recorded %d times in organization A", n)
	}
}

// TestPublishedAgentHashes (plan M5a amendment 2026-11-16, A2): the hash set holds every artifact of every published
// release, all architectures, and no artifact of a draft.
func TestPublishedAgentHashes(t *testing.T) {
	h := newInventoryHarness(t)
	ctx := context.Background()
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	pub, draft := "1.0.0-h"+uuid.NewString()[:8], "1.0.0-h"+uuid.NewString()[:8]
	amd, arm, drafted := hash(pub+"amd64"), hash(pub+"arm64"), hash(draft)
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO agent_release (version, created_by, status, published_at) VALUES ($1, 't', 'published', now())", []any{pub}},
		{"INSERT INTO agent_release (version, created_by) VALUES ($1, 't')", []any{draft}},
		{"INSERT INTO agent_artifact (version, arch, sha256, size, minisig, object_key) VALUES ($1, 'amd64', $2, 1, 'x', 'k')", []any{pub, amd}},
		{"INSERT INTO agent_artifact (version, arch, sha256, size, minisig, object_key) VALUES ($1, 'arm64', $2, 1, 'x', 'k')", []any{pub, arm}},
		{"INSERT INTO agent_artifact (version, arch, sha256, size, minisig, object_key) VALUES ($1, 'amd64', $2, 1, 'x', 'k')", []any{draft, drafted}},
	} {
		if _, err := h.super.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	got, err := h.sync.PublishedAgentHashes(systemCtx(uuid.Nil))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, amd) || !slices.Contains(got, arm) || slices.Contains(got, drafted) {
		t.Fatalf("hash set %v: want %s and %s, not %s", got, amd, arm, drafted)
	}
}
