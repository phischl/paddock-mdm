package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// stalenessHarness evaluates staleness with the worker's role.
type stalenessHarness struct {
	staleness *app.Staleness
	reports   *app.DeviceReports
	super     *pgx.Conn
	org       uuid.UUID
}

func newStalenessHarness(t *testing.T) stalenessHarness {
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
	org := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'S', 'active')", org, "s"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	return stalenessHarness{staleness: app.NewStaleness(runner, worker, time.Minute), reports: app.NewDeviceReports(runner, worker), super: super, org: org}
}

func (h stalenessHarness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// device creates a device in state that last contacted Paddock at last.
func (h stalenessHarness) device(t *testing.T, state string, last time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', $3)", id, h.org, state)
	h.exec(t, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)", id, h.org, last)
	return id
}

func (h stalenessHarness) codes(t *testing.T, device uuid.UUID) []string {
	t.Helper()
	rows, err := h.super.Query(context.Background(), "SELECT code FROM action WHERE target ->> 'id' = $1 AND code LIKE 'device.stale%' ORDER BY started_at", device.String())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

func (h stalenessHarness) open(t *testing.T, device uuid.UUID) (kind string, presumedLost bool) {
	t.Helper()
	err := h.super.QueryRow(context.Background(), `SELECT coalesce((SELECT kind FROM device_alert WHERE device_id = $1 AND cleared_at IS NULL), ''),
		(SELECT presumed_lost_at IS NOT NULL FROM device_status WHERE device_id = $1)`, device).Scan(&kind, &presumedLost)
	if err != nil {
		t.Fatal(err)
	}
	return kind, presumedLost
}

// TestStalenessTransitions (plan M5b decision 10): a silent device crosses warning and critical once each, critical
// marks it presumed lost, a contact clears both with one device.stale_cleared, and repeated rounds record nothing.
func TestStalenessTransitions(t *testing.T) {
	h := newStalenessHarness(t)
	h.exec(t, "INSERT INTO organization_update_settings (organization_id, staleness_warning_h, staleness_critical_h) VALUES ($1, 2, 5)", h.org)
	start := time.Now().UTC().Truncate(time.Second)
	d := h.device(t, "active", start)
	ctx := systemCtx(h.org)
	round := func(at time.Time) {
		t.Helper()
		if err := h.staleness.Evaluate(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	round(start.Add(time.Minute))
	if k, lost := h.open(t, d); k != "" || lost {
		t.Fatalf("fresh device: %q %v", k, lost)
	}
	round(start.Add(3 * time.Minute))
	round(start.Add(4 * time.Minute))
	if k, lost := h.open(t, d); k != "stale_warning" || lost {
		t.Fatalf("after 3 minutes: %q %v", k, lost)
	}
	round(start.Add(6 * time.Minute))
	round(start.Add(7 * time.Minute))
	if k, lost := h.open(t, d); k != "stale_critical" || !lost {
		t.Fatalf("after 6 minutes: %q %v", k, lost)
	}
	h.exec(t, "UPDATE device_status SET last_contact_at = $2 WHERE device_id = $1", d, start.Add(8*time.Minute))
	round(start.Add(8 * time.Minute))
	round(start.Add(9 * time.Minute))
	if k, lost := h.open(t, d); k != "" || lost {
		t.Fatalf("after contact: %q %v", k, lost)
	}
	got := h.codes(t, d)
	want := []string{"device.stale_warning", "device.stale_critical", "device.stale_cleared"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("audit %v, want %v", got, want)
	}
	var n int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM device_alert WHERE device_id = $1", d).Scan(&n); err != nil || n != 2 {
		t.Fatalf("%d alerts (%v), want 2", n, err)
	}
}

// TestStalenessJumpsAndLeavesInactiveDevices: a device found silent past critical gets only the critical alert; a
// device that is retired loses its alert without an event; one that never checked in is left alone.
func TestStalenessJumpsAndLeavesInactiveDevices(t *testing.T) {
	h := newStalenessHarness(t)
	now := time.Now().UTC()
	d := h.device(t, "active", now.Add(-30*24*time.Hour))
	never := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", never, h.org)
	ctx := systemCtx(h.org)
	if err := h.staleness.Evaluate(ctx, now); err != nil {
		t.Fatal(err)
	}
	if got := h.codes(t, d); len(got) != 1 || got[0] != "device.stale_critical" {
		t.Fatalf("audit %v", got)
	}
	h.exec(t, "UPDATE device SET state = 'retired' WHERE id = $1", d)
	if err := h.staleness.Evaluate(ctx, now); err != nil {
		t.Fatal(err)
	}
	if k, lost := h.open(t, d); k != "" || lost || len(h.codes(t, d)) != 1 {
		t.Fatalf("retired: %q %v %v", k, lost, h.codes(t, d))
	}
	if len(h.codes(t, never)) != 0 {
		t.Fatal("a device without contact was evaluated")
	}
}

// TestUpdatesRunIsTheLastRun (plan M5b decision 12): updates.run is audited and kept per kind as the device's last
// run.
func TestUpdatesRunIsTheLastRun(t *testing.T) {
	h := newStalenessHarness(t)
	d := h.device(t, "active", time.Now())
	at := time.Now().UTC().Truncate(time.Second)
	for i, data := range []string{
		`{"kind":"regular","upgraded":3,"held_back":["linux-generic"],"reboot_required":true,"result":"ok"}`,
		`{"kind":"security","upgraded":1,"held_back":[],"reboot_required":false,"result":"failed","error":"dpkg"}`,
		`{"kind":"bogus","result":"ok"}`,
	} {
		ev := protocol.Event{EventSeq: int64(i + 1), Type: protocol.EventUpdatesRun, OccurredAt: at, Data: json.RawMessage(data)}
		if fresh, err := h.reports.RecordEvent(systemCtx(h.org), d, ev); err != nil || !fresh {
			t.Fatalf("event %d: %v %v", i, fresh, err)
		}
	}
	var raw []byte
	if err := h.super.QueryRow(context.Background(), "SELECT login_state FROM device_status WHERE device_id = $1", d).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var state map[string]struct {
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if len(state) != 2 || state["updates_regular"].Params["upgraded"] != float64(3) || state["updates_regular"].Params["reboot_required"] != true ||
		state["updates_security"].Params["result"] != "failed" || state["updates_security"].Params["error"] != "dpkg" {
		t.Fatalf("login_state %s", raw)
	}
}

// TestAttentionRowsAreUnique (review 1): a device with an open Lock, an open Destroy and an expired Lock has three
// revocation rows on the attention list, each with its own key, so the key orders pages deterministically.
func TestAttentionRowsAreUnique(t *testing.T) {
	h := newStalenessHarness(t)
	d := h.device(t, "active", time.Now())
	admin := uuid.New()
	for _, r := range [][2]string{{"lock", "requested"}, {"destroy", "approved"}, {"lock", "expired"}} {
		h.exec(t, "INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, finished_at) VALUES ($1, $2, $3, $4, $5, $6, now())",
			uuid.Must(uuid.NewV7()), h.org, d, r[0], r[1], admin)
	}
	var rows, keys int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*), count(DISTINCT id) FROM attention_condition WHERE device_id = $1 AND kind LIKE 'revocation_%'", d).
		Scan(&rows, &keys); err != nil || rows != 3 || keys != 3 {
		t.Fatalf("%d rows with %d keys (%v), want 3 and 3", rows, keys, err)
	}
}

// TestAgentOutdatedPreReleases (PDK-022): agent_outdated compares a device's agent version with the current release
// (the most recently completed rollout) for equality, not by order, so every other pre-release of the sequence is
// flagged and the current one is not. The rollouts are rolled back: the current release is platform-wide.
func TestAgentOutdatedPreReleases(t *testing.T) {
	h := newStalenessHarness(t)
	sequence := []string{"0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0"}
	devices := make([]uuid.UUID, len(sequence))
	for i, v := range sequence {
		devices[i] = h.device(t, "active", time.Now())
		h.exec(t, "UPDATE device_status SET agent_version = $2 WHERE device_id = $1", devices[i], v)
	}
	ctx := context.Background()
	for i, current := range sequence {
		t.Run(current, func(t *testing.T) {
			tx, err := h.super.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			for j, v := range sequence {
				if _, err := tx.Exec(ctx, "INSERT INTO agent_release (version, status, created_by, published_at) VALUES ($1, 'published', 't', now()) ON CONFLICT DO NOTHING", v); err != nil {
					t.Fatal(err)
				}
				// The current release completed last, the others earlier; all of them after any rollout of other tests.
				days := j
				if j == i {
					days = len(sequence)
				}
				if _, err := tx.Exec(ctx, `INSERT INTO agent_rollout (version, status, started_by, updated_at) VALUES ($1, 'completed', 't', now() + interval '100 years' + $2 * interval '1 day')
					ON CONFLICT (version) DO UPDATE SET status = 'completed', updated_at = EXCLUDED.updated_at`, v, days); err != nil {
					t.Fatal(err)
				}
			}
			for j, d := range devices {
				var flagged bool
				if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM attention_condition WHERE device_id = $1 AND kind = 'agent_outdated')", d).Scan(&flagged); err != nil {
					t.Fatal(err)
				}
				if flagged != (j != i) {
					t.Errorf("current %s, device on %s: agent_outdated %v", current, sequence[j], flagged)
				}
			}
		})
	}
}
