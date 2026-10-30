package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// hostKeptNotices returns the rounds param of org's device.inventory_host_kept events.
func (w retentionWorld) hostKeptNotices(t *testing.T, org uuid.UUID) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT outcome || '/' || coalesce(params->>'fleet_host_kept', '') || '/' ||
		coalesce(params->>'rounds', '') FROM action WHERE organization_id = $1 AND code = 'device.inventory_host_kept'
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

// passes runs n retention passes over org, each in a round of its own.
func (w retentionWorld) passes(t *testing.T, org uuid.UUID, now time.Time, n int) {
	t.Helper()
	for range n {
		_, _ = w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	}
}

// TestRetentionPurgeRetiredInventoryHoldFirstSight (plan M10 amendment 2026-10-30, PDK-583 round 2): a retired device
// that has nothing but its host reference left when it is first listed, and whose host a device of the same hardware
// may still use, records one event with the kept answer; the following rounds with the same answer record none.
func TestRetentionPurgeRetiredInventoryHoldFirstSight(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	dev := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "h1", 0, 0, 0)
	w.hardware(t, dev, "hold-h1")
	pending := w.inventoried(t, org, "pending", now, "", 0, 0, 0)
	w.hardware(t, pending, "hold-h1")

	if n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err != nil || n != 0 {
		t.Fatalf("first pass purged %d devices (%v), want none: nothing was deleted", n, err)
	}
	w.passes(t, org, now, 2)
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 1 || events[0].outcome != "success" || events[0].params["fleet_host_in_use"] != "hardware" ||
		events[0].params["fleet_host_kept"] != "hardware" || events[0].params["fleet_host_deleted"] != false {
		t.Fatalf("events %+v, want one success keeping the host for hardware", events)
	}
	if w.inventoryRows(t, dev) != 1 || w.fleet.calls != 0 || w.fleet.lookups != 0 {
		t.Fatalf("%d rows left, %d deletions, %d lookups; want the reference, none and none", w.inventoryRows(t, dev),
			w.fleet.calls, w.fleet.lookups)
	}
	if rounds := countRows(t, w.super, "SELECT unchanged_rounds FROM retention_inventory_hold WHERE device_id = $1", dev); rounds != 2 {
		t.Fatalf("%d unchanged rounds held, want 2", rounds)
	}
}

// TestRetentionPurgeRetiredInventoryHoldAnswerChanges (plan M10 amendment 2026-10-30, PDK-583 round 2): every change
// of the answer about a retired device's Fleet host records one event, also from a failure or none to a kept answer
// and from one kept answer to another; an unchanged kept answer records none.
func TestRetentionPurgeRetiredInventoryHoldAnswerChanges(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	w.inventoried(t, org, "retired", now.Add(-400*time.Second), "h2", 0, 0, 0)
	answer, checkErr := "none", errors.New("platform pool unavailable")
	w.retention.SetHostUsers(func(context.Context, uuid.UUID, string) (string, error) { return answer, checkErr })
	w.fleet.failing = map[ports.HostRef]error{"h2": fleetDown()}
	w.fleet.seen = map[ports.HostRef]time.Time{}

	type step struct {
		answer  string
		check   error
		seen    time.Time
		outcome string
		kept    any
	}
	for i, s := range []step{
		{answer: "none", check: checkErr, outcome: "failure"},
		{answer: "none", outcome: "failure"},
		{answer: "hardware", outcome: "success", kept: "hardware"},
		{answer: "hardware"},
		{answer: "none", seen: now.Add(-time.Second), outcome: "success", kept: "seen_recently"},
		{answer: "none", seen: now.Add(-2 * time.Second)},
		{answer: "hardware", outcome: "success", kept: "hardware"},
		{answer: "none", seen: now.Add(-8 * time.Second), outcome: "success"},
	} {
		answer, checkErr, w.fleet.seen["h2"] = s.answer, s.check, s.seen
		if i == 7 {
			w.fleet.failing = nil
		}
		before := len(w.inventoryPurgedEvents(t, org))
		w.passes(t, org, now, 1)
		events := w.inventoryPurgedEvents(t, org)
		if s.outcome == "" {
			if len(events) != before {
				t.Fatalf("pass %d recorded %+v, want no event", i+1, events[before:])
			}
			continue
		}
		if len(events) != before+1 {
			t.Fatalf("pass %d recorded %d events, want one", i+1, len(events)-before)
		}
		if ev := events[before]; ev.outcome != s.outcome || ev.params["fleet_host_kept"] != s.kept {
			t.Fatalf("pass %d event %+v, want %s keeping %v", i+1, ev, s.outcome, s.kept)
		}
	}
	if last := w.inventoryPurgedEvents(t, org)[5]; last.params["fleet_host_deleted"] != true || last.params["fleet_host_seen_at"] == nil {
		t.Fatalf("last event %+v, want the host deleted with its last check-in", last)
	}
	if held := countRows(t, w.super, "SELECT count(*) FROM retention_inventory_hold h JOIN device d ON d.id = h.device_id WHERE d.organization_id = $1", org); held != 0 {
		t.Fatalf("%d answers held after the host was deleted, want 0", held)
	}
}

// TestRetentionPurgeRetiredInventoryHoldNotice (plan M10 amendment 2026-10-30, PDK-583 round 2): after holdNotice
// unchanged rounds of a kept Fleet host the round records one device.inventory_host_kept notice and deletes nothing;
// later unchanged rounds record no further notice.
func TestRetentionPurgeRetiredInventoryHoldNotice(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	dev := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "h3", 2, 0, 0)
	w.retention.SetHostUsers(func(context.Context, uuid.UUID, string) (string, error) { return "hardware", nil })
	w.retention.SetHoldNotice(3)

	w.passes(t, org, now, 3)
	if notices := w.hostKeptNotices(t, org); len(notices) != 0 {
		t.Fatalf("notices after 2 unchanged rounds %v, want none", notices)
	}
	w.passes(t, org, now, 4)
	if notices := w.hostKeptNotices(t, org); len(notices) != 1 || notices[0] != "success/hardware/3" {
		t.Fatalf("notices after 6 unchanged rounds %v, want one success/hardware/3", notices)
	}
	if events := w.inventoryPurgedEvents(t, org); len(events) != 1 || w.inventoryRows(t, dev) != 1 || w.fleet.calls != 0 {
		t.Fatalf("%d purge events, %d rows left, %d deletions; want 1, the reference and none", len(events),
			w.inventoryRows(t, dev), w.fleet.calls)
	}
}

// TestRetentionPurgeRetiredInventorySeenRecently (plan M10 amendment 2026-10-30, PDK-583 round 2): a Fleet host that
// checked in after the device's retirement and within 7 retention days is kept with the device's reference; one seen
// only before the retirement or longer ago is deleted. A failing lookup keeps every row and records a failure.
func TestRetentionPurgeRetiredInventorySeenRecently(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	if _, err := w.super.Exec(context.Background(),
		"UPDATE organization_privacy_settings SET retired_inventory_days = 1 WHERE organization_id = $1", org); err != nil {
		t.Fatal(err)
	}
	inUse := w.inventoried(t, org, "retired", now.Add(-5*time.Second), "s1", 2, 1, 0)
	before := w.inventoried(t, org, "retired", now.Add(-5*time.Second).Add(time.Millisecond), "s2", 2, 0, 0)
	stale := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "s3", 1, 0, 0)
	failing := w.inventoried(t, org, "retired", now.Add(-399*time.Second), "s4", 1, 0, 0)
	w.fleet.seen = map[ports.HostRef]time.Time{
		"s1": now.Add(-time.Second), "s2": now.Add(-6 * time.Second), "s3": now.Add(-8 * time.Second),
	}
	w.fleet.seenErr = map[ports.HostRef]error{"s4": fleetDown()}

	n, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound())
	if !errors.Is(err, problem.UpstreamUnavailable) || n != 3 {
		t.Fatalf("purged %d (%v), want 3 and the failing lookup", n, err)
	}
	if fmt.Sprint(w.fleet.deleted) != "[s3 s2]" {
		t.Fatalf("Fleet hosts deleted %v, want [s3 s2]", w.fleet.deleted)
	}
	for dev, want := range map[uuid.UUID]int{inUse: 1, before: 0, stale: 0, failing: 2} {
		if got := w.inventoryRows(t, dev); got != want {
			t.Fatalf("device %s keeps %d rows, want %d", dev, got, want)
		}
	}
	byDevice := map[string]inventoryPurgedEvent{}
	for _, ev := range w.inventoryPurgedEvents(t, org) {
		byDevice[ev.target] = ev
	}
	if ev := byDevice[inUse.String()]; ev.outcome != "success" || ev.params["fleet_host_kept"] != "seen_recently" ||
		ev.params["fleet_host_in_use"] != "none" || ev.params["fleet_host_deleted"] != false || ev.params["fleet_host_seen_at"] == nil ||
		ev.params["software"] != float64(2) {
		t.Fatalf("event of the host in use %+v", ev)
	}
	if ev := byDevice[failing.String()]; ev.outcome != "failure" || ev.errorCode != "upstream_unavailable" ||
		ev.params["fleet_host_deleted"] != false {
		t.Fatalf("event of the failing lookup %+v", ev)
	}
}

// TestRetentionPurgeRetiredInventoryLookupTrips (plan M10 amendment 2026-10-30, PDK-583 round 2): an
// upstream_unavailable failure of the check-in lookup counts toward the round's Fleet breaker like a failed deletion.
func TestRetentionPurgeRetiredInventoryLookupTrips(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	w.fleet.seenErr = map[ports.HostRef]error{}
	for i := range 4 {
		ref := ports.HostRef("t" + string(rune('1'+i)))
		w.inventoried(t, org, "retired", now.Add(time.Duration(i-400)*time.Second), string(ref), 1, 0, 0)
		w.fleet.seenErr[ref] = fleetDown()
	}
	if _, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("pass: %v, want upstream_unavailable", err)
	}
	if w.fleet.lookups != 3 || w.fleet.calls != 0 {
		t.Fatalf("%d lookups, %d deletions; want 3 and none", w.fleet.lookups, w.fleet.calls)
	}
	if skips := w.retiredInventorySkips(t, org); len(skips) != 1 || skips[0] != "failure/upstream_unavailable" {
		t.Fatalf("skip events %v, want one failure/upstream_unavailable", skips)
	}
}

// failSelect makes every read of table by the worker in org's context raise until the test ends.
func (w retentionWorld) failSelect(t *testing.T, org uuid.UUID, table string) {
	t.Helper()
	w.failCommand(t, org, table, "SELECT")
}

// failCommand makes every command (SELECT, DELETE, ...) on table by the worker in org's context raise until the test
// ends or the returned function stops it.
func (w retentionWorld) failCommand(t *testing.T, org uuid.UUID, table, command string) func() {
	t.Helper()
	ctx := context.Background()
	name := "fail_" + strings.ToLower(command) + "_" + table + "_" + strings.ReplaceAll(org.String(), "-", "")
	if _, err := w.super.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %[1]s() RETURNS boolean LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'injected failure'; END $f$;
		CREATE POLICY %[1]s ON %[2]s AS RESTRICTIVE FOR %[4]s TO paddock_worker
		  USING (CASE WHEN current_setting('paddock.org_id', true) = '%[3]s' THEN %[1]s() ELSE true END);`,
		name, table, org, command)); err != nil {
		t.Fatal(err)
	}
	stop := func() {
		_, _ = w.super.Exec(ctx, fmt.Sprintf("DROP POLICY IF EXISTS %[1]s ON %[2]s; DROP FUNCTION IF EXISTS %[1]s();", name, table))
	}
	t.Cleanup(stop)
	return stop
}

// failFirstRead makes the next read of table by the worker in org's context raise; the reads after it succeed.
func (w retentionWorld) failFirstRead(t *testing.T, org uuid.UUID, table string) {
	t.Helper()
	ctx := context.Background()
	name := "fail_once_" + table + "_" + strings.ReplaceAll(org.String(), "-", "")
	if _, err := w.super.Exec(ctx, fmt.Sprintf(`
		CREATE SEQUENCE %[1]s;
		CREATE FUNCTION %[1]s() RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $f$
		  BEGIN IF nextval('%[1]s') = 1 THEN RAISE EXCEPTION 'injected read failure'; END IF; RETURN true; END $f$;
		CREATE POLICY %[1]s ON %[2]s AS RESTRICTIVE FOR SELECT TO paddock_worker
		  USING (CASE WHEN current_setting('paddock.org_id', true) = '%[3]s' THEN %[1]s() ELSE true END);`,
		name, table, org)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = w.super.Exec(ctx, fmt.Sprintf("DROP POLICY %[1]s ON %[2]s; DROP FUNCTION %[1]s(); DROP SEQUENCE %[1]s;", name, table))
	})
}

// TestRetentionPurgeRetiredInventoryHoldCheckFails (PDK-583 review 2, R2-1): an action never runs while the device
// still has a held answer. When the pass cannot read the held answer, it drops it before the action, so a failing action
// followed by the kept answer held before records one failure and then one success; when the drop fails, the device is
// skipped this round with the error, and an unchanged answer afterwards records nothing.
func TestRetentionPurgeRetiredInventoryHoldCheckFails(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		w := newRetentionWorld(t)
		now := time.Now().UTC()
		org := w.emptyOrganization(t)
		w.inventoried(t, org, "retired", now.Add(-400*time.Second), "hc1", 0, 0, 0)
		answer := "hardware"
		w.retention.SetHostUsers(func(context.Context, uuid.UUID, string) (string, error) { return answer, nil })

		w.passes(t, org, now, 1)
		w.failFirstRead(t, org, "retention_inventory_hold")
		answer, w.fleet.err = "none", fleetDown()
		w.passes(t, org, now, 1)
		answer, w.fleet.err = "hardware", nil
		w.passes(t, org, now, 2)
		var got []string
		for _, ev := range w.inventoryPurgedEvents(t, org) {
			got = append(got, fmt.Sprint(ev.outcome, "/", ev.params["fleet_host_kept"]))
		}
		if fmt.Sprint(got) != "[success/hardware failure/<nil> success/hardware]" {
			t.Fatalf("events %v, want success, failure, success keeping the host for hardware", got)
		}
	})
	t.Run("drop", func(t *testing.T) {
		w := newRetentionWorld(t)
		now := time.Now().UTC()
		org := w.emptyOrganization(t)
		dev := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "hc2", 0, 0, 0)
		answer := "hardware"
		w.retention.SetHostUsers(func(context.Context, uuid.UUID, string) (string, error) { return answer, nil })

		w.passes(t, org, now, 1)
		stop := w.failCommand(t, org, "retention_inventory_hold", "DELETE")
		answer = "none"
		if _, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err == nil {
			t.Fatal("pass succeeded, want the failed drop")
		}
		stop()
		answer = "hardware"
		w.passes(t, org, now, 1)
		if events := w.inventoryPurgedEvents(t, org); len(events) != 1 || w.fleet.calls != 0 || w.inventoryRows(t, dev) != 1 {
			t.Fatalf("events %+v, %d deletions, %d rows left; want the first success only, none and the reference", events,
				w.fleet.calls, w.inventoryRows(t, dev))
		}
	})
}

// TestRetentionPurgeRetiredInventoryHoldLookupFails (PDK-583 review 2, R2-2 and medium B): an upstream_unavailable
// failure of the check-in lookup of a held device keeps its held answer and its count of unchanged rounds, records no
// event and fails the pass; the lookup is bounded and counts toward the round's Fleet breaker.
func TestRetentionPurgeRetiredInventoryHoldLookupFails(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	w.fleet.seen = map[ports.HostRef]time.Time{}
	var devices []uuid.UUID
	for i := range 4 {
		ref := ports.HostRef("hl" + string(rune('1'+i)))
		devices = append(devices, w.inventoried(t, org, "retired", now.Add(time.Duration(i-400)*time.Second), string(ref), 0, 0, 0))
		w.fleet.seen[ref] = now.Add(-time.Second)
	}
	w.passes(t, org, now, 2)
	rounds := "SELECT unchanged_rounds FROM retention_inventory_hold WHERE device_id = $1"
	if got := countRows(t, w.super, rounds, devices[0]); got != 1 {
		t.Fatalf("%d unchanged rounds held, want 1", got)
	}

	w.fleet.seenErr = map[ports.HostRef]error{"hl1": fleetDown()}
	if _, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("pass: %v, want upstream_unavailable", err)
	}
	w.fleet.seenErr = nil
	w.passes(t, org, now, 1)
	if got := countRows(t, w.super, rounds, devices[0]); got != 2 {
		t.Fatalf("%d unchanged rounds held after a failed lookup, want 2", got)
	}
	if events := w.inventoryPurgedEvents(t, org); len(events) != 4 {
		t.Fatalf("%d purge events, want the 4 first sights only", len(events))
	}

	w.fleet.seenErr = map[ports.HostRef]error{"hl1": fleetDown(), "hl2": fleetDown(), "hl3": fleetDown(), "hl4": fleetDown()}
	lookups := w.fleet.lookups
	if _, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("pass: %v, want upstream_unavailable", err)
	}
	if w.fleet.lookups-lookups != 3 || w.fleet.unbounded != 0 || w.fleet.calls != 0 {
		t.Fatalf("%d lookups, %d without a deadline, %d deletions; want 3, none and none", w.fleet.lookups-lookups,
			w.fleet.unbounded, w.fleet.calls)
	}
	if skips := w.retiredInventorySkips(t, org); len(skips) != 1 || skips[0] != "failure/upstream_unavailable" {
		t.Fatalf("skip events %v, want one failure/upstream_unavailable", skips)
	}
	if events := w.inventoryPurgedEvents(t, org); len(events) != 4 {
		t.Fatalf("%d purge events, want the 4 first sights only", len(events))
	}
}

// TestRetentionPurgeRetiredInventoryHoldNewRetirement (PDK-583 review 2, medium A): an answer is held for the
// retirement it was recorded for; a device reactivated and retired again records its kept answer anew, even when it is
// the same.
func TestRetentionPurgeRetiredInventoryHoldNewRetirement(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.emptyOrganization(t)
	dev := w.inventoried(t, org, "retired", now.Add(-400*time.Second), "hr1", 0, 0, 0)
	w.retention.SetHostUsers(func(context.Context, uuid.UUID, string) (string, error) { return "hardware", nil })

	w.passes(t, org, now, 2)
	if _, err := w.super.Exec(context.Background(), "UPDATE device SET state_changed_at = $2 WHERE id = $1", dev,
		now.Add(-300*time.Second)); err != nil {
		t.Fatal(err)
	}
	w.passes(t, org, now, 2)
	events := w.inventoryPurgedEvents(t, org)
	if len(events) != 2 || events[1].outcome != "success" || events[1].params["fleet_host_kept"] != "hardware" {
		t.Fatalf("events %+v, want one success per retirement keeping the host for hardware", events)
	}
	if got := countRows(t, w.super, "SELECT unchanged_rounds FROM retention_inventory_hold WHERE device_id = $1", dev); got != 1 {
		t.Fatalf("%d unchanged rounds held, want 1 since the new retirement", got)
	}
}

// TestRetentionPurgeRetiredInventoryPassFailure (plan M10 amendment 2026-10-30, PDK-583 round 2): a pass that cannot
// load the organization's privacy settings or list its first page of retired devices records one retention.purged
// failure for the organization.
func TestRetentionPurgeRetiredInventoryPassFailure(t *testing.T) {
	for _, table := range []string{"organization_privacy_settings", "device"} {
		t.Run(table, func(t *testing.T) {
			w := newRetentionWorld(t)
			now := time.Now().UTC()
			org := w.emptyOrganization(t)
			w.inventoried(t, org, "retired", now.Add(-400*time.Second), "f1", 1, 0, 0)
			w.failSelect(t, org, table)

			if _, err := w.retention.PurgeRetiredInventory(systemCtx(org), now, app.NewRetentionRound()); err == nil {
				t.Fatal("pass succeeded, want the injected failure")
			}
			if skips := w.retiredInventorySkips(t, org); len(skips) != 1 || !strings.HasPrefix(skips[0], "failure/") {
				t.Fatalf("pass events %v, want one failure", skips)
			}
			if w.fleet.calls != 0 || len(w.inventoryPurgedEvents(t, org)) != 0 {
				t.Fatal("a device was attempted")
			}
		})
	}
}
