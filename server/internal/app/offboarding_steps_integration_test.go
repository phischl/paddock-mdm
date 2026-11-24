package app_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
)

// slicedJob is the deletion with a clock that moves 10 s at every reading: inside a round (a far deadline), every
// resumable step yields after exactly one unit of work.
func (w *offboardWorld) slicedJob() *app.Offboarding {
	var mu sync.Mutex
	clock := time.Now()
	return w.job().WithClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(10 * time.Second)
		return clock
	})
}

// unit runs one call of the current step inside a round and returns its error; a tombstone-style wait for older
// transactions is passed and the call repeated.
func (w *offboardWorld) unit(t *testing.T, job *app.Offboarding) error {
	t.Helper()
	for range 50 {
		done, err := job.AdvanceWithin(context.Background(), w.org, time.Now().Add(24*time.Hour))
		if done {
			t.Fatal("the deletion completed in a single step call")
		}
		if !errors.Is(err, app.ErrOffboardingWaiting) {
			return err
		}
		w.passCutoff(t)
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the step keeps waiting for older transactions")
	return nil
}

// expectYield runs one unit and fails unless the step yields, staying current.
func (w *offboardWorld) expectYield(t *testing.T, job *app.Offboarding, step string) {
	t.Helper()
	if err := w.unit(t, job); !isYield(err, step) {
		t.Fatalf("step %s: %v, want its yield", step, err)
	}
	if _, cur, code := w.state(t); cur != step || code != "" {
		t.Fatalf("after a yield at %s with %q, want %s", cur, code, step)
	}
}

// expectCompleted runs one unit and fails unless the step completes with organization.deletion_step_completed count
// want; it returns the event's params.
func (w *offboardWorld) expectCompleted(t *testing.T, job *app.Offboarding, step string, want int) map[string]any {
	t.Helper()
	if err := w.unit(t, job); err != nil {
		t.Fatalf("last unit of %s: %v", step, err)
	}
	next, _ := offboarding.Next(step)
	if _, cur, _ := w.state(t); cur != next {
		t.Fatalf("at %s after the last unit of %s, want %s", cur, step, next)
	}
	if c := w.cursor(t); c != "" {
		t.Fatalf("cursor %q after the step completed", c)
	}
	for _, ev := range w.stepEvents(t, audit.CodeOrganizationDeletionStepCompleted) {
		if ev.Params["step"] == step {
			if ev.Params["count"] != float64(want) {
				t.Fatalf("%s completed with count %v, want %d", step, ev.Params["count"], want)
			}
			return ev.Params
		}
	}
	t.Fatalf("no completion event of %s", step)
	return nil
}

// cursor is the stored resume position of the current step; "" for NULL.
func (w *offboardWorld) cursor(t *testing.T) string {
	t.Helper()
	var c *string
	if err := w.super.QueryRow(context.Background(), "SELECT offboarding_cursor FROM organization WHERE id = $1", w.org).Scan(&c); err != nil {
		t.Fatal(err)
	}
	if c == nil {
		return ""
	}
	return *c
}

// stored is the count of step stored on the organization.
func (w *offboardWorld) stored(t *testing.T, step string) int {
	t.Helper()
	return w.count(t, "SELECT coalesce((offboarding_counts ->> $2)::int, 0) FROM organization WHERE id = $1", w.org, step)
}

// TestOffboardingDevicesStepPages (PDK-1087 AC3, plan M17 amendment 2026-11-16 s points 1.1–1.3): 1 200 devices to
// hand over take the reissue as the first unit and 3 pages of 500 after it, each yielding at the slice and resuming at
// its cursor, also in a new job as after a worker crash. The reissue runs once: a disarm removed after it is not issued
// again, and its counts do not grow. A page repeated because its stored cursor was lost adds no record and no count.
// offboarded_device holds 1 200 rows, and the completion event reports 1 200.
func TestOffboardingDevicesStepPages(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	t.Cleanup(func() { w.exec(t, "DELETE FROM offboarded_device WHERE organization_id = $1", w.org) })
	handed := `SELECT count(*) FROM device WHERE organization_id = $1 AND uninstalled_at IS NULL
		AND state NOT IN ('pending', 'retired', 'rejected')`
	w.exec(t, `INSERT INTO device (id, organization_id, hostname, state)
		SELECT gen_random_uuid(), $1, 'page-' || g || '-' || left(gen_random_uuid()::text, 8), 'active'
		FROM generate_series(1, $2::int) g`, w.org, 1200-w.count(t, handed, w.org))
	if n := w.count(t, handed, w.org); n != 1200 {
		t.Fatalf("%d devices to hand over, want 1200", n)
	}
	w.requestDueWithDevices(t, job)
	w.advanceTo(t, job, offboarding.StepDevices)
	records := func() int {
		return w.count(t, "SELECT count(*) FROM offboarded_device WHERE organization_id = $1", w.org)
	}

	sliced := w.slicedJob()
	w.expectYield(t, sliced, offboarding.StepDevices)
	if c := w.cursor(t); c != uuid.Nil.String() || records() != 0 {
		t.Fatalf("after the reissue: cursor %q, %d records; want the nil UUID and none", c, records())
	}
	reissued, disarms := w.stored(t, "devices.uninstalls_reissued"), w.stored(t, "devices.disarms_issued")
	var probe uuid.UUID
	if err := w.super.QueryRow(context.Background(), `SELECT device_id FROM device_command WHERE organization_id = $1
		AND type = 'delete_self_lock' ORDER BY device_id DESC LIMIT 1`, w.org).Scan(&probe); err != nil {
		t.Fatalf("no disarm issued by the reissue: %v", err)
	}
	w.exec(t, "DELETE FROM device_command WHERE device_id = $1 AND type = 'delete_self_lock'", probe)

	w.expectYield(t, sliced, offboarding.StepDevices)
	first := w.cursor(t)
	if records() != 500 || w.stored(t, offboarding.StepDevices) != 500 {
		t.Fatalf("after page 1: %d records, %d stored; want 500", records(), w.stored(t, offboarding.StepDevices))
	}
	restarted := w.slicedJob()
	w.expectYield(t, restarted, offboarding.StepDevices)
	if records() != 1000 || w.stored(t, offboarding.StepDevices) != 1000 || w.cursor(t) <= first {
		t.Fatalf("after page 2 in a new job: %d records, %d stored, cursor %s after %s", records(),
			w.stored(t, offboarding.StepDevices), w.cursor(t), first)
	}
	second := w.cursor(t)
	w.exec(t, "UPDATE organization SET offboarding_cursor = $2 WHERE id = $1", w.org, first)
	w.expectYield(t, restarted, offboarding.StepDevices)
	if records() != 1000 || w.stored(t, offboarding.StepDevices) != 1000 || w.cursor(t) != second {
		t.Fatalf("a repeated page 2: %d records, %d stored, cursor %s; want 1000, 1000 and %s", records(),
			w.stored(t, offboarding.StepDevices), w.cursor(t), second)
	}
	params := w.expectCompleted(t, restarted, offboarding.StepDevices, 1200)
	if records() != 1200 {
		t.Fatalf("%d offboarded devices, want 1200", records())
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1 AND type = 'delete_self_lock'", probe); n != 0 {
		t.Fatalf("the removed disarm was issued again (%d): the reissue ran more than once", n)
	}
	if params["uninstalls_reissued"] != float64(reissued) || params["disarms_issued"] != float64(disarms) || disarms < 1200 {
		t.Fatalf("completion params %v; want the reissue's counts %d and %d of its one run", params, reissued, disarms)
	}
}

// TestOffboardingFleetStepPages (PDK-1087 AC3): 450 Fleet hosts take 3 pages of at most 200, resumed at the last host
// of the stored page; a host two devices reference is listed and deleted once.
func TestOffboardingFleetStepPages(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	w.exec(t, `WITH d AS (INSERT INTO device (id, organization_id, hostname, state)
		SELECT gen_random_uuid(), $1, 'fleet-' || g, 'retired' FROM generate_series(1, 450) g RETURNING id, hostname)
		INSERT INTO device_inventory_ref (device_id, organization_id, external_id)
		SELECT id, $1, CASE WHEN hostname IN ('fleet-1', 'fleet-2') THEN 'fl-shared' ELSE 'fl-' || hostname END FROM d`, w.org)
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepFleet)
	hosts := 449 + 1

	sliced := w.slicedJob()
	w.expectYield(t, sliced, offboarding.StepFleet)
	if len(w.fleet.deleted) != 200 || w.stored(t, offboarding.StepFleet) != 200 || w.cursor(t) != w.fleet.deleted[199] {
		t.Fatalf("after page 1: %d deleted, %d stored, cursor %q", len(w.fleet.deleted), w.stored(t, offboarding.StepFleet), w.cursor(t))
	}
	w.expectYield(t, w.slicedJob(), offboarding.StepFleet)
	w.expectCompleted(t, sliced, offboarding.StepFleet, hosts)
	seen := map[string]int{}
	for _, h := range w.fleet.deleted {
		seen[h]++
	}
	if len(w.fleet.deleted) != hosts || len(seen) != hosts || seen["fl-shared"] != 1 {
		t.Fatalf("%d deletions of %d hosts (shared host %d times), want %d once each", len(w.fleet.deleted), len(seen),
			seen["fl-shared"], hosts)
	}
	if !w.fleet.hosts["host-"+w.otherDevice.String()] {
		t.Fatal("the other organization's host was deleted")
	}
}

// TestOffboardingObjectsStepYields (PDK-1087 AC3, amendment 2026-11-16 s point 1.4): a purge that stops at the slice
// makes the step store its count and yield; the next call lists again from the first prefix and the completion event
// reports every object once.
func TestOffboardingObjectsStepYields(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	for i := range 25 {
		w.bundles.objects[fmt.Sprintf("org/%s/bulk/%02d", w.org, i)] = true
	}
	w.bundles.page, w.escrow.page = 10, 10
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepObjects)

	sliced := w.slicedJob()
	w.expectYield(t, sliced, offboarding.StepObjects)
	if w.stored(t, offboarding.StepObjects) != 10 || w.cursor(t) != "" {
		t.Fatalf("after one page: %d stored, cursor %q", w.stored(t, offboarding.StepObjects), w.cursor(t))
	}
	w.expectYield(t, w.slicedJob(), offboarding.StepObjects)
	w.expectCompleted(t, sliced, offboarding.StepObjects, 2+25+1+1)
	if len(w.bundles.objects) != 2 || len(w.escrow.objects) != 1 {
		t.Fatalf("objects left: bundles %v, escrow %v", w.bundles.objects, w.escrow.objects)
	}
}

// TestOffboardingValkeyStepPages (PDK-1087 AC3): the devices' keys go in pages of 2 000 devices, resumed after the
// stored device; only the last, shorter page carries the organization's token hashes and escrow IDs, and the
// completion event counts every key once.
func TestOffboardingValkeyStepPages(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	w.exec(t, `INSERT INTO device (id, organization_id, hostname, state)
		SELECT gen_random_uuid(), $1, 'vk-' || g, 'retired' FROM generate_series(1, 4100) g`, w.org)
	w.exec(t, `INSERT INTO enrollment_token (id, organization_id, name, secret_sha256, auto_approve, max_uses, expires_at, created_by)
		VALUES (gen_random_uuid(), $1, 'pdk-1087', $2, false, 1, now() + interval '1 day', gen_random_uuid())`, w.org,
		[]byte(uuid.NewString()))
	devices := w.count(t, "SELECT count(*) FROM device WHERE organization_id = $1", w.org)
	w.cache.perDevice = true
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepValkey)

	sliced := w.slicedJob()
	w.expectYield(t, sliced, offboarding.StepValkey)
	if w.stored(t, offboarding.StepValkey) != 6+2000 || w.cursor(t) == "" {
		t.Fatalf("after page 1: %d stored, cursor %q", w.stored(t, offboarding.StepValkey), w.cursor(t))
	}
	w.expectYield(t, w.slicedJob(), offboarding.StepValkey)
	w.expectCompleted(t, sliced, offboarding.StepValkey, 6+devices)
	calls := w.cache.calls
	if len(calls) != 3 || calls[0] != (valkeyCall{devices: 2000}) || calls[1] != (valkeyCall{devices: 2000}) ||
		calls[2] != (valkeyCall{devices: devices - 4000, refs: true}) {
		t.Fatalf("DeleteOrganization calls %+v, want two full pages and a last one with the token hashes", calls)
	}
}

// failedEvents are the organization.deletion_step_failed events of the organization with their error codes.
func (w *offboardWorld) failedCodes(t *testing.T) []string {
	t.Helper()
	var codes []string
	for _, ev := range w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed) {
		codes = append(codes, ev.Params["error_code"].(string))
	}
	return codes
}

// TestOffboardingFailureRecordedOncePerCode (PDK-1087 AC4, main §32, amendment 2026-11-16 s point 3): a unit failing
// after two stored units keeps their count. The same code after intermediate progress, which cleared the stored code,
// records no second organization.deletion_step_failed; A → B → A records two events. An organization whose code the
// migration's backfill counted as recorded records nothing more for it.
func TestOffboardingFailureRecordedOncePerCode(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	for i := range 30 {
		w.bundles.objects[fmt.Sprintf("org/%s/bulk/%02d", w.org, i)] = true
	}
	w.bundles.page = 10
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepObjects)
	sliced := w.slicedJob()
	w.expectYield(t, sliced, offboarding.StepObjects)
	w.expectYield(t, sliced, offboarding.StepObjects)

	down := errors.New("connection refused")
	w.bundles.err = down
	var oe *app.OffboardingError
	if err := w.unit(t, sliced); !errors.As(err, &oe) || oe.Code != offboarding.ErrorObjectStoreUnavailable {
		t.Fatalf("unit with the store down: %v", err)
	}
	if n := w.stored(t, offboarding.StepObjects); n != 20 {
		t.Fatalf("%d objects stored after two units and a failure, want 20", n)
	}
	if codes := w.failedCodes(t); len(codes) != 1 || codes[0] != offboarding.ErrorObjectStoreUnavailable {
		t.Fatalf("failure events %v", codes)
	}

	w.bundles.err = nil
	w.expectYield(t, sliced, offboarding.StepObjects)
	w.bundles.err = down
	if err := w.unit(t, sliced); err == nil {
		t.Fatal("the unit succeeded with the store down")
	}
	if _, _, code := w.state(t); code != offboarding.ErrorObjectStoreUnavailable {
		t.Fatalf("stored code %q, want the gauge's object_store_unavailable", code)
	}
	if codes := w.failedCodes(t); len(codes) != 1 {
		t.Fatalf("failure events %v after the same code came back after progress, want still one", codes)
	}

	w.bundles.err = nil
	w.escrow.retain["org/"+w.org.String()+"/devices/d/luks-header/1"] = true
	if _, err := job.Advance(context.Background(), w.org); !errors.As(err, &oe) || oe.Code != offboarding.ErrorObjectRetained {
		t.Fatalf("Advance with a retained version: %v", err)
	}
	w.escrow.err = down
	if _, err := job.Advance(context.Background(), w.org); !errors.As(err, &oe) || oe.Code != offboarding.ErrorObjectStoreUnavailable {
		t.Fatalf("Advance with escrow down: %v", err)
	}
	codes := w.failedCodes(t)
	if len(codes) != 2 || codes[1] != offboarding.ErrorObjectRetained {
		t.Fatalf("failure events %v after A → B → A, want 2", codes)
	}
	var recorded []string
	if err := w.super.QueryRow(context.Background(), "SELECT offboarding_failures_recorded FROM organization WHERE id = $1",
		w.org).Scan(&recorded); err != nil || len(recorded) != 2 {
		t.Fatalf("recorded codes %v, %v", recorded, err)
	}

	upgraded := newOffboardWorld(t)
	ujob := upgraded.job()
	upgraded.requestDue(t, ujob)
	upgraded.advanceTo(t, ujob, offboarding.StepObjects)
	upgraded.exec(t, `UPDATE organization SET offboarding_error_code = $2, offboarding_failures_recorded = ARRAY[$2]
		WHERE id = $1`, upgraded.org, offboarding.ErrorObjectStoreUnavailable)
	upgraded.bundles.err = down
	for range 2 {
		if _, err := ujob.Advance(context.Background(), upgraded.org); !errors.As(err, &oe) {
			t.Fatalf("Advance of the upgraded organization: %v", err)
		}
	}
	if codes := upgraded.failedCodes(t); len(codes) != 0 {
		t.Fatalf("failure events %v for a code the backfill counted as recorded", codes)
	}
}
