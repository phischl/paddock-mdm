package acceptance

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestDeviceOSReleaseFollowsCheckin (PDK-695, plan M13a decision 14): a check-in that reports another os-release than
// the enrollment's updates the device record and records exactly one device.os_release_changed with the old and new
// ID and VERSION_ID; the same report again, a check-in without the field and a garbage value change nothing and still
// succeed; another organization sees no event.
func TestDeviceOSReleaseFollowsCheckin(t *testing.T) {
	alice := login(t, env.Alice)
	d := activeDevice(t, alice, "", "osr-"+uniqueSuffix())
	ctx := testContext(t, 5*time.Minute)
	db := ownerDB(t)

	// The coalescing claim hb:<device> is deleted so that each check-in is materialized (as in TestClockDrift), and
	// checkin returns only once the worker wrote the heartbeat. The worker evaluates the os-release right after that,
	// in the same handler, and the stack's single worker handles heartbeats one at a time: once a further check-in is
	// materialized, the evaluation of the one before has finished, so a later negative assertion is not vacuous.
	requireSingleService(t, testContext(t, time.Minute), "paddock-worker")
	checkin := func(osr map[string]string) {
		t.Helper()
		var before *time.Time
		if err := db.QueryRow(ctx, "SELECT max(last_contact_at) FROM device_status WHERE device_id = $1", d.DeviceID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		valkeyCLI(t, "DEL hb:"+d.DeviceID)
		d.OSRelease = osr
		if _, res, err := d.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("check-in with os_release %v: %v %d %s", osr, err, res.Status, res.Body)
		}
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(250 * time.Millisecond) {
			var at *time.Time
			if err := db.QueryRow(ctx, "SELECT max(last_contact_at) FROM device_status WHERE device_id = $1", d.DeviceID).Scan(&at); err != nil {
				t.Fatal(err)
			}
			if at != nil && (before == nil || at.After(*before)) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("check-in with os_release %v not materialized within 30 s", osr)
			}
		}
	}
	stored := func(ctx context.Context) (id, version string) {
		t.Helper()
		if err := db.QueryRow(ctx, "SELECT os_release ->> 'id', os_release ->> 'version_id' FROM device WHERE id = $1", d.DeviceID).Scan(&id, &version); err != nil {
			t.Fatal(err)
		}
		return id, version
	}
	waitEvents := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
			polled := time.Now()
			n := eventCount(t, alice, "device.os_release_changed", d.DeviceID)
			if n == want {
				return
			}
			if n > want || polled.After(deadline) {
				t.Fatalf("%d device.os_release_changed for %s, want %d", n, d.DeviceID, want)
			}
		}
	}

	checkin(map[string]string{"id": "ubuntu", "version_id": "26.04"}) // the enrollment's value
	checkin(nil)
	checkin(nil) // the evaluation of the one before has finished
	if id, v := stored(ctx); id != "ubuntu" || v != "26.04" {
		t.Fatalf("stored os_release %s %s before any change", id, v)
	}
	waitEvents(0)

	checkin(map[string]string{"id": "ubuntu", "version_id": "28.04"})
	checkin(nil)
	waitEvents(1)
	if id, v := stored(ctx); id != "ubuntu" || v != "28.04" {
		t.Fatalf("stored os_release %s %s, want ubuntu 28.04", id, v)
	}
	events, err := alice.AuditEvents(ctx, "device.os_release_changed")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Target != nil && e.Target.ID == d.DeviceID &&
			(len(e.Params) != 4 || e.Params["old_version_id"] != "26.04" || e.Params["new_version_id"] != "28.04" ||
				e.Params["old_id"] != "ubuntu" || e.Params["new_id"] != "ubuntu" || e.Outcome != "success") {
			t.Fatalf("device.os_release_changed %+v", e)
		}
	}

	checkin(map[string]string{"id": "ubuntu", "version_id": "28.04"})
	checkin(map[string]string{"id": "ubuntu", "version_id": "x y\n"})
	checkin(nil)
	checkin(map[string]string{"id": "ubuntu", "version_id": "28.04"})
	checkin(nil)
	waitEvents(1)
	if id, v := stored(ctx); id != "ubuntu" || v != "28.04" {
		t.Fatalf("stored os_release %s %s after repeated and garbage reports", id, v)
	}
	if n := eventCount(t, login(t, env.Carol), "device.os_release_changed", d.DeviceID); n != 0 {
		t.Fatalf("carol sees %d device.os_release_changed of the acme device", n)
	}
}
