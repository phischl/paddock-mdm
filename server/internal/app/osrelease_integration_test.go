package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/ingest"
)

// TestCheckinFollowsOSRelease (PDK-695): the os-release a check-in reports replaces the stored ID and VERSION_ID once,
// records one device.os_release_changed with the old and new values only and recompiles the device; the same report
// again, a check-in without the field, an older heartbeat retried after a newer one and the heartbeats of a quarantined
// device record nothing and write nothing back.
func TestCheckinFollowsOSRelease(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	ctx := context.Background()
	if _, err := h.super.Exec(ctx, `UPDATE device SET os_release = '{"id":"ubuntu","version_id":"24.04","pretty_name":"Ubuntu 24.04 LTS"}' WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour)
	beat := func(osr map[string]string) {
		t.Helper()
		at = at.Add(time.Minute)
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at,
			OSRelease: osr, Health: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	events := func() int {
		t.Helper()
		var n int
		if err := h.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.os_release_changed'", org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	recompiles := func() int {
		t.Helper()
		var n int
		if err := h.super.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE payload ->> 'scope' = 'device' AND payload ->> 'id' = $1`, dev.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	beat(nil)
	beat(map[string]string{"id": "ubuntu", "version_id": "24.04"})
	if events() != 0 || recompiles() != 0 {
		t.Fatalf("no change recorded %d events, %d recompiles", events(), recompiles())
	}

	// The enrollment value is not validated: a huge or control-character old value is recorded as "".
	if _, err := h.super.Exec(ctx, `UPDATE device SET os_release = jsonb_build_object('id', 'ubuntu', 'version_id', repeat('9', 60000) || E'\n\x1b[31m') WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	upgraded := map[string]string{"id": "ubuntu", "version_id": "26.04"}
	beat(upgraded)
	beat(upgraded)
	beat(nil)
	if n := events(); n != 1 {
		t.Fatalf("%d device.os_release_changed, want 1", n)
	}
	if n := recompiles(); n != 1 {
		t.Fatalf("%d recompiles, want 1", n)
	}
	version := func() (v, pretty string) {
		t.Helper()
		var stored map[string]string
		if err := h.super.QueryRow(ctx, "SELECT os_release FROM device WHERE id = $1", dev).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		return stored["version_id"], stored["pretty_name"]
	}
	if v, pretty := version(); v != "26.04" || pretty != "" {
		t.Fatalf("stored os_release %s %q", v, pretty)
	}

	// An older heartbeat, retried after the newer one, must not write the old release back.
	if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at.Add(-30 * time.Minute),
		OSRelease: map[string]string{"id": "ubuntu", "version_id": "24.04"}, Health: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if v, _ := version(); v != "26.04" || events() != 1 || recompiles() != 1 {
		t.Fatalf("an older heartbeat changed %s, %d events, %d recompiles", v, events(), recompiles())
	}

	// A quarantined device (clone suspected) does not follow either.
	if _, err := h.super.Exec(ctx, "UPDATE device SET state = 'quarantined' WHERE id = $1", dev); err != nil {
		t.Fatal(err)
	}
	beat(map[string]string{"id": "ubuntu", "version_id": "28.04"})
	if v, _ := version(); v != "26.04" || events() != 1 || recompiles() != 1 {
		t.Fatalf("a quarantined device changed %s, %d events, %d recompiles", v, events(), recompiles())
	}
	if _, err := h.super.Exec(ctx, "UPDATE device SET state = 'active' WHERE id = $1", dev); err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	var target string
	if err := h.super.QueryRow(ctx, "SELECT params, target ->> 'id' FROM action WHERE organization_id = $1 AND code = 'device.os_release_changed'", org).Scan(&params, &target); err != nil {
		t.Fatal(err)
	}
	if len(params) != 4 || params["old_id"] != "ubuntu" || params["old_version_id"] != "" || params["new_id"] != "ubuntu" ||
		params["new_version_id"] != "26.04" || target != dev.String() {
		t.Fatalf("params %v target %s", params, target)
	}
}
