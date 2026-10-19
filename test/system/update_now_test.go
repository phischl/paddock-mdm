package system

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// requestUpdate asks the device to install the offered release now and waits for its report.
func requestUpdate(t *testing.T, s *Stack, d *Device, version string) {
	t.Helper()
	s.Call(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/update-agent", nil, http.StatusOK)
	d.WaitEvent(t, "device.agent_updated", 10*time.Minute, func(p map[string]any) bool { return p["version"] == version })
	if got := d.AgentVersion(); got != version {
		t.Fatalf("paddockd version %q after the update, want %s", got, version)
	}
}

// TestUpdateNow is gate S-UP1 of plan M8d (AC6): a release whose first wave excludes the device is not installed
// within two check-ins; *Update agent now* installs it (self-test, probation and the switch as usual) and the
// device reports device.agent_updated with the release. A device in bucket 0 (no wave can exclude it) is held back by
// the manual policy instead.
func TestUpdateNow(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, nil)
		before := d.AgentVersion()
		out, err := paddockSQL(context.Background(), fmt.Sprintf("SELECT paddock_rollout_bucket('%s')", d.ID))
		if err != nil {
			t.Fatal(err)
		}
		bucket, err := strconv.Atoi(out)
		if err != nil {
			t.Fatalf("bucket %q: %v", out, err)
		}
		first := bucket
		if bucket == 0 {
			first = 1
			setUpdatePolicy(t, s, "manual")
			t.Cleanup(func() { setUpdatePolicy(t, s, "automatic") })
			for range 2 {
				d.Checkin()
				time.Sleep(20 * time.Second)
			}
		}
		v := version(8, "now")
		s.Release(t, v, nil, "--waves", strconv.Itoa(first)+",100", "--min-wave-minutes", "60")
		t.Cleanup(func() { retractRelease(t, v) })
		for range 2 {
			d.Checkin()
			time.Sleep(30 * time.Second)
		}
		if got := d.AgentVersion(); got != before {
			t.Fatalf("the device outside the wave installed %s", got)
		}
		requestUpdate(t, s, d, v)
		if events := s.Events(t, "device.agent_update_requested", d.ID); len(events) != 1 {
			t.Fatalf("%d device.agent_update_requested events", len(events))
		}
	})
}
