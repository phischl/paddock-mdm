package system

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// offerWait bounds the wait for the worker's rollout round to publish the offer: several rounds of 60 s plus margin.
const offerWait = 5 * time.Minute

// requestUpdate asks the device to install the offered release now and waits for its report.
func requestUpdate(t *testing.T, s *Stack, d *Device, version string) {
	t.Helper()
	path := "/api/v1/devices/" + d.ID + "/update-agent"
	// The offer reaches Valkey only through the worker's rollout round (60 s interval, which takes most of that on a
	// long-lived stack, PDK-890), so the request may meet a 409 until the first round after the release was written.
	var last portal.Response
	Until(t, "an agent release is offered to "+d.ID, offerWait, 10*time.Second, nil, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		res, err := s.session().Do(ctx, http.MethodPost, path, nil)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		last = res
		return res.Status != http.StatusConflict || !strings.Contains(string(res.Body), "no agent release is being offered")
	})
	if last.Status != http.StatusOK {
		t.Fatalf("POST %s: HTTP %d (want %d) %s", path, last.Status, http.StatusOK, last.Body)
	}
	d.WaitEvent(t, "device.agent_updated", 10*time.Minute, func(p map[string]any) bool { return p["version"] == version })
	if got := d.AgentVersion(); got != version {
		t.Fatalf("paddockd version %q after the update, want %s", got, version)
	}
}

// TestUpdateNow is gate S-UP1 of plan M8d (AC6): a release whose first wave excludes the device is not installed
// within two check-ins; *Update agent now* installs it (self-test, probation and the switch as usual) and the
// device reports device.agent_updated with the release. A device in bucket 0 (no wave can exclude it) is held back by
// the manual policy instead. The VMs share one release and the organization's policy: the first wave stops below
// every VM's bucket, and the policy is manual for all when one VM is in bucket 0.
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
		if _, err := strconv.Atoi(out); err != nil {
			t.Fatalf("bucket %q: %v", out, err)
		}
		d.Gate(t, "S-UP1")
		d.Share("S-UP1 bucket", out)
		buckets := func() (first int, manual bool) {
			first = 100
			for _, b := range d.Shared("S-UP1 bucket") {
				switch n, _ := strconv.Atoi(b); {
				case n == 0:
					manual = true
				case n < first:
					first = n
				}
			}
			if first == 100 {
				first = 1
			}
			return first, manual
		}
		policy := d.Together(t, "S-UP1", "policy", func() string {
			if _, manual := buckets(); !manual {
				return "automatic"
			}
			setUpdatePolicy(t, s, "manual")
			d.AfterAll(t, func(t *testing.T) { setUpdatePolicy(t, s, "automatic") })
			return "manual"
		})
		if policy == "manual" {
			for range 2 {
				d.Checkin()
				time.Sleep(20 * time.Second)
			}
		}
		v := d.Together(t, "S-UP1", "release", func() string {
			first, _ := buckets()
			v := version(8, "now")
			s.Release(t, v, nil, "--waves", strconv.Itoa(first)+",100", "--min-wave-minutes", "60")
			d.AfterAll(t, func(t *testing.T) { retractRelease(t, v) })
			return v
		})
		for range 2 {
			d.Checkin()
			time.Sleep(30 * time.Second)
		}
		if got := d.AgentVersion(); got != before {
			t.Fatalf("the device outside the wave installed %s", got)
		}
		requestUpdate(t, s, d, v)
		// Each 409 retry of requestUpdate is audited as a failure under the same code (one event per attempt), so only
		// the successful requests count: exactly one.
		succeeded := 0
		for _, e := range s.Events(t, "device.agent_update_requested", d.ID) {
			if e.Outcome == "success" {
				succeeded++
			}
		}
		if succeeded != 1 {
			t.Fatalf("%d successful device.agent_update_requested events, want 1", succeeded)
		}
	})
}
