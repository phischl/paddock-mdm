package system

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// setUpdatePolicy sets acme's agent update policy and keeps every other update setting.
func setUpdatePolicy(t *testing.T, s *Stack, policy string) {
	t.Helper()
	var set map[string]any
	if err := json.Unmarshal(s.Call(t, http.MethodGet, "/api/v1/settings/updates", nil, http.StatusOK).Body, &set); err != nil {
		t.Fatal(err)
	}
	delete(set, "updated_at")
	set["agent_update_policy"] = policy
	s.Call(t, http.MethodPut, "/api/v1/settings/updates", set, http.StatusOK)
}

// TestUpdatePolicyManual is gate S-UP3 of plan M8d (AC5): with the organization on manual, a completed rollout of a
// newer release is offered but not installed within three check-ins, and the agent's journal names the policy;
// *Update agent now* installs it. The VMs share the organization's policy and one release.
func TestUpdatePolicyManual(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, nil)
		d.Gate(t, "S-UP3")
		d.Together(t, "S-UP3", "policy", func() string {
			setUpdatePolicy(t, s, "manual")
			d.AfterAll(t, func(t *testing.T) { setUpdatePolicy(t, s, "automatic") })
			return ""
		})
		// The settings change recompiles every device; two check-ins apply the bundle with update_policy manual.
		for range 2 {
			d.Checkin()
			time.Sleep(20 * time.Second)
		}
		before := d.AgentVersion()
		start := time.Now()
		v := d.Together(t, "S-UP3", "release", func() string {
			v := version(7, "manual")
			// The gate needs a completed rollout; threshold 1 lets its retraction halt it by a failure report.
			s.Release(t, v, nil, "--min-wave-minutes", "1", "--failure-threshold-min", "1", "--failure-threshold-percent", "0")
			d.AfterAll(t, func(t *testing.T) { retractRelease(t, v) })
			return v
		})
		Until(t, "rollout of "+v+" completed", 5*time.Minute, 10*time.Second, nil, func() bool { return s.Rollout(t, v) == "completed" })
		for range 3 {
			d.Checkin()
			time.Sleep(20 * time.Second)
		}
		journal := d.Must("sudo journalctl -u paddock-supervisor --since @" + strconv.FormatInt(start.Unix(), 10) + " --no-pager")
		if !strings.Contains(journal, "agent update offer ignored by the organization's policy") {
			t.Fatalf("no policy line in the journal:\n%s", journal)
		}
		if d.AgentVersion() != before || d.Must("sudo ls -A /var/lib/paddock/staging 2>/dev/null || true") != "" {
			t.Fatalf("%s was installed or staged under the manual policy (running %s)", v, d.AgentVersion())
		}
		// Update agent now installs it regardless of the policy (PDK-226).
		requestUpdate(t, s, d, v)
	})
}
