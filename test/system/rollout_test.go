package system

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/portal"
)

// TestRolloutAutoStop is gate S5 of plan M2b §8: a broken release rolled out to all devices with
// failure_threshold_min 1 halts after the first failure (audit agent_rollout.halted by the system), and a second
// device that checks in afterwards is never offered it. It needs both VMs (PADDOCK_SYSTEM_VMS=all).
func TestRolloutAutoStop(t *testing.T) {
	names := vms(t)
	if len(names) < 2 {
		t.Skip("gate S5 needs both VMs: make system-test VM=all")
	}
	s := newStack(t)
	first, second := newVM(t, s.root, names[0]), newVM(t, s.root, names[1])
	first.Fresh()
	second.Fresh()
	a := Install(t, s, first, debDir(s))
	b := Install(t, s, second, debDir(s))
	a.WaitEvent(t, "device.bundle_applied", 5*time.Minute, nil)
	b.WaitEvent(t, "device.bundle_applied", 5*time.Minute, nil)
	before := b.AgentVersion() // the packaged version, or a release of an earlier completed rollout
	b.Must("sudo systemctl stop paddock-supervisor")

	// failure_threshold_percent 0: the development stack holds many simulated devices of the acceptance gates, which
	// count as eligible; with the default 2 % the threshold would exceed one failure. The single wave lasts an hour,
	// so the rollout is still running (not completed) when the failure arrives.
	v := version(6, "autostop")
	s.Release(v, []string{"paddock_testbroken_selftest"}, "--failure-threshold-min", "1", "--failure-threshold-percent", "0",
		"--min-wave-minutes", "60")
	a.WaitEvent(t, "device.agent_update_failed", 10*time.Minute, func(p map[string]any) bool { return p["version"] == v })

	idx, err := portal.NewAuditIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	var halted []string
	Until(t, "rollout halted by the worker", 3*time.Minute, 5*time.Second, nil, func() bool {
		events, err := idx.Events(context.Background(), portal.PlatformOrganization,
			"code = 'agent_rollout.halted' AND target->>'id' = $1", v)
		if err != nil {
			t.Fatal(err)
		}
		halted = halted[:0]
		for _, e := range events {
			halted = append(halted, e.ActorDisplay+"/"+e.Outcome)
		}
		return len(events) > 0
	})
	if len(halted) != 1 || halted[0] != "worker/success" || s.Rollout(v) != "halted" {
		t.Fatalf("halt events %v, rollout %s; want exactly one successful halt by the worker", halted, s.Rollout(v))
	}

	// The second device checks in only now (agent start); it must not be offered the halted release.
	haltedAt := time.Now()
	b.Must("sudo systemctl start paddock-supervisor")
	Until(t, "second device checked in", 3*time.Minute, 5*time.Second, nil, func() bool {
		out := b.Must("sudo stat -c %Y /run/paddock/last-checkin 2>/dev/null || echo 0")
		var sec int64
		_, _ = fmt.Sscan(out, &sec)
		return sec >= haltedAt.Unix()
	})
	time.Sleep(30 * time.Second) // a staged offer would be downloaded and handed over by now
	journal := b.Must("sudo journalctl -u paddock-supervisor --since @" + strconv.FormatInt(haltedAt.Unix(), 10) + " --no-pager")
	if strings.Contains(journal, v) || b.AgentVersion() != before || b.Must("sudo ls -A /var/lib/paddock/staging 2>/dev/null || true") != "" {
		t.Fatalf("the second device was offered %s:\n%s", v, journal)
	}
	// Earlier completed rollouts of the development stack may have offered other releases; only v matters here.
	for _, code := range []string{"device.agent_updated", "device.agent_update_failed", "device.agent_rolled_back"} {
		for _, e := range s.Events(code, b.ID) {
			if e.Params["version"] == v {
				t.Fatalf("second device reported %s for %s: %v", code, v, e.Params)
			}
		}
	}
}
