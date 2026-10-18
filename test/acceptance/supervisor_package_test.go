package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestSupervisorPackage is gate A7 of plan M8d (AC7, server part): once the rollout of a release with a
// paddock-supervisor package completed, the v2 bundle of an active device with a semantic agent version carries the
// package in agent.supervisor_packages; while the rollout is halted it does not. The device's reports are audited as
// device.supervisor_updated (outcome updated) and device.supervisor_update_failed (rolled_back), and neither counts
// as a failure of the rollout.
func TestSupervisorPackage(t *testing.T) {
	root, alice := login(t, env.PlatformAdmin), login(t, env.Alice)
	haltRunningRollouts(t, root)
	t.Cleanup(func() { haltRunningRollouts(t, root) })
	v := gateRelease(t, root, true, false)
	deb := []byte("!<arch>\ngate supervisor " + v)
	expectStatus(t, uploadPackage(t, root, v, "paddock-supervisor", deb, minisign.Sign(releaseKey(t), deb)), http.StatusOK, "")
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/publish", nil), http.StatusOK, "")
	d := v2Device(t, alice, "", bundle.SchemaVersion, bundle.SchemaVersion2)
	d.Arch = protocol.ArchAMD64

	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{
		"waves": []int{100}, "min_wave_minutes": 1, "failure_threshold_min": 1000, "failure_threshold_percent": 100,
	}), http.StatusCreated, "")
	// The gate's release is not a real agent: it must not stay the current release of real devices.
	t.Cleanup(func() {
		if rolloutStatus(t, root, v) != "halted" {
			expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout/halt", nil), http.StatusOK, "")
		}
	})
	waitRolloutStatus(t, root, v, "completed", 4*time.Minute)
	sum := sha256.Sum256(deb)
	want := bundle.PackageRef{Version: v, URLPath: "packages/" + v + "/paddock-supervisor_" + v + "_amd64.deb", SHA256: hex.EncodeToString(sum[:])}
	b := latestBundle(t, d, 3*time.Minute, func(b *bundle.Bundle) bool { return b.Agent.SupervisorPackages["amd64"] == want })
	if got := b.Agent.SupervisorPackages; len(got) != 1 || got["amd64"] != want {
		t.Fatalf("supervisor_packages %+v, want amd64 %+v", got, want)
	}

	report := func(seq int64, outcome string) {
		t.Helper()
		data, _ := json.Marshal(map[string]string{"version": v, "from_version": "0.1.0", "outcome": outcome})
		r, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: seq, Type: protocol.EventAgentSupervisorUpdated,
			OccurredAt: time.Now(), Data: data}})
		if err != nil || r.Status != http.StatusAccepted {
			t.Fatalf("events: %v %d", err, r.Status)
		}
	}
	report(1, protocol.SupervisorOutcomeRolledBack)
	report(2, protocol.SupervisorOutcomeUpdated)
	idx, acme := auditIndex(t), orgOf(t, alice)
	failed := expectOneIndexEvent(t, idx, acme, "code = 'device.supervisor_update_failed' AND target->>'id' = $1", d.DeviceID, "device.supervisor_update_failed", "success", time.Minute)
	if failed.Params["outcome"] != "rolled_back" || failed.Params["version"] != v {
		t.Fatalf("device.supervisor_update_failed params %v", failed.Params)
	}
	updated := expectOneIndexEvent(t, idx, acme, "code = 'device.supervisor_updated' AND target->>'id' = $1", d.DeviceID, "device.supervisor_updated", "success", time.Minute)
	if updated.Params["outcome"] != "updated" {
		t.Fatalf("device.supervisor_updated params %v", updated.Params)
	}
	if status := rolloutStatus(t, root, v); status != "completed" {
		t.Fatalf("rollout %s after supervisor reports, want completed (supervisor outcomes never count)", status)
	}

	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout/halt", nil), http.StatusOK, "")
	b = latestBundle(t, d, 3*time.Minute, func(b *bundle.Bundle) bool { return len(b.Agent.SupervisorPackages) == 0 })
	if len(b.Agent.SupervisorPackages) != 0 {
		t.Fatalf("halted release still in the bundle: %+v", b.Agent.SupervisorPackages)
	}
}
