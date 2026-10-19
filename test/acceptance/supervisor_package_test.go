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
// device.supervisor_updated (outcome updated) and device.supervisor_update_failed. Per decision 33 as amended
// (§15.2), a failure of the local health (rolled_back) counts toward the rollout's failure threshold and halts it,
// while a rollback only because the server was unreachable (rolled_back_unreachable) is audited but never counts.
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
		"waves": []int{100}, "min_wave_minutes": 1, "failure_threshold_min": 1, "failure_threshold_percent": 0,
	}), http.StatusCreated, "")
	// The gate's release is not a real agent: it must not stay the current release of real devices.
	t.Cleanup(func() { retractRelease(t, root, d, v) })
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
	idx, acme := auditIndex(t), orgOf(t, alice)
	report(1, protocol.SupervisorOutcomeUpdated)
	updated := expectOneIndexEvent(t, idx, acme, "code = 'device.supervisor_updated' AND target->>'id' = $1", d.DeviceID, "device.supervisor_updated", "success", time.Minute)
	if updated.Params["outcome"] != "updated" || updated.Params["version"] != v {
		t.Fatalf("device.supervisor_updated params %v", updated.Params)
	}
	if status := rolloutStatus(t, root, v); status != "completed" {
		t.Fatalf("rollout %s after a successful supervisor update, want completed", status)
	}

	// A rollback because the server was unreachable is audited but is no failure of the release.
	report(2, protocol.SupervisorOutcomeRolledBackUnreachable)
	unreachable := expectOneIndexEvent(t, idx, acme, "code = 'device.supervisor_update_failed' AND params->>'outcome' = 'rolled_back_unreachable' AND target->>'id' = $1",
		d.DeviceID, "device.supervisor_update_failed", "success", time.Minute)
	if unreachable.Params["version"] != v {
		t.Fatalf("device.supervisor_update_failed (unreachable) params %v", unreachable.Params)
	}
	if status := rolloutStatus(t, root, v); status != "completed" {
		t.Fatalf("rollout %s after rolled_back_unreachable, want completed (a server outage never counts)", status)
	}

	// A failed local health counts toward the threshold (1): the worker halts the release.
	report(3, protocol.SupervisorOutcomeRolledBack)
	failed := expectOneIndexEvent(t, idx, acme, "code = 'device.supervisor_update_failed' AND params->>'outcome' = 'rolled_back' AND target->>'id' = $1",
		d.DeviceID, "device.supervisor_update_failed", "success", time.Minute)
	if failed.Params["version"] != v {
		t.Fatalf("device.supervisor_update_failed params %v", failed.Params)
	}
	waitRolloutStatus(t, root, v, "halted", 3*time.Minute)

	b = latestBundle(t, d, 3*time.Minute, func(b *bundle.Bundle) bool { return len(b.Agent.SupervisorPackages) == 0 })
	if len(b.Agent.SupervisorPackages) != 0 {
		t.Fatalf("halted release still in the bundle: %+v", b.Agent.SupervisorPackages)
	}
}
