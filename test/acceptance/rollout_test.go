package acceptance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// rolloutStatus reads the rollout status of version ("" without rollout).
func rolloutStatus(t *testing.T, root *env.Portal, version string) string {
	t.Helper()
	res := call(t, root, http.MethodGet, "/api/platform/v1/agent-releases/"+version, nil)
	expectStatus(t, res, http.StatusOK, "")
	var d struct {
		Rollout *struct {
			Status string `json:"status"`
		} `json:"rollout"`
	}
	if err := res.JSON(&d); err != nil {
		t.Fatal(err)
	}
	if d.Rollout == nil {
		return ""
	}
	return d.Rollout.Status
}

func waitRolloutStatus(t *testing.T, root *env.Portal, version, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := rolloutStatus(t, root, version)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rollout of %s is %q after %s, want %q", version, got, timeout, want)
		}
		time.Sleep(2 * time.Second)
	}
}

// reportUpdateFailed sends agent.update_failed for version as the device's event seq.
func reportUpdateFailed(t *testing.T, d *devicesim.Device, version string, seq int64) {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"version": version, "from_version": "0.0.0-devicesim", "outcome": "update_failed"})
	res, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{
		EventSeq: seq, Type: protocol.EventAgentUpdateFailed, OccurredAt: time.Now(), Data: data,
	}})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("events: %v HTTP %d %s", err, res.Status, res.Body)
	}
}

// TestCurrentReleaseAutoStop is the integration test of plan M2.1 decision 1: a completed rollout (the current
// release) halts when a device reports agent.update_failed, and the device is no longer offered the release.
func TestCurrentReleaseAutoStop(t *testing.T) {
	root, alice := login(t, env.PlatformAdmin), login(t, env.Alice)
	haltRunningRollouts(t, root)
	v := gateRelease(t, root, true, true)
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{
		"waves": []int{100}, "min_wave_minutes": 1, "failure_threshold_min": 1, "failure_threshold_percent": 0,
	}), http.StatusCreated, "")
	d := activeDevice(t, alice, "", "rollout-gate")
	d.Arch = protocol.ArchAMD64
	// The gate's binary is not a real agent: should the gate fail before the worker halts the release, the failure
	// report in the cleanup makes the worker halt it, so it does not stay the current release of real devices.
	reported := false
	t.Cleanup(func() {
		if !reported && rolloutStatus(t, root, v) != "halted" {
			reportUpdateFailed(t, d, v, 1)
		}
		haltRunningRollouts(t, root)
	})

	waitRolloutStatus(t, root, v, "completed", 4*time.Minute)
	checkinUntil(t, d, 2*time.Minute, func(r protocol.CheckinResponse) bool { return r.AgentUpdate != nil && r.AgentUpdate.Version == v })

	reportUpdateFailed(t, d, v, 1)
	reported = true
	waitRolloutStatus(t, root, v, "halted", 3*time.Minute)
	e := expectOneIndexEvent(t, auditIndex(t), platformOrg, "code = 'agent_rollout.halted' AND target->>'id' = $1", v,
		"agent_rollout.halted", "success", time.Minute)
	if e.ActorDisplay != "worker" {
		t.Fatalf("agent_rollout.halted by %q, want the worker", e.ActorDisplay)
	}
	checkinUntil(t, d, 2*time.Minute, func(r protocol.CheckinResponse) bool { return r.AgentUpdate == nil })
}
