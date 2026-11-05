package acceptance

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// upgradeTarget is a release every later server knows: the release sequence keeps every released version.
const upgradeTarget = "0.1.0-alpha.9"

// outsideAgent is a release version older than every window: the gateway answers it with the update pointer only.
const outsideAgent = "0.0.0"

type upgradeCheckDoc struct {
	TargetVersion string   `json:"target_version"`
	Window        []string `json:"window"`
	Items         []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"items"`
	AgentsOutside []upgradeCheckAgent `json:"agents_outside"`
}

type upgradeCheckAgent struct {
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
}

func upgradeCheck(t *testing.T, p *env.Portal, target string) env.Response {
	t.Helper()
	return call(t, p, http.MethodGet, "/api/platform/v1/upgrade-check?"+url.Values{"target_version": {target}}.Encode(), nil)
}

// TestUpgradeCheckEndpoint (plan M16 decision 4 and 4a, ADR 0013 amendment 2026-11-04, gate C5 server part): a device
// whose agent is outside the support window checks in with 200 and gets the update pointer of the running (here:
// completed) rollout regardless of its wave, but no bundle and no commands; its events are accepted; the attention
// list shows it as agent_outdated; the platform administrator's upgrade check lists it under agents_outside. An
// unknown target version is 400, an organization session 403.
func TestUpgradeCheckEndpoint(t *testing.T) {
	root, alice := login(t, env.PlatformAdmin), login(t, env.Alice)
	expectStatus(t, upgradeCheck(t, root, "unknown"), http.StatusBadRequest, "invalid_request")
	expectStatus(t, upgradeCheck(t, alice, upgradeTarget), http.StatusForbidden, "")

	hostname := "upgrade-" + uniqueSuffix()
	d := activeDevice(t, alice, "", hostname)
	d.Arch = protocol.ArchAMD64
	// Inside the window the device is pointed to its first bundle; the same device outside the window is not.
	checkinUntil(t, d, 2*time.Minute, func(r protocol.CheckinResponse) bool { return r.Bundle != nil })
	d.AgentVersion = outsideAgent
	out, res, err := d.Checkin(testContext(t, time.Minute))
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("checkin outside the window: %v HTTP %d %s", err, res.Status, res.Body)
	}
	if out.Bundle != nil || out.Commands == nil || len(out.Commands) != 0 {
		t.Fatalf("outside the window: bundle %+v commands %s", out.Bundle, out.Commands)
	}

	// A completed rollout is the current release, so the device is agent_outdated; the gate's binary is no real agent,
	// so the device's failure report halts the release again (the TestCurrentReleaseAutoStop pattern).
	haltRunningRollouts(t, root)
	requireNoCompletedRollout(t, root)
	v := gateRelease(t, root, true, true)
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{
		"waves": []int{100}, "min_wave_minutes": 1, "failure_threshold_min": 1, "failure_threshold_percent": 0,
	}), http.StatusCreated, "")
	reported := false
	t.Cleanup(func() {
		if !reported {
			retractRelease(t, root, d, v)
		}
		haltRunningRollouts(t, root)
	})
	waitRolloutStatus(t, root, v, "completed", 4*time.Minute)
	out = checkinUntil(t, d, 2*time.Minute, func(r protocol.CheckinResponse) bool { return r.AgentUpdate != nil && r.AgentUpdate.Version == v })
	if out.Bundle != nil || len(out.Commands) != 0 || out.AgentUpdate.Requested {
		t.Fatalf("outside the window with a release: %+v", out)
	}
	// The worker materializes the heartbeat asynchronously; the device keeps checking in until it is listed.
	checkinUntil(t, d, 3*time.Minute, func(protocol.CheckinResponse) bool {
		return listCount(t, alice, "/api/v1/attention", url.Values{"q": {hostname}, "kind": {"agent_outdated"}}) == 1
	})

	report := upgradeCheck(t, root, upgradeTarget)
	expectStatus(t, report, http.StatusOK, "")
	var doc upgradeCheckDoc
	if err := report.JSON(&doc); err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(doc.Items))
	for i, it := range doc.Items {
		names[i] = it.Name
	}
	if want := []string{"migrations", "agents", "backups", "openbao", "pending", "sessions"}; !slices.Equal(names, want) ||
		doc.TargetVersion != upgradeTarget || len(doc.Window) == 0 || doc.Window[len(doc.Window)-1] != upgradeTarget {
		t.Fatalf("report %+v", doc)
	}
	if doc.Items[0].Status == "FAIL" {
		t.Errorf("migrations: %+v", doc.Items[0])
	}
	if agents := doc.Items[1]; agents.Status != "WARN" && agents.Status != "FAIL" {
		t.Errorf("agents with a device outside the window: %+v", agents)
	}
	if len(doc.AgentsOutside) < 100 && !slices.ContainsFunc(doc.AgentsOutside, func(a upgradeCheckAgent) bool {
		return a.DeviceID == d.DeviceID && a.Hostname == hostname && a.AgentVersion == outsideAgent
	}) {
		t.Errorf("device %s not among the agents outside the window: %+v", hostname, doc.AgentsOutside)
	}

	reportUpdateFailed(t, d, v, 1)
	reported = true
	waitRolloutStatus(t, root, v, "halted", 3*time.Minute)
}
