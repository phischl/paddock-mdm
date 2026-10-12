package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// devicesimVersion is the agent version every simulated device reports.
const devicesimVersion = "0.0.0-devicesim"

// reportAgentUpdate sends an agent update event for the version the simulated device runs.
func reportAgentUpdate(t *testing.T, d *devicesim.Device, seq int64, eventType, outcome string) {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"version": devicesimVersion, "from_version": "0.0.0-previous", "outcome": outcome})
	res, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: seq, Type: eventType, OccurredAt: time.Now(), Data: data}})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("events: %v HTTP %d %s", err, res.Status, res.Body)
	}
}

// rollbackPending returns the details of the device's agent_rollback_pending entries in the attention list.
func rollbackPending(t *testing.T, p *env.Portal, deviceID, hostname string) []string {
	t.Helper()
	q := url.Values{"page_size": {"100"}, "q": {hostname}, "kind": {"agent_rollback_pending"}}
	res := call(t, p, http.MethodGet, "/api/v1/attention?"+q.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Kind     string `json:"kind"`
			DeviceID string `json:"device_id"`
			Detail   string `json:"detail"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	var details []string
	for _, it := range page.Items {
		if it.DeviceID == deviceID && it.Kind == "agent_rollback_pending" {
			details = append(details, it.Detail)
		}
	}
	return details
}

// waitRollbackPending polls the attention list until want holds: the gateway accepts events before the worker has
// stored the update report, so the entry appears and disappears asynchronously.
func waitRollbackPending(t *testing.T, p *env.Portal, deviceID, hostname string, want func([]string) bool) []string {
	t.Helper()
	got := rollbackPending(t, p, deviceID, hostname)
	for deadline := time.Now().Add(time.Minute); !want(got) && time.Now().Before(deadline); time.Sleep(time.Second) {
		got = rollbackPending(t, p, deviceID, hostname)
	}
	return got
}

// TestRollbackPendingAttention is AC6 of PDK-043 (ADR 0024): a device that reports agent.update_failed with outcome
// rollback_failed for the version it runs is audited as device.agent_rollback_failed and listed on the attention page
// as agent_rollback_pending with the version; its later agent.rolled_back for that version removes the entry.
func TestRollbackPendingAttention(t *testing.T) {
	alice := login(t, env.Alice)
	d := activeDevice(t, alice, "", "rollback-pending-gate")
	checkinUntil(t, d, time.Minute, func(protocol.CheckinResponse) bool { return true })
	hostname := getDevice(t, alice, d.DeviceID).Hostname
	if got := rollbackPending(t, alice, d.DeviceID, hostname); len(got) != 0 {
		t.Fatalf("agent_rollback_pending %v before any report", got)
	}

	reportAgentUpdate(t, d, 1, protocol.EventAgentUpdateFailed, "rollback_failed")
	listed := func(got []string) bool { return len(got) == 1 && got[0] == devicesimVersion }
	if got := waitRollbackPending(t, alice, d.DeviceID, hostname, listed); !listed(got) {
		t.Fatalf("agent_rollback_pending %v after rollback_failed, want [%s]", got, devicesimVersion)
	}
	org := uuid.MustParse(d.Config.OrganizationID)
	expectOneIndexEvent(t, auditIndex(t), org, "code = 'device.agent_rollback_failed' AND target->>'id' = $1", d.DeviceID,
		"device.agent_rollback_failed", "success", auditPollTimeout)

	reportAgentUpdate(t, d, 2, protocol.EventAgentRolledBack, "rolled_back")
	cleared := func(got []string) bool { return len(got) == 0 }
	if got := waitRollbackPending(t, alice, d.DeviceID, hostname, cleared); !cleared(got) {
		t.Fatalf("agent_rollback_pending %v after rolled_back", got)
	}
}
