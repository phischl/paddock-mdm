package acceptance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type requestState struct {
	Version *string `json:"agent_update_requested_version"`
	At      *string `json:"agent_update_requested_at"`
}

func requestOf(t *testing.T, p *env.Portal, id string) requestState {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var s requestState
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestUpdateNow is gate A6 of plan M8d (AC6): with a rollout whose first wave excludes the device, an operator's
// update-now request makes the next check-in carry a requested offer; the device's report clears the request; a
// second request while the device runs the release, a request without a rollout and one for a halted rollout are
// refused; an auditor is forbidden.
func TestUpdateNow(t *testing.T) {
	root, alice, bob := login(t, env.PlatformAdmin), login(t, env.Alice), login(t, env.Bob)
	haltRunningRollouts(t, root)
	t.Cleanup(func() { haltRunningRollouts(t, root) })
	d := activeDevice(t, alice, "", "a6-"+uniqueSuffix())
	d.Arch = protocol.ArchAMD64
	path := "/api/v1/devices/" + d.DeviceID + "/update-agent"
	operator := operatorUser(t)

	res := call(t, operator.Portal, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if detail := problemDetail(t, res); detail != "no agent release is being offered" {
		t.Fatalf("without a rollout: %q", detail)
	}

	v := gateRelease(t, root, true, true)
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{
		"waves": []int{1, 100}, "min_wave_minutes": 60, "failure_threshold_min": 1000, "failure_threshold_percent": 100,
	}), http.StatusCreated, "")
	waitRolloutStatus(t, root, v, "running", time.Minute)
	time.Sleep(10 * time.Second) // the worker's rollout round writes the offer
	out, _, err := d.Checkin(testContext(t, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if out.AgentUpdate != nil && !out.AgentUpdate.Requested {
		t.Skip("the simulated device fell into the 1 % wave; the gate needs a device outside it")
	}

	expectStatus(t, call(t, bob, http.MethodPost, path, nil), http.StatusForbidden, "forbidden")
	res = call(t, operator.Portal, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, alice, res.RequestID, "device.agent_update_requested", "success")
	if ev.Params["version"] != v || ev.Params["from_version"] != "0.0.0-devicesim" {
		t.Fatalf("params %v", ev.Params)
	}
	if s := requestOf(t, alice, d.DeviceID); s.Version == nil || *s.Version != v || s.At == nil {
		t.Fatalf("request %+v", s)
	}
	offer := checkinUntil(t, d, 2*time.Minute, func(r protocol.CheckinResponse) bool { return r.AgentUpdate != nil })
	if u := offer.AgentUpdate; u.Version != v || !u.Requested || u.RequestedAt == nil {
		t.Fatalf("offer %+v", u)
	}

	data, _ := json.Marshal(map[string]string{"version": v, "from_version": "0.0.0-devicesim", "outcome": "updated"})
	if r, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: 1, Type: protocol.EventAgentUpdated, OccurredAt: time.Now(), Data: data}}); err != nil || r.Status != http.StatusAccepted {
		t.Fatalf("events: %v %d", err, r.Status)
	}
	for deadline := time.Now().Add(time.Minute); requestOf(t, alice, d.DeviceID).Version != nil; time.Sleep(2 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("the device's report did not clear the request")
		}
	}
	d.AgentVersion = v
	if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second) // the heartbeat is materialized by the worker
	res = call(t, operator.Portal, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if detail := problemDetail(t, res); detail != "the device already runs "+v {
		t.Fatalf("device on the release: %q", detail)
	}

	d.AgentVersion = "0.0.0-devicesim"
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout/halt", nil), http.StatusOK, "")
	time.Sleep(10 * time.Second)
	res = call(t, operator.Portal, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if out, _, err := d.Checkin(testContext(t, time.Minute)); err != nil || out.AgentUpdate != nil {
		t.Fatalf("halted rollout offered %+v (%v)", out.AgentUpdate, err)
	}
}
