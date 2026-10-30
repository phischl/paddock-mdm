package acceptance

import (
	"encoding/json"
	"hash/fnv"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type requestState struct {
	Version      *string `json:"agent_update_requested_version"`
	At           *string `json:"agent_update_requested_at"`
	AgentVersion *string `json:"agent_version"`
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

// rolloutBucket mirrors agentrelease.Bucket (FNV-1a of the device UUID text modulo 100), so a gate can place its
// devices inside and outside a wave without waiting on chance.
func rolloutBucket(deviceID string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(deviceID))
	return int(h.Sum32() % 100)
}

// offerWithdrawalTimeout spans two rounds of the worker's rollout loop (worker.RolloutInterval, 60 s) plus slack.
const offerWithdrawalTimeout = 150 * time.Second

// waitOfferWithdrawn waits until the stack offers no agent release any more. haltRunningRollouts only halts a rollout
// left by another gate; its offer (Valkey ar:current) stays published until the worker's next rollout round, and a
// device outside that rollout's unknown wave cannot see it (PDK-553). An update-now request is the one observable that
// reads the offer regardless of the wave, so it is made for a throwaway device, never for the gate's own one.
func waitOfferWithdrawn(t *testing.T, p *env.Portal, throwaway *devicesim.Device) {
	t.Helper()
	path := "/api/v1/devices/" + throwaway.DeviceID + "/update-agent"
	for deadline := time.Now().Add(offerWithdrawalTimeout); ; time.Sleep(3 * time.Second) {
		res := call(t, p, http.MethodPost, path, nil)
		if res.Status == http.StatusConflict && problemDetail(t, res) == "no agent release is being offered" {
			return
		}
		if res.Status != http.StatusOK {
			t.Fatalf("waiting for the offer to be withdrawn: HTTP %d %s", res.Status, res.Body)
		}
		if time.Now().After(deadline) {
			t.Fatalf("an agent release is still offered %s after halting the running rollouts", offerWithdrawalTimeout)
		}
	}
}

// TestUpdateNow is gate A6 of plan M8d (AC6): with a rollout whose first wave excludes the device, an operator's
// update-now request makes the next check-in carry a requested offer; the device's report clears the request; a
// second request while the device runs the release, a request without a rollout and one for a halted rollout are
// refused; an auditor is forbidden.
func TestUpdateNow(t *testing.T) {
	root, alice, bob := login(t, env.PlatformAdmin), login(t, env.Alice), login(t, env.Bob)
	haltRunningRollouts(t, root)
	t.Cleanup(func() { haltRunningRollouts(t, root) })
	requireNoCompletedRollout(t, root)
	d := activeDevice(t, alice, "", "a6-"+uniqueSuffix())
	// Only the worker's rollout round (every 60 s) publishes or withdraws the offer, and a device outside the wave sees
	// neither. The probe sits in the first wave, so its offer tells when the round has run.
	probe := activeDevice(t, alice, "", "a6-"+uniqueSuffix())
	for rolloutBucket(probe.DeviceID) == rolloutBucket(d.DeviceID) {
		probe = activeDevice(t, alice, "", "a6-"+uniqueSuffix())
	}
	if rolloutBucket(probe.DeviceID) > rolloutBucket(d.DeviceID) {
		d, probe = probe, d
	}
	d.Arch, probe.Arch = protocol.ArchAMD64, protocol.ArchAMD64
	path := "/api/v1/devices/" + d.DeviceID + "/update-agent"
	operator := operatorUser(t)
	waitOfferWithdrawn(t, operator.Portal, activeDevice(t, alice, "", "a6-"+uniqueSuffix()))

	res := call(t, operator.Portal, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if detail := problemDetail(t, res); detail != "no agent release is being offered" {
		t.Fatalf("without a rollout: %q", detail)
	}

	v := gateRelease(t, root, true, true)
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{
		"waves": []int{rolloutBucket(probe.DeviceID) + 1, 100}, "min_wave_minutes": 60, "failure_threshold_min": 1000, "failure_threshold_percent": 100,
	}), http.StatusCreated, "")
	waitRolloutStatus(t, root, v, "running", time.Minute)
	checkinUntil(t, probe, 2*time.Minute, func(r protocol.CheckinResponse) bool { return r.AgentUpdate != nil && r.AgentUpdate.Version == v })
	out, _, err := d.Checkin(testContext(t, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if out.AgentUpdate != nil {
		t.Fatalf("offered outside its wave: %+v", out.AgentUpdate)
	}
	// The request reads from_version from device_status, which the worker materializes asynchronously from the
	// check-in's heartbeat; until then the server does not know the device's version (PDK-459).
	checkinUntil(t, d, 3*time.Minute, func(protocol.CheckinResponse) bool {
		s := requestOf(t, alice, d.DeviceID)
		return s.AgentVersion != nil && *s.AgentVersion == "0.0.0-devicesim"
	})

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
	// The worker materializes one heartbeat per device and minute and drops the others (plan M2a decision 12), so the
	// device keeps checking in until its status reports the release.
	checkinUntil(t, d, 3*time.Minute, func(protocol.CheckinResponse) bool {
		s := requestOf(t, alice, d.DeviceID)
		return s.AgentVersion != nil && *s.AgentVersion == v
	})
	res = call(t, operator.Portal, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if detail := problemDetail(t, res); detail != "the device already runs "+v {
		t.Fatalf("device on the release: %q", detail)
	}

	d.AgentVersion = "0.0.0-devicesim"
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout/halt", nil), http.StatusOK, "")
	checkinUntil(t, probe, 2*time.Minute, func(r protocol.CheckinResponse) bool { return r.AgentUpdate == nil })
	res = call(t, operator.Portal, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if out, _, err := d.Checkin(testContext(t, time.Minute)); err != nil || out.AgentUpdate != nil {
		t.Fatalf("halted rollout offered %+v (%v)", out.AgentUpdate, err)
	}
}
