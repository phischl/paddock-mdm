package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type uninstallState struct {
	State         string  `json:"state"`
	RetiredReason *string `json:"retired_reason"`
	Uninstall     *struct {
		Mode          string  `json:"mode"`
		CommandID     string  `json:"command_id"`
		CommandStatus string  `json:"command_status"`
		UninstalledAt *string `json:"uninstalled_at"`
		LocalAdmin    *string `json:"local_admin"`
		Tpm           *string `json:"tpm"`
	} `json:"uninstall"`
}

func uninstallOf(t *testing.T, p *env.Portal, id string) uninstallState {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var s uninstallState
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// eventually polls cond every 2 s until it holds or timeout passes.
func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); !cond(); time.Sleep(2 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, timeout)
		}
	}
}

func uninstallBody(d *devicesim.Device, hostname, mode string, extra map[string]any) map[string]any {
	body := map[string]any{"mode": mode, "confirm_hostname": hostname, "reason": "gate A8 " + d.DeviceID[:8]}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// uninstallAttention returns the details of the device's uninstall_pending attention rows.
func uninstallAttention(t *testing.T, p *env.Portal, hostname string) []string {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/attention?"+url.Values{"q": {hostname}, "kind": {"uninstall_pending"}}.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Detail string `json:"detail"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, i := range page.Items {
		out = append(out, i.Detail)
	}
	return out
}

// TestUninstall is gate A8 of plan M8d (AC8, AC9 server part): an organization administrator with a step-up requests
// the removal of Paddock with the typed hostname; refusals for a missing step-up, a wrong hostname, a second request,
// reset-only options with leave, a TPM keyslot and a pending Lock; cancel before the device received the command and
// not after; the device's acceptance and removal report retire it with reason uninstalled.
func TestUninstall(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "uninstall")
	hostname := "a8-" + uniqueSuffix()
	d := activeDevice(t, alice, "", hostname)
	hostname = getDevice(t, alice, d.DeviceID).Hostname
	path := "/api/v1/devices/" + d.DeviceID + "/uninstall"

	expectStatus(t, call(t, withoutStepUp(t, admin), http.MethodPost, path, uninstallBody(d, hostname, "leave", nil)),
		http.StatusForbidden, "step_up_required")
	expectStatus(t, call(t, login(t, env.Bob), http.MethodPost, path, uninstallBody(d, hostname, "leave", nil)), http.StatusForbidden, "")
	expectStatus(t, call(t, admin.Portal, http.MethodPost, path, uninstallBody(d, "other", "leave", nil)),
		http.StatusUnprocessableEntity, "invalid_request")
	expectStatus(t, call(t, admin.Portal, http.MethodPost, path, uninstallBody(d, hostname, "leave", map[string]any{"clear_tpm": true})),
		http.StatusUnprocessableEntity, "invalid_request")

	res := call(t, admin.Portal, http.MethodPost, path, uninstallBody(d, hostname, "leave", nil))
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, alice, res.RequestID, "device.uninstall_requested", "success")
	s := uninstallOf(t, alice, d.DeviceID)
	if s.Uninstall == nil || s.Uninstall.Mode != "leave" || s.Uninstall.CommandStatus != "pending" || ev.Params["command_id"] != s.Uninstall.CommandID ||
		ev.Params["mode"] != "leave" || ev.Params["clear_tpm"] != false || ev.Params["keep_local_admin"] != false {
		t.Fatalf("uninstall %+v, params %v", s.Uninstall, ev.Params)
	}
	if got := uninstallAttention(t, alice, hostname); len(got) != 1 || got[0] != "leave:pending" {
		t.Fatalf("attention %v", got)
	}
	cmds := call(t, alice, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/commands?type=uninstall", nil)
	expectStatus(t, cmds, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID     string          `json:"id"`
			Type   string          `json:"type"`
			Params json.RawMessage `json:"params"`
		} `json:"items"`
	}
	if err := cmds.JSON(&page); err != nil || len(page.Items) != 1 || page.Items[0].Type != "uninstall" || page.Items[0].ID != s.Uninstall.CommandID {
		t.Fatalf("commands %s (%v)", cmds.Body, err)
	}
	res = call(t, admin.Portal, http.MethodPost, path, uninstallBody(d, hostname, "leave", nil))
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if detail := problemDetail(t, res); detail != "an uninstall is already requested" {
		t.Fatalf("second request: %q", detail)
	}

	// Cancel before delivery.
	res = call(t, admin.Portal, http.MethodPost, path+"/cancel", nil)
	expectStatus(t, res, http.StatusOK, "")
	expectOneEvent(t, alice, res.RequestID, "device.uninstall_cancelled", "success")
	if s := uninstallOf(t, alice, d.DeviceID); s.Uninstall != nil {
		t.Fatalf("after cancel: %+v", s.Uninstall)
	}
	if got := uninstallAttention(t, alice, hostname); len(got) != 0 {
		t.Fatalf("attention after cancel %v", got)
	}

	// A TPM keyslot refuses clear_tpm.
	d.Health = json.RawMessage(`{"reconcile":"ok","disk":{"state":"compliant","tokens":["recovery","tpm2+pin"],"keyslots":2}}`)
	if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the health report", time.Minute, func() bool {
		res := call(t, admin.Portal, http.MethodPost, path, uninstallBody(d, hostname, "reset", map[string]any{"clear_tpm": true}))
		return res.ProblemCode() == "tpm_in_use_by_disk"
	})

	// Requested again; the check-in delivers it: no cancel any more.
	res = call(t, admin.Portal, http.MethodPost, path, uninstallBody(d, hostname, "leave", nil))
	expectStatus(t, res, http.StatusOK, "")
	cmd := uninstallOf(t, alice, d.DeviceID).Uninstall.CommandID
	checkinUntil(t, d, 2*time.Minute, func(r protocol.CheckinResponse) bool { return len(r.Commands) > 0 })
	eventually(t, "the delivery", time.Minute, func() bool { return uninstallOf(t, alice, d.DeviceID).Uninstall.CommandStatus == "delivered" })
	res = call(t, admin.Portal, http.MethodPost, path+"/cancel", nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if detail := problemDetail(t, res); detail != "the device already received the command" {
		t.Fatalf("cancel after delivery: %q", detail)
	}

	// The device accepts and reports the removal: device.uninstalled by the device, device.retired by the system.
	if r, err := d.CommandResult(testContext(t, time.Minute), cmd, "succeeded", json.RawMessage(`{"accepted":true}`)); err != nil || r.Status >= 300 {
		t.Fatalf("result: %v %d %s", err, r.Status, r.Body)
	}
	data, _ := json.Marshal(protocol.AgentUninstalled{CommandID: cmd, Mode: "leave", Outcome: protocol.UninstallCompleted, LocalAdmin: "kept",
		TPM: "not_requested", Steps: map[string]string{"stop": "done", "packages": "done", "quarantine": "skipped"}})
	if r, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: 1, Type: protocol.EventAgentUninstalled,
		OccurredAt: time.Now(), Data: data}}); err != nil || r.Status != http.StatusAccepted {
		t.Fatalf("events: %v %d", err, r.Status)
	}
	idx, acme := auditIndex(t), orgOf(t, alice)
	removed := expectOneIndexEvent(t, idx, acme, "code = 'device.uninstalled' AND target->>'id' = $1", d.DeviceID, "device.uninstalled", "success", time.Minute)
	if removed.Params["outcome"] != "completed" || removed.Params["local_admin"] != "kept" || removed.Params["tpm"] != "not_requested" {
		t.Fatalf("device.uninstalled params %v", removed.Params)
	}
	retired := expectOneIndexEvent(t, idx, acme, "code = 'device.retired' AND target->>'id' = $1", d.DeviceID, "device.retired", "success", time.Minute)
	if retired.Params["reason"] != "uninstalled" {
		t.Fatalf("device.retired params %v", retired.Params)
	}
	s = uninstallOf(t, alice, d.DeviceID)
	if s.State != "retired" || s.RetiredReason == nil || *s.RetiredReason != "uninstalled" || s.Uninstall == nil || s.Uninstall.UninstalledAt == nil ||
		s.Uninstall.LocalAdmin == nil || *s.Uninstall.LocalAdmin != "kept" || s.Uninstall.Tpm == nil || *s.Uninstall.Tpm != "not_requested" {
		t.Fatalf("after the report: %+v", s)
	}
	if got := uninstallAttention(t, alice, hostname); len(got) != 0 {
		t.Fatalf("attention of a retired device %v", got)
	}

	// A pending Lock refuses the removal of its device; another organization finds neither route.
	other := "a8l-" + uniqueSuffix()
	locked := activeDevice(t, alice, "", other)
	other = getDevice(t, alice, locked.DeviceID).Hostname
	expectStatus(t, call(t, admin.Portal, http.MethodPost, "/api/v1/devices/"+locked.DeviceID+"/lock",
		map[string]any{"confirm_hostname": other, "reason": "gate A8"}), http.StatusCreated, "")
	res = call(t, admin.Portal, http.MethodPost, "/api/v1/devices/"+locked.DeviceID+"/uninstall", uninstallBody(locked, other, "leave", nil))
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if detail := problemDetail(t, res); detail != "a lock or destroy is pending for this device" {
		t.Fatalf("pending lock: %q", detail)
	}
	carol := login(t, env.Carol)
	freshStepUp(t, carol, env.Carol)
	expectStatus(t, call(t, carol, http.MethodPost, path, uninstallBody(d, hostname, "leave", nil)), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodPost, path+"/cancel", nil), http.StatusNotFound, "not_found")
}
