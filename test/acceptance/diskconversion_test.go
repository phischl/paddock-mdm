package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// eligibleDisk is the health of an unencrypted devicesim whose layout can be encrypted in place.
const eligibleDisk = `{"reconcile":"ok","disk":{"state":"not_encrypted","keyslots":0,"boot_separate":true,
	"conversion":{"eligible":true,"layout":"lvm","release":"26.04","initramfs":"dracut"}}}`

type conversionView struct {
	ID                 string  `json:"id"`
	Phase              string  `json:"phase"`
	CommandID          string  `json:"command_id"`
	CommandStatus      string  `json:"command_status"`
	Layout             *string `json:"layout"`
	LuksUUID           *string `json:"luks_uuid"`
	DataBytes          *int64  `json:"data_bytes"`
	DoneBytes          *int64  `json:"done_bytes"`
	EtaS               *int64  `json:"eta_s"`
	FailureStage       *string `json:"failure_stage"`
	FailureReason      *string `json:"failure_reason"`
	FinishedAt         *string `json:"finished_at"`
	AbortCommandID     *string `json:"abort_command_id"`
	AbortRefusedReason *string `json:"abort_refused_reason"`
	Active             bool    `json:"active"`
}

// conversionOf is the device's latest in-place encryption; nil without one.
func conversionOf(t *testing.T, p *env.Portal, id string) *conversionView {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var d struct {
		DiskConversion *conversionView `json:"disk_conversion"`
	}
	if err := res.JSON(&d); err != nil {
		t.Fatal(err)
	}
	return d.DiskConversion
}

// waitConversion polls the device's conversion until cond holds (the worker records events and results
// asynchronously).
func waitConversion(t *testing.T, p *env.Portal, id, what string, cond func(*conversionView) bool) *conversionView {
	t.Helper()
	var c *conversionView
	eventually(t, what, time.Minute, func() bool {
		c = conversionOf(t, p, id)
		return c != nil && cond(c)
	})
	return c
}

type diskView struct {
	State      string `json:"state"`
	Conversion *struct {
		Eligible  bool `json:"eligible"`
		KeyOnBoot bool `json:"key_on_boot"`
	} `json:"conversion"`
	DiskConversion *conversionView `json:"disk_conversion"`
}

// reportDisk checks d in with health until the device's disk satisfies done: the worker stores a heartbeat at most
// once a minute per device. Every check-in delivers the device's open commands. It checks in every 5 s: the gateway
// allows 30 requests per minute and device key and counts refused requests too, so a 2 s loop that runs for minutes
// is refused for good once it crossed the limit (the cause of the first CI failure of this gate).
func reportDisk(t *testing.T, p *env.Portal, d *devicesim.Device, health string, done func(diskView) bool) {
	t.Helper()
	d.Health = json.RawMessage(health)
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(5 * time.Second) {
		_, _, _ = d.Checkin(testContext(t, time.Minute))
		var disk diskView
		_ = call(t, p, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/disk", nil).JSON(&disk)
		if done(disk) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the disk report: not within 3m0s; last %+v", disk)
		}
	}
}

// conversionSim is a devicesim with an in-place encryption gate's helpers.
type conversionSim struct {
	*devicesim.Device
	hostname string
	seq      int64
}

func newConversionSim(t *testing.T, alice *env.Portal, prefix string) *conversionSim {
	t.Helper()
	d := activeDevice(t, alice, "", prefix+"-"+uniqueSuffix())
	s := &conversionSim{Device: d, hostname: getDevice(t, alice, d.DeviceID).Hostname}
	reportDisk(t, alice, d, eligibleDisk, func(disk diskView) bool { return disk.Conversion != nil && disk.Conversion.Eligible })
	return s
}

func (s *conversionSim) path(suffix string) string { return "/api/v1/devices/" + s.DeviceID + suffix }

func (s *conversionSim) encryptBody() map[string]any {
	return map[string]any{"confirm_hostname": s.hostname, "reason": "gate A1 " + s.DeviceID[:8], "backup_confirmed": true}
}

func (s *conversionSim) cancelBody() map[string]any {
	return map[string]any{"confirm_hostname": s.hostname}
}

// request opens a conversion with the stepped-up admin and returns it.
func (s *conversionSim) request(t *testing.T, admin *mfaUser, alice *env.Portal) *conversionView {
	t.Helper()
	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPost, s.path("/encrypt"), s.encryptBody()), http.StatusOK, "")
	c := conversionOf(t, alice, s.DeviceID)
	if c == nil || c.Phase != "requested" {
		t.Fatalf("conversion %+v", c)
	}
	return c
}

// deliver checks in until the device received command id.
func (s *conversionSim) deliver(t *testing.T, id string) {
	t.Helper()
	checkinUntil(t, s.Device, 2*time.Minute, func(r protocol.CheckinResponse) bool {
		for _, env := range r.Commands {
			if commandID(env) == id {
				return true
			}
		}
		return false
	})
}

// post sends one device event.
func (s *conversionSim) post(t *testing.T, typ string, data map[string]any) {
	t.Helper()
	s.seq++
	raw, _ := json.Marshal(data)
	if r, err := s.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: s.seq, Type: typ, OccurredAt: time.Now(), Data: raw}}); err != nil ||
		r.Status != http.StatusAccepted {
		t.Fatalf("event %s: %v %d %s", typ, err, r.Status, r.Body)
	}
}

// result posts a command result.
func (s *conversionSim) result(t *testing.T, id, status, result string) {
	t.Helper()
	if r, err := s.CommandResult(testContext(t, time.Minute), id, status, json.RawMessage(result)); err != nil || r.Status >= 300 {
		t.Fatalf("result: %v %d %s", err, r.Status, r.Body)
	}
}

func expectDetail(t *testing.T, res env.Response, status int, code, detail string) {
	t.Helper()
	expectStatus(t, res, status, code)
	if got := problemDetail(t, res); got != detail {
		t.Fatalf("detail %q, want %q", got, detail)
	}
}

// commandsOfType lists the device's commands of one type.
func commandsOfType(t *testing.T, p *env.Portal, id, typ string) []struct {
	ID     string          `json:"id"`
	Status string          `json:"status"`
	Params json.RawMessage `json:"params"`
} {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id+"/commands?"+url.Values{"type": {typ}}.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID     string          `json:"id"`
			Status string          `json:"status"`
			Params json.RawMessage `json:"params"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Items
}

// TestDiskConversion is gate A1 of plan M8e (AC2, AC11 server part, decisions 7–10): the request with its refusals,
// the cancel before delivery, the device's phases with the progress of the last check-in, a refused command and a
// failure on the attention list, and a new request after a failed conversion.
func TestDiskConversion(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "encrypt")
	s := newConversionSim(t, alice, "a1e")
	encrypt := s.path("/encrypt")

	expectStatus(t, call(t, withoutStepUp(t, admin), http.MethodPost, encrypt, s.encryptBody()), http.StatusForbidden, "step_up_required")
	expectStatus(t, call(t, operatorUser(t).Portal, http.MethodPost, encrypt, s.encryptBody()), http.StatusForbidden, "forbidden")
	bad := s.encryptBody()
	bad["confirm_hostname"] = "other"
	expectDetail(t, call(t, admin.Portal, http.MethodPost, encrypt, bad), http.StatusUnprocessableEntity, "invalid_request",
		"confirm_hostname does not match")
	bad = s.encryptBody()
	bad["backup_confirmed"] = false
	expectDetail(t, call(t, admin.Portal, http.MethodPost, encrypt, bad), http.StatusUnprocessableEntity, "invalid_request",
		"backup_confirmed must be true")

	res := call(t, admin.Portal, http.MethodPost, encrypt, s.encryptBody())
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, alice, res.RequestID, "device.encrypt_requested", "success")
	c := conversionOf(t, alice, s.DeviceID)
	if c == nil || c.Phase != "requested" || c.CommandStatus != "pending" || !c.Active || ev.Params["backup_confirmed"] != true ||
		ev.Params["command_id"] != c.CommandID || ev.Params["conversion_id"] != c.ID {
		t.Fatalf("conversion %+v, params %v", c, ev.Params)
	}
	if cmds := commandsOfType(t, alice, s.DeviceID, "encrypt_disk"); len(cmds) != 1 || cmds[0].ID != c.CommandID ||
		!strings.Contains(string(cmds[0].Params), `"conversion_id": "`+c.ID+`"`) && !strings.Contains(string(cmds[0].Params), `"conversion_id":"`+c.ID+`"`) {
		t.Fatalf("commands %+v", cmds)
	}
	expectDetail(t, call(t, admin.Portal, http.MethodPost, encrypt, s.encryptBody()), http.StatusConflict, "invalid_state",
		"a conversion is already open")

	// Cancel before delivery: the command and the conversion are cancelled at once.
	admin.stepUp(t)
	res = call(t, admin.Portal, http.MethodPost, encrypt+"/cancel", s.cancelBody())
	expectStatus(t, res, http.StatusOK, "")
	if ev := expectOneEvent(t, alice, res.RequestID, "device.encrypt_cancelled", "success"); ev.Params["mode"] != "command_cancelled" {
		t.Fatalf("cancel params %v", ev.Params)
	}
	if c := conversionOf(t, alice, s.DeviceID); c.Phase != "cancelled" || c.CommandStatus != "cancelled" || c.FinishedAt == nil || c.Active {
		t.Fatalf("after cancel %+v", c)
	}

	// The device's phases.
	c = s.request(t, admin, alice)
	s.deliver(t, c.CommandID)
	s.result(t, c.CommandID, "succeeded", `{"accepted":true}`)
	volume := "6f1c2a7e-3b5d-4c8e-9a0f-1d2e3f4a5b6c"
	s.post(t, protocol.EventDiskConversionPrepared, map[string]any{"conversion_id": c.ID, "layout": "lvm", "volume": volume, "data_bytes": 100})
	p := waitConversion(t, alice, s.DeviceID, "prepared", func(c *conversionView) bool { return c.Phase == "prepared" })
	if p.Layout == nil || *p.Layout != "lvm" || p.LuksUUID == nil || *p.LuksUUID != volume || p.DataBytes == nil || *p.DataBytes != 100 {
		t.Fatalf("prepared %+v", p)
	}
	idx, acme := auditIndex(t), orgOf(t, alice)
	prepared := expectOneIndexEvent(t, idx, acme, "code = 'device.disk_conversion_prepared' AND target->>'id' = $1", s.DeviceID,
		"device.disk_conversion_prepared", "success", time.Minute)
	if prepared.Params["conversion_id"] != c.ID || prepared.Params["layout"] != "lvm" || prepared.Params["volume"] != volume {
		t.Fatalf("prepared params %v", prepared.Params)
	}
	s.post(t, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": c.ID, "volume": volume, "init_s": 40, "init_result": "ok"})
	waitConversion(t, alice, s.DeviceID, "encrypting", func(c *conversionView) bool { return c.Phase == "encrypting" })
	reportDisk(t, alice, s.Device, `{"reconcile":"ok","disk":{"state":"encrypting","keyslots":1,"tokens":["password"],
		"conversion":{"eligible":false,"phase":"encrypting","data_bytes":100,"done_bytes":50,"eta_s":60}}}`,
		func(d diskView) bool { return d.State == "encrypting" })
	if c := conversionOf(t, alice, s.DeviceID); c.DoneBytes == nil || *c.DoneBytes != 50 || c.EtaS == nil || *c.EtaS != 60 || !c.Active {
		t.Fatalf("progress %+v", c)
	}
	if n := listCount(t, alice, "/api/v1/devices", url.Values{"disk_state": {"encrypting"}, "q": {s.hostname}}); n != 1 {
		t.Fatalf("disk_state filter found %d devices", n)
	}
	s.post(t, protocol.EventDiskConversionCompleted, map[string]any{"conversion_id": c.ID, "volume": volume, "data_bytes": 100, "duration_s": 600})
	if done := waitConversion(t, alice, s.DeviceID, "completed", func(c *conversionView) bool { return c.Phase == "completed" }); done.FinishedAt == nil {
		t.Fatalf("completed %+v", done)
	}

	// A refused command fails the conversion; a new request is possible at once and its failure is listed.
	d2 := newConversionSim(t, alice, "a1f")
	c = d2.request(t, admin, alice)
	d2.deliver(t, c.CommandID)
	d2.result(t, c.CommandID, "failed", `{"accepted":false,"reason":"not_eligible","reasons":["low_free_space"]}`)
	f := waitConversion(t, alice, d2.DeviceID, "refused", func(c *conversionView) bool { return c.Phase == "failed" })
	if f.FailureStage == nil || *f.FailureStage != "preflight" || f.FailureReason == nil || *f.FailureReason != "not_eligible" {
		t.Fatalf("refused %+v", f)
	}
	c = d2.request(t, admin, alice)
	d2.deliver(t, c.CommandID)
	d2.post(t, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": c.ID, "stage": "init", "reason": "on_battery"})
	waitConversion(t, alice, d2.DeviceID, "failed", func(c *conversionView) bool { return c.Phase == "failed" })
	eventually(t, "the attention entry", time.Minute, func() bool {
		res := call(t, alice, http.MethodGet, "/api/v1/attention?"+url.Values{"q": {d2.hostname}, "kind": {"disk_conversion_failed"}}.Encode(), nil)
		return res.Status == http.StatusOK && strings.Contains(string(res.Body), `"detail":"init:on_battery"`)
	})

	// Refusals: not eligible, a pending uninstall, a pending Lock; another organization finds neither route.
	ineligible := activeDevice(t, alice, "", "a1n-"+uniqueSuffix())
	reportDisk(t, alice, ineligible, `{"reconcile":"ok","disk":{"state":"not_encrypted","keyslots":0,"conversion":{"eligible":false,"reasons":["no_separate_boot"]}}}`,
		func(d diskView) bool { return d.Conversion != nil })
	host := getDevice(t, alice, ineligible.DeviceID).Hostname
	admin.stepUp(t)
	expectDetail(t, call(t, admin.Portal, http.MethodPost, "/api/v1/devices/"+ineligible.DeviceID+"/encrypt",
		map[string]any{"confirm_hostname": host, "reason": "gate A1", "backup_confirmed": true}), http.StatusConflict, "invalid_state",
		"the device does not report an eligible disk layout: no_separate_boot")

	d3 := newConversionSim(t, alice, "a1u")
	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPost, d3.path("/uninstall"),
		map[string]any{"mode": "leave", "confirm_hostname": d3.hostname, "reason": "gate A1"}), http.StatusOK, "")
	expectDetail(t, call(t, admin.Portal, http.MethodPost, d3.path("/encrypt"), d3.encryptBody()), http.StatusConflict, "invalid_state",
		"an uninstall is pending")
	expectStatus(t, call(t, admin.Portal, http.MethodPost, d3.path("/uninstall/cancel"), nil), http.StatusOK, "")
	expectStatus(t, call(t, admin.Portal, http.MethodPost, d3.path("/lock"), map[string]any{"confirm_hostname": d3.hostname, "reason": "gate A1"}),
		http.StatusCreated, "")
	expectDetail(t, call(t, admin.Portal, http.MethodPost, d3.path("/encrypt"), d3.encryptBody()), http.StatusConflict, "invalid_state",
		"a lock or destroy is pending for this device")

	carol := login(t, env.Carol)
	freshStepUp(t, carol, env.Carol)
	expectStatus(t, call(t, carol, http.MethodPost, encrypt, s.encryptBody()), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodPost, encrypt+"/cancel", s.cancelBody()), http.StatusNotFound, "not_found")
}

// TestDiskConversionAbort is the cancel after delivery of gate A1 (plan M8e decisions 8, 9 and 27): the device is
// sent encrypt_disk_abort, a second cancel is refused while it is on its way, the device's abort cancels the
// conversion; a refused abort is stored and a device that restarted cannot be cancelled any more.
func TestDiskConversionAbort(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "encrypt-abort")
	s := newConversionSim(t, alice, "a1a")
	cancel := s.path("/encrypt/cancel")

	c := s.request(t, admin, alice)
	s.deliver(t, c.CommandID)
	waitConversion(t, alice, s.DeviceID, "the delivery", func(c *conversionView) bool { return c.CommandStatus == "delivered" })
	expectStatus(t, call(t, withoutStepUp(t, admin), http.MethodPost, cancel, s.cancelBody()), http.StatusForbidden, "step_up_required")
	admin.stepUp(t)
	res := call(t, admin.Portal, http.MethodPost, cancel, s.cancelBody())
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, alice, res.RequestID, "device.encrypt_cancelled", "success")
	after := conversionOf(t, alice, s.DeviceID)
	if ev.Params["mode"] != "abort_sent" || after.Phase != "requested" || after.AbortCommandID == nil || ev.Params["command_id"] != *after.AbortCommandID {
		t.Fatalf("abort %+v, params %v", after, ev.Params)
	}
	if aborts := commandsOfType(t, alice, s.DeviceID, "encrypt_disk_abort"); len(aborts) != 1 || !strings.Contains(string(aborts[0].Params), c.ID) {
		t.Fatalf("abort commands %+v", aborts)
	}
	expectDetail(t, call(t, admin.Portal, http.MethodPost, cancel, s.cancelBody()), http.StatusConflict, "invalid_state",
		"a cancellation is already on its way")
	s.post(t, protocol.EventDiskConversionAborted, map[string]any{"conversion_id": c.ID, "by": "admin"})
	waitConversion(t, alice, s.DeviceID, "cancelled", func(c *conversionView) bool { return c.Phase == "cancelled" })

	// The device refuses the abort because it restarted meanwhile.
	c = s.request(t, admin, alice)
	s.deliver(t, c.CommandID)
	s.post(t, protocol.EventDiskConversionPrepared, map[string]any{"conversion_id": c.ID, "layout": "lvm", "data_bytes": 100})
	waitConversion(t, alice, s.DeviceID, "prepared", func(c *conversionView) bool { return c.Phase == "prepared" })
	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPost, cancel, s.cancelBody()), http.StatusOK, "")
	abort := *conversionOf(t, alice, s.DeviceID).AbortCommandID
	s.deliver(t, abort)
	s.result(t, abort, "failed", `{"aborted":false,"reason":"not_abortable"}`)
	s.post(t, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": c.ID, "init_result": "ok"})
	refused := waitConversion(t, alice, s.DeviceID, "the refused abort", func(c *conversionView) bool {
		return c.Phase == "encrypting" && c.AbortRefusedReason != nil
	})
	if *refused.AbortRefusedReason != "not_abortable" {
		t.Fatalf("refused %+v", refused)
	}
	admin.stepUp(t)
	expectDetail(t, call(t, admin.Portal, http.MethodPost, cancel, s.cancelBody()), http.StatusConflict,
		"conversion_not_cancellable", "the device already started the encryption; it cannot be cancelled")
}

// TestDiskConversionAdoption covers the adoption of gate A1 (plan M8e decision 9, §14.10 I2): a stale initrd converted
// the disk of an aborted conversion; disk.conversion_started for it is recorded but refused while another conversion
// of the device is open, and moves it from cancelled to encrypting once none is.
func TestDiskConversionAdoption(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "encrypt-adopt")
	s := newConversionSim(t, alice, "a1o")
	aborted := s.request(t, admin, alice)
	s.deliver(t, aborted.CommandID)
	s.post(t, protocol.EventDiskConversionAborted, map[string]any{"conversion_id": aborted.ID, "by": "operator"})
	waitConversion(t, alice, s.DeviceID, "aborted", func(c *conversionView) bool { return c.ID == aborted.ID && c.Phase == "cancelled" })

	open := s.request(t, admin, alice)
	s.post(t, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": aborted.ID, "init_result": "ok"})
	idx, acme := auditIndex(t), orgOf(t, alice)
	expectOneIndexEvent(t, idx, acme, "code = 'device.disk_conversion_started' AND target->>'id' = $1", s.DeviceID,
		"device.disk_conversion_started", "success", time.Minute)
	if c := conversionOf(t, alice, s.DeviceID); c.ID != open.ID || c.Phase != "requested" {
		t.Fatalf("refused adoption: latest %+v, want the open request %s", c, open.ID)
	}

	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPost, s.path("/encrypt/cancel"), s.cancelBody()), http.StatusOK, "")
	waitConversion(t, alice, s.DeviceID, "the cancel", func(c *conversionView) bool { return c.ID == open.ID && c.Phase == "cancelled" })
	s.post(t, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": aborted.ID, "init_result": "ok"})
	adopted := waitConversion(t, alice, s.DeviceID, "the adoption", func(c *conversionView) bool { return c.ID == aborted.ID && c.Phase == "encrypting" })
	if adopted.FinishedAt != nil || !adopted.Active {
		t.Fatalf("adopted %+v", adopted)
	}
}

// TestDiskConversionUninstall covers the uninstall refusal of gate A1 (plan M8e §14.5 decision 36, §14.6 decision
// 50, amendment 2026-10-21): refused while the conversion is requested, while a failed conversion's disk reports
// encrypting and while a completed one's key is still on /boot (key_on_boot); accepted once the key left the initrd,
// also while the boot PIN is still missing.
func TestDiskConversionUninstall(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "encrypt-uninstall")
	s := newConversionSim(t, alice, "a1r")
	uninstall := func() env.Response {
		admin.stepUp(t)
		return call(t, admin.Portal, http.MethodPost, s.path("/uninstall"), map[string]any{"mode": "leave", "confirm_hostname": s.hostname, "reason": "gate A1"})
	}
	c := s.request(t, admin, alice)
	expectDetail(t, uninstall(), http.StatusConflict, "invalid_state", "an in-place encryption is open; cancel it first")

	s.deliver(t, c.CommandID)
	s.post(t, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": c.ID, "init_result": "ok"})
	s.post(t, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": c.ID, "stage": "resume", "reason": "helper_failed"})
	waitConversion(t, alice, s.DeviceID, "failed", func(c *conversionView) bool { return c.Phase == "failed" })
	reportDisk(t, alice, s.Device, `{"reconcile":"ok","disk":{"state":"encrypting","keyslots":2,"tokens":["password","tpm2+pin"]}}`,
		func(d diskView) bool { return d.State == "encrypting" })
	if c := conversionOf(t, alice, s.DeviceID); !c.Active {
		t.Fatalf("failed with health encrypting %+v", c)
	}
	expectDetail(t, uninstall(), http.StatusConflict, "invalid_state", "the in-place encryption is unfinished; wait for its completion")

	s.post(t, protocol.EventDiskConversionCompleted, map[string]any{"conversion_id": c.ID})
	waitConversion(t, alice, s.DeviceID, "completed", func(c *conversionView) bool { return c.Phase == "completed" })
	reportDisk(t, alice, s.Device, `{"reconcile":"ok","disk":{"state":"tpm_pin_missing","keyslots":2,"tokens":["password","recovery"],
		"conversion":{"eligible":false,"phase":"completed","key_on_boot":true}}}`,
		func(d diskView) bool {
			return d.State == "tpm_pin_missing" && d.Conversion != nil && d.Conversion.KeyOnBoot
		})
	if c := conversionOf(t, alice, s.DeviceID); !c.Active {
		t.Fatalf("completed with key_on_boot %+v", c)
	}
	expectDetail(t, uninstall(), http.StatusConflict, "invalid_state", "the in-place encryption is unfinished; wait for its completion")

	reportDisk(t, alice, s.Device, `{"reconcile":"ok","disk":{"state":"tpm_pin_missing","keyslots":2,"tokens":["password","recovery"],
		"conversion":{"eligible":false,"phase":"completed"}}}`,
		func(d diskView) bool {
			return d.State == "tpm_pin_missing" && d.Conversion != nil && !d.Conversion.KeyOnBoot
		})
	if c := conversionOf(t, alice, s.DeviceID); c.Active {
		t.Fatalf("completed, key no longer on /boot %+v", c)
	}
	expectStatus(t, uninstall(), http.StatusOK, "")
}

// TestDiskConversionLockAndRetire covers the lifecycle actions of gate A1 (plan M8e §14.5 decisions 38 and 39, §14.6
// decision 50): a Lock and a Retire withdraw an undelivered encrypt_disk command and record it on their own event; a
// delivered one is left alone.
func TestDiskConversionLockAndRetire(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "encrypt-lock")

	locked := newConversionSim(t, alice, "a1l")
	c := locked.request(t, admin, alice)
	res := call(t, admin.Portal, http.MethodPost, locked.path("/lock"), map[string]any{"confirm_hostname": locked.hostname, "reason": "gate A1"})
	expectStatus(t, res, http.StatusCreated, "")
	ev := expectOneEvent(t, alice, res.RequestID, "revocation.requested", "success")
	if ev.Params["conversion_cancelled"] != "before_delivery" || ev.Params["conversion_id"] != c.ID {
		t.Fatalf("revocation.requested params %v", ev.Params)
	}
	if c := conversionOf(t, alice, locked.DeviceID); c.Phase != "cancelled" || c.CommandStatus != "cancelled" {
		t.Fatalf("after the lock %+v", c)
	}

	retired := newConversionSim(t, alice, "a1t")
	c = retired.request(t, admin, alice)
	res = call(t, admin.Portal, http.MethodPost, retired.path("/retire"), nil)
	expectStatus(t, res, http.StatusOK, "")
	ev = expectOneEvent(t, alice, res.RequestID, "device.retired", "success")
	if ev.Params["conversion_cancelled"] != "before_delivery" || ev.Params["conversion_id"] != c.ID {
		t.Fatalf("device.retired params %v", ev.Params)
	}
	if c := conversionOf(t, alice, retired.DeviceID); c.Phase != "cancelled" {
		t.Fatalf("after the retirement %+v", c)
	}

	delivered := newConversionSim(t, alice, "a1d")
	c = delivered.request(t, admin, alice)
	delivered.deliver(t, c.CommandID)
	waitConversion(t, alice, delivered.DeviceID, "the delivery", func(c *conversionView) bool { return c.CommandStatus == "delivered" })
	res = call(t, admin.Portal, http.MethodPost, delivered.path("/retire"), nil)
	expectStatus(t, res, http.StatusOK, "")
	ev = expectOneEvent(t, alice, res.RequestID, "device.retired", "success")
	if ev.Params["conversion_cancelled"] != nil || ev.Params["conversion_phase"] != "requested" || ev.Params["conversion_id"] != c.ID {
		t.Fatalf("device.retired params %v", ev.Params)
	}
	if c := conversionOf(t, alice, delivered.DeviceID); c.Phase != "requested" || c.CommandStatus != "delivered" {
		t.Fatalf("after the retirement %+v", c)
	}
}

// TestDiskConversionBundle is gate A2 of plan M8e (decision 11): the v2 bundle carries the organization's boot PIN
// length, 8 by default.
func TestDiskConversionBundle(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	installRelease(t, root)
	slug, _ := gateOrganization(t)
	user, password := tempUser(t, "pinlength", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	d := v2Device(t, admin, "", bundle.SchemaVersion, bundle.SchemaVersion2)
	if b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Disk != nil }); b.Disk.BootPINMinLength != 8 {
		t.Fatalf("default bundle disk %+v", b.Disk)
	}
	settings := currentLoginSettings(t, admin)
	settings["boot_pin_min_length"] = 10
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/settings/login", settings), http.StatusOK, "")
	if b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Disk != nil && b.Disk.BootPINMinLength == 10 }); b.Disk.BootPINMinLength != 10 {
		t.Fatalf("bundle disk %+v", b.Disk)
	}
}

// TestListContractM8e is gate A3 of plan M8e (decision 10): the device list filters by the disk state encrypting and
// the command list by the new command types.
func TestListContractM8e(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "encrypt-list")
	s := newConversionSim(t, alice, "a3e")
	c := s.request(t, admin, alice)
	reportDisk(t, alice, s.Device, `{"reconcile":"ok","disk":{"state":"encrypting","keyslots":1,"tokens":["password"]}}`,
		func(d diskView) bool { return d.State == "encrypting" })
	if n := listCount(t, alice, "/api/v1/devices", url.Values{"disk_state": {"encrypting"}, "q": {s.hostname}}); n != 1 {
		t.Fatalf("disk_state filter found %d devices", n)
	}
	if n := listCount(t, alice, "/api/v1/devices", url.Values{"disk_state": {"not_encrypted"}, "q": {s.hostname}}); n != 0 {
		t.Fatalf("disk_state not_encrypted found %d devices", n)
	}
	if cmds := commandsOfType(t, alice, s.DeviceID, "encrypt_disk"); len(cmds) != 1 || cmds[0].ID != c.CommandID {
		t.Fatalf("commands %+v", cmds)
	}
}
