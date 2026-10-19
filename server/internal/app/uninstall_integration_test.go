package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type uninstallWorld struct {
	harness
	uninstalls *app.Uninstalls
	devices    *app.Devices
	reports    *app.DeviceReports
	cache      *fakeUninstallCache
	api        *db.OrgPool
	device     uuid.UUID
	hostname   string
}

func newUninstallWorld(t *testing.T) uninstallWorld {
	t.Helper()
	h := newHarness(t)
	env := pgtest.SharedPaddock(t)
	api, err := db.NewOrgPool(context.Background(), env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	worker, err := db.NewOrgPool(context.Background(), env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	cache := &fakeUninstallCache{claims: map[uuid.UUID]string{}}
	w := uninstallWorld{harness: h, uninstalls: app.NewUninstalls(h.runner, api, cache), devices: app.NewDevices(h.runner, api),
		reports: app.NewDeviceReports(app.NewActionRunner(worker, nil, httpx.RequestID), worker), cache: cache, api: api}
	w.device, w.hostname = w.newDevice(t, h.org, "active")
	return w
}

// fakeUninstallCache is the gateway's result claims (cres:) and the commands it removed from cmd:<device_id>.
type fakeUninstallCache struct {
	mu      sync.Mutex
	claims  map[uuid.UUID]string // command ID → "<device>:<status>"
	deleted []uuid.UUID
}

func (c *fakeUninstallCache) ClaimResult(_ context.Context, device, id uuid.UUID, status string) (uuid.UUID, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.claims[id]; ok {
		dev, st, _ := strings.Cut(v, ":")
		return uuid.MustParse(dev), st, nil
	}
	c.claims[id] = device.String() + ":" + status
	return device, status, nil
}

func (c *fakeUninstallCache) DeleteCommand(_ context.Context, _, id uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleted = append(c.deleted, id)
	return nil
}

func (w uninstallWorld) newDevice(t *testing.T, org uuid.UUID, state string) (uuid.UUID, string) {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	host := "un-" + id.String()[24:]
	w.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, $4)", id, org, host, state)
	return id, host
}

func (w uninstallWorld) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := w.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// as is an administrator of org with role, stepped up now when stepUp is set.
func (w uninstallWorld) as(org uuid.UUID, role principal.Role, stepUp bool) context.Context {
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: role, OrganizationID: org,
		IP: "192.0.2.1"}
	if stepUp {
		p.StepUpAt = time.Now()
	}
	return httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())
}

func (w uninstallWorld) leave() app.UninstallInput {
	return app.UninstallInput{Mode: "leave", ConfirmHostname: w.hostname, Reason: "returned laptop"}
}

// event returns the params of the newest audit event of code for the device and its outcome.
func (w uninstallWorld) event(t *testing.T, code string) (map[string]any, string) {
	t.Helper()
	var raw []byte
	var outcome string
	err := w.super.QueryRow(context.Background(), `SELECT payload -> 'params', payload ->> 'outcome' FROM outbox
		WHERE payload ->> 'code' = $1 AND payload -> 'target' ->> 'id' = $2 ORDER BY id DESC LIMIT 1`, code, w.device.String()).Scan(&raw, &outcome)
	if err != nil {
		t.Fatalf("%s: %v", code, err)
	}
	var params map[string]any
	_ = json.Unmarshal(raw, &params)
	return params, outcome
}

func (w uninstallWorld) count(t *testing.T, sql string, args ...any) (n int) {
	t.Helper()
	if err := w.super.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func expectUninstallProblem(t *testing.T, err error, code string, status int, detail string) {
	t.Helper()
	p := problem.From(err)
	if p.Code != code || p.Status != status || (detail != "" && p.Detail != detail) {
		t.Fatalf("error %v (status %d), want %s %d %q", err, p.Status, code, status, detail)
	}
}

// TestUninstallRequestAndCancel (plan M8d decisions 37 and 38): an organization administrator with a step-up issues
// the command uninstall; without a step-up, with another role, a wrong hostname or reset-only options with leave the
// request is refused; a second request conflicts; the request shows on the device and the attention list; cancel
// works while the command is pending, failed or expired and not once the device received it.
func TestUninstallRequestAndCancel(t *testing.T) {
	w := newUninstallWorld(t)
	_, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, false), w.device, w.leave())
	if !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("without a step-up: %v", err)
	}
	if _, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgOperator, true), w.device, w.leave()); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator: %v", err)
	}
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	bad := w.leave()
	bad.ConfirmHostname = "other"
	_, err = w.uninstalls.Request(admin, w.device, bad)
	expectUninstallProblem(t, err, "invalid_request", 422, "confirm_hostname does not match")
	for _, in := range []app.UninstallInput{
		{Mode: "leave", ConfirmHostname: w.hostname, Reason: "r1", ClearTPM: true},
		{Mode: "leave", ConfirmHostname: w.hostname, Reason: "r1", KeepLocalAdmin: true},
		{Mode: "wipe", ConfirmHostname: w.hostname, Reason: "r1"},
		{Mode: "reset", ConfirmHostname: w.hostname, Reason: "r"},
	} {
		_, err := w.uninstalls.Request(admin, w.device, in)
		expectUninstallProblem(t, err, "invalid_request", 422, "")
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1", w.device); n != 0 {
		t.Fatalf("%d commands after refused requests", n)
	}

	dev, err := w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil || dev.UninstallMode == nil || *dev.UninstallMode != "leave" || dev.UninstallRequestedAt == nil || !dev.UninstallCommandID.Valid {
		t.Fatalf("request: %+v, %v", dev, err)
	}
	cmd := dev.UninstallCommandID.UUID
	var params []byte
	var expires time.Duration
	if err := w.super.QueryRow(context.Background(), `SELECT params, expires_at - issued_at FROM device_command
		WHERE id = $1 AND type = 'uninstall' AND status = 'pending'`, cmd).Scan(&params, &expires); err != nil {
		t.Fatal(err)
	}
	if string(params) != `{"mode": "leave"}` || expires != 7*24*time.Hour {
		t.Fatalf("command params %s, lifetime %s", params, expires)
	}
	p, outcome := w.event(t, "device.uninstall_requested")
	if outcome != "success" || p["mode"] != "leave" || p["clear_tpm"] != false || p["keep_local_admin"] != false ||
		p["reason"] != "returned laptop" || p["command_id"] != cmd.String() || p["hostname"] != w.hostname {
		t.Fatalf("params %v (%s)", p, outcome)
	}
	detail, err := w.devices.Get(w.as(w.org, principal.RoleOrgAuditor, false), w.device)
	if err != nil || detail.Uninstall == nil || detail.Uninstall.CommandStatus != "pending" || detail.Uninstall.Mode != "leave" ||
		detail.Uninstall.CommandID != cmd {
		t.Fatalf("detail %+v, %v", detail.Uninstall, err)
	}
	attention := "SELECT count(*) FROM attention_condition WHERE device_id = $1 AND kind = 'uninstall_pending' AND detail = $2"
	if n := w.count(t, attention, w.device, "leave:pending"); n != 1 {
		t.Fatalf("attention rows %d", n)
	}
	_, err = w.uninstalls.Request(admin, w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "an uninstall is already requested")

	// Isolation: another organization's administrator finds neither the device nor its request.
	other := uuid.Must(uuid.NewV7())
	w.exec(t, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')", other, "o"+other.String()[24:])
	foreign := w.as(other, principal.RoleOrgAdmin, true)
	_, err = w.uninstalls.Request(foreign, w.device, w.leave())
	expectUninstallProblem(t, err, "not_found", 404, "")
	_, err = w.uninstalls.Cancel(foreign, w.device)
	expectUninstallProblem(t, err, "not_found", 404, "")
	if _, err := w.uninstalls.Cancel(w.as(w.org, principal.RoleOrgOperator, false), w.device); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator cancel: %v", err)
	}

	dev, err = w.uninstalls.Cancel(w.as(w.org, principal.RoleOrgAdmin, false), w.device)
	if err != nil || dev.UninstallRequestedAt != nil || dev.UninstallMode != nil || dev.UninstallCommandID.Valid {
		t.Fatalf("cancel: %+v, %v", dev, err)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'cancelled' AND finished_at IS NOT NULL", cmd); n != 1 {
		t.Fatal("command not cancelled")
	}
	if p, _ := w.event(t, "device.uninstall_cancelled"); p["command_id"] != cmd.String() || p["mode"] != "leave" {
		t.Fatalf("cancel params %v", p)
	}
	if n := w.count(t, attention, w.device, "leave:pending"); n != 0 {
		t.Fatal("attention row after the cancel")
	}
	_, err = w.uninstalls.Cancel(admin, w.device)
	expectUninstallProblem(t, err, "invalid_state", 409, "no uninstall is requested")

	// Delivered: no cancel; failed or expired: cancel.
	dev, err = w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	w.exec(t, "UPDATE device_command SET status = 'delivered' WHERE id = $1", dev.UninstallCommandID.UUID)
	_, err = w.uninstalls.Cancel(admin, w.device)
	expectUninstallProblem(t, err, "invalid_state", 409, "the device already received the command")
	for _, status := range []string{"failed", "expired"} {
		w.exec(t, "UPDATE device_command SET status = $2 WHERE id = $1", dev.UninstallCommandID.UUID, status)
		if _, err := w.uninstalls.Cancel(admin, w.device); err != nil {
			t.Fatalf("cancel after %s: %v", status, err)
		}
		if dev, err = w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave()); err != nil {
			t.Fatal(err)
		}
	}
	w.exec(t, "UPDATE device_command SET status = 'succeeded' WHERE id = $1", dev.UninstallCommandID.UUID)
	_, err = w.uninstalls.Cancel(admin, w.device)
	expectUninstallProblem(t, err, "invalid_state", 409, "the uninstall completed")
}

// TestUninstallRefusals: a device that is not active, an open Lock and clear_tpm while a volume unlocks with the TPM
// refuse the request; reset with clear_tpm is accepted on a passphrase-only disk.
func TestUninstallRefusals(t *testing.T) {
	w := newUninstallWorld(t)
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	quarantined, host := w.newDevice(t, w.org, "quarantined")
	_, err := w.uninstalls.Request(admin, quarantined, app.UninstallInput{Mode: "leave", ConfirmHostname: host, Reason: "rr"})
	expectUninstallProblem(t, err, "invalid_state", 409, "only active devices can be uninstalled")

	lock := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by)
		VALUES ($1, $2, $3, 'lock', 'issued', $4)`, lock, w.org, w.device, uuid.Must(uuid.NewV7()))
	_, err = w.uninstalls.Request(admin, w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "a lock or destroy is pending for this device")
	w.exec(t, "UPDATE revocation_request SET status = 'confirmed' WHERE id = $1", lock)

	reset := app.UninstallInput{Mode: "reset", ConfirmHostname: w.hostname, Reason: "reissue", ClearTPM: true}
	for _, health := range []string{
		`{"disk": {"state": "compliant", "tokens": ["recovery", "tpm2+pin"], "keyslots": 2}}`,
		`{"disk": {"state": "compliant", "tokens": ["password"], "keyslots": 1, "volumes": [{"uuid": "u", "device": "/dev/sdb1", "tokens": ["tpm2"], "keyslots": 1, "escrowed": true}]}}`,
	} {
		w.exec(t, `INSERT INTO device_status (device_id, organization_id, health) VALUES ($1, $2, $3)
			ON CONFLICT (device_id) DO UPDATE SET health = EXCLUDED.health`, w.device, w.org, health)
		_, err = w.uninstalls.Request(admin, w.device, reset)
		expectUninstallProblem(t, err, "tpm_in_use_by_disk", 409, "the disk unlocks with the TPM; clearing it would leave only the recovery key")
	}
	w.exec(t, `UPDATE device_status SET health = '{"disk": {"state": "compliant", "tokens": ["password", "recovery"], "keyslots": 2}}'
		WHERE device_id = $1`, w.device)
	dev, err := w.uninstalls.Request(admin, w.device, reset)
	if err != nil {
		t.Fatal(err)
	}
	var params []byte
	if err := w.super.QueryRow(context.Background(), "SELECT params FROM device_command WHERE id = $1", dev.UninstallCommandID.UUID).Scan(&params); err != nil {
		t.Fatal(err)
	}
	if string(params) != `{"mode": "reset", "clear_tpm": true}` {
		t.Fatalf("params %s", params)
	}
}

// TestUninstalledRetiresTheDevice (plan M8d decision 41): the device's report is audited as device.uninstalled with
// the device as actor and its params, marks the device and keeps the outcome with the command; the retirement records
// device.retired with reason uninstalled once, and a redelivery records nothing.
func TestUninstalledRetiresTheDevice(t *testing.T) {
	w := newUninstallWorld(t)
	dev, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	cmd := dev.UninstallCommandID.UUID
	w.exec(t, "UPDATE device_command SET status = 'succeeded', result = '{\"accepted\": true}' WHERE id = $1", cmd)
	steps := map[string]string{"stop": "done", "apt": "done", "sudoers": "done", "quarantine": "skipped", "packages": "done"}
	data, _ := json.Marshal(protocol.AgentUninstalled{CommandID: cmd.String(), Mode: "leave", Outcome: protocol.UninstallCompleted,
		LocalAdmin: "kept", TPM: "not_requested", Steps: steps})
	ev := protocol.Event{EventSeq: 7, Type: protocol.EventAgentUninstalled, OccurredAt: time.Now(), Data: data}
	for range 2 {
		if _, err := w.reports.RecordEvent(systemCtx(w.org), w.device, ev); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.count(t, "SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'device.uninstalled' AND payload -> 'target' ->> 'id' = $1", w.device.String()); n != 1 {
		t.Fatalf("%d device.uninstalled events", n)
	}
	p, _ := w.event(t, "device.uninstalled")
	if p["outcome"] != "completed" || p["local_admin"] != "kept" || p["tpm"] != "not_requested" || p["mode"] != "leave" ||
		p["command_id"] != cmd.String() || len(p["steps"].(map[string]any)) != len(steps) {
		t.Fatalf("params %v", p)
	}
	for range 2 {
		if _, err := w.reports.RetireUninstalled(systemCtx(w.org), w.device); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.count(t, "SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'device.retired' AND payload -> 'target' ->> 'id' = $1", w.device.String()); n != 1 {
		t.Fatalf("%d device.retired events", n)
	}
	p, _ = w.event(t, "device.retired")
	if p["reason"] != "uninstalled" || p["from_state"] != "active" {
		t.Fatalf("retired params %v", p)
	}
	detail, err := w.devices.Get(w.as(w.org, principal.RoleOrgAuditor, false), w.device)
	if err != nil || detail.Device.State != "retired" || detail.Device.RetiredReason == nil || *detail.Device.RetiredReason != "uninstalled" ||
		detail.Device.UninstalledAt == nil || detail.Uninstall == nil || detail.Uninstall.LocalAdmin != "kept" ||
		detail.Uninstall.Tpm != "not_requested" || detail.Uninstall.UninstalledAt == nil {
		t.Fatalf("device %+v uninstall %+v, %v", detail.Device, detail.Uninstall, err)
	}
	if n := w.count(t, "SELECT count(*) FROM attention_condition WHERE device_id = $1", w.device); n != 0 {
		t.Fatalf("%d attention rows of a retired device", n)
	}
	// A device without a removal report is never retired by it.
	other, _ := w.newDevice(t, w.org, "active")
	if retired, err := w.reports.RetireUninstalled(systemCtx(w.org), other); err != nil || retired {
		t.Fatalf("retired %v, %v", retired, err)
	}
}

// TestUninstallHelperFailed (plan M8d decision 39): a device that could not start the removal reports helper_failed;
// the device stays active, the request ends and can be made again.
func TestUninstallHelperFailed(t *testing.T) {
	w := newUninstallWorld(t)
	dev, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	w.exec(t, "UPDATE device_command SET status = 'succeeded', result = '{\"accepted\": true}' WHERE id = $1", dev.UninstallCommandID.UUID)
	data, _ := json.Marshal(protocol.AgentUninstalled{CommandID: dev.UninstallCommandID.UUID.String(), Mode: "leave",
		Outcome: protocol.UninstallHelperFailed, LocalAdmin: "kept", TPM: "not_requested", Steps: map[string]string{}})
	if _, err := w.reports.RecordEvent(systemCtx(w.org), w.device, protocol.Event{EventSeq: 3, Type: protocol.EventAgentUninstalled,
		OccurredAt: time.Now(), Data: data}); err != nil {
		t.Fatal(err)
	}
	if retired, err := w.reports.RetireUninstalled(systemCtx(w.org), w.device); err != nil || retired {
		t.Fatalf("retired %v, %v", retired, err)
	}
	detail, err := w.devices.Get(w.as(w.org, principal.RoleOrgAuditor, false), w.device)
	if err != nil || detail.Device.State != "active" || detail.Uninstall != nil || detail.Device.UninstalledAt != nil {
		t.Fatalf("device %+v uninstall %+v, %v", detail.Device, detail.Uninstall, err)
	}
	if _, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave()); err != nil {
		t.Fatalf("request again: %v", err)
	}
}

// uninstalledEvent is the device's removal report for cmd.
func uninstalledEvent(seq int64, cmd uuid.UUID) protocol.Event {
	data, _ := json.Marshal(protocol.AgentUninstalled{CommandID: cmd.String(), Mode: "leave", Outcome: protocol.UninstallCompleted,
		LocalAdmin: "kept", TPM: "not_requested", Steps: map[string]string{"apt": "done"}})
	return protocol.Event{EventSeq: seq, Type: protocol.EventAgentUninstalled, OccurredAt: time.Now(), Data: data}
}

// TestUninstallCancelWithdrawsFromTheGateway (review finding 1): a cancel claims the command's result as cancelled
// and removes the command from cmd:<device_id>, so a result the device posts afterwards is a conflict; a result the
// device posted before the worker recorded it refuses the cancel; a report after a cancel retires nothing.
func TestUninstallCancelWithdrawsFromTheGateway(t *testing.T) {
	w := newUninstallWorld(t)
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	dev, err := w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	cmd := dev.UninstallCommandID.UUID
	if _, err := w.uninstalls.Cancel(admin, w.device); err != nil {
		t.Fatal(err)
	}
	if w.cache.claims[cmd] != w.device.String()+":cancelled" || len(w.cache.deleted) != 1 || w.cache.deleted[0] != cmd {
		t.Fatalf("claims %v, deleted %v", w.cache.claims, w.cache.deleted)
	}
	if _, status, _ := w.cache.ClaimResult(context.Background(), w.device, cmd, "succeeded"); status != "cancelled" {
		t.Fatalf("the device's later result was accepted: %s", status)
	}
	// The device's report after the cancel is audited but does not mark or retire the device.
	if _, err := w.reports.RecordEvent(systemCtx(w.org), w.device, uninstalledEvent(11, cmd)); err != nil {
		t.Fatal(err)
	}
	if retired, err := w.reports.RetireUninstalled(systemCtx(w.org), w.device); err != nil || retired {
		t.Fatalf("retired after a cancel: %v, %v", retired, err)
	}
	if n := w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND state = 'active' AND uninstalled_at IS NULL", w.device); n != 1 {
		t.Fatal("device marked after a cancel")
	}

	// The device's result was claimed before the cancel (the worker has not recorded it yet): the cancel is refused.
	dev, err = w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	cmd = dev.UninstallCommandID.UUID
	w.cache.claims[cmd] = w.device.String() + ":succeeded"
	_, err = w.uninstalls.Cancel(admin, w.device)
	expectUninstallProblem(t, err, "invalid_state", 409, "the device already received the command")
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'pending'", cmd); n != 1 {
		t.Fatal("refused cancel changed the command")
	}
	if len(w.cache.deleted) != 1 {
		t.Fatalf("refused cancel removed the command: %v", w.cache.deleted)
	}
}

// TestUninstalledOnlyForTheRequest (review finding 2): an unsolicited report, one for another command and one whose
// command has no successful result never mark or retire the device; a report that arrives before the worker recorded
// the result is retried and marks the device once the result succeeded.
func TestUninstalledOnlyForTheRequest(t *testing.T) {
	w := newUninstallWorld(t)
	if _, err := w.reports.RecordEvent(systemCtx(w.org), w.device, uninstalledEvent(1, uuid.Must(uuid.NewV7()))); err != nil {
		t.Fatal(err)
	}
	if _, outcome := w.event(t, "device.uninstalled"); outcome != "success" {
		t.Fatalf("unsolicited report not audited: %s", outcome)
	}
	if retired, err := w.reports.RetireUninstalled(systemCtx(w.org), w.device); err != nil || retired {
		t.Fatalf("unsolicited report retired: %v, %v", retired, err)
	}
	dev, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	cmd := dev.UninstallCommandID.UUID
	if _, err := w.reports.RecordEvent(systemCtx(w.org), w.device, uninstalledEvent(2, uuid.Must(uuid.NewV7()))); err != nil {
		t.Fatal(err)
	}
	w.exec(t, "UPDATE device_command SET status = 'failed' WHERE id = $1", cmd)
	if _, err := w.reports.RecordEvent(systemCtx(w.org), w.device, uninstalledEvent(3, cmd)); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstalled_at IS NULL", w.device); n != 1 {
		t.Fatal("device marked by a report without a successful command")
	}
	w.exec(t, "UPDATE device_command SET status = 'delivered' WHERE id = $1", cmd)
	if err := w.reports.RecordEvents(systemCtx(w.org), w.device, []protocol.Event{uninstalledEvent(4, cmd)}); err == nil {
		t.Fatal("report before the result was not retried")
	}
	w.exec(t, "UPDATE device_command SET status = 'succeeded' WHERE id = $1", cmd)
	if err := w.reports.RecordEvents(systemCtx(w.org), w.device, []protocol.Event{uninstalledEvent(4, cmd)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.reports.RetireUninstalled(systemCtx(w.org), w.device)
		}()
	}
	wg.Wait()
	if n := w.count(t, "SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'device.retired' AND payload -> 'target' ->> 'id' = $1", w.device.String()); n != 1 {
		t.Fatalf("%d device.retired events for concurrent reports", n)
	}
}

// TestUninstallReportOverdue (review finding 8): a request the device received more than UninstallReportTimeout ago
// without a removal report can be cancelled and requested again (param report_overdue); a report of the old command
// then retires nothing.
func TestUninstallReportOverdue(t *testing.T) {
	w := newUninstallWorld(t)
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	dev, err := w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	old := dev.UninstallCommandID.UUID
	w.exec(t, "UPDATE device_command SET status = 'succeeded', delivered_at = now() - interval '23 hours', finished_at = now() - interval '23 hours' WHERE id = $1", old)
	_, err = w.uninstalls.Cancel(admin, w.device)
	expectUninstallProblem(t, err, "invalid_state", 409, "the uninstall completed")
	_, err = w.uninstalls.Request(admin, w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "an uninstall is already requested")

	if detail, err := w.devices.Get(admin, w.device); err != nil || detail.UninstallReportOverdue {
		t.Fatalf("overdue after 23 hours: %v", err)
	}
	w.exec(t, "UPDATE device_command SET finished_at = now() - interval '25 hours' WHERE id = $1", old)
	if detail, err := w.devices.Get(admin, w.device); err != nil || !detail.UninstallReportOverdue {
		t.Fatalf("not overdue after 25 hours: %v", err)
	}
	dev, err = w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil || dev.UninstallCommandID.UUID == old {
		t.Fatalf("request again: %+v, %v", dev, err)
	}
	if p, _ := w.event(t, "device.uninstall_requested"); p["report_overdue"] != true {
		t.Fatalf("params %v", p)
	}
	w.exec(t, "UPDATE device_command SET status = 'delivered', delivered_at = now() - interval '25 hours' WHERE id = $1", dev.UninstallCommandID.UUID)
	if _, err := w.uninstalls.Cancel(admin, w.device); err != nil {
		t.Fatal(err)
	}
	if p, _ := w.event(t, "device.uninstall_cancelled"); p["report_overdue"] != true {
		t.Fatalf("params %v", p)
	}
	if _, err := w.reports.RecordEvent(systemCtx(w.org), w.device, uninstalledEvent(9, old)); err != nil {
		t.Fatal(err)
	}
	if retired, err := w.reports.RetireUninstalled(systemCtx(w.org), w.device); err != nil || retired {
		t.Fatalf("a report of the withdrawn command retired: %v, %v", retired, err)
	}
}

// TestUninstallOverdueWithdrawsTheDeliveredCommand (review 2 finding A): an overdue cancel or re-request of an
// uninstall whose command the device received cancels that command, claims its result as cancelled and removes it
// from the gateway, so a device that comes back with it never removes itself; a result the device claimed first
// refuses both.
func TestUninstallOverdueWithdrawsTheDeliveredCommand(t *testing.T) {
	w := newUninstallWorld(t)
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	deliveredLongAgo := func(id uuid.UUID) {
		w.exec(t, "UPDATE device_command SET status = 'delivered', delivered_at = now() - interval '25 hours' WHERE id = $1", id)
	}
	withdrawn := func(id uuid.UUID) {
		t.Helper()
		if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'cancelled'", id); n != 1 {
			t.Fatalf("command %s not cancelled", id)
		}
		if owner, status, _ := w.cache.ClaimResult(context.Background(), uuid.Nil, id, "succeeded"); owner != w.device || status != "cancelled" {
			t.Fatalf("result claim of %s: %s %s", id, owner, status)
		}
		if !slices.Contains(w.cache.deleted, id) {
			t.Fatalf("command %s left in the gateway cache", id)
		}
	}

	dev, err := w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	first := dev.UninstallCommandID.UUID
	deliveredLongAgo(first)
	if dev, err = w.uninstalls.Request(admin, w.device, w.leave()); err != nil {
		t.Fatal(err)
	}
	withdrawn(first)
	second := dev.UninstallCommandID.UUID
	deliveredLongAgo(second)
	if _, err := w.uninstalls.Cancel(admin, w.device); err != nil {
		t.Fatal(err)
	}
	withdrawn(second)

	dev, err = w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	third := dev.UninstallCommandID.UUID
	deliveredLongAgo(third)
	if _, _, err := w.cache.ClaimResult(context.Background(), w.device, third, "succeeded"); err != nil {
		t.Fatal(err)
	}
	_, err = w.uninstalls.Cancel(admin, w.device)
	expectUninstallProblem(t, err, "invalid_state", 409, "the device already reported a result")
	_, err = w.uninstalls.Request(admin, w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "the device already reported a result")
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'delivered'", third); n != 1 {
		t.Fatal("the command the device reported was changed")
	}
	if n := w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_command_id = $2", w.device, third); n != 1 {
		t.Fatal("the request was cleared")
	}
}

// stepUpTokens hands out a step-up ID token for every jti.
type stepUpTokens struct{}

func (stepUpTokens) Get(context.Context, string) (string, bool, error) { return "id-token", true, nil }

// TestRevocationCancelsUninstall (review 2 finding D, replaces PDK-327's refusal): Lock and Destroy are never blocked
// by an uninstall. The request cancels an uninstall without a removal report in the same transaction — a pending or
// delivered command is withdrawn like a cancel, one the device already answered stays — and records it as the params
// uninstall_cancelled and uninstall_command_id of the one revocation.requested event (no second event: ActionRunner
// records exactly one per attempt); after_delivery warns that the device may already have removed paddock-revoke. A
// refused revocation leaves the uninstall alone.
func TestRevocationCancelsUninstall(t *testing.T) {
	w := newUninstallWorld(t)
	revocations := app.NewRevocations(w.runner, w.api, stepUpTokens{}, w.cache, true)
	stepUp := func() context.Context {
		p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: principal.RoleOrgAdmin,
			OrganizationID: w.org, IP: "192.0.2.1", StepUpAt: time.Now(), StepUpJTI: uuid.NewString(), Subject: uuid.NewString()}
		return httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())
	}
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	events := func(dev uuid.UUID, code string) int {
		return w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = $1 AND payload -> 'target' ->> 'id' = $2`, code, dev.String())
	}

	for _, tc := range []struct {
		name, action, status string
		deviceClaimed        bool
		want                 string
		withdrawn            bool
	}{
		{"pending", "lock", "pending", false, app.UninstallCancelledBeforeDelivery, true},
		{"delivered", "destroy", "delivered", false, app.UninstallCancelledAfterDelivery, true},
		{"device reported first", "lock", "delivered", true, app.UninstallCancelledAfterDelivery, false},
		{"succeeded", "lock", "succeeded", false, app.UninstallCancelledAfterDelivery, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev, host := w.newDevice(t, w.org, "active")
			u, err := w.uninstalls.Request(admin, dev, app.UninstallInput{Mode: "leave", ConfirmHostname: host, Reason: "returned laptop"})
			if err != nil {
				t.Fatal(err)
			}
			cmd := u.UninstallCommandID.UUID
			if tc.status != "pending" {
				w.exec(t, "UPDATE device_command SET status = $2, delivered_at = now() WHERE id = $1", cmd, tc.status)
			}
			if tc.deviceClaimed {
				if _, _, err := w.cache.ClaimResult(context.Background(), dev, cmd, "succeeded"); err != nil {
					t.Fatal(err)
				}
			}
			req, cancelled, err := revocations.Request(stepUp(), app.RevocationInput{DeviceID: dev, Action: tc.action, ConfirmHostname: host, Reason: "stolen"})
			if err != nil || cancelled != tc.want || req.DeviceID != dev {
				t.Fatalf("request: %q, %v; want %q", cancelled, err, tc.want)
			}
			if n := w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_requested_at IS NULL", dev); n != 1 {
				t.Fatal("the uninstall stayed requested")
			}
			wantStatus := tc.status
			if tc.withdrawn {
				wantStatus = "cancelled"
			}
			if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = $2", cmd, wantStatus); n != 1 {
				t.Fatalf("command not %s", wantStatus)
			}
			if tc.withdrawn {
				if _, status, _ := w.cache.ClaimResult(context.Background(), uuid.Nil, cmd, "succeeded"); status != "cancelled" {
					t.Fatalf("result claim %q", status)
				}
			}
			if events(dev, "device.uninstall_cancelled") != 0 || events(dev, "revocation.requested") != 1 {
				t.Fatalf("events: %d device.uninstall_cancelled, %d revocation.requested", events(dev, "device.uninstall_cancelled"),
					events(dev, "revocation.requested"))
			}
			var raw []byte
			if err := w.super.QueryRow(context.Background(), `SELECT payload -> 'params' FROM outbox WHERE payload ->> 'code' = 'revocation.requested'
				AND payload -> 'target' ->> 'id' = $1`, dev.String()).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var params map[string]any
			_ = json.Unmarshal(raw, &params)
			if params["uninstall_cancelled"] != tc.want || params["uninstall_command_id"] != cmd.String() || params["request_id"] != req.ID.String() {
				t.Fatalf("params %v", params)
			}
		})
	}

	t.Run("refused revocation", func(t *testing.T) {
		dev, host := w.newDevice(t, w.org, "active")
		if _, err := w.uninstalls.Request(admin, dev, app.UninstallInput{Mode: "leave", ConfirmHostname: host, Reason: "returned laptop"}); err != nil {
			t.Fatal(err)
		}
		_, _, err := revocations.Request(admin, app.RevocationInput{DeviceID: dev, Action: "lock", ConfirmHostname: host, Reason: "stolen"})
		if !errors.Is(err, problem.StepUpRequired) {
			t.Fatalf("without a step-up proof: %v", err)
		}
		if n := w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_requested_at IS NOT NULL", dev); n != 1 {
			t.Fatal("a refused revocation cleared the uninstall")
		}
		if n := events(dev, "device.uninstall_cancelled"); n != 0 {
			t.Fatalf("%d device.uninstall_cancelled after a refused revocation", n)
		}
		if n := w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'revocation.requested' AND payload -> 'target' ->> 'id' = $1
			AND payload -> 'params' ? 'uninstall_cancelled'`, dev.String()); n != 0 {
			t.Fatal("a refused revocation recorded uninstall_cancelled")
		}
	})

	t.Run("no uninstall", func(t *testing.T) {
		dev, host := w.newDevice(t, w.org, "active")
		_, cancelled, err := revocations.Request(stepUp(), app.RevocationInput{DeviceID: dev, Action: "lock", ConfirmHostname: host, Reason: "stolen"})
		if err != nil || cancelled != "" || events(dev, "device.uninstall_cancelled") != 0 || events(dev, "revocation.requested") != 1 {
			t.Fatalf("%q, %v", cancelled, err)
		}
		if n := w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'revocation.requested' AND payload -> 'target' ->> 'id' = $1
			AND payload -> 'params' ? 'uninstall_cancelled'`, dev.String()); n != 0 {
			t.Fatal("uninstall_cancelled without an uninstall")
		}
	})
}

// resultMeanwhileCache is a fakeUninstallCache whose claims let the worker record the device's result first: the
// gateway publishes a result before it claims it.
type resultMeanwhileCache struct {
	*fakeUninstallCache
	record func(id uuid.UUID)
}

func (c resultMeanwhileCache) ClaimResult(ctx context.Context, device, id uuid.UUID, status string) (uuid.UUID, string, error) {
	c.record(id)
	return c.fakeUninstallCache.ClaimResult(ctx, device, id, status)
}

// TestUninstallResultRecordedWhileWithdrawn (review 3 finding F): the worker records the device's result between the
// read of the command and its withdrawal, although the withdrawal won the result claim. A Lock still goes ahead, with
// after_delivery and the request cleared; a cancel is refused.
func TestUninstallResultRecordedWhileWithdrawn(t *testing.T) {
	w := newUninstallWorld(t)
	cache := resultMeanwhileCache{fakeUninstallCache: w.cache, record: func(id uuid.UUID) {
		w.exec(t, "UPDATE device_command SET status = 'succeeded', finished_at = now() WHERE id = $1", id)
	}}
	revocations := app.NewRevocations(w.runner, w.api, stepUpTokens{}, cache, true)
	uninstalls := app.NewUninstalls(w.runner, w.api, cache)
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: principal.RoleOrgAdmin,
		OrganizationID: w.org, IP: "192.0.2.1", StepUpAt: time.Now(), StepUpJTI: uuid.NewString(), Subject: uuid.NewString()}
	admin := httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())

	t.Run("lock", func(t *testing.T) {
		dev, host := w.newDevice(t, w.org, "active")
		u, err := w.uninstalls.Request(admin, dev, app.UninstallInput{Mode: "leave", ConfirmHostname: host, Reason: "returned laptop"})
		if err != nil {
			t.Fatal(err)
		}
		cmd := u.UninstallCommandID.UUID
		w.exec(t, "UPDATE device_command SET status = 'delivered', delivered_at = now() WHERE id = $1", cmd)
		_, cancelled, err := revocations.Request(admin, app.RevocationInput{DeviceID: dev, Action: "lock", ConfirmHostname: host, Reason: "stolen"})
		if err != nil || cancelled != app.UninstallCancelledAfterDelivery {
			t.Fatalf("lock: %q, %v; want after_delivery", cancelled, err)
		}
		if n := w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_requested_at IS NULL", dev); n != 1 {
			t.Fatal("the uninstall stayed requested")
		}
		if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'succeeded'", cmd); n != 1 {
			t.Fatal("the recorded result was changed")
		}
		if n := w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'revocation.requested' AND payload ->> 'outcome' = 'success'
			AND payload -> 'target' ->> 'id' = $1 AND payload -> 'params' ->> 'uninstall_cancelled' = 'after_delivery'`, dev.String()); n != 1 {
			t.Fatalf("%d revocation.requested with after_delivery", n)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		dev, host := w.newDevice(t, w.org, "active")
		u, err := w.uninstalls.Request(admin, dev, app.UninstallInput{Mode: "leave", ConfirmHostname: host, Reason: "returned laptop"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = uninstalls.Cancel(admin, dev)
		expectUninstallProblem(t, err, "invalid_state", 409, "the command can no longer be cancelled")
		if n := w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_command_id = $2", dev, u.UninstallCommandID.UUID); n != 1 {
			t.Fatal("a refused cancel cleared the request")
		}
	})
}

// TestUninstallOverdueRequestClaimsAfterItsChecks (review 3 finding G): a re-request of an overdue uninstall that
// fails a check leaves the delivered command and its result unclaimed, because the claim survives a rollback.
func TestUninstallOverdueRequestClaimsAfterItsChecks(t *testing.T) {
	w := newUninstallWorld(t)
	admin := w.as(w.org, principal.RoleOrgAdmin, true)
	dev, err := w.uninstalls.Request(admin, w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	cmd := dev.UninstallCommandID.UUID
	w.exec(t, "UPDATE device_command SET status = 'delivered', delivered_at = now() - interval '25 hours' WHERE id = $1", cmd)
	in := w.leave()
	in.ClearTPM = true
	_, err = w.uninstalls.Request(admin, w.device, in)
	expectUninstallProblem(t, err, "invalid_request", 422, "clear_tpm and keep_local_admin apply to mode reset only")
	if owner, status, _ := w.cache.ClaimResult(context.Background(), w.device, cmd, "succeeded"); owner != w.device || status != "succeeded" {
		t.Fatalf("result of the open command already claimed: %s %s", owner, status)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'delivered'", cmd); n != 1 {
		t.Fatal("a refused request changed the open command")
	}
}
