package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/disk"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type conversionWorld struct {
	uninstallWorld
	conversions *app.DiskConversions
	commands    *app.DeviceCommands
	seq         *int64
}

// eligibleHealth is the health of an unencrypted device with a convertible layout.
const eligibleHealth = `{"disk": {"state": "not_encrypted", "keyslots": 0, "boot_separate": true,
	"conversion": {"eligible": true, "layout": "lvm", "release": "26.04", "initramfs": "dracut"}}}`

func newConversionWorld(t *testing.T) conversionWorld {
	t.Helper()
	w := conversionWorld{uninstallWorld: newUninstallWorld(t), seq: new(int64)}
	worker, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	w.conversions = app.NewDiskConversions(w.runner, w.api, w.cache)
	w.commands = app.NewDeviceCommands(worker)
	w.health(t, w.device, eligibleHealth)
	return w
}

func (w conversionWorld) health(t *testing.T, dev uuid.UUID, health string) {
	t.Helper()
	w.exec(t, `INSERT INTO device_status (device_id, organization_id, health) VALUES ($1, $2, $3)
		ON CONFLICT (device_id) DO UPDATE SET health = EXCLUDED.health`, dev, w.org, health)
}

func (w conversionWorld) input() app.DiskConversionInput {
	return app.DiskConversionInput{ConfirmHostname: w.hostname, Reason: "policy", BackupConfirmed: true}
}

func (w conversionWorld) admin() context.Context { return w.as(w.org, principal.RoleOrgAdmin, true) }

// request opens a conversion of the world's device and returns it with its command.
func (w conversionWorld) request(t *testing.T) (conversion, cmd uuid.UUID) {
	t.Helper()
	if _, err := w.conversions.Request(w.admin(), w.device, w.input()); err != nil {
		t.Fatal(err)
	}
	if err := w.super.QueryRow(context.Background(), `SELECT id, command_id FROM device_disk_conversion WHERE device_id = $1
		ORDER BY requested_at DESC, id DESC LIMIT 1`, w.device).Scan(&conversion, &cmd); err != nil {
		t.Fatal(err)
	}
	return conversion, cmd
}

// row is the phase and the failure of a conversion.
func (w conversionWorld) row(t *testing.T, id uuid.UUID) (phase, stage, reason string, finished bool) {
	t.Helper()
	var s, r *string
	var f *time.Time
	if err := w.super.QueryRow(context.Background(), `SELECT phase, failure_stage, failure_reason, finished_at
		FROM device_disk_conversion WHERE id = $1`, id).Scan(&phase, &s, &r, &f); err != nil {
		t.Fatal(err)
	}
	if s != nil {
		stage = *s
	}
	if r != nil {
		reason = *r
	}
	return phase, stage, reason, f != nil
}

func (w conversionWorld) expectPhase(t *testing.T, id uuid.UUID, want string) {
	t.Helper()
	if phase, _, _, _ := w.row(t, id); phase != want {
		t.Fatalf("phase %s, want %s", phase, want)
	}
}

// post records a device event of the world's device.
func (w conversionWorld) post(t *testing.T, dev uuid.UUID, typ string, data map[string]any) {
	t.Helper()
	*w.seq++
	raw, _ := json.Marshal(data)
	if _, err := w.reports.RecordEvent(systemCtx(w.org), dev, protocol.Event{EventSeq: *w.seq, Type: typ, OccurredAt: time.Now(), Data: raw}); err != nil {
		t.Fatal(err)
	}
}

// result records a command result as the worker does.
func (w conversionWorld) result(t *testing.T, cmd uuid.UUID, status, result string) {
	t.Helper()
	if err := w.commands.Finish(systemCtx(w.org), ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org, CommandID: cmd,
		Status: status, Result: json.RawMessage(result), ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

// TestDiskConversionRequest (plan M8e decision 7): an organization administrator with a step-up asks an active,
// eligible device to encrypt in place; every precondition is checked and the request records one event with the
// command and the conversion.
func TestDiskConversionRequest(t *testing.T) {
	w := newConversionWorld(t)
	if _, err := w.conversions.Request(w.as(w.org, principal.RoleOrgAdmin, false), w.device, w.input()); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("without a step-up: %v", err)
	}
	if _, err := w.conversions.Request(w.as(w.org, principal.RoleOrgOperator, true), w.device, w.input()); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator: %v", err)
	}
	if _, err := w.conversions.Request(w.as(uuid.Must(uuid.NewV7()), principal.RoleOrgAdmin, true), w.device, w.input()); !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization: %v", err)
	}
	bad := w.input()
	bad.ConfirmHostname = "other"
	_, err := w.conversions.Request(w.admin(), w.device, bad)
	expectUninstallProblem(t, err, "invalid_request", 422, "confirm_hostname does not match")
	bad = w.input()
	bad.BackupConfirmed = false
	_, err = w.conversions.Request(w.admin(), w.device, bad)
	expectUninstallProblem(t, err, "invalid_request", 422, "backup_confirmed must be true")
	bad = w.input()
	bad.Reason = "x"
	_, err = w.conversions.Request(w.admin(), w.device, bad)
	expectUninstallProblem(t, err, "invalid_request", 422, "reason must have 2 to 500 characters")

	w.health(t, w.device, `{"disk": {"state": "not_encrypted", "keyslots": 0,
		"conversion": {"eligible": false, "reasons": ["root_not_ext4", "no_separate_boot"]}}}`)
	_, err = w.conversions.Request(w.admin(), w.device, w.input())
	expectUninstallProblem(t, err, "invalid_state", 409, "the device does not report an eligible disk layout: no_separate_boot, root_not_ext4")
	w.health(t, w.device, `{"disk": {"state": "compliant", "keyslots": 2}}`)
	_, err = w.conversions.Request(w.admin(), w.device, w.input())
	expectUninstallProblem(t, err, "invalid_state", 409, "the device does not report an eligible disk layout: already_encrypted")
	w.health(t, w.device, eligibleHealth)

	quarantined, host := w.newDevice(t, w.org, "quarantined")
	w.health(t, quarantined, eligibleHealth)
	_, err = w.conversions.Request(w.admin(), quarantined, app.DiskConversionInput{ConfirmHostname: host, Reason: "rr", BackupConfirmed: true})
	expectUninstallProblem(t, err, "invalid_state", 409, "only active devices can be encrypted")

	lock := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by)
		VALUES ($1, $2, $3, 'lock', 'issued', $4)`, lock, w.org, w.device, uuid.Must(uuid.NewV7()))
	_, err = w.conversions.Request(w.admin(), w.device, w.input())
	expectUninstallProblem(t, err, "invalid_state", 409, "a lock or destroy is pending for this device")
	w.exec(t, "UPDATE revocation_request SET status = 'confirmed' WHERE id = $1", lock)

	if _, err := w.uninstalls.Request(w.admin(), w.device, w.leave()); err != nil {
		t.Fatal(err)
	}
	_, err = w.conversions.Request(w.admin(), w.device, w.input())
	expectUninstallProblem(t, err, "invalid_state", 409, "an uninstall is pending")
	if _, err := w.uninstalls.Cancel(w.admin(), w.device); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM device_disk_conversion WHERE device_id = $1", w.device); n != 0 {
		t.Fatalf("%d conversions after refused requests", n)
	}

	conversion, cmd := w.request(t)
	var params []byte
	var lifetime time.Duration
	if err := w.super.QueryRow(context.Background(), `SELECT params, expires_at - issued_at FROM device_command
		WHERE id = $1 AND type = 'encrypt_disk' AND status = 'pending'`, cmd).Scan(&params, &lifetime); err != nil {
		t.Fatal(err)
	}
	if string(params) != `{"conversion_id": "`+conversion.String()+`"}` || lifetime != 7*24*time.Hour {
		t.Fatalf("command params %s, lifetime %s", params, lifetime)
	}
	p, outcome := w.event(t, "device.encrypt_requested")
	if outcome != "success" || p["backup_confirmed"] != true || p["reason"] != "policy" || p["hostname"] != w.hostname ||
		p["command_id"] != cmd.String() || p["conversion_id"] != conversion.String() {
		t.Fatalf("params %v (%s)", p, outcome)
	}
	detail, err := w.devices.Get(w.as(w.org, principal.RoleOrgAuditor, false), w.device)
	if err != nil || detail.DiskConversion == nil || detail.DiskConversion.DeviceDiskConversion.Phase != "requested" ||
		detail.DiskConversion.CommandStatus != "pending" || !detail.DiskConversion.Active {
		t.Fatalf("detail %+v, %v", detail.DiskConversion, err)
	}
	_, err = w.conversions.Request(w.admin(), w.device, w.input())
	expectUninstallProblem(t, err, "invalid_state", 409, "a conversion is already open")
}

// TestDiskConversionCancel (plan M8e decision 8): an undelivered command is withdrawn and the conversion cancelled at
// once; after delivery the device is sent encrypt_disk_abort and the phase stays; a second cancel while the abort is on
// its way and a cancel once the device encrypts are refused.
func TestDiskConversionCancel(t *testing.T) {
	w := newConversionWorld(t)
	_, err := w.conversions.Cancel(w.admin(), w.device, w.hostname)
	expectUninstallProblem(t, err, "invalid_state", 409, "no conversion is open")

	conversion, cmd := w.request(t)
	if _, err := w.conversions.Cancel(w.as(w.org, principal.RoleOrgAdmin, false), w.device, w.hostname); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("without a step-up: %v", err)
	}
	_, err = w.conversions.Cancel(w.admin(), w.device, "other")
	expectUninstallProblem(t, err, "invalid_request", 422, "confirm_hostname does not match")
	if _, err := w.conversions.Cancel(w.admin(), w.device, w.hostname); err != nil {
		t.Fatal(err)
	}
	if phase, _, _, finished := w.row(t, conversion); phase != "cancelled" || !finished {
		t.Fatalf("phase %s, finished %v", phase, finished)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'cancelled'", cmd); n != 1 {
		t.Fatal("the command was not cancelled")
	}
	if len(w.cache.deleted) != 1 || w.cache.deleted[0] != cmd {
		t.Fatalf("removed from the gateway: %v", w.cache.deleted)
	}
	p, _ := w.event(t, "device.encrypt_cancelled")
	if p["mode"] != app.ConversionCancelCommand || p["command_id"] != cmd.String() || p["conversion_id"] != conversion.String() {
		t.Fatalf("params %v", p)
	}

	conversion, cmd = w.request(t)
	w.exec(t, "UPDATE device_command SET status = 'delivered', delivered_at = now() WHERE id = $1", cmd)
	if _, err := w.conversions.Cancel(w.admin(), w.device, w.hostname); err != nil {
		t.Fatal(err)
	}
	w.expectPhase(t, conversion, "requested")
	var abort uuid.UUID
	var params []byte
	if err := w.super.QueryRow(context.Background(), `SELECT c.id, c.params FROM device_disk_conversion d
		JOIN device_command c ON c.id = d.abort_command_id WHERE d.id = $1 AND c.type = 'encrypt_disk_abort'`, conversion).Scan(&abort, &params); err != nil {
		t.Fatal(err)
	}
	if string(params) != `{"conversion_id": "`+conversion.String()+`"}` {
		t.Fatalf("abort params %s", params)
	}
	if p, _ := w.event(t, "device.encrypt_cancelled"); p["mode"] != app.ConversionCancelAbort || p["command_id"] != abort.String() {
		t.Fatalf("params %v", p)
	}
	_, err = w.conversions.Cancel(w.admin(), w.device, w.hostname)
	expectUninstallProblem(t, err, "invalid_state", 409, "a cancellation is already on its way")

	w.result(t, abort, "failed", `{"aborted": false, "reason": "not_abortable"}`)
	var refused *string
	if err := w.super.QueryRow(context.Background(), "SELECT abort_refused_reason FROM device_disk_conversion WHERE id = $1", conversion).Scan(&refused); err != nil ||
		refused == nil || *refused != "not_abortable" {
		t.Fatalf("abort_refused_reason %v, %v", refused, err)
	}
	w.expectPhase(t, conversion, "requested")
	w.post(t, w.device, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": conversion.String(), "init_s": 42, "init_result": "ok"})
	w.expectPhase(t, conversion, "encrypting")
	_, err = w.conversions.Cancel(w.admin(), w.device, w.hostname)
	expectUninstallProblem(t, err, "conversion_not_cancellable", 409, "the device already started the encryption; it cannot be cancelled")
	if n := w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'device.encrypt_cancelled' AND payload ->> 'outcome' = 'success'
		AND payload -> 'target' ->> 'id' = $1`, w.device.String()); n != 2 {
		t.Fatalf("%d successful cancels", n)
	}
}

// TestDiskConversionEvents (plan M8e decision 9, §14.10 I2): the device's phase events move the conversion they name;
// an event for an unknown conversion or another device's is audited and changes nothing; a refused command fails the
// conversion at stage preflight; disk.conversion_started adopts a cancelled conversion unless another one is open.
func TestDiskConversionEvents(t *testing.T) {
	w := newConversionWorld(t)
	conversion, cmd := w.request(t)
	w.result(t, cmd, "succeeded", `{"accepted": true}`)
	w.expectPhase(t, conversion, "requested")
	volume := uuid.Must(uuid.NewV7())
	w.post(t, w.device, protocol.EventDiskConversionPrepared, map[string]any{"conversion_id": conversion.String(), "layout": "lvm",
		"volume": volume.String(), "data_bytes": 1000})
	var layout string
	var luks uuid.UUID
	var data int64
	if err := w.super.QueryRow(context.Background(), `SELECT phase, layout, luks_uuid, data_bytes FROM device_disk_conversion WHERE id = $1`,
		conversion).Scan(new(string), &layout, &luks, &data); err != nil || layout != "lvm" || luks != volume || data != 1000 {
		t.Fatalf("prepared %s %s %d, %v", layout, luks, data, err)
	}
	w.expectPhase(t, conversion, "prepared")
	p, _ := w.event(t, "device.disk_conversion_prepared")
	if p["conversion_id"] != conversion.String() || p["layout"] != "lvm" || p["volume"] != volume.String() || p["data_bytes"] != float64(1000) {
		t.Fatalf("params %v", p)
	}

	other, _ := w.newDevice(t, w.org, "active")
	w.post(t, other, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": conversion.String(), "stage": "init", "reason": "x"})
	w.post(t, w.device, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": uuid.NewString(), "stage": "init", "reason": "x"})
	w.expectPhase(t, conversion, "prepared")
	if n := w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'device.disk_conversion_failed'
		AND payload -> 'target' ->> 'id' IN ($1, $2)`, w.device.String(), other.String()); n != 2 {
		t.Fatalf("%d failure events", n)
	}

	w.post(t, w.device, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": conversion.String(), "init_s": 30, "init_result": "ok"})
	w.expectPhase(t, conversion, "encrypting")
	if p, _ := w.event(t, "device.disk_conversion_started"); p["init_s"] != float64(30) || p["init_result"] != "ok" {
		t.Fatalf("params %v", p)
	}
	at := time.Now().UTC().Truncate(time.Second)
	w.health(t, w.device, `{"disk": {"state": "encrypting", "keyslots": 1, "conversion": {"eligible": false, "phase": "encrypting",
		"data_bytes": 100, "done_bytes": 50, "eta_s": 60, "paused_reason": "on_battery", "updated_at": "`+at.Format(time.RFC3339)+`"}}}`)
	detail, err := w.devices.Get(w.admin(), w.device)
	if err != nil || detail.DiskConversion == nil || detail.DiskConversion.Progress == nil || detail.DiskConversion.Progress.DoneBytes != 50 ||
		detail.DiskConversion.Progress.ETASeconds != 60 || detail.DiskConversion.Progress.PausedReason != "on_battery" || !detail.DiskConversion.Active {
		t.Fatalf("detail %+v, %v", detail.DiskConversion, err)
	}
	w.post(t, w.device, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": conversion.String(), "stage": "resume", "reason": "io"})
	if phase, stage, reason, finished := w.row(t, conversion); phase != "failed" || stage != "resume" || reason != "io" || !finished {
		t.Fatalf("failed %s %s %s %v", phase, stage, reason, finished)
	}
	attention := "SELECT count(*) FROM attention_condition WHERE device_id = $1 AND kind = 'disk_conversion_failed' AND detail = $2"
	if n := w.count(t, attention, w.device, "resume:io"); n != 1 {
		t.Fatalf("attention rows %d", n)
	}
	w.post(t, w.device, protocol.EventDiskConversionCompleted, map[string]any{"conversion_id": conversion.String(), "data_bytes": 100, "duration_s": 600})
	if phase, stage, _, finished := w.row(t, conversion); phase != "completed" || stage != "resume" || !finished {
		t.Fatalf("completed %s %s %v", phase, stage, finished)
	}
	if n := w.count(t, attention, w.device, "resume:io"); n != 0 {
		t.Fatal("the attention entry stayed after the completion")
	}

	w.health(t, w.device, eligibleHealth)
	conversion, cmd = w.request(t)
	w.result(t, cmd, "failed", `{"accepted": false, "reason": "not_eligible", "reasons": ["low_free_space"]}`)
	if phase, stage, reason, _ := w.row(t, conversion); phase != "failed" || stage != "preflight" || reason != "not_eligible" {
		t.Fatalf("refused %s %s %s", phase, stage, reason)
	}
	if n := w.count(t, attention, w.device, "preflight:not_eligible"); n != 1 {
		t.Fatalf("attention rows %d", n)
	}

	conversion, _ = w.request(t)
	w.post(t, w.device, protocol.EventDiskConversionAborted, map[string]any{"conversion_id": conversion.String(), "by": "admin"})
	if phase, _, _, finished := w.row(t, conversion); phase != "cancelled" || !finished {
		t.Fatalf("aborted %s %v", phase, finished)
	}
	if p, _ := w.event(t, "device.disk_conversion_aborted"); p["by"] != "admin" {
		t.Fatalf("params %v", p)
	}
	if n := w.count(t, attention, w.device, "preflight:not_eligible"); n != 0 {
		t.Fatal("a newer request did not replace the failed conversion on the attention list")
	}

	// A stale initrd converted the disk of the cancelled conversion (§14.10 I2): the device adopts it, unless another
	// conversion of the device is open.
	open, _ := w.request(t)
	w.post(t, w.device, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": conversion.String(), "init_result": "ok"})
	w.expectPhase(t, conversion, "cancelled")
	w.expectPhase(t, open, "requested")
	if _, err := w.conversions.Cancel(w.admin(), w.device, w.hostname); err != nil {
		t.Fatal(err)
	}
	w.post(t, w.device, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": conversion.String(), "init_result": "ok"})
	if phase, _, _, finished := w.row(t, conversion); phase != "encrypting" || finished {
		t.Fatalf("adopted %s %v", phase, finished)
	}
}

// TestDiskConversionBlocksUninstall (plan M8e §14.5 decision 36 as amended on 2026-10-21, §14.6 decision 50): the
// uninstall is refused while the conversion is active — open, a failed conversion whose disk still reports encrypting,
// a completed one whose key is still on /boot (key_on_boot), a recent completion without a health report — and
// accepted once the key left the initrd, also while the boot PIN is still missing.
func TestDiskConversionBlocksUninstall(t *testing.T) {
	w := newConversionWorld(t)
	conversion, _ := w.request(t)
	_, err := w.uninstalls.Request(w.admin(), w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "an in-place encryption is open; cancel it first")

	w.post(t, w.device, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": conversion.String(), "init_result": "ok"})
	w.post(t, w.device, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": conversion.String(), "stage": "resume", "reason": "io"})
	w.health(t, w.device, `{"disk": {"state": "encrypting", "keyslots": 2}}`)
	_, err = w.uninstalls.Request(w.admin(), w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "the in-place encryption is unfinished; wait for its completion")

	w.post(t, w.device, protocol.EventDiskConversionCompleted, map[string]any{"conversion_id": conversion.String()})
	active := func(want bool) {
		t.Helper()
		if detail, err := w.devices.Get(w.admin(), w.device); err != nil || detail.DiskConversion == nil || detail.DiskConversion.Active != want {
			t.Fatalf("detail %+v, %v, want active %v", detail.DiskConversion, err, want)
		}
	}
	w.health(t, w.device, `{"disk": {"state": "tpm_pin_missing", "keyslots": 2, "conversion": {"eligible": false, "key_on_boot": true}}}`)
	_, err = w.uninstalls.Request(w.admin(), w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "the in-place encryption is unfinished; wait for its completion")
	active(true)

	w.exec(t, "DELETE FROM device_status WHERE device_id = $1", w.device)
	_, err = w.uninstalls.Request(w.admin(), w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "the in-place encryption is unfinished; wait for its completion")
	active(true)

	w.health(t, w.device, `{"disk": {"state": "tpm_pin_missing", "keyslots": 2, "conversion": {"eligible": false}}}`)
	active(false)
	if _, err := w.uninstalls.Request(w.admin(), w.device, w.leave()); err != nil {
		t.Fatal(err)
	}
}

// TestDiskConversionRetireAndLock (plan M8e §14.5 decisions 38 and 39): Retire, Lock and Destroy are never refused for
// a conversion; they withdraw an undelivered encrypt_disk command and cancel its conversion, and leave a delivered one
// alone, recording either on their own event.
func TestDiskConversionRetireAndLock(t *testing.T) {
	w := newConversionWorld(t)
	revocations := app.NewRevocations(w.runner, w.api, stepUpTokens{}, w.cache, true)
	stepUp := func() context.Context {
		p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: principal.RoleOrgAdmin,
			OrganizationID: w.org, IP: "192.0.2.1", StepUpAt: time.Now(), StepUpJTI: uuid.NewString(), Subject: uuid.NewString()}
		return httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())
	}
	params := func(code string, dev uuid.UUID) map[string]any {
		var raw []byte
		if err := w.super.QueryRow(context.Background(), `SELECT payload -> 'params' FROM outbox WHERE payload ->> 'code' = $1
			AND payload -> 'target' ->> 'id' = $2 ORDER BY id DESC LIMIT 1`, code, dev.String()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		return p
	}
	for _, tc := range []struct {
		name, action, status string
		cancelled            bool
	}{
		{"retire pending", "retire", "pending", true},
		{"retire delivered", "retire", "delivered", false},
		{"lock pending", "lock", "pending", true},
		{"destroy delivered", "destroy", "delivered", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev, host := w.newDevice(t, w.org, "active")
			w.health(t, dev, eligibleHealth)
			if _, err := w.conversions.Request(w.admin(), dev, app.DiskConversionInput{ConfirmHostname: host, Reason: "policy", BackupConfirmed: true}); err != nil {
				t.Fatal(err)
			}
			var conversion, cmd uuid.UUID
			if err := w.super.QueryRow(context.Background(), "SELECT id, command_id FROM device_disk_conversion WHERE device_id = $1", dev).
				Scan(&conversion, &cmd); err != nil {
				t.Fatal(err)
			}
			if tc.status != "pending" {
				w.exec(t, "UPDATE device_command SET status = $2, delivered_at = now() WHERE id = $1", cmd, tc.status)
			}
			code := "revocation.requested"
			if tc.action == "retire" {
				code = "device.retired"
				if _, err := w.devices.Retire(w.admin(), dev); err != nil {
					t.Fatal(err)
				}
			} else if _, _, err := revocations.Request(stepUp(), app.RevocationInput{DeviceID: dev, Action: tc.action, ConfirmHostname: host, Reason: "stolen"}); err != nil {
				t.Fatal(err)
			}
			p := params(code, dev)
			if p["conversion_id"] != conversion.String() {
				t.Fatalf("params %v", p)
			}
			var phase, status string
			if err := w.super.QueryRow(context.Background(), `SELECT d.phase, c.status FROM device_disk_conversion d
				JOIN device_command c ON c.id = d.command_id WHERE d.id = $1`, conversion).Scan(&phase, &status); err != nil {
				t.Fatal(err)
			}
			if tc.cancelled {
				if p["conversion_cancelled"] != app.ConversionCancelledBeforeDelivery || p["conversion_phase"] != nil || phase != "cancelled" ||
					status != "cancelled" {
					t.Fatalf("params %v, phase %s, command %s", p, phase, status)
				}
				return
			}
			if p["conversion_cancelled"] != nil || p["conversion_phase"] != "requested" || phase != "requested" || status != tc.status {
				t.Fatalf("params %v, phase %s, command %s", p, phase, status)
			}
		})
	}
}

// TestDiskConversionLatestAfterAdoption (architect decision 2026-10-21, PDK-241 review 1): the latest conversion is
// the open one, else the one whose phase changed last, so an older conversion the device adopted wins over a newer
// request that was refused meanwhile — on the device, for active and the uninstall refusal, and on the attention list.
// A completion also ends a cancelled conversion whose adoption was refused (decision 9).
func TestDiskConversionLatestAfterAdoption(t *testing.T) {
	w := newConversionWorld(t)
	adopted, _ := w.request(t)
	w.post(t, w.device, protocol.EventDiskConversionAborted, map[string]any{"conversion_id": adopted.String(), "by": "operator"})
	refused, cmd := w.request(t)
	w.result(t, cmd, "failed", `{"accepted": false, "reason": "not_eligible", "reasons": ["cleanup_pending"]}`)
	w.expectPhase(t, refused, "failed")
	w.post(t, w.device, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": adopted.String(), "init_result": "ok"})
	w.expectPhase(t, adopted, "encrypting")
	w.health(t, w.device, `{"disk": {"state": "encrypting", "keyslots": 1}}`)
	latest := func() *app.DiskConversion {
		t.Helper()
		detail, err := w.devices.Get(w.admin(), w.device)
		if err != nil || detail.DiskConversion == nil {
			t.Fatalf("detail %+v, %v", detail.DiskConversion, err)
		}
		return detail.DiskConversion
	}
	if c := latest(); c.DeviceDiskConversion.ID != adopted || !c.Active {
		t.Fatalf("latest %s (active %v), want the adopted %s", c.DeviceDiskConversion.ID, c.Active, adopted)
	}
	attention := "SELECT count(*) FROM attention_condition WHERE device_id = $1 AND kind = 'disk_conversion_failed'"
	if n := w.count(t, attention, w.device); n != 0 {
		t.Fatal("the refused request is listed although the adopted conversion is open")
	}

	w.post(t, w.device, protocol.EventDiskConversionCompleted, map[string]any{"conversion_id": adopted.String()})
	w.health(t, w.device, `{"disk": {"state": "tpm_pin_missing", "keyslots": 2}}`)
	if c := latest(); c.DeviceDiskConversion.ID != adopted || c.DeviceDiskConversion.Phase != "completed" || !c.Active {
		t.Fatalf("latest %+v (active %v), want the completed adopted conversion", c.DeviceDiskConversion, c.Active)
	}
	_, err := w.uninstalls.Request(w.admin(), w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "the in-place encryption is unfinished; wait for its completion")
	if n := w.count(t, attention, w.device); n != 0 {
		t.Fatal("the refused request is listed although the adopted conversion is newer")
	}

	// A cancelled conversion whose adoption was refused (another one open) still completes, and it keeps the device's
	// conversion active until the disk is compliant, also once the other row is no longer open (plan M8e amendment
	// 2026-10-21).
	other, _ := w.newDevice(t, w.org, "active")
	w.device, w.hostname = other, w.hostnameOf(t, other)
	w.health(t, w.device, eligibleHealth)
	stale, _ := w.request(t)
	w.post(t, w.device, protocol.EventDiskConversionAborted, map[string]any{"conversion_id": stale.String(), "by": "admin"})
	open, _ := w.request(t)
	w.post(t, w.device, protocol.EventDiskConversionStarted, map[string]any{"conversion_id": stale.String(), "init_result": "ok"})
	w.expectPhase(t, stale, "cancelled")
	w.post(t, w.device, protocol.EventDiskConversionCompleted, map[string]any{"conversion_id": stale.String()})
	w.expectPhase(t, stale, "completed")
	w.expectPhase(t, open, "requested")
	if _, err := w.conversions.Cancel(w.admin(), w.device, w.hostname); err != nil {
		t.Fatal(err)
	}
	w.health(t, w.device, `{"disk": {"state": "tpm_pin_missing", "keyslots": 2}}`)
	if c := latest(); c.DeviceDiskConversion.ID != open || c.DeviceDiskConversion.Phase != "cancelled" || !c.Active {
		t.Fatalf("latest %+v (active %v), want the cancelled request, active through the completed conversion",
			c.DeviceDiskConversion, c.Active)
	}
	_, err = w.uninstalls.Request(w.admin(), w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "the in-place encryption is unfinished; wait for its completion")
	w.health(t, w.device, `{"disk": {"state": "compliant", "tokens": ["recovery", "tpm2+pin"], "keyslots": 2}}`)
	if c := latest(); c.Active {
		t.Fatalf("active after compliant: %+v", c.DeviceDiskConversion)
	}
	if _, err := w.uninstalls.Request(w.admin(), w.device, w.leave()); err != nil {
		t.Fatal(err)
	}
}

// hostnameOf is the hostname of a device of the world.
func (w conversionWorld) hostnameOf(t *testing.T, id uuid.UUID) (host string) {
	t.Helper()
	if err := w.super.QueryRow(context.Background(), "SELECT hostname FROM device WHERE id = $1", id).Scan(&host); err != nil {
		t.Fatal(err)
	}
	return host
}

// TestDiskConversionWithdrawalUnderTheRowLock (PDK-241 review 1 finding 4): a Retire that read a requested conversion
// re-reads it under its row lock; an event that moved it to prepared meanwhile wins — the command is not withdrawn, and
// the event records the phase the conversion has.
func TestDiskConversionWithdrawalUnderTheRowLock(t *testing.T) {
	w := newConversionWorld(t)
	conversion, cmd := w.request(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE device_disk_conversion SET phase = 'prepared' WHERE id = $1", conversion); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.devices.Retire(w.admin(), w.device)
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p, _ := w.event(t, "device.retired")
	if p["conversion_phase"] != "prepared" || p["conversion_cancelled"] != nil || p["conversion_id"] != conversion.String() {
		t.Fatalf("params %v", p)
	}
	w.expectPhase(t, conversion, "prepared")
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'pending'", cmd); n != 1 {
		t.Fatal("the command was withdrawn next to a prepared conversion")
	}
	if _, ok := w.cache.claims[cmd]; ok {
		t.Fatal("the result was claimed")
	}
}

// TestDiskConversionKeyOnBootBlocksUninstall (PDK-241 review 2, plan M8e amendment 2026-10-21): a health report with
// key_on_boot refuses the uninstall whatever the conversions say — here a failed one and no completed one.
func TestDiskConversionKeyOnBootBlocksUninstall(t *testing.T) {
	w := newConversionWorld(t)
	conversion, _ := w.request(t)
	w.post(t, w.device, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": conversion.String(), "stage": "prepare", "reason": "x"})
	w.expectPhase(t, conversion, "failed")
	w.health(t, w.device, `{"disk": {"state": "tpm_pin_missing", "keyslots": 2, "conversion": {"eligible": false, "key_on_boot": true}}}`)
	_, err := w.uninstalls.Request(w.admin(), w.device, w.leave())
	expectUninstallProblem(t, err, "invalid_state", 409, "the in-place encryption is unfinished; wait for its completion")
	w.health(t, w.device, `{"disk": {"state": "tpm_pin_missing", "keyslots": 2, "conversion": {"eligible": false}}}`)
	if _, err := w.uninstalls.Request(w.admin(), w.device, w.leave()); err != nil {
		t.Fatal(err)
	}
}

// failingClaims fails the result claim of one command, after the claims before it were won.
type failingClaims struct {
	*fakeUninstallCache
	fail uuid.UUID
}

func (c failingClaims) ClaimResult(ctx context.Context, device, id uuid.UUID, status string) (uuid.UUID, string, error) {
	if id == c.fail {
		return uuid.Nil, "", errors.New("valkey down")
	}
	return c.fakeUninstallCache.ClaimResult(ctx, device, id, status)
}

// TestWithdrawalReleasesClaimsOnRollback (PDK-241 review 2): a Lock that won the result claim of an uninstall command
// and then fails takes the claim back, so the device's result is not a conflict after the rollback.
func TestWithdrawalReleasesClaimsOnRollback(t *testing.T) {
	w := newConversionWorld(t)
	dev, err := w.uninstalls.Request(w.admin(), w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	uninstall := dev.UninstallCommandID.UUID
	encrypt, conversion := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO device_command (id, organization_id, device_id, type, params, status, expires_at)
		VALUES ($1, $2, $3, 'encrypt_disk', '{}', 'pending', now() + interval '7 days')`, encrypt, w.org, w.device)
	w.exec(t, `INSERT INTO device_disk_conversion (id, organization_id, device_id, command_id, reason, phase)
		VALUES ($1, $2, $3, $4, 'rollback', 'requested')`, conversion, w.org, w.device, encrypt)
	revocations := app.NewRevocations(w.runner, w.api, stepUpTokens{}, failingClaims{fakeUninstallCache: w.cache, fail: encrypt}, true)
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: principal.RoleOrgAdmin,
		OrganizationID: w.org, IP: "192.0.2.1", StepUpAt: time.Now(), StepUpJTI: uuid.NewString(), Subject: uuid.NewString()}
	ctx := httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())
	if _, _, err := revocations.Request(ctx, app.RevocationInput{DeviceID: w.device, Action: "lock", ConfirmHostname: w.hostname, Reason: "stolen"}); err == nil {
		t.Fatal("the lock committed although a claim failed")
	}
	if _, ok := w.cache.claims[uninstall]; ok || len(w.cache.released) != 1 || w.cache.released[0] != uninstall {
		t.Fatalf("claims %v, released %v", w.cache.claims, w.cache.released)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id IN ($1, $2) AND status = 'pending'", uninstall, encrypt); n != 2 {
		t.Fatalf("%d pending commands after the rollback", n)
	}
	w.expectPhase(t, conversion, "requested")
}

// TestDiskConversionConcurrentCancel (PDK-241 review 2): a cancel, the device's command result and its event batch
// [prepared, started] run at once on one conversion. All paths lock device, command, conversion in one order, so none
// deadlocks, and the end state is consistent: a cancelled conversion has a cancelled command (the device may still
// adopt it, §14.10 I2), a command with the device's result was never withdrawn.
func TestDiskConversionConcurrentCancel(t *testing.T) {
	base := newConversionWorld(t)
	for i := range 12 {
		w := base
		w.device, w.hostname = w.newDevice(t, w.org, "active")
		w.health(t, w.device, eligibleHealth)
		conversion, cmd := w.request(t)
		start := make(chan struct{})
		errs := make(chan error, 3)
		var cancelErr error
		go func() {
			<-start
			_, cancelErr = w.conversions.Cancel(w.admin(), w.device, w.hostname)
			errs <- nil
		}()
		go func() {
			<-start
			errs <- w.commands.Finish(systemCtx(w.org), ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org,
				CommandID: cmd, Status: "succeeded", Result: json.RawMessage(`{"accepted": true}`), ReceivedAt: time.Now()})
		}()
		go func() {
			<-start
			data := func(m map[string]any) json.RawMessage { raw, _ := json.Marshal(m); return raw }
			errs <- w.reports.RecordEvents(systemCtx(w.org), w.device, time.Now(), []protocol.Event{
				{EventSeq: 1, Type: protocol.EventDiskConversionPrepared, OccurredAt: time.Now(),
					Data: data(map[string]any{"conversion_id": conversion.String(), "layout": "lvm"})},
				{EventSeq: 2, Type: protocol.EventDiskConversionStarted, OccurredAt: time.Now(),
					Data: data(map[string]any{"conversion_id": conversion.String(), "init_result": "ok"})},
			})
		}()
		close(start)
		for range 3 {
			if err := <-errs; err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
		}
		if cancelErr != nil && problem.From(cancelErr).Status != 409 {
			t.Fatalf("round %d: cancel %v", i, cancelErr)
		}
		var phase, status string
		if err := w.super.QueryRow(context.Background(), `SELECT d.phase, c.status FROM device_disk_conversion d
			JOIN device_command c ON c.id = d.command_id WHERE d.id = $1`, conversion).Scan(&phase, &status); err != nil {
			t.Fatal(err)
		}
		switch {
		case phase == "cancelled" && status != "cancelled":
			t.Fatalf("round %d: conversion cancelled, command %s", i, status)
		case status == "cancelled" && phase != "cancelled" && phase != "encrypting":
			t.Fatalf("round %d: command cancelled, conversion %s", i, phase)
		case status == "succeeded" && phase == "cancelled":
			t.Fatalf("round %d: command succeeded, conversion cancelled", i)
		case phase != "cancelled" && phase != "encrypting":
			t.Fatalf("round %d: the batch left the conversion %s", i, phase)
		}
	}
}

// TestDiskConversionRefusedResultDuringWithdrawal (PDK-241 review 2 note 1): the gateway publishes a result before it
// claims it, so the worker can record a refused encrypt_disk while a cancel or a retirement withdraws the command.
// Both lock device, command, conversion in that order: no deadlock; either the withdrawal wins (command and
// conversion cancelled, the result changes nothing) or the result does (command failed, conversion failed:preflight,
// the cancel refused, the retirement records the phase).
func TestDiskConversionRefusedResultDuringWithdrawal(t *testing.T) {
	base := newConversionWorld(t)
	for i := range 16 {
		retire := i%2 == 1
		w := base
		w.device, w.hostname = w.newDevice(t, w.org, "active")
		w.health(t, w.device, eligibleHealth)
		conversion, cmd := w.request(t)
		start := make(chan struct{})
		var finishErr, withdrawErr error
		done := make(chan struct{}, 2)
		go func() {
			<-start
			finishErr = w.commands.Finish(systemCtx(w.org), ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org,
				CommandID: cmd, Status: "failed", Result: json.RawMessage(`{"accepted": false, "reason": "not_eligible"}`),
				ReceivedAt: time.Now()})
			done <- struct{}{}
		}()
		go func() {
			<-start
			if retire {
				_, withdrawErr = w.devices.Retire(w.admin(), w.device)
			} else {
				_, withdrawErr = w.conversions.Cancel(w.admin(), w.device, w.hostname)
			}
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done
		if finishErr != nil {
			t.Fatalf("round %d: finish %v", i, finishErr)
		}
		if withdrawErr != nil && (retire || problem.From(withdrawErr).Status != 409) {
			t.Fatalf("round %d (retire %v): %v", i, retire, withdrawErr)
		}
		phase, stage, _, _ := w.row(t, conversion)
		var status string
		if err := w.super.QueryRow(context.Background(), "SELECT status FROM device_command WHERE id = $1", cmd).Scan(&status); err != nil {
			t.Fatal(err)
		}
		switch {
		case status == "cancelled" && phase == "cancelled" && withdrawErr == nil:
		case status == "failed" && phase == "failed" && stage == "preflight":
		default:
			t.Fatalf("round %d (retire %v): command %s, conversion %s:%s, withdrawal %v", i, retire, status, phase, stage, withdrawErr)
		}
	}
}

// TestDiskConversionNotes (plan M8e amendment 2026-10-21, items 17 to 19): the device detail carries packages_busy with
// its start while the device prepares, the cleanup's reason only once the conversion failed and the initrd issue in
// every phase, all from the last check-in, and gone once a check-in no longer reports them; another organization's
// administrator sees nothing.
func TestDiskConversionNotes(t *testing.T) {
	w := newConversionWorld(t)
	conversion, _ := w.request(t)
	since := time.Now().UTC().Truncate(time.Second)
	report := func(state, phase string) string {
		return `{"disk": {"state": "` + state + `", "keyslots": 0, "conversion": {"eligible": false, "phase": "` + phase + `",
			"paused_reason": "packages_busy", "paused_since": "` + since.Format(time.RFC3339) + `", "cleanup_error": "dracut failed",
			"initrd_issue": "boot_space_low", "boot_space_needed": 90, "boot_space_free": 40}}}`
	}
	notes := func() disk.ConversionNotes {
		t.Helper()
		detail, err := w.devices.Get(w.admin(), w.device)
		if err != nil || detail.DiskConversion == nil || detail.DiskConversion.DeviceDiskConversion.ID != conversion {
			t.Fatalf("detail %+v, %v", detail.DiskConversion, err)
		}
		return detail.DiskConversion.Notes
	}

	w.health(t, w.device, report("not_encrypted", "preparing"))
	n := notes()
	if n.PausedReason != "packages_busy" || n.PausedSince == nil || !n.PausedSince.Equal(since) || n.CleanupError != "" ||
		n.InitrdIssue != "boot_space_low" || n.BootSpaceNeeded != 90 || n.BootSpaceFree != 40 {
		t.Fatalf("preparing %+v", n)
	}
	if _, err := w.devices.Get(w.as(uuid.Must(uuid.NewV7()), principal.RoleOrgAdmin, true), w.device); !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization: %v", err)
	}

	w.post(t, w.device, protocol.EventDiskConversionPrepared, map[string]any{"conversion_id": conversion.String(), "layout": "lvm",
		"volume": uuid.NewString(), "data_bytes": 1000})
	w.health(t, w.device, report("not_encrypted", "prepared"))
	if n := notes(); n.PausedReason != "" || n.PausedSince != nil || n.CleanupError != "" || n.InitrdIssue != "boot_space_low" {
		t.Fatalf("prepared %+v", n)
	}

	w.post(t, w.device, protocol.EventDiskConversionFailed, map[string]any{"conversion_id": conversion.String(), "stage": "prepare", "reason": "x"})
	w.expectPhase(t, conversion, "failed")
	w.health(t, w.device, report("not_encrypted", "failed"))
	if n := notes(); n.PausedReason != "" || n.PausedSince != nil || n.CleanupError != "dracut failed" || n.InitrdIssue != "boot_space_low" {
		t.Fatalf("failed %+v", n)
	}
	w.health(t, w.device, `{"disk": {"state": "not_encrypted", "keyslots": 0, "conversion": {"eligible": false, "phase": "failed"}}}`)
	if n := notes(); n != (disk.ConversionNotes{}) {
		t.Fatalf("after a check-in without notes %+v", n)
	}
}
