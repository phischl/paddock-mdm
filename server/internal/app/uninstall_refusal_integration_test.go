package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// refusalWorld is an uninstall world with the worker's command use cases, which record the device's results.
type refusalWorld struct {
	uninstallWorld
	commands *app.DeviceCommands
}

func newRefusalWorld(t *testing.T) refusalWorld {
	t.Helper()
	w := refusalWorld{uninstallWorld: newUninstallWorld(t)}
	worker, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	w.commands = app.NewDeviceCommands(app.NewActionRunner(worker, nil, httpx.RequestID), worker)
	return w
}

// requestDelivered requests an uninstall of the world's device and marks its command delivered.
func (w refusalWorld) requestDelivered(t *testing.T) uuid.UUID {
	t.Helper()
	dev, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave())
	if err != nil {
		t.Fatal(err)
	}
	cmd := dev.UninstallCommandID.UUID
	w.exec(t, "UPDATE device_command SET status = 'delivered', delivered_at = now() WHERE id = $1", cmd)
	return cmd
}

func (w refusalWorld) finish(t *testing.T, cmd uuid.UUID, status, result string) {
	t.Helper()
	if err := w.commands.Finish(systemCtx(w.org), ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org,
		CommandID: cmd, Status: status, Result: json.RawMessage(result), ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func (w refusalWorld) failedEvents(t *testing.T) int {
	t.Helper()
	return w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'device.uninstall_failed'
		AND payload -> 'target' ->> 'id' = $1`, w.device.String())
}

// TestUninstallRefusedInvalidParamsEndsTheRequest (PDK-403): a refusal with invalid_params can never succeed, so it
// ends the request as failed with exactly one device.uninstall_failed event by the device; a duplicate result records
// nothing more, and the administrator can request the removal again.
func TestUninstallRefusedInvalidParamsEndsTheRequest(t *testing.T) {
	w := newRefusalWorld(t)
	cmd := w.requestDelivered(t)
	w.finish(t, cmd, "failed", `{"accepted":false,"reason":"invalid_params"}`)
	w.finish(t, cmd, "failed", `{"accepted":false,"reason":"invalid_params"}`)

	detail, err := w.devices.Get(w.as(w.org, principal.RoleOrgAuditor, false), w.device)
	if err != nil || detail.Device.State != "active" || detail.Uninstall != nil || detail.Device.UninstallRequestedAt != nil {
		t.Fatalf("device %+v uninstall %+v, %v", detail.Device, detail.Uninstall, err)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE id = $1 AND status = 'failed' AND result ->> 'reason' = 'invalid_params'", cmd); n != 1 {
		t.Fatalf("command not recorded as failed: %d", n)
	}
	if n := w.failedEvents(t); n != 1 {
		t.Fatalf("%d device.uninstall_failed events, want 1", n)
	}
	params, outcome := w.event(t, "device.uninstall_failed")
	if outcome != "success" || params["reason"] != "invalid_params" || params["command_id"] != cmd.String() ||
		params["mode"] != "leave" || params["hostname"] != w.hostname {
		t.Fatalf("event %v (%s)", params, outcome)
	}
	if n := w.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'device.uninstall_failed'
		AND payload -> 'actor' ->> 'type' = 'device' AND payload -> 'actor' ->> 'id' = $1`, w.device.String()); n != 1 {
		t.Fatalf("actor is not the device: %d", n)
	}
	if _, err := w.uninstalls.Request(w.as(w.org, principal.RoleOrgAdmin, true), w.device, w.leave()); err != nil {
		t.Fatalf("request again: %v", err)
	}
}

// TestUninstallTransientRefusalKeepsTheRequestOpen (PDK-403): conversion_pending and revocation_pending clear up, so
// the request stays open with the reason visible and no event; the administrator cancels it.
func TestUninstallTransientRefusalKeepsTheRequestOpen(t *testing.T) {
	for _, reason := range []string{"conversion_pending", "revocation_pending"} {
		t.Run(reason, func(t *testing.T) {
			w := newRefusalWorld(t)
			cmd := w.requestDelivered(t)
			w.finish(t, cmd, "failed", `{"accepted":false,"reason":"`+reason+`"}`)

			detail, err := w.devices.Get(w.as(w.org, principal.RoleOrgAuditor, false), w.device)
			if err != nil || detail.Uninstall == nil || detail.Uninstall.CommandStatus != "failed" || detail.Uninstall.RefusedReason != reason {
				t.Fatalf("uninstall %+v, %v", detail.Uninstall, err)
			}
			if n := w.failedEvents(t); n != 0 {
				t.Fatalf("%d device.uninstall_failed events, want 0", n)
			}
			if _, err := w.uninstalls.Cancel(w.as(w.org, principal.RoleOrgAdmin, false), w.device); err != nil {
				t.Fatalf("cancel: %v", err)
			}
		})
	}
}

// TestUninstallRefusalOnlyEndsItsOpenRequest (PDK-403): an accepted command shows no refusal reason and ends nothing;
// an invalid_params result of a command the administrator already cancelled records no event.
func TestUninstallRefusalOnlyEndsItsOpenRequest(t *testing.T) {
	w := newRefusalWorld(t)
	cmd := w.requestDelivered(t)
	w.finish(t, cmd, "succeeded", `{"accepted":true}`)
	detail, err := w.devices.Get(w.as(w.org, principal.RoleOrgAuditor, false), w.device)
	if err != nil || detail.Uninstall == nil || detail.Uninstall.CommandStatus != "succeeded" || detail.Uninstall.RefusedReason != "" {
		t.Fatalf("uninstall %+v, %v", detail.Uninstall, err)
	}

	other := newRefusalWorld(t)
	dev, err := other.uninstalls.Request(other.as(other.org, principal.RoleOrgAdmin, true), other.device, other.leave())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.uninstalls.Cancel(other.as(other.org, principal.RoleOrgAdmin, false), other.device); err != nil {
		t.Fatal(err)
	}
	other.finish(t, dev.UninstallCommandID.UUID, "failed", `{"accepted":false,"reason":"invalid_params"}`)
	if n := other.failedEvents(t); n != 0 {
		t.Fatalf("%d device.uninstall_failed events for a cancelled request, want 0", n)
	}
	if n := w.failedEvents(t); n != 0 {
		t.Fatalf("%d device.uninstall_failed events for an accepted command, want 0", n)
	}
}
