package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/commandsign"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicecommand"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/baotest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// commandWorld is a worker with a signing AppRole, a device and the trust of the device.
type commandWorld struct {
	fixture
	c      *Commands
	device uuid.UUID
	trust  command.Trust
}

func newCommandWorld(t *testing.T) commandWorld {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	b := baotest.Start(t)
	role := b.AppRole(t, "paddock-worker")
	signer, err := bao.New(b.Addr, role.RoleID, role.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := bao.NewWithToken(b.Addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := commandsign.PublicKeys(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := command.TrustFromKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	w := commandWorld{fixture: f, trust: trust, device: uuid.Must(uuid.NewV7()),
		c: NewCommands(app.NewDeviceCommands(f.pool), app.NewRevocationReports(app.NewActionRunner(f.pool, nil, httpx.RequestID), f.pool),
			f.pool, platform, f.cache, signer)}
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-cmd', 'active')",
		w.device, f.org); err != nil {
		t.Fatal(err)
	}
	return w
}

// command inserts a pending command as the api does and returns its ID.
func (w commandWorld) command(t *testing.T, expires time.Duration, notBefore *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), `INSERT INTO device_command
		(id, organization_id, device_id, type, status, issued_at, expires_at, not_before)
		VALUES ($1, $2, $3, 'rotate_admin_password', 'pending', now(), now() + $4::interval, $5)`,
		id, w.org, w.device, expires.String(), notBefore); err != nil {
		t.Fatal(err)
	}
	return id
}

func (w commandWorld) status(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := w.super.QueryRow(context.Background(), "SELECT status FROM device_command WHERE id = $1", id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (w commandWorld) published(t *testing.T) map[uuid.UUID]*command.Command {
	t.Helper()
	cmds, err := w.cache.Commands(context.Background(), w.device, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := map[uuid.UUID]*command.Command{}
	for id, c := range cmds {
		cmd, err := command.Verify(c.Envelope, w.trust, w.device.String(), w.org.String(), time.Now())
		if err != nil || cmd.CommandID != id.String() {
			t.Fatalf("published envelope of %s: %+v %v", id, cmd, err)
		}
		out[id] = cmd
	}
	return out
}

func issuedBody(t *testing.T, org, id uuid.UUID) []byte {
	t.Helper()
	b, err := json.Marshal(devicecommand.Issued{OrganizationID: org, CommandID: id})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCommandIssuedAndResult(t *testing.T) {
	w := newCommandWorld(t)
	ctx := context.Background()
	id := w.command(t, time.Hour, nil)
	if o := w.c.issued(ctx, id.String(), issuedBody(t, w.org, id)); o != ack {
		t.Fatalf("issued: outcome %v", o)
	}
	if cmd := w.published(t)[id]; cmd == nil || cmd.Type != command.TypeRotateAdminPassword || string(cmd.Params) != "{}" {
		t.Fatalf("published %+v", w.published(t))
	}
	// Delivery is recorded from the heartbeat of the check-in that carried the command.
	r := NewReports(app.NewDeviceReports(app.NewActionRunner(w.pool, nil, func(context.Context) string { return "t" }), w.pool),
		app.NewDeviceCommands(w.pool), w.cache)
	hb, _ := json.Marshal(ingest.Heartbeat{DeviceID: w.device, OrganizationID: w.org, ReceivedAt: time.Now(), Seq: 1,
		DeliveredCommands: []uuid.UUID{id}})
	if o := r.heartbeat(ctx, "hb", hb); o != ack || w.status(t, id) != devicecommand.StatusDelivered {
		t.Fatalf("heartbeat: outcome %v, status %s", o, w.status(t, id))
	}

	result := func(status string) outcome {
		body, _ := json.Marshal(ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org, CommandID: id, Status: status,
			Result: json.RawMessage(`{"generation":1}`), ReceivedAt: time.Now()})
		return w.c.result(ctx, id.String()+":"+status, body)
	}
	if o := result("succeeded"); o != ack || w.status(t, id) != devicecommand.StatusSucceeded || len(w.published(t)) != 0 {
		t.Fatalf("result: outcome %v, status %s, published %v", o, w.status(t, id), w.published(t))
	}
	// The first result counts.
	if o := result("failed"); o != ack || w.status(t, id) != devicecommand.StatusSucceeded {
		t.Fatalf("second result: outcome %v, status %s", o, w.status(t, id))
	}
	// A message for a command that does not exist is acknowledged; a malformed one is poison.
	unknown := uuid.Must(uuid.NewV7())
	if o := w.c.issued(ctx, "x", issuedBody(t, w.org, unknown)); o != ack {
		t.Fatalf("unknown command: outcome %v", o)
	}
	if o := w.c.issued(ctx, "x", []byte(`{"command":1}`)); o != poison {
		t.Fatalf("malformed message: outcome %v", o)
	}
}

// TestCommandRound: the round publishes due commands that are missing in Valkey (delayed or lost), never commands
// that are not due yet, and expires commands whose lifetime ended.
func TestCommandRound(t *testing.T) {
	w := newCommandWorld(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)
	lost, delayed := w.command(t, time.Hour, nil), w.command(t, 2*time.Hour, &later)
	if err := w.c.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.published(t); got[lost] == nil || got[delayed] != nil {
		t.Fatalf("after the first round: %v", got)
	}
	w.c.now = func() time.Time { return later.Add(time.Second) }
	if err := w.c.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.published(t); got[delayed] == nil {
		t.Fatalf("delayed command not published when due: %v", got)
	}
	w.c.now = func() time.Time { return later.Add(2 * time.Hour) }
	if err := w.c.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if w.status(t, lost) != devicecommand.StatusExpired || w.status(t, delayed) != devicecommand.StatusExpired {
		t.Fatalf("statuses %s %s, want expired", w.status(t, lost), w.status(t, delayed))
	}
	if present, _ := w.cache.HasCommand(ctx, w.device, lost); present {
		t.Fatal("expired command left in Valkey")
	}
}

// TestRevocationDeliveryAndConfirmation (plan M4c decision 10): an issued revocation token travels like a command:
// the heartbeat records its delivery, the device's result confirms it once (audited device.revocation_confirmed with
// the device as actor), and an unconfirmed token expires with its lifetime.
func TestRevocationDeliveryAndConfirmation(t *testing.T) {
	w := newCommandWorld(t)
	ctx := context.Background()
	admin := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(ctx, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, 'alice', 'alice', 'org_admin')`, admin, w.org, admin.String()); err != nil {
		t.Fatal(err)
	}
	revoke := func(expires time.Duration) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := w.super.Exec(ctx, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by,
			issued_at, expires_at, envelope) VALUES ($1, $2, $3, 'lock', 'issued', $4, now(), now() + $5::interval, '\x7b7d')`,
			id, w.org, w.device, admin, fmt.Sprintf("%d seconds", int(expires.Seconds()))); err != nil {
			t.Fatal(err)
		}
		return id
	}
	status := func(id uuid.UUID) string {
		var s string
		if err := w.super.QueryRow(ctx, "SELECT status FROM revocation_request WHERE id = $1", id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	id := revoke(time.Hour)
	r := NewReports(app.NewDeviceReports(app.NewActionRunner(w.pool, nil, func(context.Context) string { return "t" }), w.pool),
		app.NewDeviceCommands(w.pool), w.cache)
	hb, _ := json.Marshal(ingest.Heartbeat{DeviceID: w.device, OrganizationID: w.org, ReceivedAt: time.Now(), Seq: 1,
		DeliveredCommands: []uuid.UUID{id}})
	if o := r.heartbeat(ctx, "hb", hb); o != ack || status(id) != "delivered" {
		t.Fatalf("heartbeat: outcome %v, status %s", o, status(id))
	}
	result := func(id uuid.UUID, s string) outcome {
		body, _ := json.Marshal(ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org, CommandID: id, Status: s,
			Result: json.RawMessage(`{"erased":true,"slots_before":2,"slots_after":0}`), ReceivedAt: time.Now()})
		return w.c.result(ctx, id.String()+":"+s, body)
	}
	if o := result(id, "succeeded"); o != ack || status(id) != "confirmed" {
		t.Fatalf("confirmation: outcome %v, status %s", o, status(id))
	}
	if o := result(id, "failed"); o != ack || status(id) != "confirmed" {
		t.Fatalf("second result: outcome %v, status %s", o, status(id))
	}
	var events []string
	rows, _ := w.super.Query(ctx, `SELECT code || ':' || (actor ->> 'type') || ':' || (params ->> 'slots_before') FROM action
		WHERE params ->> 'request_id' = $1`, id.String())
	events, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if len(events) != 1 || events[0] != "device.revocation_confirmed:device:2" {
		t.Fatalf("events %v", events)
	}

	expired := revoke(time.Second)
	time.Sleep(1500 * time.Millisecond)
	if err := w.c.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if status(expired) != "expired" {
		t.Fatalf("after its lifetime: %s", status(expired))
	}
}
