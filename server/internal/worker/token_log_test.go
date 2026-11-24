package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/fleet"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// captureLogs sends every log record of the test to a JSON buffer at debug level.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestFleetDeviceTokenNeverLogged (ADR 0057, H12 and H13): the device token appears in no log record, returned error or
// audit param of the heartbeat path, of any binding decision and of an adapter transport error.
func TestFleetDeviceTokenNeverLogged(t *testing.T) {
	logs := captureLogs(t)
	r := newBindRig(t)
	ctx := context.Background()
	tokens := []string{tokenA, tokenB, tokenC, tokenD, tokenE, tokenF}
	var errs []error

	runner := app.NewActionRunner(r.f.pool, nil, httpx.RequestID)
	reports := NewReports(app.NewDeviceReports(runner, r.f.pool), app.NewDeviceCommands(runner, r.f.pool), r.f.cache)
	hwBeat := uuid.NewString()
	beat := r.device(t, hwBeat)
	for n, at := range []time.Time{time.Now(), time.Now().Add(time.Second), time.Now().Add(-time.Hour)} {
		body, _ := json.Marshal(ingest.Heartbeat{DeviceID: beat, OrganizationID: r.f.org, ReceivedAt: at, FleetDeviceToken: tokenA})
		if o := reports.heartbeat(ctx, fmt.Sprintf("m%d", n), body); o != ack {
			t.Fatalf("heartbeat %d: %v", n, o)
		}
	}

	hw := map[string]string{}
	devs := map[string]uuid.UUID{}
	for _, name := range []string{"bound", "rebound", "mismatch", "unknown", "expired", "current"} {
		hw[name] = uuid.NewString()
		devs[name] = r.device(t, hw[name])
	}
	r.host(r.id(10), hw["bound"], true)
	r.host(r.id(20), hw["rebound"], true)
	r.host(r.id(21), hw["rebound"], true)
	r.host(r.id(60), hw["current"], true)
	r.src.seenAt[r.id(20)] = r.clock.Add(-time.Hour)
	r.binder.hosts[tokenA] = ports.HostSeen{Ref: r.id(10), HardwareUUID: hw["bound"]}
	r.binder.hosts[tokenB] = ports.HostSeen{Ref: r.id(21), HardwareUUID: hw["rebound"]}
	r.binder.hosts[tokenC] = ports.HostSeen{Ref: r.id(30), HardwareUUID: uuid.NewString()}
	if _, err := r.f.super.Exec(ctx, "INSERT INTO device_fleet_binding (device_id, organization_id, host_id, bound_at) VALUES ($1, $3, $4, $6), ($2, $3, $5, $6)",
		devs["rebound"], devs["current"], r.f.org, string(r.id(20)), string(r.id(60)), r.clock.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	reported := r.clock.Add(-time.Minute)
	r.report(t, devs["bound"], tokenA, reported)
	r.report(t, devs["rebound"], tokenB, reported)
	r.report(t, devs["mismatch"], tokenC, reported)
	r.report(t, devs["unknown"], tokenD, reported)
	r.report(t, devs["expired"], tokenF, r.clock.Add(-inventory.TokenMaxAge))
	r.report(t, devs["current"], tokenE, reported)
	errs = append(errs, r.inv.Round(r.sys))
	r.binder.err = fmt.Errorf("%w: resolve a fleet device token: HTTP 503", problem.UpstreamUnavailable)
	r.report(t, devs["unknown"], tokenD, r.clock)
	errs = append(errs, r.inv.Round(r.sys))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	_, _, err = fleet.New("http://"+addr, "t", "https://fleet.example.org").ResolveDeviceToken(ctx, tokenA)
	if err == nil {
		t.Fatal("no transport error")
	}
	errs = append(errs, err)
	r.binder.err = err
	r.report(t, devs["unknown"], tokenD, r.clock.Add(time.Second))
	errs = append(errs, r.inv.Round(r.sys))

	for _, tok := range tokens {
		if strings.Contains(logs.String(), tok) {
			t.Errorf("token %s… in the logs", tok[:8])
		}
		for _, e := range errs {
			if e != nil && strings.Contains(e.Error(), tok) {
				t.Errorf("token %s… in the error %v", tok[:8], e)
			}
		}
		if n := r.f.count(t, "SELECT count(*) FROM action WHERE params::text LIKE '%' || $1 || '%'", tok); n != 0 {
			t.Errorf("token %s… in %d audit params", tok[:8], n)
		}
	}
	if !strings.Contains(logs.String(), "inventory host bound") || !strings.Contains(logs.String(), "inventory host binding refused") ||
		!strings.Contains(logs.String(), "inventory host rebound") || !strings.Contains(logs.String(), "resolving the device tokens failed") {
		t.Fatalf("the binding outcomes were not logged:\n%s", logs.String())
	}
}

// TestReportsHeartbeatFleetDeviceToken (ADR 0057, H4 and H13): a heartbeat that is coalesced still records its token,
// a token that waited TokenMaxAge or longer is not recorded, and a heartbeat of an organization that is being deleted
// is acknowledged.
func TestReportsHeartbeatFleetDeviceToken(t *testing.T) {
	f := newFixture(t)
	runner := app.NewActionRunner(f.pool, nil, httpx.RequestID)
	r := NewReports(app.NewDeviceReports(runner, f.pool), app.NewDeviceCommands(runner, f.pool), f.cache)
	ctx := context.Background()
	dev, waited := f.device(t, "active"), f.device(t, "active")
	beatOf := func(dev uuid.UUID, id string, at time.Time, token string) outcome {
		body, _ := json.Marshal(ingest.Heartbeat{DeviceID: dev, OrganizationID: f.org, ReceivedAt: at, FleetDeviceToken: token})
		return r.heartbeat(ctx, id, body)
	}
	beat := func(id string, at time.Time, token string) outcome {
		body, _ := json.Marshal(ingest.Heartbeat{DeviceID: dev, OrganizationID: f.org, ReceivedAt: at, FleetDeviceToken: token})
		return r.heartbeat(ctx, id, body)
	}
	pendingOf := func(dev uuid.UUID) string {
		var tok *string
		_ = f.super.QueryRow(ctx, "SELECT pending_token FROM device_fleet_binding WHERE device_id = $1", dev).Scan(&tok)
		if tok == nil {
			return ""
		}
		return *tok
	}
	pending := func() string { return pendingOf(dev) }
	now := time.Now().UTC()
	if o := beat("m1", now, ""); o != ack {
		t.Fatalf("outcome %v", o)
	}
	if o := beat("m2", now.Add(time.Second), tokenA); o != ack || pending() != tokenA {
		t.Fatalf("coalesced heartbeat: %v, pending %q", o, pending())
	}
	if o := beatOf(waited, "m3", now.Add(-inventory.TokenMaxAge), tokenB); o != ack || pendingOf(waited) != "" {
		t.Fatalf("a token that waited %s in the queue: %v, pending %q", inventory.TokenMaxAge, o, pendingOf(waited))
	}
	if _, err := f.super.Exec(ctx, `UPDATE organization SET status = 'deleted', deleted_at = now(), deletion_requested_at = now(),
		deletion_requested_by = 'platform admin', deletion_reason = 'test', delete_after = now() WHERE id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
	if o := beat("m4", now.Add(2*time.Second), tokenC); o != ack {
		t.Fatalf("organization being deleted: %v", o)
	}
}
