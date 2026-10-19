package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type nameWorld struct {
	privilegesHarness
	devices  *app.Devices
	operator principal.Principal
}

func newNameWorld(t *testing.T) nameWorld {
	t.Helper()
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return nameWorld{privilegesHarness: h, devices: app.NewDevices(h.runner, pool), operator: h.account(t, principal.RoleOrgOperator, false)}
}

func (w nameWorld) device(t *testing.T, org uuid.UUID, hostname, state string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, $4)",
		id, org, hostname, state); err != nil {
		t.Fatal(err)
	}
	return id
}

func (w nameWorld) setName(p principal.Principal, id uuid.UUID, name *string) (app.DeviceDetail, error) {
	return w.devices.SetName(principal.With(context.Background(), p), id, name)
}

func (w nameWorld) recompiles(t *testing.T, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM outbox WHERE payload->>'scope' = $1 AND payload->>'id' = $2",
		statechange.ScopeDevice, id.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func name(s string) *string { return &s }

// TestSetDeviceName (ADR 0041 decision 2, plan M8h decision 4): an operator sets and clears the managed name; each
// attempt is one device.name_changed with hostname, name and previous_name, and a success recompiles the device.
func TestSetDeviceName(t *testing.T) {
	w := newNameWorld(t)
	dev := w.device(t, w.org, "ubuntu", "active")

	var d app.DeviceDetail
	got := w.during(t, func() {
		var err error
		if d, err = w.setName(w.operator, dev, name("lap-0421")); err != nil {
			t.Fatalf("set = %v", err)
		}
	})
	if strings.Join(got, ",") != "device.name_changed:success:" || d.Device.Name == nil || *d.Device.Name != "lap-0421" ||
		app.NameState(d.Device.Name, d.Device.Hostname) != app.NamePending {
		t.Fatalf("actions %v, device %+v", got, d.Device)
	}
	ev := w.lastEvent(t)
	if ev.Params["hostname"] != "ubuntu" || ev.Params["name"] != "lap-0421" || ev.Params["previous_name"] != "" ||
		ev.Target == nil || ev.Target.Display != "ubuntu" {
		t.Fatalf("event %+v", ev)
	}
	if n := w.recompiles(t, dev); n != 1 {
		t.Fatalf("%d recompiles, want 1", n)
	}

	if _, err := w.setName(w.operator, dev, name("lap-0421")); err != nil {
		t.Fatalf("same name again = %v", err)
	}
	if n := w.recompiles(t, dev); n != 2 {
		t.Fatalf("same name: %d recompiles, want 2", n)
	}

	got = w.during(t, func() {
		if d, _ = w.setName(w.operator, dev, nil); d.Device.Name != nil {
			t.Fatalf("cleared device %+v", d.Device)
		}
	})
	if strings.Join(got, ",") != "device.name_changed:success:" {
		t.Fatalf("clear actions %v", got)
	}
	if ev := w.lastEvent(t); ev.Params["name"] != "" || ev.Params["previous_name"] != "lap-0421" {
		t.Fatalf("clear event %+v", ev)
	}
	if app.NameState(d.Device.Name, d.Device.Hostname) != app.NameUnmanaged {
		t.Fatal("cleared name is not unmanaged")
	}
}

// TestSetDeviceNameRefusals: invalid names, a name another non-retired device holds, a retired target, a foreign
// device and an auditor are refused and audited; a retired device's name is free for reuse.
func TestSetDeviceNameRefusals(t *testing.T) {
	w := newNameWorld(t)
	dev := w.device(t, w.org, "a", "active")
	holder := w.device(t, w.org, "b", "active")
	retired := w.device(t, w.org, "c", "retired")
	if _, err := w.setName(w.operator, holder, name("taken")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(context.Background(), "UPDATE device SET name = 'old-name' WHERE id = $1", retired); err != nil {
		t.Fatal(err)
	}

	got := w.during(t, func() {
		for _, bad := range []string{"A1", "a.b", "localhost", strings.Repeat("a", 64), ""} {
			_, err := w.setName(w.operator, dev, name(bad))
			if !errors.Is(err, problem.InvalidRequest) ||
				problem.From(err).Detail != `name must be a lowercase host name label of 1 to 63 characters (letters, digits, hyphens), not "localhost"` {
				t.Errorf("%q = %v", bad, err)
			}
		}
		if _, err := w.setName(w.operator, dev, name("taken")); !errors.Is(err, problem.Conflict) ||
			problem.From(err).Detail != "name is used by another device of this organization" {
			t.Errorf("taken = %v", err)
		}
		if _, err := w.setName(w.operator, retired, name("fresh")); !errors.Is(err, problem.InvalidState) {
			t.Errorf("retired target = %v", err)
		}
		if _, err := w.setName(w.account(t, principal.RoleOrgAuditor, false), dev, name("x")); !errors.Is(err, problem.Forbidden) {
			t.Errorf("auditor = %v", err)
		}
	})
	want := strings.Repeat("device.name_changed:failure:invalid_request,", 5) +
		"device.name_changed:failure:conflict,device.name_changed:failure:invalid_state,device.name_changed:denied:forbidden"
	if strings.Join(got, ",") != want {
		t.Fatalf("actions %v", got)
	}
	if _, err := w.setName(w.operator, dev, name("old-name")); err != nil {
		t.Fatalf("name of a retired device = %v", err)
	}

	other := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'B', 'active')",
		other, "b"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	foreign := w.device(t, other, "foreign", "active")
	if _, err := w.setName(w.operator, foreign, name("mine")); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign device = %v", err)
	}
	if _, err := w.setName(w.operator, uuid.Must(uuid.NewV7()), name("mine")); !errors.Is(err, problem.NotFound) {
		t.Fatalf("missing device = %v", err)
	}
}

// TestNameState: unmanaged without a name, applied when the reported hostname equals it, pending otherwise.
func TestNameState(t *testing.T) {
	for _, c := range []struct {
		name     *string
		hostname string
		want     string
	}{
		{nil, "ubuntu", app.NameUnmanaged},
		{name("lap-0421"), "lap-0421", app.NameApplied},
		{name("lap-0421"), "ubuntu", app.NamePending},
	} {
		if got := app.NameState(c.name, c.hostname); got != c.want {
			t.Errorf("NameState(%v, %q) = %q, want %q", c.name, c.hostname, got, c.want)
		}
	}
}

// TestReportedHostname (plan M8h decision 9): a check-in's health.hostname becomes device.hostname; an equal value
// leaves the row untouched (no device_cache_notify), an invalid or absent one is ignored.
func TestReportedHostname(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	ctx := context.Background()
	seq := int64(0)
	checkin := func(health string) (hostname, xmin string) {
		t.Helper()
		seq++
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, Seq: seq,
			ReceivedAt: time.Now(), Health: json.RawMessage(health)}); err != nil {
			t.Fatal(err)
		}
		if err := h.super.QueryRow(ctx, "SELECT hostname, xmin::text FROM device WHERE id = $1", dev).Scan(&hostname, &xmin); err != nil {
			t.Fatal(err)
		}
		return hostname, xmin
	}
	if got, _ := checkin(`{"hostname":"lap-0421"}`); got != "lap-0421" {
		t.Fatalf("reported hostname %q", got)
	}
	_, before := checkin(`{"hostname":"lap-0421"}`)
	if got, after := checkin(`{"hostname":"lap-0421"}`); got != "lap-0421" || after != before {
		t.Fatalf("equal value rewrote the row: %q, xmin %s → %s", got, before, after)
	}
	for _, ignored := range []string{
		`{"hostname":"` + strings.Repeat("a", 254) + `"}`, `{"hostname":"a\u0007b"}`, `{"hostname":""}`, `{"reconcile":"ok"}`,
		`{"hostname":42}`,
	} {
		if got, _ := checkin(ignored); got != "lap-0421" {
			t.Fatalf("%s changed the hostname to %q", ignored, got)
		}
	}
}

// TestHostnameOwnedManagedFiles (ADR 0041 decision 6): /etc/hostname and /etc/machine-info are refused as managed
// files on create and update; /etc/hosts stays allowed.
func TestHostnameOwnedManagedFiles(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	files := app.NewManagedConfig(h.runner, pool)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	in := func(path string) app.FileInput {
		mode, content := "0644", "x"
		return app.FileInput{Path: &path, Mode: &mode, Content: &content}
	}
	const detail = "path is owned by the device name policy"
	for _, path := range []string{"/etc/hostname", "/etc/machine-info"} {
		if _, err := files.CreateFile(ctx, in(path)); !errors.Is(err, problem.InvalidRequest) || problem.From(err).Detail != detail {
			t.Errorf("create %s = %v", path, err)
		}
	}
	hosts, err := files.CreateFile(ctx, in("/etc/hosts"))
	if err != nil {
		t.Fatalf("create /etc/hosts = %v", err)
	}
	path := "/etc/hostname"
	if _, err := files.UpdateFile(ctx, hosts.ID, app.FileInput{Path: &path}); !errors.Is(err, problem.InvalidRequest) ||
		problem.From(err).Detail != detail {
		t.Errorf("update to /etc/hostname = %v", err)
	}
}
