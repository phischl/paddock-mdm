package app_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestDeviceContactJoin (PDK-089, ADR 0028 decision 3, migration 00043): the overview, the device list with its
// contact filter and count, and the device detail derive the contact state from the device's joined open alert
// through an inlinable paddock_device_contact. The test pins the buckets and per-device states for every contact
// case, that a cleared alert or another organization's alert changes nothing, that the function is never executed as
// a call (the per-row sub-executor cost about 385 ms at 10 000 devices, docs/operations/capacity.md), and that a
// second open alert for a device is rejected by device_alert_open_idx, which keeps the join free of duplicate rows.
// Everything runs as paddock_api in one transaction that is rolled back.
func TestDeviceContactJoin(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	tx, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("SET LOCAL track_functions = 'all'")
	org := func() uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", id, "o"+id.String()[24:])
		return id
	}
	contacted := time.Now().Add(-48 * time.Hour)
	// device inserts a device; status false means no device_status row.
	device := func(org uuid.UUID, hostname, state string, status bool, lastContact, presumedLost *time.Time) uuid.UUID {
		t.Helper()
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, $4)", id, org, hostname, state)
		if status {
			exec("INSERT INTO device_status (device_id, organization_id, last_contact_at, presumed_lost_at) VALUES ($1, $2, $3, $4)",
				id, org, lastContact, presumedLost)
		}
		return id
	}
	alert := func(org, device uuid.UUID, kind string, cleared bool) {
		t.Helper()
		var clearedAt *time.Time
		if cleared {
			clearedAt = &contacted
		}
		exec("INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at, cleared_at) VALUES ($1, $2, $3, $4, now(), $5)",
			uuid.Must(uuid.NewV7()), org, device, kind, clearedAt)
	}

	acme, globex := org(), org()
	want := map[uuid.UUID]string{}
	warn := device(acme, "warn", "active", true, &contacted, nil)
	alert(acme, warn, "stale_critical", true)
	alert(acme, warn, "stale_warning", false)
	want[warn] = "stale_warning"
	lost := device(acme, "lost", "active", true, &contacted, &contacted)
	alert(acme, lost, "stale_critical", false)
	want[lost] = "presumed_lost"
	critical := device(acme, "critical", "active", true, &contacted, nil)
	alert(acme, critical, "stale_critical", false)
	want[critical] = "stale_critical"
	cleared := device(acme, "cleared", "active", true, &contacted, nil)
	alert(acme, cleared, "stale_warning", true)
	alert(acme, cleared, "stale_critical", true)
	want[cleared] = "ok"
	want[device(acme, "nostatus", "active", false, nil, nil)] = "never"
	want[device(acme, "nocontact", "active", true, nil, nil)] = "never"
	want[device(acme, "pending", "pending", true, nil, nil)] = "never"
	want[device(acme, "retired", "retired", true, &contacted, nil)] = "ok"
	want[device(acme, "retiredn", "retired", true, nil, nil)] = "never"
	quarantined := device(acme, "quarantined", "quarantined", true, &contacted, nil)
	alert(acme, quarantined, "stale_warning", false)
	want[quarantined] = "ok"

	type read struct {
		overview pgstore.OverviewDevicesRow
		contact  map[uuid.UUID]string
		lists    map[string][]string
		counts   map[string]int64
		all      int
	}
	filters := map[string][]string{"warning": {"stale_warning"}, "lost or critical": {"presumed_lost", "stale_critical"}}
	calls := func() int64 {
		t.Helper()
		var n int64
		if err := tx.QueryRow(ctx, "SELECT coalesce(sum(pg_stat_get_xact_function_calls(oid)), 0) FROM pg_proc WHERE proname = 'paddock_device_contact'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	api := func(asking uuid.UUID) read {
		t.Helper()
		before := calls()
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sp.Rollback(ctx) }()
		if _, err := sp.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", asking.String()); err != nil {
			t.Fatal(err)
		}
		q := pgstore.New(sp)
		out := read{contact: map[uuid.UUID]string{}, lists: map[string][]string{}, counts: map[string]int64{}}
		if out.overview, err = q.OverviewDevices(ctx); err != nil {
			t.Fatalf("OverviewDevices: %v", err)
		}
		rows, err := q.ListDevices(ctx, pgstore.ListDevicesParams{Sort: "hostname", MaxRows: 100})
		if err != nil {
			t.Fatalf("ListDevices: %v", err)
		}
		out.all = len(rows)
		for _, r := range rows {
			c, err := q.DeviceContact(ctx, r.Device.ID)
			if err != nil {
				t.Fatalf("DeviceContact %s: %v", r.Device.Hostname, err)
			}
			if c != r.Contact {
				t.Errorf("%s: DeviceContact %q, list contact %q", r.Device.Hostname, c, r.Contact)
			}
			out.contact[r.Device.ID] = c
		}
		for name, contacts := range filters {
			rows, err := q.ListDevices(ctx, pgstore.ListDevicesParams{Contacts: contacts, Sort: "hostname", MaxRows: 100})
			if err != nil {
				t.Fatalf("ListDevices %s: %v", name, err)
			}
			for _, r := range rows {
				out.lists[name] = append(out.lists[name], r.Device.Hostname)
			}
			if out.counts[name], err = q.CountDevices(ctx, pgstore.CountDevicesParams{Contacts: contacts, CountLimit: 10001}); err != nil {
				t.Fatalf("CountDevices %s: %v", name, err)
			}
		}
		if n := calls() - before; n != 0 {
			t.Errorf("paddock_device_contact executed %d times as a function call, want 0 (inlined)", n)
		}
		return out
	}
	check := func(label string, got read) {
		t.Helper()
		wantOverview := pgstore.OverviewDevicesRow{Total: 8, Active: 6, Pending: 1, Quarantined: 1, Retired: 2,
			Online: 1, Silent: 1, SilentCritical: 1, PresumedLost: 1, NeverContacted: 2}
		if got.overview != wantOverview {
			t.Errorf("%s: overview %+v, want %+v", label, got.overview, wantOverview)
		}
		if got.all != len(want) {
			t.Errorf("%s: list has %d rows, want %d (one per device)", label, got.all, len(want))
		}
		for id, c := range want {
			if got.contact[id] != c {
				t.Errorf("%s: device %s contact %q, want %q", label, id, got.contact[id], c)
			}
		}
		wantLists := map[string][]string{"warning": {"warn"}, "lost or critical": {"critical", "lost"}}
		for name, hosts := range wantLists {
			sort.Strings(got.lists[name])
			if len(got.lists[name]) != len(hosts) || got.counts[name] != int64(len(hosts)) {
				t.Errorf("%s: filter %s lists %v (total %d), want %v", label, name, got.lists[name], got.counts[name], hosts)
				continue
			}
			for i := range hosts {
				if got.lists[name][i] != hosts[i] {
					t.Errorf("%s: filter %s lists %v, want %v", label, name, got.lists[name], hosts)
				}
			}
		}
	}

	check("acme alone", api(acme))

	// Another organization's open alerts do not reach acme's buckets, list or count.
	globexWarn := device(globex, "warn", "active", true, &contacted, nil)
	alert(globex, globexWarn, "stale_warning", false)
	globexCritical := device(globex, "gcritical", "active", true, &contacted, nil)
	alert(globex, globexCritical, "stale_critical", false)
	check("with globex alerts", api(acme))
	if o := api(globex).overview; o.Active != 2 || o.Silent != 1 || o.SilentCritical != 1 || o.Online != 0 {
		t.Errorf("globex overview %+v, want 2 active, silent 1, silent critical 1", o)
	}

	// The join relies on at most one open alert per device; a second one is rejected by device_alert_open_idx.
	sp, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sp.Exec(ctx, "INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at) VALUES ($1, $2, $3, 'stale_critical', now())",
		uuid.Must(uuid.NewV7()), acme, warn)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" || pgErr.ConstraintName != "device_alert_open_idx" {
		t.Errorf("second open alert: %v, want unique violation of device_alert_open_idx", err)
	}
	_ = sp.Rollback(ctx)

	var strict bool
	var volatility, parallel string
	if err := tx.QueryRow(ctx, `SELECT proisstrict, provolatile::text, proparallel::text FROM pg_proc
		WHERE oid = 'paddock_device_contact(text, timestamptz, timestamptz, text)'::regprocedure`).Scan(&strict, &volatility, &parallel); err != nil {
		t.Fatal(err)
	}
	if strict || volatility != "i" || parallel != "s" {
		t.Errorf("paddock_device_contact: strict %t, volatility %s, parallel %s; want not strict, immutable (i), parallel safe (s)", strict, volatility, parallel)
	}
}
