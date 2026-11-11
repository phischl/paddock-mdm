package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// softwareReport is health.software of a heartbeat.
func softwareReport(t *testing.T, digest string, items ...protocol.SoftwareItem) json.RawMessage {
	t.Helper()
	report := protocol.SoftwareHealth{Digest: digest}
	if items != nil {
		report.Items = &items
	}
	raw, err := json.Marshal(map[string]any{"software": report})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// softwareEntry inserts a catalog entry of an organization that resolves to nano on every ubuntu, and returns its ID.
func (h releaseHarness) softwareEntry(t *testing.T, org uuid.UUID, name, packages string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO software_catalog_entry (id, organization_id, name, packages) VALUES ($1, $2, $3, $4::jsonb)`,
		id, org, name, packages); err != nil {
		t.Fatal(err)
	}
	return id
}

const nanoEverywhere = `[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano"}]`

type softwareRow struct {
	Entry                                        uuid.UUID
	Package, Intent, State, Version, Reason, Err string
	At                                           time.Time
}

func (h releaseHarness) softwareRows(t *testing.T, dev uuid.UUID) map[uuid.UUID]softwareRow {
	t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT catalog_entry_id, package, intent, state, version, reason, error, reported_at
		FROM device_software_status WHERE device_id = $1`, dev)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]softwareRow{}
	for rows.Next() {
		var r softwareRow
		if err := rows.Scan(&r.Entry, &r.Package, &r.Intent, &r.State, &r.Version, &r.Reason, &r.Err, &r.At); err != nil {
			t.Fatal(err)
		}
		out[r.Entry] = r
	}
	return out
}

func (h releaseHarness) softwareDigest(t *testing.T, dev uuid.UUID) string {
	t.Helper()
	var digest string
	if err := h.super.QueryRow(context.Background(), `SELECT software_digest FROM device_status WHERE device_id = $1`, dev).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	return digest
}

// TestSoftwareStatusIngestion (ticket PDK-411): health.software replaces the device's rows and stores the digest, a
// digest alone keeps the rows, items of unknown or foreign entries are skipped, at most 200 are stored, and a report
// that is older than the newest one or comes from a device that is not active changes nothing.
func TestSoftwareStatusIngestion(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	otherOrg, _ := h.device(t)
	ctx := systemCtx(org)
	e1 := h.softwareEntry(t, org, "Editor", nanoEverywhere)
	e2 := h.softwareEntry(t, org, "Browser", nanoEverywhere)
	foreign := h.softwareEntry(t, otherOrg, "Foreign", nanoEverywhere)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	beat := func(at time.Time, health json.RawMessage) {
		t.Helper()
		if err := h.reports.RecordStatus(ctx, ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at, Health: health}); err != nil {
			t.Fatal(err)
		}
	}
	item := func(id any, state string) protocol.SoftwareItem {
		return protocol.SoftwareItem{CatalogEntryID: fmt.Sprint(id), Package: "nano", Intent: "required", State: state, Version: "1.0"}
	}

	beat(at, softwareReport(t, "d1", item(e1, "installed")))
	rows := h.softwareRows(t, dev)
	if len(rows) != 1 || rows[e1].State != "installed" || rows[e1].Version != "1.0" || !rows[e1].At.Equal(at) || h.softwareDigest(t, dev) != "d1" {
		t.Fatalf("rows %+v, digest %q", rows, h.softwareDigest(t, dev))
	}

	beat(at.Add(time.Minute), softwareReport(t, "d1"))
	if rows = h.softwareRows(t, dev); len(rows) != 1 || !rows[e1].At.Equal(at) {
		t.Fatalf("a digest alone changed the rows: %+v", rows)
	}
	beat(at.Add(2*time.Minute), softwareReport(t, "d2"))
	if h.softwareDigest(t, dev) != "d2" || len(h.softwareRows(t, dev)) != 1 {
		t.Fatalf("digest %q, rows %+v", h.softwareDigest(t, dev), h.softwareRows(t, dev))
	}

	// An older heartbeat delivered late must not write old state back, and a device that is not active is not followed.
	beat(at.Add(-time.Minute), softwareReport(t, "old", item(e2, "failed")))
	if rows = h.softwareRows(t, dev); len(rows) != 1 || h.softwareDigest(t, dev) != "d2" {
		t.Fatalf("an older heartbeat changed %+v, digest %q", rows, h.softwareDigest(t, dev))
	}
	if _, err := h.super.Exec(context.Background(), `UPDATE device SET state = 'quarantined' WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	beat(at.Add(3*time.Minute), softwareReport(t, "clone", item(e2, "installed")))
	if rows = h.softwareRows(t, dev); len(rows) != 1 || h.softwareDigest(t, dev) != "d2" {
		t.Fatalf("a quarantined device changed %+v, digest %q", rows, h.softwareDigest(t, dev))
	}
	if _, err := h.super.Exec(context.Background(), `UPDATE device SET state = 'active' WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}

	// Replacement: E1 is no longer named, E2 is new; "x", an unknown entry and another organization's entry are skipped.
	long := strings.Repeat("e", 500)
	skipped := []protocol.SoftwareItem{
		item("x", "installed"), item(uuid.New(), "installed"), item(foreign, "installed"), item(e1, "unknown_state"),
		{CatalogEntryID: e1.String(), Package: "", Intent: "required", State: "installed"},
		{CatalogEntryID: e1.String(), Package: "nano", Intent: "suggested", State: "installed"},
	}
	beat(at.Add(4*time.Minute), softwareReport(t, "d3", append(skipped, protocol.SoftwareItem{CatalogEntryID: e2.String(), Package: "nano",
		Intent: "hold", State: "failed", Reason: "apt_failed", Error: long})...))
	rows = h.softwareRows(t, dev)
	if len(rows) != 1 || rows[e2].State != "failed" || rows[e2].Intent != "hold" || len(rows[e2].Err) != 200 || rows[e2].Reason != "apt_failed" {
		t.Fatalf("rows after the replacement %+v", rows)
	}

	// A report whose items are all unusable is a misbehaving agent, not the device's state: the rows stay.
	beat(at.Add(5*time.Minute), softwareReport(t, "d4", skipped[0], skipped[3], skipped[4], skipped[5]))
	if rows = h.softwareRows(t, dev); len(rows) != 1 || rows[e2].State != "failed" {
		t.Fatalf("an unusable report changed %+v", rows)
	}

	// An empty list is the device's state: nothing is managed any more.
	beat(at.Add(6*time.Minute), json.RawMessage(`{"software":{"digest":"d5","items":[]}}`))
	if rows = h.softwareRows(t, dev); len(rows) != 0 || h.softwareDigest(t, dev) != "d5" {
		t.Fatalf("rows after an empty list %+v, digest %q", rows, h.softwareDigest(t, dev))
	}

	// A health without software, and a software object of the wrong type, change nothing.
	beat(at.Add(7*time.Minute), softwareReport(t, "d6", item(e1, "installed")))
	beat(at.Add(8*time.Minute), json.RawMessage(`{"reconcile":"ok"}`))
	beat(at.Add(9*time.Minute), json.RawMessage(`{"software":"nope"}`))
	if rows = h.softwareRows(t, dev); len(rows) != 1 || h.softwareDigest(t, dev) != "d6" {
		t.Fatalf("rows %+v, digest %q", rows, h.softwareDigest(t, dev))
	}

	// Deleting the entry deletes the row.
	if _, err := h.super.Exec(context.Background(), `DELETE FROM software_catalog_entry WHERE id = $1`, e1); err != nil {
		t.Fatal(err)
	}
	if rows = h.softwareRows(t, dev); len(rows) != 0 {
		t.Fatalf("rows of a deleted entry %+v", rows)
	}
}

// TestSoftwareStatusScopes (plan M13b decision 17, PDK-803): an entry keeps one row per scope; an item without a scope
// is a system row (agents before alpha.10), an available item is stored, a later report without the user-scope item
// deletes that row only, and items of the nil entry (the flatpak runtime package) or of an unknown scope are skipped.
func TestSoftwareStatusScopes(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	e1 := h.softwareEntry(t, org, "GIMP", nanoEverywhere)
	e2 := h.softwareEntry(t, org, "Editor", nanoEverywhere)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	beat := func(at time.Time, items ...protocol.SoftwareItem) {
		t.Helper()
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at,
			Health: softwareReport(t, at.String(), items...)}); err != nil {
			t.Fatal(err)
		}
	}
	scoped := func() string {
		t.Helper()
		var got string
		if err := h.super.QueryRow(context.Background(), `SELECT coalesce(string_agg(CASE catalog_entry_id WHEN $2 THEN 'e1' ELSE 'e2' END
			|| ':' || scope || ':' || username || ':' || intent || ':' || state, ' ' ORDER BY catalog_entry_id = $2 DESC, scope), '')
			FROM device_software_status WHERE device_id = $1`, dev, e1).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	item := func(id uuid.UUID, scope, intent string) protocol.SoftwareItem {
		return protocol.SoftwareItem{CatalogEntryID: id.String(), Package: "flatpak:org.gimp.GIMP", Intent: intent, State: "installed", Scope: scope}
	}

	beat(at, item(e1, "", "required"), item(e1, "user", "available"), item(e2, "system", "available"),
		item(uuid.Nil, "", "required"), item(e2, "group", "required"))
	if got := scoped(); got != "e1:system::required:installed e1:user::available:installed e2:system::available:installed" {
		t.Fatalf("rows %q", got)
	}

	// The reads list an entry once per scope, the scope filter selects one; another organization's reader sees nothing.
	api, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	status := app.NewSoftwareStatus(api)
	reader := adminCtx(org, principal.RoleOrgAuditor, "auditor")
	if _, err := h.super.Exec(context.Background(), `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, intent) VALUES ($1, $2, $3, 'required')`,
		uuid.Must(uuid.NewV7()), org, e1); err != nil {
		t.Fatal(err)
	}
	str := func(s string) *string { return &s }
	managed := func(scope *string) string {
		t.Helper()
		got, err := status.DeviceManagedSoftware(reader, dev, app.DeviceManagedSoftwareQuery{Page: app.ListPage{Sort: "name", Limit: 100}, Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, it := range got.Items {
			out = append(out, it.Name+":"+it.Scope+":"+it.Intent)
		}
		return strings.Join(out, " ")
	}
	if got := managed(nil); got != "Editor:system:available GIMP:system:required GIMP:user:available" {
		t.Fatalf("managed software %q", got)
	}
	if got := managed(str("user")); got != "GIMP:user:available" {
		t.Fatalf("managed software in user scope %q", got)
	}
	devices := func(scope *string) string {
		t.Helper()
		got, err := status.CatalogDevices(reader, e1, app.SoftwareCatalogDeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 100}, Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, it := range got.Items {
			out = append(out, it.Scope+":"+it.State)
		}
		return strings.Join(out, " ")
	}
	if got := devices(nil); got != "system:installed user:installed" {
		t.Fatalf("devices of the entry %q", got)
	}
	if got := devices(str("system")); got != "system:installed" {
		t.Fatalf("devices of the entry in system scope %q", got)
	}
	// PDK-999: an entry that reaches the device without a device assignment (through its owners) lists the device that
	// reported it, as the device's managed software does.
	got, err := status.CatalogDevices(reader, e2, app.SoftwareCatalogDeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 100}})
	if err != nil || len(got.Items) != 1 || got.Items[0].DeviceID != dev || got.Items[0].Scope != "system" ||
		got.Items[0].State != "installed" || got.Items[0].Intent != "available" {
		t.Fatalf("devices of an entry without a device assignment %+v, %v", got.Items, err)
	}
	otherOrg, _ := h.device(t)
	if _, err := status.DeviceManagedSoftware(adminCtx(otherOrg, principal.RoleOrgAuditor, "auditor"), dev,
		app.DeviceManagedSoftwareQuery{Page: app.ListPage{Sort: "name", Limit: 10}, Scope: str("user")}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization read the device: %v", err)
	}

	beat(at.Add(time.Minute), item(e1, "system", "required"), item(e2, "", "available"))
	if got := scoped(); got != "e1:system::required:installed e2:system::available:installed" {
		t.Fatalf("rows after the user-scope item was dropped %q", got)
	}
	beat(at.Add(2*time.Minute), item(e1, "user", "available"))
	if got := scoped(); got != "e1:user::available:installed" {
		t.Fatalf("rows after the system items were dropped %q", got)
	}
}

// TestSoftwareStatusBoundsItems: 250 items store 200 rows, and a repeated entry keeps its last item.
func TestSoftwareStatusBoundsItems(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	var items []protocol.SoftwareItem
	for i := range 250 {
		id := h.softwareEntry(t, org, fmt.Sprintf("App %03d", i), nanoEverywhere)
		items = append(items, protocol.SoftwareItem{CatalogEntryID: id.String(), Package: "nano", Intent: "required", State: "installed"})
	}
	items = append(items[:1], items...) // the first entry named twice; the 250 items now carry 249 distinct entries
	items[0].State = "pending"
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at,
		Health: softwareReport(t, "big", items[:251]...)}); err != nil {
		t.Fatal(err)
	}
	rows := h.softwareRows(t, dev)
	if len(rows) != protocol.MaxSoftwareItems-1 {
		t.Fatalf("%d rows, want %d (200 items, one a repeat)", len(rows), protocol.MaxSoftwareItems-1)
	}
	first, _ := uuid.Parse(items[1].CatalogEntryID)
	if rows[first].State != "installed" {
		t.Fatalf("the repeated entry keeps %q, want its last item (installed)", rows[first].State)
	}
}

// TestSoftwareStatusReads (ticket PDK-411, ADR 0028): the device's managed software and the devices of an entry list the
// reported rows and derive not_applicable and unknown; the state filter covers both, a group narrows, and another
// organization's device or entry is not found.
func TestSoftwareStatusReads(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	otherOrg, otherDev := h.device(t)
	api, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	status := app.NewSoftwareStatus(api)
	reader := adminCtx(org, principal.RoleOrgAuditor, "auditor")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE device SET os_release = '{"id":"ubuntu","version_id":"24.04"}' WHERE id = $1`, dev)
	exec(`UPDATE device SET hostname = 'zeta' WHERE id = $1`, dev)
	other := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO device (id, organization_id, hostname, state, os_release) VALUES ($1, $2, 'alpha', 'active', '{"id":"debian","version_id":"12"}')`, other, org)
	retired := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'retired', 'retired')`, retired, org)
	group := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'Laptops')`, group, org)
	exec(`INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)`, org, group, dev)
	// PDK-716: zeta has a display name and two groups, alpha neither a name nor a group.
	exec(`UPDATE device SET name = 'zeta-laptop' WHERE id = $1`, dev)
	secondGroup := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'Studio')`, secondGroup, org)
	exec(`INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)`, org, secondGroup, dev)
	emptyGroup := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'Nobody')`, emptyGroup, org)

	installed := h.softwareEntry(t, org, "Editor", nanoEverywhere)
	debianOnly := h.softwareEntry(t, org, "Debian tool", `[{"distribution":"debian","release":"*","architecture":"*","package":"deb-tool"}]`)
	pending := h.softwareEntry(t, org, "Browser", `[{"distribution":"ubuntu","release":"24.04","architecture":"amd64","package":"firefox"}]`)
	groupOnly := h.softwareEntry(t, org, "Group app", nanoEverywhere)
	foreign := h.softwareEntry(t, otherOrg, "Foreign", nanoEverywhere)
	assign := func(org, entry uuid.UUID, group any, intent string) {
		exec(`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, device_group_id, intent) VALUES ($1, $2, $3, $4, $5)`,
			uuid.Must(uuid.NewV7()), org, entry, group, intent)
	}
	assign(org, installed, nil, "required")
	assign(org, debianOnly, nil, "required")
	assign(org, pending, nil, "hold")
	assign(org, pending, group, "forbid")
	assign(org, groupOnly, group, "required")
	assign(otherOrg, foreign, nil, "required")
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at, Arch: "amd64",
		Health: softwareReport(t, "d1", protocol.SoftwareItem{CatalogEntryID: installed.String(), Package: "nano", Intent: "required", State: "installed", Version: "7.2"})}); err != nil {
		t.Fatal(err)
	}

	page := func(sort string, state, intent *string) []app.DeviceManagedSoftware {
		t.Helper()
		got, err := status.DeviceManagedSoftware(reader, dev, app.DeviceManagedSoftwareQuery{Page: app.ListPage{Sort: sort, Limit: 100}, State: state, Intent: intent})
		if err != nil {
			t.Fatal(err)
		}
		return got.Items
	}
	str := func(s string) *string { return &s }
	names := func(items []app.DeviceManagedSoftware) string {
		var out []string
		for _, i := range items {
			out = append(out, i.Name+":"+i.State+":"+i.Intent)
		}
		return strings.Join(out, ",")
	}
	all := page("name", nil, nil)
	if got := names(all); got != "Browser:unknown:forbid,Debian tool:not_applicable:required,Editor:installed:required,Group app:unknown:required" {
		t.Fatalf("managed software %s", got)
	}
	if all[0].Package != "firefox" || all[0].ReportedAt != nil || all[2].Version != "7.2" || all[2].ReportedAt == nil || !all[2].ReportedAt.Equal(at) {
		t.Fatalf("items %+v", all)
	}
	if got := names(page("-name", nil, nil)); !strings.HasPrefix(got, "Group app") {
		t.Fatalf("descending %s", got)
	}
	if got := names(page("name", str("unknown"), nil)); got != "Browser:unknown:forbid,Group app:unknown:required" {
		t.Fatalf("state=unknown %s", got)
	}
	if got := names(page("name", str("not_applicable"), nil)); got != "Debian tool:not_applicable:required" {
		t.Fatalf("state=not_applicable %s", got)
	}
	if got := names(page("name", str("failed"), nil)); got != "" {
		t.Fatalf("state=failed %s", got)
	}
	if got := names(page("name", nil, str("forbid"))); got != "Browser:unknown:forbid" {
		t.Fatalf("intent=forbid %s", got)
	}
	if got := names(page("-reported_at", nil, nil)); got != "Browser:unknown:forbid,Debian tool:not_applicable:required,Group app:unknown:required,Editor:installed:required" {
		t.Fatalf("-reported_at %s", got)
	}
	if got := names(page("reported_at", nil, nil)); got != "Editor:installed:required,Browser:unknown:forbid,Debian tool:not_applicable:required,Group app:unknown:required" {
		t.Fatalf("reported_at %s", got)
	}
	if got := names(page("state", nil, nil)); got != "Editor:installed:required,Debian tool:not_applicable:required,Browser:unknown:forbid,Group app:unknown:required" {
		t.Fatalf("state sort %s", got)
	}
	paged, err := status.DeviceManagedSoftware(reader, dev, app.DeviceManagedSoftwareQuery{Page: app.ListPage{Sort: "name", Offset: 3, Limit: 2}})
	if err != nil || paged.Count != 4 || len(paged.Items) != 1 {
		t.Fatalf("page %+v, %v", paged, err)
	}
	search := "%edit%"
	if got, err := status.DeviceManagedSoftware(reader, dev, app.DeviceManagedSoftwareQuery{Page: app.ListPage{Sort: "name", QPattern: &search, Limit: 100}}); err != nil || got.Count != 1 {
		t.Fatalf("q %+v, %v", got, err)
	}
	for _, c := range []struct {
		name string
		ctx  context.Context
		dev  uuid.UUID
	}{{"foreign device", reader, otherDev}, {"unknown device", reader, uuid.New()}} {
		if _, err := status.DeviceManagedSoftware(c.ctx, c.dev, app.DeviceManagedSoftwareQuery{Page: app.ListPage{Sort: "name", Limit: 10}}); !errors.Is(err, problem.NotFound) {
			t.Errorf("%s: %v, want not found", c.name, err)
		}
	}

	devices := func(entry uuid.UUID, query app.SoftwareCatalogDeviceQuery) []app.SoftwareCatalogDevice {
		t.Helper()
		query.Page.Limit = 100
		if query.Page.Sort == "" {
			query.Page.Sort = "hostname"
		}
		got, err := status.CatalogDevices(reader, entry, query)
		if err != nil {
			t.Fatal(err)
		}
		return got.Items
	}
	host := func(items []app.SoftwareCatalogDevice) string {
		var out []string
		for _, i := range items {
			out = append(out, i.Hostname+":"+i.State)
		}
		return strings.Join(out, ",")
	}
	// Organization-wide: every active device, the retired one not; alpha runs debian, for which the entry names no package.
	if got := host(devices(installed, app.SoftwareCatalogDeviceQuery{})); got != "alpha:not_applicable,zeta:installed" {
		t.Fatalf("installed %s", got)
	}
	if got := host(devices(debianOnly, app.SoftwareCatalogDeviceQuery{})); got != "alpha:unknown,zeta:not_applicable" {
		t.Fatalf("debian %s", got)
	}
	// An assignment of a group: its members only; the other group assignment of pending does not widen the scope.
	if got := host(devices(groupOnly, app.SoftwareCatalogDeviceQuery{})); got != "zeta:unknown" {
		t.Fatalf("group only %s", got)
	}
	if got := host(devices(installed, app.SoftwareCatalogDeviceQuery{DeviceGroupID: &group})); got != "zeta:installed" {
		t.Fatalf("group filter %s", got)
	}
	if got := host(devices(installed, app.SoftwareCatalogDeviceQuery{DeviceGroupID: &secondGroup})); got != "zeta:installed" {
		t.Fatalf("second group filter %s", got)
	}
	if got := host(devices(installed, app.SoftwareCatalogDeviceQuery{DeviceGroupID: &emptyGroup})); got != "" {
		t.Fatalf("empty group filter %s", got)
	}
	both := devices(installed, app.SoftwareCatalogDeviceQuery{})
	wantGroups := []uuid.UUID{group, secondGroup}
	slices.SortFunc(wantGroups, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	if len(both) != 2 || both[0].Name != "" || both[0].DeviceGroupIDs == nil || len(both[0].DeviceGroupIDs) != 0 ||
		both[1].Name != "zeta-laptop" || !slices.Equal(both[1].DeviceGroupIDs, wantGroups) {
		t.Fatalf("names and groups %+v", both)
	}
	// The group filter narrows the rows but not the groups listed for a device.
	if only := devices(installed, app.SoftwareCatalogDeviceQuery{DeviceGroupID: &group}); len(only) != 1 || !slices.Equal(only[0].DeviceGroupIDs, wantGroups) {
		t.Fatalf("filtered device lists %+v", only)
	}
	state := "installed"
	if got := host(devices(installed, app.SoftwareCatalogDeviceQuery{State: &state})); got != "zeta:installed" {
		t.Fatalf("state filter %s", got)
	}
	if got := host(devices(installed, app.SoftwareCatalogDeviceQuery{Page: app.ListPage{Sort: "-hostname"}})); got != "zeta:installed,alpha:not_applicable" {
		t.Fatalf("-hostname %s", got)
	}
	if got := host(devices(installed, app.SoftwareCatalogDeviceQuery{Page: app.ListPage{Sort: "state"}})); !slices.Equal(strings.Split(got, ","), []string{"zeta:installed", "alpha:not_applicable"}) {
		t.Fatalf("state sort %s", got)
	}
	for _, id := range []uuid.UUID{foreign, uuid.New()} {
		if _, err := status.CatalogDevices(reader, id, app.SoftwareCatalogDeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 10}}); !errors.Is(err, problem.NotFound) {
			t.Errorf("entry %s: %v, want not found", id, err)
		}
	}
	if _, err := status.CatalogDevices(context.Background(), installed, app.SoftwareCatalogDeviceQuery{}); err == nil {
		t.Error("a request without a principal was served")
	}
}

// TestSoftwareDigestWritesOnChangeOnly (review 1, M1): every check-in carries the digest, so an unchanged one must not
// write a new version of the device_status row.
func TestSoftwareDigestWritesOnChangeOnly(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: time.Now().UTC(),
		Health: softwareReport(t, "d1")}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	xmin := func() string {
		t.Helper()
		var x string
		if err := h.super.QueryRow(ctx, `SELECT xmin::text FROM device_status WHERE device_id = $1`, dev).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	q := pgstore.New(h.super)
	before := xmin()
	if err := q.SetDeviceSoftwareDigest(ctx, pgstore.SetDeviceSoftwareDigestParams{DeviceID: dev, Digest: "d1"}); err != nil {
		t.Fatal(err)
	}
	if xmin() != before {
		t.Fatal("an unchanged digest wrote the row")
	}
	if err := q.SetDeviceSoftwareDigest(ctx, pgstore.SetDeviceSoftwareDigestParams{DeviceID: dev, Digest: "d2"}); err != nil {
		t.Fatal(err)
	}
	if xmin() == before || h.softwareDigest(t, dev) != "d2" {
		t.Fatalf("a changed digest was not written: %q", h.softwareDigest(t, dev))
	}
}

// TestSoftwareReportKinds (PDK-701, PDK-700): an absent or null items list is no report and keeps the rows, an explicit
// empty list prunes them, an alpha.7 agent's health without software changes nothing, and the truncated flag is stored
// and cleared by the next report with items and kept by one without.
func TestSoftwareReportKinds(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	e1 := h.softwareEntry(t, org, "Editor", nanoEverywhere)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	beat := func(health string) {
		t.Helper()
		at = at.Add(time.Minute)
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at, Health: json.RawMessage(health)}); err != nil {
			t.Fatal(err)
		}
	}
	truncated := func() bool {
		t.Helper()
		var v bool
		if err := h.super.QueryRow(context.Background(), `SELECT software_truncated FROM device_status WHERE device_id = $1`, dev).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	item := `{"id":"` + e1.String() + `","package":"nano","intent":"required","state":"failed"}`
	beat(`{"software":{"digest":"d1","truncated":true,"items":[` + item + `]}}`)
	if len(h.softwareRows(t, dev)) != 1 || !truncated() {
		t.Fatalf("rows %+v, truncated %v", h.softwareRows(t, dev), truncated())
	}
	for name, health := range map[string]string{
		"absent": `{"software":{"digest":"d2"}}`, "null": `{"software":{"digest":"d3","items":null}}`,
		"alpha.7 agent": `{"reconcile":"ok","components":{"paddockd":"0.1.0"}}`,
	} {
		beat(health)
		if len(h.softwareRows(t, dev)) != 1 || !truncated() {
			t.Fatalf("%s changed the rows %+v or the flag %v", name, h.softwareRows(t, dev), truncated())
		}
	}
	beat(`{"software":{"digest":"d4","items":[]}}`)
	if len(h.softwareRows(t, dev)) != 0 || truncated() || h.softwareDigest(t, dev) != "d4" {
		t.Fatalf("an empty list left rows %+v, truncated %v", h.softwareRows(t, dev), truncated())
	}
}

// TestSoftwareReportRoundTrip: the protocol type tells "no report" (absent) from "no items" ([]).
func TestSoftwareReportRoundTrip(t *testing.T) {
	var absent, empty protocol.SoftwareHealth
	empty.Items = &[]protocol.SoftwareItem{}
	for _, c := range []struct {
		name string
		in   protocol.SoftwareHealth
		want string
	}{{"absent", absent, `{"digest":""}`}, {"empty", empty, `{"digest":"","items":[]}`}} {
		raw, err := json.Marshal(c.in)
		if err != nil || string(raw) != c.want {
			t.Fatalf("%s: %s, %v", c.name, raw, err)
		}
		var back protocol.SoftwareHealth
		if err := json.Unmarshal(raw, &back); err != nil || (back.Items == nil) != (c.name == "absent") {
			t.Fatalf("%s did not round-trip: %+v, %v", c.name, back, err)
		}
	}
}
