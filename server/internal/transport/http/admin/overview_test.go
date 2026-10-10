package admin_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// fleet seeds acme with one device per overview bucket (plan M7c decision 26) and one device in two buckets, which
// must count once, in the more severe one. The worker's tables are written directly, as devices_test.go does.
type fleet struct {
	online, silent, silentCritical, presumedLost, lostAndSilent, never, pending, retired, quarantined uuid.UUID
}

func (e *env) seedFleet(t *testing.T) fleet {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	f := fleet{
		online: e.insertDevice(e.acme, "ov-online", "active"), silent: e.insertDevice(e.acme, "ov-silent", "active"),
		silentCritical: e.insertDevice(e.acme, "ov-silent-critical", "active"), presumedLost: e.insertDevice(e.acme, "ov-lost", "active"),
		lostAndSilent: e.insertDevice(e.acme, "ov-lost-and-silent", "active"), never: e.insertDevice(e.acme, "ov-never", "active"),
		pending: e.insertDevice(e.acme, "ov-pending", "pending"), retired: e.insertDevice(e.acme, "ov-retired", "retired"),
		quarantined: e.insertDevice(e.acme, "ov-quarantined", "quarantined"),
	}
	status := func(id uuid.UUID, health, loginState string, agent *string, contact *time.Time, lost *time.Time) {
		if _, err := e.super.Exec(ctx, `INSERT INTO device_status (device_id, organization_id, last_contact_at, agent_version, health, login_state, presumed_lost_at)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)`, id, e.acme, contact, agent, health, loginState, lost); err != nil {
			t.Fatal(err)
		}
	}
	alert := func(id uuid.UUID, kind string) {
		if _, err := e.super.Exec(ctx, `INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at) VALUES ($1, $2, $3, $4, $5)`,
			uuid.Must(uuid.NewV7()), e.acme, id, kind, now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	finding := func(id uuid.UUID, cve, pkg, severity string) {
		if _, err := e.super.Exec(ctx, `INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, severity)
			VALUES ($1, $2, $3, $4, '1.0', nullif($5, ''))`, id, e.acme, cve, pkg, severity); err != nil {
			t.Fatal(err)
		}
	}
	v191 := "1.9.1"
	recent := now.Add(-2 * time.Hour).Format(time.RFC3339)
	old := now.Add(-72 * time.Hour).Format(time.RFC3339)
	status(f.online, `{"disk":{"state":"compliant"},"reboot_required":true}`, `{"updates_security":{"occurred_at":"`+recent+`","params":{"result":"ok"}}}`, &v191, &now, nil)
	status(f.silent, `{"disk":{"state":"not_encrypted"}}`, `{"updates_security":{"occurred_at":"`+old+`","params":{"result":"ok"}}}`, &v191, &now, nil)
	alert(f.silent, "stale_warning")
	status(f.silentCritical, `{"disk":{"state":"escrow_pending"}}`, `{"updates_security":{"occurred_at":"`+recent+`","params":{"result":"failed"}}}`, nil, &now, nil)
	alert(f.silentCritical, "stale_critical")
	status(f.presumedLost, `{"disk":{"state":"compliant"}}`, `{}`, &v191, &now, &now)
	status(f.lostAndSilent, `{}`, `{}`, &v191, &now, &now)
	alert(f.lostAndSilent, "stale_critical")
	// ov-never has no status row; ov-pending, ov-retired and ov-quarantined are not active.
	status(f.quarantined, `{"disk":{"state":"compliant"}}`, `{}`, &v191, &now, nil)
	finding(f.online, "CVE-2026-0001", "openssh-server", "critical")
	finding(f.silent, "CVE-2026-0001", "openssh-client", "critical")
	finding(f.silent, "CVE-2026-0002", "libxml2", "high")
	finding(f.quarantined, "CVE-2026-0003", "apport", "") // not rated by Ubuntu: severity NULL
	return f
}

// TestOverview: the counters of GET /api/v1/overview (plan M7c decision 26) with one device per bucket; a device in
// two buckets counts once; the roles org_admin, org_operator and org_auditor may read it, a platform admin may not.
func TestOverview(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	e.seedFleet(t)
	r := e.do(call{method: "GET", path: "/api/v1/overview", cookie: alice})
	var o adminapi.Overview
	r.decode(t, &o)
	if r.status != http.StatusOK {
		t.Fatalf("overview: %d %s", r.status, r.body)
	}
	want := adminapi.OverviewDevices{Total: 8, Active: 6, Pending: 1, Quarantined: 1, Retired: 1, Rejected: 0, Online: 1, Silent: 1, SilentCritical: 1, PresumedLost: 2, NeverContacted: 1}
	if o.Devices != want {
		t.Fatalf("devices %+v, want %+v", o.Devices, want)
	}
	if o.Encryption != (adminapi.OverviewEncryption{Encrypted: 2, NotEncrypted: 1, Partial: 1, NotReported: 2}) {
		t.Fatalf("encryption %+v", o.Encryption)
	}
	if o.Vulnerabilities.ByHighestSeverity != (adminapi.OverviewSeverityBuckets{Critical: 2, High: 0, Medium: 0, Low: 0, Unknown: 1, None: 4}) {
		t.Fatalf("buckets %+v", o.Vulnerabilities.ByHighestSeverity)
	}
	if len(o.Vulnerabilities.Top) != 3 || o.Vulnerabilities.Top[0].Cve != "CVE-2026-0001" || o.Vulnerabilities.Top[0].Devices != 2 ||
		o.Vulnerabilities.Top[0].Severity != adminapi.SeverityCritical || len(o.Vulnerabilities.Top[0].Packages) != 2 ||
		o.Vulnerabilities.Top[1].Cve != "CVE-2026-0002" || o.Vulnerabilities.Top[2].Severity != adminapi.SeverityUnknown {
		t.Fatalf("top %+v", o.Vulnerabilities.Top)
	}
	// Overdue: ov-silent (old run), ov-silent-critical (failed), ov-lost, ov-lost-and-silent (no run); ov-never has no contact.
	if o.Updates.SecurityOverdue != 4 || o.Updates.RebootRequired != 1 {
		t.Fatalf("updates %+v", o.Updates)
	}
	if o.Updates.Agent.CurrentVersion != nil || o.Updates.Agent.OnCurrent != 0 || o.Updates.Agent.Outdated != 0 || o.Updates.Agent.Unknown != 2 {
		t.Fatalf("agent %+v", o.Updates.Agent)
	}
	if len(o.Updates.OsReleases) != 1 || o.Updates.OsReleases[0].Release != "unknown" || o.Updates.OsReleases[0].Devices != 6 {
		t.Fatalf("os releases %+v", o.Updates.OsReleases)
	}
	var attention adminapi.AttentionPage
	e.do(call{method: "GET", path: "/api/v1/attention?page_size=100", cookie: alice}).decode(t, &attention)
	if o.Attention.Conditions != attention.Total || o.Attention.Devices < 5 || o.Attention.Devices > o.Attention.Conditions {
		t.Fatalf("attention %+v, list total %d", o.Attention, attention.Total)
	}
	if o.GeneratedAt.IsZero() {
		t.Fatal("generated_at missing")
	}
	for _, role := range []principal.Role{principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		if r := e.do(call{method: "GET", path: "/api/v1/overview", cookie: e.session(e.acme, role)}); r.status != http.StatusOK {
			t.Fatalf("%s: %d", role, r.status)
		}
	}
	if r := e.do(call{method: "GET", path: "/api/v1/overview", cookie: e.platformSession()}); r.status != http.StatusForbidden {
		t.Fatalf("platform admin: %d", r.status)
	}
	// Another organization sees its own, empty, numbers.
	e.do(call{method: "GET", path: "/api/v1/overview", cookie: e.session(e.globex, principal.RoleOrgAdmin)}).decode(t, &o)
	if o.Devices.Total != 0 || o.Attention.Conditions != 0 {
		t.Fatalf("globex overview %+v", o.Devices)
	}
}

// TestDeviceContact: the contact state of the device list and detail and the contact filter (plan M7c §6.2).
func TestDeviceContact(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	f := e.seedFleet(t)
	var page adminapi.DevicePage
	e.do(call{method: "GET", path: "/api/v1/devices?page_size=100&sort=hostname", cookie: alice}).decode(t, &page)
	got := map[string]adminapi.DeviceContact{}
	for _, d := range page.Items {
		got[d.Hostname] = d.Contact
	}
	want := map[string]adminapi.DeviceContact{
		"ov-online": adminapi.DeviceContactOk, "ov-silent": adminapi.DeviceContactStaleWarning, "ov-silent-critical": adminapi.DeviceContactStaleCritical, "ov-lost": adminapi.DeviceContactPresumedLost,
		"ov-lost-and-silent": adminapi.DeviceContactPresumedLost, "ov-never": adminapi.DeviceContactNever, "ov-pending": adminapi.DeviceContactNever, "ov-retired": adminapi.DeviceContactNever,
		"ov-quarantined": adminapi.DeviceContactOk,
	}
	for host, contact := range want {
		if got[host] != contact {
			t.Errorf("%s: contact %q, want %q", host, got[host], contact)
		}
	}
	e.do(call{method: "GET", path: "/api/v1/devices?contact=presumed_lost&contact=stale_critical&sort=hostname", cookie: alice}).decode(t, &page)
	if page.Total != 3 || page.Items[0].Hostname != "ov-lost" || page.Items[2].Hostname != "ov-silent-critical" {
		t.Fatalf("contact filter: %+v", page)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/devices?contact=bogus", cookie: alice, skipReqCheck: true}); r.status != http.StatusBadRequest {
		t.Fatalf("bogus contact: %d", r.status)
	}
	var detail adminapi.DeviceDetail
	e.do(call{method: "GET", path: "/api/v1/devices/" + f.lostAndSilent.String(), cookie: alice}).decode(t, &detail)
	if detail.Contact != adminapi.DeviceContactPresumedLost {
		t.Fatalf("detail contact %q", detail.Contact)
	}
}

// TestAttentionDevices: the attention list grouped by device (plan M7c decision 27): one row per device with every
// condition most severe first, the kind filter keeps all conditions, sorts are honoured, the per-condition list stays.
func TestAttentionDevices(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	f := e.seedFleet(t)
	var page adminapi.AttentionDevicePage
	r := e.do(call{method: "GET", path: "/api/v1/attention/devices?page_size=100", cookie: alice})
	r.decode(t, &page)
	if r.status != http.StatusOK || page.Sort != "-severity" {
		t.Fatalf("grouped: %d %s", r.status, r.body)
	}
	byID := map[uuid.UUID]adminapi.AttentionDevice{}
	for _, d := range page.Items {
		if _, dup := byID[d.DeviceId]; dup {
			t.Fatalf("device %s listed twice", d.Hostname)
		}
		byID[d.DeviceId] = d
	}
	both := byID[f.lostAndSilent]
	if both.Severity != adminapi.AttentionDeviceSeverityCritical || len(both.Conditions) != 2 ||
		both.Conditions[0].Kind != adminapi.AttentionKindPresumedLost && both.Conditions[0].Kind != adminapi.AttentionKindStaleCritical ||
		both.Conditions[1].Kind != adminapi.AttentionKindPresumedLost && both.Conditions[1].Kind != adminapi.AttentionKindStaleCritical {
		t.Fatalf("lost-and-silent: %+v", both)
	}
	silent := byID[f.silent] // stale_warning (warn) and disk_not_compliant (warn)
	if silent.Severity != adminapi.AttentionDeviceSeverityWarn || len(silent.Conditions) != 2 || silent.State != adminapi.DeviceStateActive || silent.LastContactAt == nil {
		t.Fatalf("silent: %+v", silent)
	}
	if page.Items[0].Severity != adminapi.AttentionDeviceSeverityCritical || page.Items[len(page.Items)-1].Severity == adminapi.AttentionDeviceSeverityCritical {
		t.Fatalf("not sorted by severity: %+v", page.Items)
	}
	// The kind filter selects devices with that condition and keeps every condition of the device.
	e.do(call{method: "GET", path: "/api/v1/attention/devices?kind=stale_warning", cookie: alice}).decode(t, &page)
	if page.Total != 1 || page.Items[0].DeviceId != f.silent || len(page.Items[0].Conditions) != 2 {
		t.Fatalf("kind filter: %+v", page)
	}
	e.do(call{method: "GET", path: "/api/v1/attention/devices?sort=hostname&q=ov-lost", cookie: alice}).decode(t, &page)
	if page.Total != 2 || page.Items[0].Hostname != "ov-lost" || page.Items[1].Hostname != "ov-lost-and-silent" {
		t.Fatalf("hostname sort with search: %+v", page)
	}
	var flat adminapi.AttentionPage
	e.do(call{method: "GET", path: "/api/v1/attention?page_size=100", cookie: alice}).decode(t, &flat)
	conditions := 0
	for _, d := range byID {
		conditions += len(d.Conditions)
	}
	if conditions != flat.Total {
		t.Fatalf("%d grouped conditions, %d flat rows", conditions, flat.Total)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/attention/devices", cookie: e.platformSession()}); r.status != http.StatusForbidden {
		t.Fatalf("platform admin: %d", r.status)
	}
}

// TestAuditEventDevice: the device of an audit event is resolved at read time (plan M7c decision 30): a target of
// type device or params.device_id, the hostname only when the organization has the device; the stored params are
// unchanged; target_id filters by the target.
func TestAuditEventDevice(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	known := e.insertDevice(e.acme, "audit-known", "active")
	foreign := e.insertDevice(e.globex, "audit-foreign", "active")
	gone := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()
	events := map[string]uuid.UUID{}
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.EnsureAuditPartition(ctx, now); err != nil {
			return err
		}
		insert := func(name string, target, params string) error {
			id := uuid.Must(uuid.NewV7())
			events[name] = id
			_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
				EventID: id, OrganizationID: e.acme, OccurredAt: now.Add(-time.Duration(len(events)) * time.Second), RecordedAt: now,
				Code: "device.approved", Outcome: "success", Source: "portal",
				Actor: []byte(`{"type":"admin","display":"alice","step_up":false}`), Target: []byte(target), Params: []byte(params),
				CorrelationID: "c", ObjectKey: "k",
			})
			return err
		}
		if err := insert("target", `{"type":"device","id":"`+known.String()+`","display":""}`, `{}`); err != nil {
			return err
		}
		if err := insert("params", `{"type":"revocation_request","id":"r1"}`, `{"device_id":"`+known.String()+`","action":"lock"}`); err != nil {
			return err
		}
		if err := insert("foreign", `{"type":"device","id":"`+foreign.String()+`"}`, `{}`); err != nil {
			return err
		}
		if err := insert("gone", `{"type":"device","id":"`+gone.String()+`"}`, `{}`); err != nil {
			return err
		}
		return insert("none", `{"type":"device_group","id":"g"}`, `{"name":"g"}`)
	})
	if err != nil {
		t.Fatal(err)
	}
	var page adminapi.AuditEventPage
	r := e.do(call{method: "GET", path: "/api/v1/audit-events?page_size=100", cookie: alice})
	r.decode(t, &page)
	if r.status != http.StatusOK || len(page.Items) != 5 {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	byID := map[uuid.UUID]adminapi.AuditEvent{}
	for _, ev := range page.Items {
		byID[ev.EventId] = ev
	}
	host := "audit-known"
	check := func(name string, want *adminapi.AuditDeviceRef) {
		t.Helper()
		got := byID[events[name]].Device
		switch {
		case want == nil && got != nil:
			t.Errorf("%s: device %+v, want none", name, got)
		case want != nil && got == nil:
			t.Errorf("%s: no device, want %+v", name, want)
		case want != nil && (got.Id != want.Id || (got.Hostname == nil) != (want.Hostname == nil) || (want.Hostname != nil && *got.Hostname != *want.Hostname)):
			t.Errorf("%s: device %+v, want %+v", name, got, want)
		}
	}
	check("target", &adminapi.AuditDeviceRef{Id: known, Hostname: &host})
	check("params", &adminapi.AuditDeviceRef{Id: known, Hostname: &host})
	check("foreign", &adminapi.AuditDeviceRef{Id: foreign, Hostname: nil})
	check("gone", &adminapi.AuditDeviceRef{Id: gone, Hostname: nil})
	check("none", nil)
	if p := byID[events["params"]].Params; p["device_id"] != known.String() || p["action"] != "lock" || len(p) != 2 {
		t.Fatalf("stored params rewritten: %v", p)
	}
	e.do(call{method: "GET", path: "/api/v1/audit-events?target_id=" + known.String(), cookie: alice}).decode(t, &page)
	if page.Total != 1 || page.Items[0].EventId != events["target"] {
		t.Fatalf("target_id filter: %+v", page)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/audit-events?target_id=not-a-uuid", cookie: alice, skipReqCheck: true}); r.status != http.StatusBadRequest {
		t.Fatalf("malformed target_id: %d", r.status)
	}
}
