package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// readAuditCodes are the read-access codes of plan M10 §6.4.
var readAuditCodes = []string{"audit.searched", "device.inventory_viewed"}

// TestReadAccessAudit is gate R3 of plan M10 (PDK-139): with the privacy switches off, searching the audit log and
// viewing a device's software record nothing; with both on, two searches of one administrator within the hour record
// exactly one audit.searched without the search text, the software and vulnerabilities of one device viewed twice
// record exactly one device.inventory_viewed, an auditor's search records its own event, and another organization's
// administrator sees none of them. The organization is fresh, so no other gate's reads fall into its windows.
func TestReadAccessAudit(t *testing.T) {
	slug, org := gateOrganization(t)
	admin := tempPortal(t, "readaudit-admin", env.RoleGroup(slug, "admins"))
	auditor := tempPortal(t, "readaudit-auditor", env.RoleGroup(slug, "auditors"))
	adminID, auditorID := whoami(t, admin).ID, whoami(t, auditor).ID
	d := activeDevice(t, admin, "", "r3-"+uniqueSuffix())
	idx := auditIndex(t)
	readEvents := func() []env.IndexEvent {
		t.Helper()
		found, err := idx.Events(testContext(t, time.Minute), org, "code = ANY($1)", readAuditCodes)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	software := "/api/v1/devices/" + d.DeviceID + "/software"
	get := func(p *env.Portal, path string) {
		t.Helper()
		expectStatus(t, call(t, p, http.MethodGet, path, nil), http.StatusOK, "")
	}

	get(admin, "/api/v1/audit-events")
	get(admin, software)
	time.Sleep(10 * time.Second)
	if found := readEvents(); len(found) != 0 {
		t.Fatalf("read-access events with the switches off: %+v", found)
	}

	settings := currentPrivacySettings(t, admin)
	settings["audit_search_recorded"], settings["inventory_view_recorded"] = true, true
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/settings/privacy", settings), http.StatusOK, "")

	awayFromHourBoundary(t)
	get(admin, "/api/v1/audit-events")
	get(admin, "/api/v1/audit-events?q=alice&outcome=denied")
	get(admin, software)
	get(admin, "/api/v1/devices/"+d.DeviceID+"/vulnerabilities")
	get(admin, software)
	get(auditor, "/api/v1/audit-events")

	searched := expectOneIndexEvent(t, idx, org, "code = 'audit.searched' AND actor->>'id' = $1", adminID,
		"audit.searched", "success", 30*time.Second)
	for _, key := range []string{"from", "to", "q_used", "window_start"} {
		if _, ok := searched.Params[key]; !ok {
			t.Errorf("audit.searched without %s: %v", key, searched.Params)
		}
	}
	if _, ok := searched.Params["q"]; ok || searched.Params["q_used"] != false {
		t.Errorf("audit.searched params %v: the first search of the hour had no search text, and q is never recorded", searched.Params)
	}
	viewed := expectOneIndexEvent(t, idx, org, "code = 'device.inventory_viewed' AND target->>'id' = $1", d.DeviceID,
		"device.inventory_viewed", "success", 30*time.Second)
	if viewed.Params["view"] != "software" {
		t.Errorf("device.inventory_viewed params %v, want view software", viewed.Params)
	}
	expectOneIndexEvent(t, idx, org, "code = 'audit.searched' AND actor->>'type' = 'admin' AND actor->>'id' = $1", auditorID,
		"audit.searched", "success", 30*time.Second)

	carol := login(t, env.Carol)
	res := call(t, carol, http.MethodGet, "/api/v1/audit-events?code=audit.searched&code=device.inventory_viewed", nil)
	expectStatus(t, res, http.StatusOK, "")
	if leaked := containsAny(res.Body, []string{adminID, auditorID, d.DeviceID, org.String()}); leaked != "" {
		t.Fatalf("carol sees the read-access events of %s: %s", leaked, res.Body)
	}
}

// tempPortal signs in a new user of groups.
func tempPortal(t *testing.T, prefix string, groups ...string) *env.Portal {
	t.Helper()
	user, password := tempUser(t, prefix, groups...)
	p, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// awayFromHourBoundary waits until the next clock hour has begun when the current one ends within the next minute, so
// the reads of one test fall into one window (an hour, and a day for the inventory views).
func awayFromHourBoundary(t *testing.T) {
	t.Helper()
	now := time.Now().UTC()
	if next := now.Truncate(time.Hour).Add(time.Hour); next.Sub(now) < time.Minute {
		t.Logf("waiting %s for the next clock hour", next.Sub(now).Round(time.Second))
		time.Sleep(next.Sub(now) + time.Second)
	}
}
