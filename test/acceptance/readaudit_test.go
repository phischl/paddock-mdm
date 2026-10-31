package acceptance

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// readAuditCodes are the read-access codes of plan M10 §6.4.
var readAuditCodes = []string{"audit.searched", "device.inventory_viewed", "vulnerability.devices_viewed"}

// TestReadAccessAudit is gate R3 of plan M10 (PDK-139, amendment 2026-10-30 round 2): with the privacy switches off,
// searching the audit log and viewing a device's software record nothing; with both on, one audit.searched per
// administrator, hour and set of filters is recorded, so two searches with the same filters and different search
// texts record one event without the text; a target_id that is no device of the organization is recorded only as
// target_id_used; the software and vulnerabilities of one device viewed twice record exactly one
// device.inventory_viewed; a refused search and a view of a missing device record one failure each, the view without
// the device ID, only with target_id_used (amendment 2026-10-31, PDK-139 round 3); the device list of a CVE with a finding
// viewed twice (once with a search text) records one vulnerability.devices_viewed with the CVE and the device count and
// no device or text, an unknown CVE one failure (PDK-606); an auditor's
// search records its own event, and another organization's administrator sees none of them. The organization is fresh, so no other gate's reads fall into its windows.
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
	cve, unknownCVE := uniqueCVE(), uniqueCVE()
	storeInventory(t, d.DeviceID, nil, [][4]string{{cve, "r3-package", "1.0", "7.5"}})
	cveDevices := "/api/v1/vulnerabilities/" + cve + "/devices"
	get := func(p *env.Portal, path string) {
		t.Helper()
		expectStatus(t, call(t, p, http.MethodGet, path, nil), http.StatusOK, "")
	}

	get(admin, "/api/v1/audit-events")
	get(admin, software)
	get(admin, cveDevices)
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
	get(admin, "/api/v1/audit-events?q=bob&outcome=denied")
	get(admin, "/api/v1/audit-events?target_id="+uuid.NewString())
	get(admin, software)
	get(admin, "/api/v1/devices/"+d.DeviceID+"/vulnerabilities")
	get(admin, software)
	get(admin, cveDevices)
	get(admin, cveDevices+"?q=r3-package")
	get(auditor, "/api/v1/audit-events")
	expectStatus(t, call(t, admin, http.MethodGet, "/api/v1/vulnerabilities/"+unknownCVE+"/devices", nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, admin, http.MethodGet, "/api/v1/audit-events?from=2099-01-01T00:00:00Z", nil), http.StatusBadRequest, "invalid_request")
	missingDevice := uuid.NewString()
	expectStatus(t, call(t, admin, http.MethodGet, "/api/v1/devices/"+missingDevice+"/software", nil), http.StatusNotFound, "not_found")

	searched := expectOneIndexEvent(t, idx, org, `code = 'audit.searched' AND outcome = 'success' AND actor->>'id' = $1
		AND params->>'q_used' = 'false' AND NOT params ? 'target_id_used'`, adminID, "audit.searched", "success", 30*time.Second)
	for _, key := range []string{"from", "to", "q_used", "window_start"} {
		if _, ok := searched.Params[key]; !ok {
			t.Errorf("audit.searched without %s: %v", key, searched.Params)
		}
	}
	withText := expectOneIndexEvent(t, idx, org, `code = 'audit.searched' AND outcome = 'success' AND actor->>'id' = $1
		AND params->>'q_used' = 'true'`, adminID, "audit.searched", "success", 30*time.Second)
	if _, ok := withText.Params["q"]; ok || containsAny([]byte(fmt.Sprint(withText.Params)), []string{"alice", "bob"}) != "" {
		t.Errorf("audit.searched params %v: two search texts with the same filters record one event, and q is never recorded", withText.Params)
	}
	unknownTarget := expectOneIndexEvent(t, idx, org, `code = 'audit.searched' AND outcome = 'success' AND actor->>'id' = $1
		AND params ? 'target_id_used'`, adminID, "audit.searched", "success", 30*time.Second)
	if _, ok := unknownTarget.Params["target_id"]; ok {
		t.Errorf("audit.searched records a target_id that is no device of the organization: %v", unknownTarget.Params)
	}
	refused := expectOneIndexEvent(t, idx, org, "code = 'audit.searched' AND outcome = 'failure' AND actor->>'id' = $1", adminID,
		"audit.searched", "failure", 30*time.Second)
	if refused.Params["error_code"] != "invalid_request" {
		t.Errorf("refused search params %v, want error_code invalid_request", refused.Params)
	}
	viewed := expectOneIndexEvent(t, idx, org, "code = 'device.inventory_viewed' AND outcome = 'success' AND target->>'id' = $1", d.DeviceID,
		"device.inventory_viewed", "success", 30*time.Second)
	if viewed.Params["view"] != "software" {
		t.Errorf("device.inventory_viewed params %v, want view software", viewed.Params)
	}
	missing := expectOneIndexEvent(t, idx, org, `code = 'device.inventory_viewed' AND outcome = 'failure' AND actor->>'id' = $1
		AND coalesce(target::text, 'null') = 'null'`, adminID, "device.inventory_viewed", "failure", 30*time.Second)
	if missing.Params["error_code"] != "not_found" || missing.Params["target_id_used"] != true ||
		containsAny([]byte(fmt.Sprint(missing.Params)), []string{missingDevice}) != "" {
		t.Errorf("refused view params %v, want error_code not_found, target_id_used and no device ID", missing.Params)
	}
	listed := expectOneIndexEvent(t, idx, org, "code = 'vulnerability.devices_viewed' AND outcome = 'success' AND actor->>'id' = $1", adminID,
		"vulnerability.devices_viewed", "success", 30*time.Second)
	if listed.Params["cve"] != cve || listed.Params["device_count"] != float64(1) ||
		containsAny([]byte(fmt.Sprint(listed.Params)), []string{d.DeviceID, "r3-package"}) != "" {
		t.Errorf("vulnerability.devices_viewed params %v, want cve %s, device_count 1 and no device or search text", listed.Params, cve)
	}
	unknown := expectOneIndexEvent(t, idx, org, "code = 'vulnerability.devices_viewed' AND outcome = 'failure' AND actor->>'id' = $1", adminID,
		"vulnerability.devices_viewed", "failure", 30*time.Second)
	if unknown.Params["error_code"] != "not_found" {
		t.Errorf("refused CVE view params %v, want error_code not_found", unknown.Params)
	}
	expectOneIndexEvent(t, idx, org, "code = 'audit.searched' AND actor->>'type' = 'admin' AND actor->>'id' = $1", auditorID,
		"audit.searched", "success", 30*time.Second)

	carol := login(t, env.Carol)
	res := call(t, carol, http.MethodGet, "/api/v1/audit-events?code=audit.searched&code=device.inventory_viewed&code=vulnerability.devices_viewed", nil)
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
