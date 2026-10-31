package acceptance

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestRetentionUserSeen is gate R1 of plan M10 (PDK-137): the development stack counts retention days in seconds and
// runs the retention round every 15 s, so a session login older than 365 s is deleted within two rounds with one
// retention.purged event (actor system, store device_user_seen); an organization without expired rows gets none.
// Both organizations are fresh, so no other gate's logins expire into the same events.
func TestRetentionUserSeen(t *testing.T) {
	slug, org := gateOrganization(t)
	_, idle := gateOrganization(t)
	user, password := tempUser(t, "retention", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	d := activeDevice(t, admin, "", "r1-"+uniqueSuffix())
	sendSessionLogins(t, d, 1, "retention-"+uniqueSuffix()+"@"+slug+".test", time.Now().UTC().Add(-400*time.Second))

	idx := auditIndex(t)
	const where = "code = 'retention.purged' AND params->>'store' = $1"
	ev := expectOneIndexEvent(t, idx, org, where, "device_user_seen", "retention.purged", "success", 90*time.Second)
	if deleted, _ := ev.Params["deleted"].(float64); deleted < 1 || ev.ActorDisplay != "worker" {
		t.Fatalf("retention.purged params %v, actor %q", ev.Params, ev.ActorDisplay)
	}
	if cutoff, _ := ev.Params["cutoff"].(string); cutoff == "" {
		t.Fatalf("retention.purged without cutoff: %v", ev.Params)
	} else if _, err := time.Parse(time.RFC3339, cutoff); err != nil {
		t.Fatalf("cutoff %q: %v", cutoff, err)
	}
	found, err := idx.Events(testContext(t, time.Minute), idle, where, "device_user_seen")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("organization without expired rows has retention.purged events %+v", found)
	}
}

// TestRetentionDeviceCommand covers the control-plane stores of PDK-180 (ADR 0032 amendments 2026-10-18 and
// 2026-10-31): the development stack counts the 400-day index retention in seconds, and the purge never runs ahead of
// the index, which drops whole UTC months: the cutoff is the start of the month containing now − 400 s. A command that
// finished 40 days ago, before that month in any case, is deleted within two rounds with one retention.purged event
// (actor system, store device_command), while a command that finished just now stays. The commands are written
// directly, as gate C1 backdates its command: no device runs for 400 s in a gate. The insert is a SELECT, so psql
// prints the id without a command tag.
//
// Other gates must not depend on these stores outliving the development timing: with PADDOCK_RETENTION_UNIT=seconds
// the round deletes finished commands, cleared alerts, filled event gaps and finished actions from before the current
// UTC month (and, in the first 400 s of a month, from before the previous one).
func TestRetentionDeviceCommand(t *testing.T) {
	slug, org := gateOrganization(t)
	user, password := tempUser(t, "retention", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	d := activeDevice(t, admin, "", "r5-"+uniqueSuffix())
	insert := func(finished string) string {
		return paddockSQL(t, `WITH c AS (INSERT INTO device_command (id, organization_id, device_id, type, status, issued_at, expires_at, finished_at)
			SELECT gen_random_uuid(), organization_id, id, 'run_bundle', 'succeeded', `+finished+` - interval '1 second',
			       `+finished+` + interval '1 day', `+finished+` FROM device WHERE id = '`+d.DeviceID+`' RETURNING id) SELECT id FROM c`)
	}
	expired, fresh := insert("now() - interval '40 days'"), insert("now()")

	idx := auditIndex(t)
	const where = "code = 'retention.purged' AND params->>'store' = $1"
	ev := expectOneIndexEvent(t, idx, org, where, "device_command", "retention.purged", "success", 90*time.Second)
	if deleted, _ := ev.Params["deleted"].(float64); deleted != 1 || ev.ActorDisplay != "worker" {
		t.Fatalf("retention.purged params %v, actor %q", ev.Params, ev.ActorDisplay)
	}
	left := paddockSQL(t, "SELECT string_agg(id::text, ',') FROM device_command WHERE id IN ('"+expired+"', '"+fresh+"')")
	if left != fresh {
		t.Fatalf("commands left %q, want only the fresh one %s", left, fresh)
	}
}

// TestAuditIndexPurge is gate R4 (plan M10 §9, PDK-140): the dry run of the audit index purge runs in the audit-writer
// container with the writer's credentials and, as no partition of the development stack is older than the 400-day
// retention, prints "nothing to purge" or KEEP lines only.
func TestAuditIndexPurge(t *testing.T) {
	ctx := testContext(t, 2*time.Minute)
	code, out, err := stack.PaddockServer(ctx, "audit", "purge", "--dry-run")
	if err != nil || code != 0 {
		t.Fatalf("audit purge --dry-run: exit %d, %v\n%s", code, err, out)
	}
	nothing, keep := false, 0
	for _, line := range strings.Split(out, "\n") {
		switch {
		case line == "nothing to purge":
			nothing = true
		case strings.HasPrefix(line, "KEEP "):
			keep++
		case strings.HasPrefix(line, "DROP "), strings.HasPrefix(line, "FAIL "):
			t.Errorf("the development stack has a partition past the retention: %s", line)
		}
	}
	if nothing == (keep > 0) {
		t.Errorf("want either \"nothing to purge\" or KEEP lines, got:\n%s", out)
	}
}

// TestRetentionRetiredInventory is gate R2 of plan M10 (PDK-138): a device with software in Paddock and a host in
// Fleet is retired in an organization that keeps a retired device's inventory for one day (a second on the development
// stack); within the next rounds one device.inventory_purged success event (actor system) names the device and the
// deleted rows, its software list is empty and Fleet's admin API no longer knows the host. The organization is fresh,
// so its period does not touch other gates' retired devices.
func TestRetentionRetiredInventory(t *testing.T) {
	slug, org := gateOrganization(t)
	user, password := tempUser(t, "retention", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	suffix := uniqueSuffix()
	hostname := "r2-" + suffix
	d := activeDevice(t, admin, "", hostname)
	host := enrollFleetHost(t, d.HardwareUUID(), hostname, [][2]string{{"r2-package-" + suffix, "1.0"}})
	if err := host.WaitAnswered(testContext(t, 2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	software := "/api/v1/devices/" + d.DeviceID + "/software"
	for deadline := time.Now().Add(10 * time.Minute); listInventory(t, admin, software).Total == 0; time.Sleep(10 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("no software stored within 10 minutes")
		}
		if _, err := host.Answer(testContext(t, time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if !fleetHostExists(t, d.HardwareUUID()) {
		t.Fatal("Fleet does not know the host before the purge")
	}

	res := call(t, admin, http.MethodPut, "/api/v1/settings/privacy", map[string]any{
		"retired_inventory_days": 1, "audit_search_recorded": false, "inventory_view_recorded": false,
	})
	expectStatus(t, res, http.StatusOK, "")
	res = call(t, admin, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/retire", nil)
	expectStatus(t, res, http.StatusOK, "")

	idx := auditIndex(t)
	ev := expectOneIndexEvent(t, idx, org, "code = 'device.inventory_purged' AND target->>'id' = $1", d.DeviceID,
		"device.inventory_purged", "success", 90*time.Second)
	if n, _ := ev.Params["software"].(float64); n < 1 || ev.Params["fleet_host_deleted"] != true ||
		ev.Params["hostname"] != hostname || ev.ActorDisplay != "worker" {
		t.Fatalf("device.inventory_purged params %v, actor %q", ev.Params, ev.ActorDisplay)
	}
	if retired, _ := ev.Params["retired_at"].(string); retired == "" {
		t.Fatalf("device.inventory_purged without retired_at: %v", ev.Params)
	}
	if left := listInventory(t, admin, software).Total; left != 0 {
		t.Fatalf("%d packages listed after the purge", left)
	}
	if fleetHostExists(t, d.HardwareUUID()) {
		t.Fatal("Fleet still knows the host after the purge")
	}
}
