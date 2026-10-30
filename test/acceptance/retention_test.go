package acceptance

import (
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
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
