package acceptance

import (
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
