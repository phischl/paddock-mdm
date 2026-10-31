package admin_test

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestWatchedUnitsAPI (plan M9 decision 38): GET/PUT /api/v1/settings/watched-units with the step-up and the
// refusals of the contract; another organization never sees the list.
func TestWatchedUnitsAPI(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	const path = "/api/v1/settings/watched-units"
	put := func(c *http.Cookie, units any) result {
		return e.do(call{method: "PUT", path: path, cookie: c, body: map[string]any{"units": units}})
	}
	wazuh := []string{"wazuh-agent.service"}

	if r := put(alice, wazuh); r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.status, r.body)
	}
	for _, units := range [][]string{{"paddockd.service"}, {"orbit.service"}, {"foo.timer"}} {
		if r := put(e.steppedUp(alice, time.Now()), units); r.status != http.StatusUnprocessableEntity || r.problemCode(t) != "unit_not_allowed" {
			t.Fatalf("%v: %d %s", units, r.status, r.body)
		}
	}
	if r := put(e.steppedUp(alice, time.Now()), []string{"a.service", "a.service"}); r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("duplicates: %d %s", r.status, r.body)
	}
	r := put(e.steppedUp(alice, time.Now()), wazuh)
	if r.status != http.StatusOK {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "settings.watched_units_changed:success:")
	var got adminapi.WatchedUnits
	e.do(call{method: "GET", path: path, cookie: alice}).decode(t, &got)
	if !slices.Equal(got.Units, wazuh) || got.UpdatedAt == nil {
		t.Fatalf("get %+v", got)
	}
	e.do(call{method: "GET", path: path, cookie: carol}).decode(t, &got)
	if len(got.Units) != 0 || got.UpdatedAt != nil {
		t.Fatalf("another organization sees %+v", got)
	}
}
