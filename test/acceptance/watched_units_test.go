package acceptance

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestWatchedUnits is the server part of gate N10 (plan M9 §9): the units of the presence policy are set by an
// administrator with a step-up and audited with added, reserved and non-service units are refused, the next bundle of
// an active v2 device carries them (and none without units), and the declarative document applies the same list.
func TestWatchedUnits(t *testing.T) {
	admin, _ := gateOrg(t, "n10-admin")
	const path = "/api/v1/settings/watched-units"
	dev := v2Device(t, admin.Portal, "", 1, 2)
	hasWatch := func(b *bundle.Bundle) bool { return b.Watch != nil }
	unit := []string{"wazuh-agent.service"}

	res := call(t, withoutStepUp(t, admin), http.MethodPut, path, map[string]any{"units": unit})
	expectStatus(t, res, http.StatusForbidden, "step_up_required")

	for _, bad := range [][]string{{"paddockd.service"}, {"orbit.service"}, {"foo.timer"}} {
		admin.stepUp(t)
		expectStatus(t, call(t, admin.Portal, http.MethodPut, path, map[string]any{"units": bad}), http.StatusUnprocessableEntity, "unit_not_allowed")
	}
	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPut, path, map[string]any{"units": []string{"a.service", "a.service"}}), http.StatusBadRequest, "invalid_request")

	admin.stepUp(t)
	res = call(t, admin.Portal, http.MethodPut, path, map[string]any{"units": unit})
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "settings.watched_units_changed", "success")
	if added, _ := ev.Params["added"].([]any); len(added) != 1 || added[0] != unit[0] {
		t.Fatalf("event params %v", ev.Params)
	}
	b := latestBundle(t, dev, 90*time.Second, hasWatch)
	if !slices.Equal(b.Watch.Units, unit) {
		t.Fatalf("watch section %+v", b.Watch)
	}

	// The declarative document shows the diff in a dry run and applies the list.
	doc := getConfig(t, admin.Portal)
	two := []any{"falcon-sensor.service", unit[0]}
	doc["settings"].(map[string]any)["watched_units"] = two
	admin.stepUp(t)
	plan := configResultOf(t, putConfig(t, admin.Portal, doc, true))
	if len(plan.Plan.Changes) != 1 || plan.Plan.Changes[0].Section != "settings.watched_units" || plan.Plan.Changes[0].Action != "update" {
		t.Fatalf("dry run %+v", plan.Plan)
	}
	admin.stepUp(t)
	expectStatus(t, putConfig(t, admin.Portal, doc, false), http.StatusOK, "")
	b = latestBundle(t, dev, 90*time.Second, func(b *bundle.Bundle) bool { return b.Watch != nil && len(b.Watch.Units) == 2 })
	if !slices.Equal(b.Watch.Units, []string{"falcon-sensor.service", unit[0]}) {
		t.Fatalf("watch section after apply %+v", b.Watch)
	}

	// An empty list removes the section.
	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPut, path, map[string]any{"units": []string{}}), http.StatusOK, "")
	latestBundle(t, dev, 90*time.Second, func(b *bundle.Bundle) bool { return b.Watch == nil })

	// Another organization never sees the list.
	other := login(t, env.Alice)
	var got struct {
		Units []string `json:"units"`
	}
	if err := call(t, other, http.MethodGet, path, nil).JSON(&got); err != nil || slices.Contains(got.Units, unit[0]) {
		t.Fatalf("acme sees %v (%v)", got.Units, err)
	}
}
