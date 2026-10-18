package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestAgentUpdatePolicy is gate A5 of plan M8d (AC5, server part): the organization's policy and the overrides of a
// device's groups reach the bundle's agent.update_policy (manual wins over automatic, automatic lifts a manual
// organization, automatic without overrides is absent); settings.updates_changed records the policy; the declarative
// document applies it.
func TestAgentUpdatePolicy(t *testing.T) {
	slug, _ := gateOrganization(t)
	user, password := tempUser(t, "updatepolicy", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	settings := currentUpdateSettings(t, admin)
	if settings["agent_update_policy"] != "automatic" {
		t.Fatalf("default policy %v", settings["agent_update_policy"])
	}
	bad := currentUpdateSettings(t, admin)
	bad["agent_update_policy"] = "sometimes"
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/settings/updates", bad), http.StatusBadRequest, "")

	autoGroup := namedGroup(t, admin, "a5 automatic")
	manualGroup := namedGroup(t, admin, "a5 manual")
	expectStatus(t, call(t, admin, http.MethodPatch, "/api/v1/device-groups/"+autoGroup, map[string]any{"agent_update_policy": "automatic"}),
		http.StatusOK, "")
	expectStatus(t, call(t, admin, http.MethodPatch, "/api/v1/device-groups/"+manualGroup, map[string]any{"agent_update_policy": "manual"}),
		http.StatusOK, "")
	plain := v2Device(t, admin, "", 1, 2)
	lifted := v2Device(t, admin, autoGroup, 1, 2)
	both := v2Device(t, admin, autoGroup, 1, 2)
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/devices/"+both.DeviceID+"/groups",
		map[string]any{"device_group_ids": []string{autoGroup, manualGroup}}), http.StatusOK, "")
	if b := latestBundle(t, plain, time.Minute, func(*bundle.Bundle) bool { return true }); b.Agent.UpdatePolicy != "" {
		t.Fatalf("automatic organization renders %q", b.Agent.UpdatePolicy)
	}

	settings["agent_update_policy"] = "manual"
	res := call(t, admin, http.MethodPut, "/api/v1/settings/updates", settings)
	expectStatus(t, res, http.StatusOK, "")
	if ev := expectOneEvent(t, admin, res.RequestID, "settings.updates_changed", "success"); ev.Params["agent_update_policy"] != "manual" {
		t.Fatalf("params %v", ev.Params)
	}
	for _, c := range []struct {
		sim  *devicesim.Device
		want string
	}{{plain, "manual"}, {lifted, "automatic"}, {both, "manual"}} {
		b := latestBundle(t, c.sim, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Agent.UpdatePolicy == c.want })
		if b.Agent.UpdatePolicy != c.want {
			t.Fatalf("device %s: %q, want %q", c.sim.DeviceID, b.Agent.UpdatePolicy, c.want)
		}
	}

	// The declarative document carries the policy (paddockctl apply goes through PUT /api/v1/config).
	settings["agent_update_policy"] = "automatic"
	doc := map[string]any{"api_version": "paddock/v1", "kind": "OrganizationConfig", "settings": map[string]any{"updates": settings}}
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/config", doc), http.StatusOK, "")
	if got := currentUpdateSettings(t, admin)["agent_update_policy"]; got != "automatic" {
		t.Fatalf("after the document: %v", got)
	}
	expectStatus(t, call(t, admin, http.MethodPatch, "/api/v1/device-groups/"+autoGroup, map[string]any{"agent_update_policy": nil}),
		http.StatusOK, "")
	expectStatus(t, call(t, admin, http.MethodPatch, "/api/v1/device-groups/"+manualGroup, map[string]any{"agent_update_policy": nil}),
		http.StatusOK, "")
	if b := latestBundle(t, both, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Agent.UpdatePolicy == "" }); b.Agent.UpdatePolicy != "" {
		t.Fatalf("without overrides: %q", b.Agent.UpdatePolicy)
	}
}
