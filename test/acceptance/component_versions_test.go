package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type componentTarget struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Source    string `json:"source"`
}

func componentTargets(t *testing.T, root *env.Portal) map[string]componentTarget {
	t.Helper()
	res := call(t, root, http.MethodGet, "/api/platform/v1/component-targets", nil)
	expectStatus(t, res, http.StatusOK, "")
	var out struct {
		Targets []componentTarget `json:"targets"`
	}
	if err := res.JSON(&out); err != nil {
		t.Fatal(err)
	}
	m := map[string]componentTarget{}
	for _, c := range out.Targets {
		m[c.Component] = c
	}
	return m
}

type deviceComponent struct {
	Name      string  `json:"name"`
	Installed string  `json:"installed"`
	Expected  *string `json:"expected"`
	Status    string  `json:"status"`
}

func deviceComponents(t *testing.T, p *env.Portal, id string) map[string]deviceComponent {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var d struct {
		Components []deviceComponent `json:"components"`
	}
	if err := res.JSON(&d); err != nil {
		t.Fatal(err)
	}
	m := map[string]deviceComponent{}
	for _, c := range d.Components {
		m[c.Name] = c
	}
	return m
}

// TestComponentTargets is gate A12 of plan M8d §14.4: the platform administrator reads the targets — Himmelblau from
// the compiler's setting, paddockd from the current release once its rollout completed; an organization
// administrator is refused.
func TestComponentTargets(t *testing.T) {
	root, alice := login(t, env.PlatformAdmin), login(t, env.Alice)
	haltRunningRollouts(t, root)
	t.Cleanup(func() { haltRunningRollouts(t, root) })
	v := gateRelease(t, root, true, true)
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{
		"waves": []int{100}, "min_wave_minutes": 1, "failure_threshold_min": 1000, "failure_threshold_percent": 100,
	}), http.StatusCreated, "")
	t.Cleanup(func() {
		if rolloutStatus(t, root, v) != "halted" {
			expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout/halt", nil), http.StatusOK, "")
		}
	})
	waitRolloutStatus(t, root, v, "completed", 4*time.Minute)
	eventually(t, "the targets of the current release", 3*time.Minute, func() bool { return componentTargets(t, root)["paddockd"].Version == v })
	got := componentTargets(t, root)
	if h := got["himmelblau"]; h.Version == "" || h.Source != "PADDOCK_HIMMELBLAU_VERSION" {
		t.Fatalf("himmelblau target %+v", h)
	}
	if p := got["paddockd"]; p.Source != "agent_release" || got["paddock_supervisor"].Version != v {
		t.Fatalf("release targets %+v", got)
	}
	expectStatus(t, call(t, alice, http.MethodGet, "/api/platform/v1/component-targets", nil), http.StatusForbidden, "")
}

// TestComponentVersions is gate A11 of plan M8d §14.4: a device reporting its components is listed with each status
// against the targets; an outdated Himmelblau puts it into the component_outdated filter until it reports the
// target; a device without components shows every status unknown.
func TestComponentVersions(t *testing.T) {
	root, alice := login(t, env.PlatformAdmin), login(t, env.Alice)
	targets := componentTargets(t, root)
	himmelblau := targets["himmelblau"].Version
	if himmelblau == "" {
		t.Fatal("no Himmelblau target (the compiler sets it at start)")
	}
	d := activeDevice(t, alice, "", "a11-"+uniqueSuffix())
	hostname := getDevice(t, alice, d.DeviceID).Hostname
	paddockd := targets["paddockd"].Version
	if paddockd == "" {
		paddockd = "0.1.0"
	}
	outdatedListed := func() int {
		return listCount(t, alice, "/api/v1/devices", url.Values{"component_outdated": {"true"}, "q": {hostname}})
	}
	// reportUntil checks in with the components until cond holds: the worker writes device_status at most once a
	// minute per device.
	reportUntil := func(what string, components map[string]string, cond func() bool) {
		t.Helper()
		health := map[string]any{"reconcile": "ok"}
		if components != nil {
			health["components"] = components
		}
		d.Health, _ = json.Marshal(health)
		for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(5 * time.Second) {
			_, _, _ = d.Checkin(testContext(t, time.Minute))
			if cond() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: not within 3 minutes", what)
			}
		}
	}
	reportUntil("the outdated Himmelblau", map[string]string{"paddockd": paddockd, "paddock_supervisor": paddockd, "paddock_revoke": "",
		"himmelblau": "4.0.3-1", "fleetd": ""}, func() bool { return outdatedListed() == 1 })
	c := deviceComponents(t, alice, d.DeviceID)
	if c["paddockd"].Status != "ok" || c["himmelblau"].Status != "outdated" || c["paddock_revoke"].Status != "missing" ||
		c["fleetd"].Status != "missing" || c["himmelblau"].Expected == nil || *c["himmelblau"].Expected != himmelblau {
		t.Fatalf("components %+v", c)
	}
	reportUntil("the current Himmelblau", map[string]string{"paddockd": paddockd, "paddock_supervisor": paddockd, "paddock_revoke": "",
		"himmelblau": himmelblau + "-1", "fleetd": ""}, func() bool { return outdatedListed() == 0 })
	if c := deviceComponents(t, alice, d.DeviceID); c["himmelblau"].Status != "ok" {
		t.Fatalf("after the update %+v", c["himmelblau"])
	}

	other := activeDevice(t, alice, "", "a11b-"+uniqueSuffix())
	for name, c := range deviceComponents(t, alice, other.DeviceID) {
		if c.Status != "unknown" {
			t.Fatalf("%s of a device without components: %+v", name, c)
		}
	}
}
