package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

func (h releaseHarness) targets(t *testing.T) map[string]string {
	t.Helper()
	rows, err := h.super.Query(context.Background(), "SELECT component, version FROM component_target")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var c, v string
		if err := rows.Scan(&c, &v); err != nil {
			t.Fatal(err)
		}
		out[c] = v
	}
	return out
}

// TestReleaseTargets (plan M8d decision 53): a completed current rollout sets paddockd and the supervisor to the
// release, paddock-revoke only with its package, fleetd to the newest fleet-osquery package; a halted one removes the
// four rows and leaves Himmelblau's. Platform administrators read them, organization roles do not.
func TestReleaseTargets(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.exec(t, "UPDATE agent_rollout SET status = 'halted' WHERE status IN ('running', 'completed')")
	h.exec(t, `INSERT INTO component_target (component, version, source) VALUES ('himmelblau', '4.0.4', 'PADDOCK_HIMMELBLAU_VERSION')
		ON CONFLICT (component) DO NOTHING`)
	ctx := systemCtx(uuid.Nil)
	if err := h.releases.UpsertReleaseTargets(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.targets(t); len(got) != 1 || got["himmelblau"] == "" {
		t.Fatalf("without a completed rollout %v", got)
	}
	v := h.completedRollout(t, time.Now().Add(2*time.Minute))
	if err := h.releases.UpsertReleaseTargets(ctx); err != nil {
		t.Fatal(err)
	}
	got := h.targets(t)
	if got["paddockd"] != v || got["paddock_supervisor"] != v || got["himmelblau"] == "" {
		t.Fatalf("targets %v for release %s", got, v)
	}
	if _, ok := got["paddock_revoke"]; ok {
		t.Fatalf("paddock_revoke without its package: %v", got)
	}
	h.exec(t, "UPDATE agent_rollout SET status = 'halted' WHERE version = $1", v)
	if err := h.releases.UpsertReleaseTargets(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.targets(t); len(got) != 1 || got["himmelblau"] == "" {
		t.Fatalf("after the halt %v", got)
	}
	if list, err := h.releases.ComponentTargets(platformAdmin()); err != nil || len(list) != 1 {
		t.Fatalf("platform list %v, %v", list, err)
	}
	org, _ := h.device(t)
	if _, err := h.releases.ComponentTargets(h.operatorIn(t, org, principal.RoleOrgAdmin)); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("organization administrator: %v", err)
	}
}

// TestComponentsOutdated (plan M8d decisions 54 and 55): the heartbeat stores the outdated components, the device list
// filters by them, the detail lists every component with its status, and a device without components is unknown.
func TestComponentsOutdated(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.exec(t, `INSERT INTO component_target (component, version, source) VALUES ('himmelblau', '4.0.4', 'PADDOCK_HIMMELBLAU_VERSION')
		ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version`)
	org, dev := h.device(t)
	heartbeat := func(components map[string]string) {
		t.Helper()
		health := map[string]any{}
		if components != nil {
			health["components"] = components
		}
		raw, _ := json.Marshal(health)
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: time.Now(),
			AgentVersion: "0.1.0", Health: raw}); err != nil {
			t.Fatal(err)
		}
	}
	heartbeat(map[string]string{"paddockd": "0.1.0", "paddock_supervisor": "0.1.0", "paddock_revoke": "", "himmelblau": "4.0.3-1", "fleetd": ""})
	var outdated []string
	if err := h.super.QueryRow(context.Background(), "SELECT components_outdated FROM device_status WHERE device_id = $1", dev).Scan(&outdated); err != nil ||
		!slices.Equal(outdated, []string{"himmelblau"}) {
		t.Fatalf("components_outdated %v, %v", outdated, err)
	}
	api, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	devices := app.NewDevices(h.runner, api, nil)
	reader := h.operatorIn(t, org, principal.RoleOrgAuditor)
	yes, no := true, false
	list := func(flag *bool) int {
		t.Helper()
		res, err := devices.List(reader, app.DeviceQuery{Page: app.ListPage{Limit: 10, Sort: "hostname"}, ComponentOutdated: flag})
		if err != nil {
			t.Fatal(err)
		}
		return res.Count
	}
	if list(&yes) != 1 || list(&no) != 0 {
		t.Fatalf("filter: outdated %d, current %d", list(&yes), list(&no))
	}
	detail, err := devices.Get(reader, dev)
	if err != nil || detail.ComponentTargets["himmelblau"] != "4.0.4" {
		t.Fatalf("detail targets %v, %v", detail.ComponentTargets, err)
	}
	heartbeat(map[string]string{"himmelblau": "4.0.4-1"})
	if list(&yes) != 0 {
		t.Fatal("the device stays outdated after reporting the target")
	}
	heartbeat(nil)
	if list(&no) != 1 {
		t.Fatal("a device without components is not listed as current")
	}
}
