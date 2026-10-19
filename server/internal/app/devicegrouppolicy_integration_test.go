package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestDeviceGroupPolicyOverrides (plan M8d decision 11): a group stores its contact thresholds, update policy and
// unlock mode, validated with the organization's bounds; null clears an override, absence keeps it; the events carry
// every override (null when unset).
func TestDeviceGroupPolicyOverrides(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	groups := app.NewDeviceGroups(h.runner, pool)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgOperator, false))
	manual, tpmOnly := "manual", "tpm_only"

	g, err := groups.Create(ctx, "laptops", nil, app.DeviceGroupPolicy{Staleness: &app.GroupStaleness{WarningH: 120, CriticalH: 840},
		AgentUpdatePolicy: &manual})
	if err != nil {
		t.Fatal(err)
	}
	if p := app.PolicyOf(g); p.Staleness == nil || p.Staleness.WarningH != 120 || p.AgentUpdatePolicy == nil || p.DiskUnlockMode != nil {
		t.Fatalf("stored %+v", p)
	}
	ev := h.lastEvent(t)
	if ev.Params["staleness_warning_h"] != float64(120) || ev.Params["staleness_critical_h"] != float64(840) ||
		ev.Params["agent_update_policy"] != "manual" || ev.Params["disk_unlock_mode"] != nil {
		t.Fatalf("created params %v", ev.Params)
	}
	if _, ok := ev.Params["disk_unlock_mode"]; !ok {
		t.Fatal("disk_unlock_mode missing from the params")
	}

	for name, pol := range map[string]app.DeviceGroupPolicy{
		"warning only":       {Staleness: &app.GroupStaleness{WarningH: 2}},
		"critical = warning": {Staleness: &app.GroupStaleness{WarningH: 4, CriticalH: 4}},
		"warning too high":   {Staleness: &app.GroupStaleness{WarningH: 721, CriticalH: 800}},
		"critical too high":  {Staleness: &app.GroupStaleness{WarningH: 2, CriticalH: 2161}},
		"unknown policy":     {AgentUpdatePolicy: ptr("sometimes")},
		"unknown mode":       {DiskUnlockMode: ptr("tpm_pin_plus")},
	} {
		if _, err := groups.Create(ctx, "bad "+name, nil, pol); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}

	g, err = groups.Update(ctx, g.ID, nil, nil, app.DeviceGroupPolicyPatch{DiskUnlockMode: app.Change[string]{Set: true, Value: &tpmOnly}})
	if err != nil {
		t.Fatal(err)
	}
	if p := app.PolicyOf(g); p.Staleness == nil || p.AgentUpdatePolicy == nil || p.DiskUnlockMode == nil || *p.DiskUnlockMode != "tpm_only" {
		t.Fatalf("absent fields must stay: %+v", p)
	}
	g, err = groups.Update(ctx, g.ID, nil, nil, app.DeviceGroupPolicyPatch{Staleness: app.Change[app.GroupStaleness]{Set: true},
		AgentUpdatePolicy: app.Change[string]{Set: true}})
	if err != nil {
		t.Fatal(err)
	}
	if p := app.PolicyOf(g); p.Staleness != nil || p.AgentUpdatePolicy != nil || p.DiskUnlockMode == nil {
		t.Fatalf("null must clear: %+v", p)
	}
	ev = h.lastEvent(t)
	if ev.Params["staleness_warning_h"] != nil || ev.Params["agent_update_policy"] != nil || ev.Params["disk_unlock_mode"] != "tpm_only" {
		t.Fatalf("updated params %v", ev.Params)
	}
	if _, err := groups.Update(ctx, g.ID, nil, nil, app.DeviceGroupPolicyPatch{
		Staleness: app.Change[app.GroupStaleness]{Set: true, Value: &app.GroupStaleness{WarningH: 2}},
	}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("invalid patch = %v", err)
	}
}
