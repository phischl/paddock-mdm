package app_test

import (
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

var upgradeWindow = []string{"0.1.0-alpha.7", "0.1.0-alpha.8", "0.1.0-alpha.9"}

// TestAgentsItemThresholds (ADR 0047 decision 2): FAIL when more than 1 % of the active devices or more than 5,
// whichever is larger, run an agent outside the window; WARN with the list below; PASS without any.
func TestAgentsItemThresholds(t *testing.T) {
	for _, c := range []struct {
		active, outside int
		want            string
	}{
		{120, 0, app.CheckPass},
		{0, 0, app.CheckPass},
		{120, 5, app.CheckWarn}, // limit max(1.2, 5) = 5
		{120, 6, app.CheckFail},
		{3, 3, app.CheckWarn},     // small installations: 5 devices are tolerated
		{1000, 10, app.CheckWarn}, // limit 10
		{1000, 11, app.CheckFail},
		{1050, 10, app.CheckWarn}, // limit 10.5
		{1050, 11, app.CheckFail},
	} {
		listed := make([]app.OutdatedAgent, min(c.outside, 25))
		for i := range listed {
			listed[i] = app.OutdatedAgent{Hostname: "lt-" + string(rune('a'+i))}
		}
		item := app.AgentsItem(c.active, c.outside, upgradeWindow, listed)
		if item.Name != app.CheckAgents || item.Status != c.want {
			t.Errorf("%d of %d outside: %s, want %s (%s)", c.outside, c.active, item.Status, c.want, item.Detail)
		}
		if !strings.Contains(item.Detail, "0.1.0-alpha.7, 0.1.0-alpha.8, 0.1.0-alpha.9") {
			t.Errorf("detail %q does not name the window", item.Detail)
		}
	}
	item := app.AgentsItem(120, 30, upgradeWindow, make([]app.OutdatedAgent, 25))
	if strings.Count(item.Detail, ", ") > 20+2+1 || !strings.HasSuffix(item.Detail, ", …") {
		t.Errorf("detail is not bounded: %q", item.Detail)
	}
	if got := app.AgentsItem(10, 1, upgradeWindow, []app.OutdatedAgent{{Hostname: "lt-01"}}).Detail; !strings.HasSuffix(got, ": lt-01") {
		t.Errorf("detail %q", got)
	}
}

// TestMigrationsItem: a database ahead of the binary is a downgrade (FAIL); equal or behind passes.
func TestMigrationsItem(t *testing.T) {
	for _, c := range []struct {
		database, binary int64
		want             string
	}{{103, 102, app.CheckFail}, {102, 102, app.CheckPass}, {99, 102, app.CheckPass}} {
		if got := app.MigrationsItem(c.database, c.binary); got.Status != c.want || got.Name != app.CheckMigrations {
			t.Errorf("database %d binary %d: %+v", c.database, c.binary, got)
		}
	}
}

// TestPendingItem: a running agent rollout or a halted configuration rollout is a WARN only (plan M16 §11).
func TestPendingItem(t *testing.T) {
	if got := app.PendingItem(nil, 0, "restore plans: n/a (plan M15)"); got.Status != app.CheckPass || !strings.Contains(got.Detail, "n/a") {
		t.Errorf("nothing pending: %+v", got)
	}
	if got := app.PendingItem([]string{"0.1.0-alpha.8"}, 0, ""); got.Status != app.CheckWarn || !strings.Contains(got.Detail, "0.1.0-alpha.8") {
		t.Errorf("running rollout: %+v", got)
	}
	if got := app.PendingItem(nil, 2, ""); got.Status != app.CheckWarn || !strings.Contains(got.Detail, "2 configuration rollouts halted") {
		t.Errorf("halted configuration rollouts: %+v", got)
	}
}

func TestReportFailed(t *testing.T) {
	r := app.UpgradeCheckReport{Items: []app.UpgradeCheckItem{{Status: app.CheckWarn}, {Status: app.CheckInfo}}}
	if r.Failed() {
		t.Error("WARN and INFO failed the report")
	}
	r.Items = append(r.Items, app.UpgradeCheckItem{Status: app.CheckFail})
	if !r.Failed() {
		t.Error("FAIL did not fail the report")
	}
}
