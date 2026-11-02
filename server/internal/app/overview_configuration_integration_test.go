package app_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

// TestOverviewConfiguration (PDK-164, plan M11 decision 46): the configuration card counts the rollout with the rule
// of the rollout API, the failed resources and devices of active devices without the plan errors of report-only
// reports (amendments R6.6, R6.15), and the active devices in report-only mode; retired devices never count.
func TestOverviewConfiguration(t *testing.T) {
	h := newRolloutHarness(t)
	overview := app.NewOverview(h.pool)

	empty, err := overview.Get(h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Configuration.Rollout != nil || empty.Configuration.FailedResources != 0 || empty.Configuration.FailedDevices != 0 || empty.Configuration.ReportOnlyDevices != 0 {
		t.Fatalf("empty organization: %+v", empty.Configuration)
	}

	enableRollouts(t, h.writeHarness, []int{100}, nil)
	r := h.stage(t, "/etc/acme/card.conf")
	now := time.Now()
	failing := h.device(t, r.id, 100, true)
	planErrors := h.device(t, r.id, 100, true)
	retired := h.device(t, r.id, 100, true)
	idleReportOnly := h.device(t, r.id, 100, true)
	h.exec(t, "UPDATE device SET config_mode = 'report_only' WHERE id = ANY($1)", []uuid.UUID{planErrors, idleReportOnly})
	h.exec(t, "UPDATE device SET state = 'retired', config_mode = 'report_only' WHERE id = $1", retired)
	h.report(t, failing, r.id, 1, "applied", "enforce", "file:/etc/acme/card.conf", now)
	h.report(t, planErrors, r.id, 1, "applied", "report_only", "file:/etc/acme/plan-error.conf", now)
	h.report(t, retired, r.id, 1, "applied", "enforce", "file:/etc/acme/retired.conf", now)

	got, err := overview.Get(h.admin)
	if err != nil {
		t.Fatal(err)
	}
	c := got.Configuration
	if c.FailedResources != 1 || c.FailedDevices != 1 || c.ReportOnlyDevices != 2 {
		t.Fatalf("configuration %+v, want 1 failed resource on 1 device and 2 report-only devices", c)
	}
	if c.Rollout == nil || c.Rollout.ID != r.id {
		t.Fatalf("rollout %+v, want %s", c.Rollout, r.id)
	}
	detail, err := h.api.Get(h.admin, r.id)
	if err != nil {
		t.Fatal(err)
	}
	if c.Rollout.Counts != detail.Counts {
		t.Fatalf("overview counts %+v, rollout counts %+v", c.Rollout.Counts, detail.Counts)
	}

	h.exec(t, "UPDATE config_rollout SET status = 'completed', ended_at = now(), ended_reason = 'done' WHERE id = $1", r.id)
	closed, err := overview.Get(h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Configuration.Rollout != nil {
		t.Fatalf("a completed rollout is not open: %+v", closed.Configuration.Rollout)
	}
}
