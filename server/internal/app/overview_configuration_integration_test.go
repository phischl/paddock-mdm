package app_test

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

// TestOverviewConfiguration (PDK-164, plan M11 decision 46): the configuration card carries the open rollout without counts (amendment R6.16),
// counts the failed resources and devices of active devices without the plan errors of report-only reports
// (amendments R6.6, R6.15), and the active devices in report-only mode; retired devices never count.
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
	// Distinct counting: a second failed resource on the same device, and the same resource failed on a second device.
	second := h.device(t, r.id, 100, true)
	h.report(t, second, r.id, 1, "applied", "enforce", "file:/etc/acme/card.conf", now)
	h.exec(t, `INSERT INTO device_resource_status (device_id, organization_id, resource_id, status, bundle_version, occurred_at)
		VALUES ($1, $2, 'file:/etc/acme/second.conf', 'failed', 1, $3)`, failing, h.org, now)
	h.report(t, retired, r.id, 1, "applied", "enforce", "file:/etc/acme/retired.conf", now)

	got, err := overview.Get(h.admin)
	if err != nil {
		t.Fatal(err)
	}
	c := got.Configuration
	if c.FailedResources != 2 || c.FailedDevices != 2 || c.ReportOnlyDevices != 2 {
		t.Fatalf("configuration %+v, want 2 failed resources on 2 devices and 2 report-only devices", c)
	}
	if c.Rollout == nil || c.Rollout.ID != r.id {
		t.Fatalf("rollout %+v, want %s", c.Rollout, r.id)
	}
	detail, err := h.api.Get(h.admin, r.id)
	if err != nil {
		t.Fatal(err)
	}
	if o := c.Rollout; o.Status != detail.Status || o.CurrentWaveIndex != detail.CurrentWaveIndex || !slices.Equal(o.Waves, detail.Waves) || !o.StartedAt.Equal(detail.StartedAt) {
		t.Fatalf("overview rollout %+v, rollout API %+v", o, detail.ConfigRollout)
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
