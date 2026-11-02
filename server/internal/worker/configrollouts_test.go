package worker

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestConfigRolloutRound (plan M11 decision 33): the round evaluates the running rollout of every organization as the
// worker, completes a single-wave rollout whose wave duration passed with one audited event, and exports the gauge of
// rollouts by status.
func TestConfigRolloutRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	round := NewConfigRollouts(app.NewConfigRollouts(app.NewActionRunner(f.pool, platform, httpx.RequestID), f.pool), f.pool, platform)
	changeSet, rollout := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	plan := `{"changes":[{"section":"managed_files","key":"[null,\"/etc/w.conf\"]","action":"create"}],"created":1}`
	if _, err := f.super.Exec(ctx, `INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections, plan, rollout)
		VALUES ($1, $2, '{"type":"admin","display":"a"}', 'session', 1, 0, 0, '{managed_files}', $3, 'staged')`, changeSet, f.org, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO config_rollout (id, organization_id, change_set_id, waves, min_wave_minutes,
		failure_threshold_percent, failure_threshold_min, status, started_by, wave_started_at)
		VALUES ($1, $2, $3, '{100}', 1, 2, 3, 'running', 'a', now() - interval '2 minutes')`, rollout, f.org, changeSet); err != nil {
		t.Fatal(err)
	}
	if err := round.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM config_rollout WHERE id = $1 AND status = 'completed' AND ended_reason = 'every wave passed'", rollout); n != 1 {
		t.Fatal("the rollout did not complete")
	}
	if n := f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'config_rollout.completed' AND outcome = 'success'", f.org); n != 1 {
		t.Fatalf("%d completed actions, want 1", n)
	}
	if got := testutil.ToFloat64(metricConfigRollouts.WithLabelValues("completed")); got < 1 {
		t.Fatalf("paddock_config_rollouts{status=completed} = %v", got)
	}
	if err := round.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code LIKE 'config_rollout.%'", f.org); n != 1 {
		t.Fatalf("%d actions after a second round, want 1", n)
	}
}
