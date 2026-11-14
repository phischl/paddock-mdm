package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestMessagesOfDeletingOrganizationDropped: once an organization is deleting, the ingest consumers acknowledge its
// messages without writing anything and count them (plan M17 amendment 2026-11-14 d point 4); an enrollment is
// cached as refused and creates no device (amendment e point 11); an active organization's messages are processed as
// before.
func TestMessagesOfDeletingOrganizationDropped(t *testing.T) {
	f := newFixture(t)
	runner := app.NewActionRunner(f.pool, nil, httpx.RequestID)
	reports := NewReports(app.NewDeviceReports(runner, f.pool), app.NewDeviceCommands(runner, f.pool), f.cache)
	enroll := NewEnrollment(app.NewEnrollments(runner, f.pool), f.cache)
	ctx := context.Background()
	dev := f.device(t, "active")
	now := time.Now().UTC()
	heartbeat, _ := json.Marshal(ingest.Heartbeat{DeviceID: dev, OrganizationID: f.org, ReceivedAt: now,
		AppliedBundleVersion: 2, AgentVersion: "0.1.0", Health: json.RawMessage(`{"reconcile":"ok"}`), Seq: 1})
	events, _ := json.Marshal(ingest.Events{DeviceID: dev, OrganizationID: f.org, ReceivedAt: now, Events: []protocol.Event{
		{EventSeq: 1, Type: protocol.EventBundleApplied, OccurredAt: now, Data: json.RawMessage(`{"bundle_version":3}`)},
	}})
	secret, _ := f.token(t, true)
	req, enrollBody := f.message(t, secret)
	dropped := func() float64 { return testutil.ToFloat64(metricDropped.WithLabelValues("organization_unavailable")) }

	before := dropped()
	if o := reports.events(ctx, "active-batch", events); o != ack {
		t.Fatalf("events of an active organization: %v", o)
	}
	if dropped() != before {
		t.Fatal("a message of an active organization was counted as dropped")
	}
	actions := f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1", f.org)

	if _, err := f.super.Exec(ctx, `UPDATE organization SET status = 'deleting', deletion_requested_at = now(),
		deletion_requested_by = 'platform admin', deletion_reason = 'contract ended', delete_after = now(),
		offboarding_step = 'database' WHERE id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	if o := reports.heartbeat(ctx, "hb", heartbeat); o != ack {
		t.Errorf("heartbeat: %v, want ack", o)
	}
	if o := reports.events(ctx, "batch", events); o != ack {
		t.Errorf("events: %v, want ack", o)
	}
	if o := enroll.process(ctx, req.EnrollmentID.String(), enrollBody); o != ack {
		t.Errorf("enrollment: %v, want ack", o)
	}
	if got := dropped() - before; got != 3 {
		t.Errorf("dropped counter rose by %v, want 3", got)
	}
	if n := f.count(t, "SELECT count(*) FROM device_status WHERE device_id = $1", dev); n != 0 {
		t.Errorf("%d status rows written for a deleting organization", n)
	}
	if n := f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1", f.org); n != actions {
		t.Errorf("%d actions, want %d: something was recorded for a deleting organization", n, actions)
	}
	// The enrollment is answered, so the gateway can refuse it (plan M17 amendment 2026-11-14 e point 11).
	enr, ok, err := f.cache.Enrollment(ctx, req.EnrollmentID)
	if err != nil || !ok || enr.Status != protocol.EnrollRejected || enr.Reason != devicecache.ReasonOrganizationUnavailable ||
		enr.DeviceID != uuid.Nil {
		t.Errorf("enrollment of a deleting organization: %+v, %v, %v", enr, ok, err)
	}
	if n := f.count(t, "SELECT count(*) FROM device WHERE organization_id = $1 AND id <> $2", f.org, dev); n != 0 {
		t.Errorf("%d devices enrolled into a deleting organization", n)
	}
}

func TestUnavailableMatchesOnlyTheGate(t *testing.T) {
	ctx := context.Background()
	before := testutil.ToFloat64(metricDropped.WithLabelValues("organization_unavailable"))
	for _, err := range []error{nil, errors.New("database down"), problem.Forbidden, problem.NotFound} {
		if unavailable(ctx, err) {
			t.Errorf("unavailable(%v) = true", err)
		}
	}
	if !unavailable(ctx, errors.Join(errors.New("db"), problem.OrganizationInactive)) {
		t.Error("unavailable(organization_inactive) = false")
	}
	if got := testutil.ToFloat64(metricDropped.WithLabelValues("organization_unavailable")) - before; got != 1 {
		t.Errorf("counter rose by %v, want 1", got)
	}
}
