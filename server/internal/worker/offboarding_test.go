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
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

// fakeOffboarder records the round's calls; advance decides each Advance's answer.
type fakeOffboarder struct {
	pending  []pgstore.Organization
	started  int
	attempts map[uuid.UUID][]time.Time
	now      func() time.Time
	advance  func(org uuid.UUID) error
}

func (f *fakeOffboarder) StartDue(context.Context) ([]uuid.UUID, error) {
	f.started++
	return nil, nil
}

func (f *fakeOffboarder) Pending(context.Context) ([]pgstore.Organization, error) {
	return f.pending, nil
}

func (f *fakeOffboarder) Advance(_ context.Context, org uuid.UUID) (bool, error) {
	f.attempts[org] = append(f.attempts[org], f.now())
	return false, f.advance(org)
}

// fakeLock grants the leader lock unless held.
type fakeLock struct{ held bool }

func (l *fakeLock) WithLeaderLock(ctx context.Context, _ int64, fn func(context.Context) error) (bool, error) {
	if l.held {
		return false, nil
	}
	return true, fn(ctx)
}

func deletingOrg(id uuid.UUID, step, code string) pgstore.Organization {
	o := pgstore.Organization{ID: id, Status: organization.StatusDeleting, OffboardingStep: &step}
	if code != "" {
		o.OffboardingErrorCode = &code
	}
	return o
}

// TestOffboardingRoundBackoff (main's requirement of 2026-11-14, §18): a failing step is retried after a wait that
// doubles from the round interval up to OffboardingBackoffCap; reaching the cap raises the alert metric once and the
// step keeps being retried at the cap; success resets the wait. A healthy organization is advanced every round
// meanwhile.
func TestOffboardingRoundBackoff(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	failing, healthy := uuid.New(), uuid.New()
	broken := true
	f := &fakeOffboarder{attempts: map[uuid.UUID][]time.Time{}, now: func() time.Time { return now },
		pending: []pgstore.Organization{deletingOrg(failing, offboarding.StepAuthentik, offboarding.ErrorAuthentikUnavailable),
			deletingOrg(healthy, offboarding.StepFleet, "")},
		advance: func(org uuid.UUID) error {
			if org == failing && broken {
				return &app.OffboardingError{Code: offboarding.ErrorAuthentikUnavailable, Err: errors.New("down")}
			}
			return nil
		}}
	r := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return now })
	capReached := testutil.ToFloat64(metricOffboardingCapReached)
	ctx := context.Background()
	for range 120 {
		if err := r.Round(ctx); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	start := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	var waits []time.Duration
	for i, at := range f.attempts[failing][1:] {
		waits = append(waits, at.Sub(f.attempts[failing][i]))
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute,
		30 * time.Minute}
	if f.attempts[failing][0] != start || len(waits) != len(want) {
		t.Fatalf("attempts at %v (waits %v), want waits %v", f.attempts[failing], waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits %v, want %v", waits, want)
		}
	}
	if n := len(f.attempts[healthy]); n != 120 {
		t.Fatalf("the healthy organization was advanced %d times in 120 rounds", n)
	}
	if got := testutil.ToFloat64(metricOffboardingCapReached) - capReached; got != 1 {
		t.Fatalf("cap reached %v times, want once", got)
	}
	if got := testutil.ToFloat64(metricOffboardingRetryCapped); got != 1 {
		t.Fatalf("capped gauge %v, want 1", got)
	}
	if got := testutil.ToFloat64(metricOffboardingStepFailing.WithLabelValues(offboarding.StepAuthentik,
		offboarding.ErrorAuthentikUnavailable)); got != 1 {
		t.Fatalf("failing gauge %v, want 1", got)
	}

	broken = false
	last := f.attempts[failing][len(f.attempts[failing])-1]
	for now.Before(last.Add(OffboardingBackoffCap)) {
		now = now.Add(time.Minute)
	}
	f.pending[0] = deletingOrg(failing, offboarding.StepFleet, "")
	for range 3 {
		if err := r.Round(ctx); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	tail := f.attempts[failing][len(f.attempts[failing])-3:]
	if tail[1].Sub(tail[0]) != time.Minute || tail[2].Sub(tail[1]) != time.Minute {
		t.Fatalf("after recovery the organization is advanced at %v, want every round", tail)
	}
	if got := testutil.ToFloat64(metricOffboardingRetryCapped); got != 0 {
		t.Fatalf("capped gauge %v after recovery", got)
	}
	if got := testutil.ToFloat64(metricOffboardingStepFailing.WithLabelValues(offboarding.StepAuthentik,
		offboarding.ErrorAuthentikUnavailable)); got != 0 {
		t.Fatalf("failing gauge %v after recovery", got)
	}
}

// TestOffboardingRoundWaiting: a tombstone waiting for older transactions is no failure: it is asked again every round
// and counted in paddock_offboarding_finalize_busy_total.
func TestOffboardingRoundWaiting(t *testing.T) {
	now := time.Now()
	org := uuid.New()
	f := &fakeOffboarder{attempts: map[uuid.UUID][]time.Time{}, now: func() time.Time { return now },
		pending: []pgstore.Organization{deletingOrg(org, offboarding.StepTombstone, "")},
		advance: func(uuid.UUID) error { return app.ErrOffboardingWaiting }}
	r := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return now })
	busy := testutil.ToFloat64(metricOffboardingFinalizeBusy)
	for range 5 {
		if err := r.Round(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	if len(f.attempts[org]) != 5 || testutil.ToFloat64(metricOffboardingFinalizeBusy)-busy != 5 || f.started != 5 {
		t.Fatalf("attempts %d, busy %v, started %d; want 5 each", len(f.attempts[org]),
			testutil.ToFloat64(metricOffboardingFinalizeBusy)-busy, f.started)
	}
}

// TestOffboardingRoundLeaderLock: a replica without the leader lock neither starts nor advances a deletion, and resets
// the gauges it exported while it led (review 1 nit 6).
func TestOffboardingRoundLeaderLock(t *testing.T) {
	org := uuid.New()
	f := &fakeOffboarder{attempts: map[uuid.UUID][]time.Time{}, now: time.Now,
		pending: []pgstore.Organization{deletingOrg(org, offboarding.StepSessions, "")},
		advance: func(uuid.UUID) error { return nil }}
	lock := &fakeLock{}
	f.advance = func(uuid.UUID) error {
		return &app.OffboardingError{Code: offboarding.ErrorAuthentikUnavailable, Err: errors.New("down")}
	}
	f.pending[0] = deletingOrg(org, offboarding.StepAuthentik, offboarding.ErrorAuthentikUnavailable)
	r := NewOffboarding(f, lock)
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	metricOffboardingRetryCapped.Set(1)
	lock.held = true
	f.started, f.attempts = 0, map[uuid.UUID][]time.Time{}
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.started != 0 || len(f.attempts[org]) != 0 {
		t.Fatalf("started %d, attempts %d without the lock", f.started, len(f.attempts[org]))
	}
	failing := testutil.ToFloat64(metricOffboardingStepFailing.WithLabelValues(offboarding.StepAuthentik, offboarding.ErrorAuthentikUnavailable))
	if testutil.ToFloat64(metricOffboardingRetryCapped) != 0 || failing != 0 || len(r.retries) != 0 {
		t.Fatalf("after losing the lock: capped %v, failing %v, retries %d; want all reset",
			testutil.ToFloat64(metricOffboardingRetryCapped), failing, len(r.retries))
	}
}

// TestMessagesOfDeletedOrganizationDropped (PDK-1015 review 1, amendment l point 3): an offboarded device keeps its
// keys after the tombstone, so its heartbeats and events may still reach the worker; they are acknowledged and
// dropped without writing anything into the deleted organization.
func TestMessagesOfDeletedOrganizationDropped(t *testing.T) {
	f := newFixture(t)
	runner := app.NewActionRunner(f.pool, nil, httpx.RequestID)
	reports := NewReports(app.NewDeviceReports(runner, f.pool), app.NewDeviceCommands(runner, f.pool), f.cache)
	ctx := context.Background()
	dev := f.device(t, "active")
	now := time.Now().UTC()
	actions := f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1", f.org)
	if _, err := f.super.Exec(ctx, `UPDATE organization SET status = 'deleted', deleted_at = now(), deletion_requested_at = now(),
		deletion_requested_by = 'platform admin', deletion_reason = 'contract ended', delete_after = now() WHERE id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
	heartbeat, _ := json.Marshal(ingest.Heartbeat{DeviceID: dev, OrganizationID: f.org, ReceivedAt: now,
		AppliedBundleVersion: 2, AgentVersion: "0.1.0", Health: json.RawMessage(`{"reconcile":"ok"}`), Seq: 1})
	events, _ := json.Marshal(ingest.Events{DeviceID: dev, OrganizationID: f.org, ReceivedAt: now, Events: []protocol.Event{
		{EventSeq: 1, Type: protocol.EventBundleApplied, OccurredAt: now, Data: json.RawMessage(`{"bundle_version":3}`)},
	}})
	dropped := func() float64 { return testutil.ToFloat64(metricDropped.WithLabelValues("organization_unavailable")) }
	before := dropped()
	if o := reports.heartbeat(ctx, "hb", heartbeat); o != ack {
		t.Errorf("heartbeat: %v, want ack", o)
	}
	if o := reports.events(ctx, "batch", events); o != ack {
		t.Errorf("events: %v, want ack", o)
	}
	if got := dropped() - before; got != 2 {
		t.Errorf("dropped counter rose by %v, want 2", got)
	}
	if n := f.count(t, "SELECT count(*) FROM device_status WHERE device_id = $1", dev); n != 0 {
		t.Errorf("%d status rows written for a deleted organization", n)
	}
	if n := f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1", f.org); n != actions {
		t.Errorf("%d actions, want %d: something was recorded for a deleted organization", n, actions)
	}
}
