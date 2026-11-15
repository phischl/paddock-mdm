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
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

// fakeOffboarder records the round's calls; advance decides each Advance's answer.
type fakeOffboarder struct {
	pending  []pgstore.Organization
	started  int
	attempts map[uuid.UUID][]time.Time
	now      func() time.Time
	advance  func(org uuid.UUID) error
	// done decides whether an Advance completes the deletion; nil means every Advance does, so one call ends an organization.
	done func(org uuid.UUID) bool
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
	err := f.advance(org)
	return err == nil && (f.done == nil || f.done(org)), err
}

// fakeLock grants the leader lock unless held.
type fakeLock struct {
	held bool
	lose func()
}

func (l *fakeLock) Lead(ctx context.Context, _ int64, _ time.Duration, fn func(context.Context) error) (bool, error) {
	if l.held {
		return false, nil
	}
	var cancel context.CancelCauseFunc
	ctx, cancel = context.WithCancelCause(ctx)
	defer cancel(nil)
	l.lose = func() { cancel(db.ErrLeadershipLost) }
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

// stepper is a fake deletion of several steps: each Advance takes one step and costs cost of fake time.
type stepper struct {
	left map[uuid.UUID]int
	now  *time.Time
	cost time.Duration
	log  []uuid.UUID
}

func (s *stepper) fake(orgs ...uuid.UUID) *fakeOffboarder {
	f := &fakeOffboarder{attempts: map[uuid.UUID][]time.Time{}, now: func() time.Time { return *s.now }}
	for _, o := range orgs {
		f.pending = append(f.pending, deletingOrg(o, offboarding.StepSessions, ""))
	}
	f.advance = func(org uuid.UUID) error {
		s.log = append(s.log, org)
		s.left[org]--
		*s.now = s.now.Add(s.cost)
		return nil
	}
	f.done = func(org uuid.UUID) bool { return s.left[org] <= 0 }
	return f
}

func newStepper(cost time.Duration, steps map[uuid.UUID]int) (*stepper, *time.Time) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	return &stepper{left: steps, now: &now, cost: cost}, &now
}

// TestOffboardingRoundCarriesThroughSteps (PDK-946c): with no step waiting, one round takes an organization through
// all ten steps.
func TestOffboardingRoundCarriesThroughSteps(t *testing.T) {
	org := uuid.New()
	s, now := newStepper(time.Second, map[uuid.UUID]int{org: len(offboarding.Steps())})
	r := NewOffboarding(s.fake(org), &fakeLock{}).WithClock(func() time.Time { return *now })
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.log) != len(offboarding.Steps()) || s.left[org] != 0 {
		t.Fatalf("%d steps in one round, want %d", len(s.log), len(offboarding.Steps()))
	}
}

// TestOffboardingRoundStopsAtWaitingStep: a waiting or failing step ends the organization's round; the others go on
// and the organization is asked again next round.
func TestOffboardingRoundStopsAtWaitingStep(t *testing.T) {
	waits, failing, healthy := uuid.New(), uuid.New(), uuid.New()
	s, now := newStepper(time.Second, map[uuid.UUID]int{waits: 10, failing: 10, healthy: 4})
	f := s.fake(waits, failing, healthy)
	inner := f.advance
	f.advance = func(org uuid.UUID) error {
		_ = inner(org)
		switch {
		case org == waits && s.left[org] == 7:
			return app.ErrOffboardingWaiting
		case org == failing && s.left[org] == 7:
			return &app.OffboardingError{Code: offboarding.ErrorOutboxPending, Err: errors.New("outbox")}
		}
		return nil
	}
	r := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return *now })
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.left[waits] != 7 || s.left[failing] != 7 || s.left[healthy] != 0 {
		t.Fatalf("steps left: waiting %d, failing %d, healthy %d; want 7, 7, 0", s.left[waits], s.left[failing], s.left[healthy])
	}
}

// TestOffboardingRoundBudgetHandsOver: when the wall-clock budget is used the round ends after the running step and
// the next round continues at the next step; the budget is time, not a step count.
func TestOffboardingRoundBudgetHandsOver(t *testing.T) {
	org := uuid.New()
	s, now := newStepper(10*time.Second, map[uuid.UUID]int{org: 10})
	r := NewOffboarding(s.fake(org), &fakeLock{}).WithClock(func() time.Time { return *now })
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(s.log); got != 5 {
		t.Fatalf("%d steps in a 45 s round of 10 s steps, want 5", got)
	}
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.left[org] != 0 || len(s.log) != 10 {
		t.Fatalf("second round left %d steps (%d run)", s.left[org], len(s.log))
	}
}

// TestOffboardingRoundFairness (main's condition 1): one large deletion whose steps use the whole budget does not
// starve the others; every organization takes a step before any takes a second.
func TestOffboardingRoundFairness(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	s, now := newStepper(20*time.Second, map[uuid.UUID]int{a: 10, b: 10, c: 10})
	r := NewOffboarding(s.fake(a, b, c), &fakeLock{}).WithClock(func() time.Time { return *now })
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.log) < 3 || s.log[0] != a || s.log[1] != b || s.log[2] != c {
		t.Fatalf("order of steps %v, want every organization once first", s.log)
	}
}

// TestOffboardingRoundBetweenSteps (main's condition 2): the round holds nothing between steps but the leader
// connection: every step is its own Advance call, and the budget is checked against the clock between them, so a
// round of slow steps ends on time.
func TestOffboardingRoundBetweenSteps(t *testing.T) {
	org := uuid.New()
	s, now := newStepper(OffboardingRoundBudget, map[uuid.UUID]int{org: 3})
	r := NewOffboarding(s.fake(org), &fakeLock{}).WithClock(func() time.Time { return *now })
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.log) != 1 {
		t.Fatalf("%d steps after one that used the whole budget, want 1", len(s.log))
	}
}

// TestOffboardingRoundWithinLease (main's condition 3): the round budget ends before the next round and with it the
// lock, and a round whose leadership is lost starts no further step.
func TestOffboardingRoundWithinLease(t *testing.T) {
	if OffboardingRoundBudget >= OffboardingInterval {
		t.Fatalf("round budget %v must stay below the interval %v", OffboardingRoundBudget, OffboardingInterval)
	}
	org := uuid.New()
	s, now := newStepper(time.Second, map[uuid.UUID]int{org: 10})
	f := s.fake(org)
	lock := &fakeLock{}
	inner := f.advance
	f.advance = func(o uuid.UUID) error {
		err := inner(o)
		if len(s.log) == 2 {
			lock.lose()
		}
		return err
	}
	r := NewOffboarding(f, lock).WithClock(func() time.Time { return *now })
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.log) != 2 {
		t.Fatalf("%d steps ran, want 2: none after the leadership was lost", len(s.log))
	}
}

// TestOffboardingRoundCrashResumes: a crash (the context ends) after a step ends the round there; a new round, as of a
// restarted worker, takes the next step of the same organization, not the first.
func TestOffboardingRoundCrashResumes(t *testing.T) {
	org := uuid.New()
	s, now := newStepper(time.Second, map[uuid.UUID]int{org: 10})
	f := s.fake(org)
	lock := &fakeLock{}
	inner := f.advance
	f.advance = func(o uuid.UUID) error {
		err := inner(o)
		if len(s.log) == 4 {
			lock.lose()
		}
		return err
	}
	if err := NewOffboarding(f, lock).WithClock(func() time.Time { return *now }).Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.left[org] != 6 {
		t.Fatalf("%d steps left after the crash, want 6", s.left[org])
	}
	f.advance = inner
	if err := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return *now }).Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.left[org] != 0 || len(s.log) != 10 {
		t.Fatalf("after resume %d steps left, %d run; want 0 and 10 (no step repeated)", s.left[org], len(s.log))
	}
}
