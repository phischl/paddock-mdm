package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
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
	// deadline is the round deadline the last Advance got.
	deadline time.Time
}

func (f *fakeOffboarder) StartDue(context.Context) ([]uuid.UUID, error) {
	f.started++
	return nil, nil
}

func (f *fakeOffboarder) Pending(context.Context) ([]pgstore.Organization, error) {
	return f.pending, nil
}

func (f *fakeOffboarder) AdvanceWithin(_ context.Context, org uuid.UUID, deadline time.Time) (bool, error) {
	f.attempts[org] = append(f.attempts[org], f.now())
	f.deadline = deadline
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
	s.log = nil
	s.cost = OffboardingRoundBudget
	for _, want := range []uuid.UUID{a, b, c} {
		*now = now.Add(OffboardingInterval)
		if err := r.Round(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(s.log) != 1 || s.log[0] != want {
			t.Fatalf("round ran %v, want the organization that waited longest (%v) alone", s.log, want)
		}
		s.log = nil
	}
}

// TestOffboardingRoundBetweenSteps (main's condition 2, clock part): every step is its own Advance call and the budget
// is checked against the clock between them. That the round holds no transaction between steps follows from Advance
// taking its own transactions; this test cannot observe connections.
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

// largeDatabaseRounds runs rounds until the small deletion (4 steps of 1 s) is done and returns how many it took. With
// large set, a large deletion is pending too; its database step never finishes and each call costs step(start of the
// call, round deadline) of fake time. It checks that every call got the round's deadline.
func largeDatabaseRounds(t *testing.T, large bool, step func(now, deadline time.Time) time.Duration) int {
	t.Helper()
	big, small := uuid.New(), uuid.New()
	left := map[uuid.UUID]int{small: 4}
	orgs := []uuid.UUID{small}
	if large {
		// The large deletion comes first in database order, as in TestOffboardingRoundsRotate.
		left[big] = 1_000_000
		orgs = []uuid.UUID{big, small}
	}
	s, now := newStepper(time.Second, left)
	f := s.fake(orgs...)
	inner := f.advance
	var start time.Time
	f.advance = func(org uuid.UUID) error {
		if org != big {
			return inner(org)
		}
		if want := start.Add(OffboardingRoundBudget); !f.deadline.Equal(want) {
			t.Fatalf("the database step got deadline %v, want the round's %v", f.deadline, want)
		}
		s.log = append(s.log, org)
		*now = now.Add(step(*now, f.deadline))
		return app.OffboardingYield{Step: offboarding.StepDatabase}
	}
	r := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return *now })
	for round := 1; round <= 20; round++ {
		start = *now
		if err := r.Round(context.Background()); err != nil {
			t.Fatal(err)
		}
		if over := now.Sub(start) - OffboardingRoundBudget; over > app.OffboardingStepSlice {
			t.Fatalf("round %d took %v, more than the budget plus one slice", round, now.Sub(start))
		}
		if s.left[small] <= 0 {
			return round
		}
		*now = now.Add(OffboardingInterval)
	}
	t.Fatalf("the small deletion did not finish in 20 rounds: %v", s.log)
	return 0
}

// TestOffboardingRoundLargeDatabaseStep (plan M17 amendment q point 9, amendment p point 2a, main §61): the database
// step gets the round's deadline and yields after OffboardingStepSlice, so the round's passes interleave the
// organizations: with a large deletion running, a small one finishes in as many rounds as alone. The second half shows
// that the check tells the behaviours apart: a database step that runs to the round deadline (before §61) delays the
// small deletion by several rounds.
func TestOffboardingRoundLargeDatabaseStep(t *testing.T) {
	slice := func(now, deadline time.Time) time.Duration {
		return min(app.OffboardingStepSlice, max(deadline.Sub(now), time.Second))
	}
	alone := largeDatabaseRounds(t, false, slice)
	if with := largeDatabaseRounds(t, true, slice); with != alone {
		t.Fatalf("the small deletion took %d rounds next to a large database step, %d alone", with, alone)
	}
	toDeadline := func(now, deadline time.Time) time.Duration { return max(deadline.Sub(now), time.Second) }
	if old := largeDatabaseRounds(t, true, toDeadline); old <= alone {
		t.Fatalf("a step running to the deadline let the small deletion finish in %d rounds (alone %d): the test does not discriminate", old, alone)
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

// TestOffboardingRoundsRotate (main's condition 1, review 1 blocker): with the slow organization first in database
// order, every organization still advances within a bounded number of rounds.
func TestOffboardingRoundsRotate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cost   time.Duration
		orgs   int
		rounds int
	}{{"steps of the whole budget", OffboardingRoundBudget, 2, 2}, {"25 s steps", 25 * time.Second, 3, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			ids := make([]uuid.UUID, tc.orgs)
			steps := map[uuid.UUID]int{}
			for i := range ids {
				ids[i] = uuid.New()
				steps[ids[i]] = 100
			}
			s, now := newStepper(tc.cost, steps)
			r := NewOffboarding(s.fake(ids...), &fakeLock{}).WithClock(func() time.Time { return *now })
			for range tc.rounds {
				if err := r.Round(context.Background()); err != nil {
					t.Fatal(err)
				}
				*now = now.Add(OffboardingInterval)
			}
			for _, id := range ids {
				if steps[id] == 100 {
					t.Fatalf("an organization took no step in %d rounds: %v", tc.rounds, s.log)
				}
			}
		})
	}
}

type fakeAuditFinal struct {
	got []offboarding.AuditRetired
	err error
}

func (f *fakeAuditFinal) RecordAuditFinal(_ context.Context, ack offboarding.AuditRetired) error {
	f.got = append(f.got, ack)
	return f.err
}

// TestAuditRetirementsProcess: a valid acknowledgement is applied and acknowledged, a failure to apply it is retried,
// and a message that is no valid acknowledgement is dead-lettered without being applied.
func TestAuditRetirementsProcess(t *testing.T) {
	ctx := context.Background()
	org := uuid.New()
	valid, _ := json.Marshal(offboarding.AuditRetired{OrganizationID: org, FinalOutcome: offboarding.AuditFinalFailed,
		FinalVerifiedAt: time.Now()})
	f := &fakeAuditFinal{}
	a := NewAuditRetirements(f)
	if o := a.process(ctx, valid); o != ack || len(f.got) != 1 || f.got[0].OrganizationID != org ||
		f.got[0].FinalOutcome != offboarding.AuditFinalFailed {
		t.Fatalf("valid acknowledgement: outcome %v, applied %+v", o, f.got)
	}
	f.err = errors.New("database down")
	if o := a.process(ctx, valid); o != retry {
		t.Fatalf("failed apply: outcome %v, want retry", o)
	}
	f.got, f.err = nil, nil
	for _, body := range []string{`not json`, `{}`, `{"organization_id":"` + org.String() + `","final_outcome":"maybe","final_verified_at":"2026-11-15T00:00:00Z"}`,
		`{"organization_id":"` + org.String() + `","final_outcome":"verified"}`} {
		if o := a.process(ctx, []byte(body)); o != poison {
			t.Errorf("%s: outcome %v, want poison", body, o)
		}
	}
	if len(f.got) != 0 {
		t.Fatalf("invalid messages were applied: %+v", f.got)
	}
}

// TestAuditRetirementsGaugeOnlyWhereRegistered (main §46): the package alone puts no
// paddock_worker_offboarding_consumer_connected into the default registry, which every role serves; the worker's
// registry gets it at 0, and the hook follows the consumer's state.
func TestAuditRetirementsGaugeOnlyWhereRegistered(t *testing.T) {
	const name = "paddock_worker_offboarding_consumer_connected"
	if n, err := testutil.GatherAndCount(prometheus.DefaultGatherer, name); err != nil || n != 0 {
		t.Fatalf("default registry: %d series of %s (%v), want none", n, name, err)
	}
	reg := prometheus.NewRegistry()
	connected, err := NewAuditRetirementsGauge(reg)
	if err != nil {
		t.Fatal(err)
	}
	value := func() float64 {
		t.Helper()
		families, err := reg.Gather()
		if err != nil || len(families) != 1 || families[0].GetName() != name || len(families[0].GetMetric()) != 1 {
			t.Fatalf("worker registry: %v %v", families, err)
		}
		return families[0].GetMetric()[0].GetGauge().GetValue()
	}
	if v := value(); v != 0 {
		t.Fatalf("before the first session: %v, want 0", v)
	}
	connected(true)
	if v := value(); v != 1 {
		t.Fatalf("connected: %v, want 1", v)
	}
	connected(false)
	if v := value(); v != 0 {
		t.Fatalf("disconnected: %v, want 0", v)
	}
	if _, err := NewAuditRetirementsGauge(reg); err == nil {
		t.Fatal("a second registration in the same registry succeeded")
	}
}

// TestOffboardingRoundYieldingStep (PDK-1087 AC5, plan M17 amendment 2026-11-16 s points 1.6 and 1.7): a large deletion
// whose step yields on every call stays in the passes and gets one call per pass, and a small deletion with 10 quick
// steps next to it completes in the first round. Every yield is counted by step.
func TestOffboardingRoundYieldingStep(t *testing.T) {
	large, small := uuid.New(), uuid.New()
	s, now := newStepper(100*time.Millisecond, map[uuid.UUID]int{small: 10, large: 1_000_000})
	f := s.fake(large, small)
	inner := f.advance
	f.advance = func(org uuid.UUID) error {
		if org == small {
			return inner(org)
		}
		s.log = append(s.log, org)
		*now = now.Add(2 * time.Second)
		return app.OffboardingYield{Step: offboarding.StepObjects}
	}
	yields := testutil.ToFloat64(metricOffboardingStepYields.WithLabelValues(offboarding.StepObjects))
	r := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return *now })
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.left[small] != 0 {
		t.Fatalf("the small deletion has %d steps left after the first round: %v", s.left[small], s.log)
	}
	for i := 0; i+1 < 20; i += 2 {
		if s.log[i] != large || s.log[i+1] != small {
			t.Fatalf("pass %d ran %v, want the large deletion once, then the small one", i/2, s.log[i:i+2])
		}
	}
	calls := 0
	for _, id := range s.log {
		if id == large {
			calls++
		}
	}
	if got := testutil.ToFloat64(metricOffboardingStepYields.WithLabelValues(offboarding.StepObjects)) - yields; got != float64(calls) {
		t.Fatalf("%v yields counted for %d yielding calls", got, calls)
	}
	if len(r.retries) != 0 {
		t.Fatalf("a yield started a backoff: %v", r.retries)
	}
}

// TestOffboardingRoundBackoffFromFailureEnd (PDK-1087 AC6, amendment 2026-11-16 s point 2.1): a step that fails after
// running 10 minutes is retried no earlier than the end of the failed attempt plus the backoff, not from its start.
func TestOffboardingRoundBackoffFromFailureEnd(t *testing.T) {
	start := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	now := start
	org := uuid.New()
	f := &fakeOffboarder{attempts: map[uuid.UUID][]time.Time{}, now: func() time.Time { return now },
		pending: []pgstore.Organization{deletingOrg(org, offboarding.StepObjects, "")},
		advance: func(uuid.UUID) error {
			now = now.Add(10 * time.Minute)
			return &app.OffboardingError{Code: offboarding.ErrorObjectStoreUnavailable, Err: errors.New("down")}
		}}
	r := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return now })
	ctx := context.Background()
	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	failed := start.Add(10 * time.Minute)
	for _, at := range []time.Time{start.Add(time.Minute), failed, failed.Add(OffboardingInterval - time.Second)} {
		now = at
		if err := r.Round(ctx); err != nil {
			t.Fatal(err)
		}
		if n := len(f.attempts[org]); n != 1 {
			t.Fatalf("retried at %v, %v after the failed attempt ended: %d attempts", at, at.Sub(failed), n)
		}
	}
	now = failed.Add(OffboardingInterval)
	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.attempts[org]); n != 2 {
		t.Fatalf("%d attempts at the end of the failed attempt plus the backoff, want 2", n)
	}
}

// TestOffboardingRoundPollsAuditFinal (PDK-1087 AC7, amendment 2026-11-16 s point 2.2): a step that waits for an
// acknowledgement is asked at most every 2 s, and a round with only such an organization sleeps in between instead of
// spinning: at most 23 calls in the 45 s budget. An acknowledgement is seen at the next poll.
func TestOffboardingRoundPollsAuditFinal(t *testing.T) {
	start := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	now := start
	org := uuid.New()
	var ackAt time.Time
	f := &fakeOffboarder{attempts: map[uuid.UUID][]time.Time{}, now: func() time.Time { return now },
		pending: []pgstore.Organization{deletingOrg(org, offboarding.StepAuditFinal, "")},
		advance: func(uuid.UUID) error {
			if !ackAt.IsZero() && !now.Before(ackAt) {
				return nil
			}
			return app.ErrOffboardingPolling
		}}
	r := NewOffboarding(f, &fakeLock{}).WithClock(func() time.Time { return now })
	slept := time.Duration(0)
	r.sleep = func(_ context.Context, d time.Duration) {
		slept += d
		now = now.Add(d)
	}
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := f.attempts[org]
	if len(calls) > 23 || len(calls) < 20 {
		t.Fatalf("%d calls in a round with only a polling organization, want at most 23 (one per 2 s)", len(calls))
	}
	for i := 1; i < len(calls); i++ {
		if gap := calls[i].Sub(calls[i-1]); gap < offboardingPollInterval {
			t.Fatalf("polls %v apart, want at least %v", gap, offboardingPollInterval)
		}
	}
	if slept < OffboardingRoundBudget-offboardingPollInterval {
		t.Fatalf("the round slept %v of its budget", slept)
	}

	now = start.Add(OffboardingInterval)
	ackAt = now.Add(7500 * time.Millisecond)
	f.attempts[org] = nil
	f.done = func(uuid.UUID) bool { return true }
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls = f.attempts[org]
	if last := calls[len(calls)-1]; last.Before(ackAt) || last.Sub(ackAt) > offboardingPollInterval || len(calls) != 5 {
		t.Fatalf("calls at %v; the acknowledgement at %v must be seen at the next poll", calls, ackAt)
	}
}

// TestOffboardingRoundOverrun (amendment 2026-11-16 s point 2.3): a round longer than twice the interval is counted in
// paddock_offboarding_round_overruns_total; a round within the budget is not.
func TestOffboardingRoundOverrun(t *testing.T) {
	org := uuid.New()
	s, now := newStepper(time.Second, map[uuid.UUID]int{org: 3})
	r := NewOffboarding(s.fake(org), &fakeLock{}).WithClock(func() time.Time { return *now })
	before := testutil.ToFloat64(metricOffboardingRoundOverruns)
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metricOffboardingRoundOverruns) - before; got != 0 {
		t.Fatalf("a 3 s round counted %v overruns", got)
	}
	s.left[org], s.cost = 1, 2*OffboardingInterval+time.Second
	if err := r.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metricOffboardingRoundOverruns) - before; got != 1 {
		t.Fatalf("a round of %v counted %v overruns, want 1", s.cost, got)
	}
}
