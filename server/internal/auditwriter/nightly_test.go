package auditwriter_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
)

type verifyCall struct {
	org      uuid.UUID
	trigger  string
	from, to string
}

// nightlyFakes records what the cycle verifies and records.
type nightlyFakes struct {
	mu       sync.Mutex
	verified []verifyCall
	recorded []verifyCall
	broken   map[uuid.UUID]error
	problems map[uuid.UUID][]string
}

func (f *nightlyFakes) verify(_ context.Context, org uuid.UUID, from, to time.Time) (*auditwriter.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified = append(f.verified, verifyCall{org: org, from: from.Format(time.DateOnly), to: to.Format(time.DateOnly)})
	if err := f.broken[org]; err != nil {
		return nil, err
	}
	return &auditwriter.Report{Days: int(to.Sub(from)/(24*time.Hour)) + 1, Problems: f.problems[org]}, nil
}

func (f *nightlyFakes) record(_ context.Context, org uuid.UUID, trigger string, from, to, _ time.Time, _ *auditwriter.Report) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, verifyCall{org: org, trigger: trigger, from: from.Format(time.DateOnly), to: to.Format(time.DateOnly)})
	return uuid.Must(uuid.NewV7()), nil
}

func (f *nightlyFakes) recordedFor(org uuid.UUID) []verifyCall {
	var out []verifyCall
	for _, c := range f.recorded {
		if c.org == org {
			out = append(out, c)
		}
	}
	return out
}

func gaugeValue(t *testing.T, name string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name && len(f.GetMetric()) == 1 {
			return f.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("gauge %s not exported", name)
	return 0
}

// nightlyClock is 2026-10-15 00:45 UTC: the last sealable day is 2026-10-14.
var nightlyClock = time.Date(2026, 10, 15, 0, 45, 0, 0, time.UTC)

func threeOrganizations() (first, second, third uuid.UUID, index *auditwriter.FakeIndex) {
	first, second, third = uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	index = &auditwriter.FakeIndex{Orgs: []auditwriter.AuditOrganization{
		{ID: first, FirstDay: day("2026-10-01")},
		{ID: second, FirstDay: day("2026-10-12")},
		{ID: third, FirstDay: day("2026-10-15")},
	}}
	return first, second, third, index
}

// TestNightlyCycleSchedule (AC unit 2): the window is the last 7 sealed days, bounded by the first audit day; a
// sample day is drawn from the older days only; an organization without a sealable day is skipped.
func TestNightlyCycleSchedule(t *testing.T) {
	first, second, third, index := threeOrganizations()
	for range 20 {
		f := &nightlyFakes{}
		n := auditwriter.NewTestNightly(index, f.verify, f.record, auditwriter.NewTestVerifyMetrics(), func() time.Time { return nightlyClock })
		if err := n.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}

		got := f.recordedFor(first)
		if len(got) != 2 || got[0] != (verifyCall{first, "nightly", "2026-10-08", "2026-10-14"}) {
			t.Fatalf("first organization: %+v", got)
		}
		if s := got[1]; s.trigger != "sample" || s.from != s.to || s.from < "2026-10-01" || s.from > "2026-10-07" {
			t.Fatalf("sample of the first organization: %+v, want one day in 2026-10-01..2026-10-07", s)
		}
		if got := f.recordedFor(second); len(got) != 1 || got[0] != (verifyCall{second, "nightly", "2026-10-12", "2026-10-14"}) {
			t.Fatalf("second organization: %+v", got)
		}
		if got := f.recordedFor(third); len(got) != 0 {
			t.Fatalf("third organization (nothing sealable): %+v", got)
		}
		for _, v := range f.verified {
			if v.org == third {
				t.Fatalf("third organization verified: %+v", v)
			}
		}
	}
	if got := gaugeValue(t, "paddock_audit_verify_failed_organizations"); got != 0 {
		t.Errorf("failed organizations = %v, want 0", got)
	}
	if got := gaugeValue(t, "paddock_audit_verify_last_run_timestamp_seconds"); got != float64(nightlyClock.Unix()) {
		t.Errorf("last run = %v, want %d", got, nightlyClock.Unix())
	}
}

// TestNightlyCycleIsolatesOrganizations (AC unit 2): a store error on the first organization does not stop the
// second; the failed-organizations gauge counts errored and broken organizations; the last-run gauge is the end of
// the cycle.
func TestNightlyCycleIsolatesOrganizations(t *testing.T) {
	first, second, _, index := threeOrganizations()
	f := &nightlyFakes{
		broken:   map[uuid.UUID]error{first: errors.New("object store unreachable")},
		problems: map[uuid.UUID][]string{second: {"2026-10-13: no manifest (chain broken)"}},
	}
	metrics := auditwriter.NewTestVerifyMetrics()
	clock := nightlyClock
	n := auditwriter.NewTestNightly(index, f.verify, f.record, metrics, func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	})
	if err := n.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := f.recordedFor(first); len(got) != 0 {
		t.Fatalf("errored organization recorded: %+v", got)
	}
	if got := f.recordedFor(second); len(got) != 1 || got[0].trigger != "nightly" {
		t.Fatalf("second organization after the first errored: %+v", got)
	}
	if got := gaugeValue(t, "paddock_audit_verify_failed_organizations"); got != 2 {
		t.Errorf("failed organizations = %v, want 2 (one errored, one broken)", got)
	}
	if got := gaugeValue(t, "paddock_audit_verify_last_run_timestamp_seconds"); got != float64(clock.Unix()) {
		t.Errorf("last run = %v, want the cycle's end %d", got, clock.Unix())
	}
	series := gather(t, metrics)
	if series[[2]string{"nightly", "error"}] != 1 || series[[2]string{"sample", "error"}] != 1 {
		t.Errorf("error counts: %v, want nightly and sample of the errored organization", series)
	}
}

// TestNightlyCycleLocked: another replica holds the lock; nothing is verified and the gauges stay.
func TestNightlyCycleLocked(t *testing.T) {
	_, _, _, index := threeOrganizations()
	index.Locked = true
	f := &nightlyFakes{}
	n := auditwriter.NewTestNightly(index, f.verify, f.record, auditwriter.NewTestVerifyMetrics(), func() time.Time { return nightlyClock })
	if err := n.Cycle(context.Background()); !errors.Is(err, auditwriter.ErrVerifyLocked) {
		t.Fatalf("Cycle = %v, want ErrVerifyLocked", err)
	}
	if len(f.verified) != 0 {
		t.Fatalf("verified under a foreign lock: %+v", f.verified)
	}
}

// TestNightlyInitLastRun: at start the last-run gauge is the newest recorded nightly run or, without any, the start
// time, and the failed-organizations gauge counts the organizations whose newest nightly or sample run failed, so a
// restart keeps PaddockAuditChainBroken firing; a read error leaves both unset so PaddockAuditVerifyStale is not
// masked.
func TestNightlyInitLastRun(t *testing.T) {
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	latest := time.Date(2026, 10, 19, 0, 46, 0, 0, time.UTC)
	broken := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	for _, tc := range []struct {
		name       string
		index      *auditwriter.FakeIndex
		want       float64
		wantFailed float64
		wantErr    bool
	}{
		{"recorded run", &auditwriter.FakeIndex{Latest: latest}, float64(latest.Unix()), 0, false},
		{"recorded failed runs", &auditwriter.FakeIndex{Latest: latest, Failed: broken}, float64(latest.Unix()), 2, false},
		{"no run yet", &auditwriter.FakeIndex{}, float64(start.Unix()), 0, false},
		{"database error", &auditwriter.FakeIndex{LastErr: errors.New("down"), Failed: broken}, 0, 0, true},
		{"failed organizations unreadable", &auditwriter.FakeIndex{Latest: latest, FailedErr: errors.New("down")}, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditwriter.ResetLastRun()
			f := &nightlyFakes{}
			n := auditwriter.NewTestNightly(tc.index, f.verify, f.record, auditwriter.NewTestVerifyMetrics(), func() time.Time { return start })
			if err := auditwriter.InitLastRun(n, context.Background()); (err != nil) != tc.wantErr {
				t.Fatalf("InitLastRun = %v, want error %v", err, tc.wantErr)
			}
			if got := gaugeValue(t, "paddock_audit_verify_last_run_timestamp_seconds"); got != tc.want {
				t.Errorf("last run = %v, want %v", got, tc.want)
			}
			if got := gaugeValue(t, "paddock_audit_verify_failed_organizations"); got != tc.wantFailed {
				t.Errorf("failed organizations = %v, want %v", got, tc.wantFailed)
			}
		})
	}
}

// fakeTimer hands every wait of RunNightly to the test, which fires it.
type fakeTimer struct {
	waits chan time.Duration
	fire  chan time.Time
}

func newFakeTimer() *fakeTimer {
	return &fakeTimer{waits: make(chan time.Duration), fire: make(chan time.Time)}
}

func (f *fakeTimer) after(d time.Duration) <-chan time.Time {
	f.waits <- d
	return f.fire
}

// runNightly starts RunNightly on a fake timer and stops it when the test ends.
func runNightly(t *testing.T, index *auditwriter.FakeIndex, now func() time.Time) *fakeTimer {
	t.Helper()
	auditwriter.ResetLastRun()
	f := &nightlyFakes{}
	n := auditwriter.NewTestNightly(index, f.verify, f.record, auditwriter.NewTestVerifyMetrics(), now)
	timer := newFakeTimer()
	auditwriter.SetAfter(n, timer.after)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.RunNightly(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return timer
}

// TestNightlyRetriesLastRun: while the last nightly run cannot be read, the gauge stays unset and the read is retried
// every minute; once it succeeds, the gauge is set and RunNightly waits for the next cycle.
func TestNightlyRetriesLastRun(t *testing.T) {
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	latest := time.Date(2026, 10, 19, 0, 46, 0, 0, time.UTC)
	index := &auditwriter.FakeIndex{Latest: latest, LastErr: errors.New("down")}
	timer := runNightly(t, index, func() time.Time { return start })

	for i := range 3 {
		if d := <-timer.waits; d != time.Minute {
			t.Fatalf("wait while the read fails = %s, want 1m", d)
		}
		if got := gaugeValue(t, "paddock_audit_verify_last_run_timestamp_seconds"); got != 0 {
			t.Fatalf("last run while the read fails = %v, want unset (0)", got)
		}
		if i == 2 {
			index.LastErr = nil
		}
		timer.fire <- start
	}
	if d := <-timer.waits; d != 12*time.Hour+45*time.Minute {
		t.Fatalf("wait after a successful read = %s, want the next cycle at 00:45 UTC", d)
	}
	if got := gaugeValue(t, "paddock_audit_verify_last_run_timestamp_seconds"); got != float64(latest.Unix()) {
		t.Errorf("last run after the retry = %v, want %d", got, latest.Unix())
	}
}

// TestNightlyCycleEndsLastRunRetry: when the read keeps failing, the first finished cycle sets the gauge and ends the
// retries.
func TestNightlyCycleEndsLastRunRetry(t *testing.T) {
	clock := time.Date(2026, 10, 20, 0, 44, 30, 0, time.UTC)
	timer := runNightly(t, &auditwriter.FakeIndex{LastErr: errors.New("down")}, func() time.Time { return clock })

	if d := <-timer.waits; d != 30*time.Second {
		t.Fatalf("wait before the cycle = %s, want 30s", d)
	}
	clock = clock.Add(30 * time.Second)
	timer.fire <- clock
	if d := <-timer.waits; d != 24*time.Hour {
		t.Fatalf("wait after the cycle = %s, want the next cycle", d)
	}
	if got := gaugeValue(t, "paddock_audit_verify_last_run_timestamp_seconds"); got != float64(clock.Unix()) {
		t.Errorf("last run after the cycle = %v, want the cycle's end %d", got, clock.Unix())
	}
}

// TestNightlyPoolIndex: the cycle lists every organization with its first audit day under the audit-verify lock,
// refuses to run while another session holds it, and finds the newest nightly run.
func TestNightlyPoolIndex(t *testing.T) {
	e := newRecorderEnv(t)
	ctx := context.Background()
	locked, latest, _ := auditwriter.PoolIndex(e.pool)
	org := uuid.Must(uuid.NewV7())
	if _, err := e.recorder.Record(ctx, org, auditwriter.TriggerNightly, day("2026-10-01"), day("2026-10-07"), e.now, &auditwriter.Report{Days: 7}); err != nil {
		t.Fatal(err)
	}

	var found *auditwriter.AuditOrganization
	err := locked(ctx, func(ctx context.Context, orgs []auditwriter.AuditOrganization) error {
		for i := range orgs {
			if orgs[i].ID == org {
				found = &orgs[i]
			}
		}
		// A second session cannot take the lock while the cycle holds it.
		return locked(ctx, func(context.Context, []auditwriter.AuditOrganization) error {
			t.Error("second session entered the locked cycle")
			return nil
		})
	})
	if !errors.Is(err, auditwriter.ErrVerifyLocked) {
		t.Fatalf("nested cycle = %v, want ErrVerifyLocked", err)
	}
	if found == nil || !found.FirstDay.Equal(utcDay(e.now)) {
		t.Fatalf("organization with the verification event: %+v, want first day %s", found, utcDay(e.now))
	}
	if err := locked(ctx, func(context.Context, []auditwriter.AuditOrganization) error { return nil }); err != nil {
		t.Fatalf("lock not released: %v", err)
	}

	finished, ok, err := latest(ctx)
	if err != nil || !ok || finished.Before(e.now) {
		t.Fatalf("latest nightly run = %s, %v, %v; want at least %s", finished, ok, err, e.now)
	}
}

// TestNightlyPoolIndexFailedOrganizations: an organization counts as failed when its newest nightly window or its
// newest sample day failed; an older failure that a later run superseded and a failed CLI run do not count.
func TestNightlyPoolIndexFailedOrganizations(t *testing.T) {
	e := newRecorderEnv(t)
	ctx := context.Background()
	_, _, failed := auditwriter.PoolIndex(e.pool)
	broken := &auditwriter.Report{Days: 1, Problems: []string{"2026-10-07: broken link"}}
	intact := &auditwriter.Report{Days: 1}
	repaired, brokenWindow, brokenSample, cliOnly := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()),
		uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, r := range []struct {
		org     uuid.UUID
		trigger string
		report  *auditwriter.Report
	}{
		{repaired, auditwriter.TriggerNightly, broken},
		{repaired, auditwriter.TriggerSample, broken},
		{repaired, auditwriter.TriggerNightly, intact},
		{repaired, auditwriter.TriggerSample, intact},
		{brokenWindow, auditwriter.TriggerNightly, intact},
		{brokenWindow, auditwriter.TriggerNightly, broken},
		{brokenSample, auditwriter.TriggerNightly, intact},
		{brokenSample, auditwriter.TriggerSample, broken},
		{cliOnly, auditwriter.TriggerNightly, intact},
		{cliOnly, auditwriter.TriggerCLI, broken},
	} {
		if _, err := e.recorder.Record(ctx, r.org, r.trigger, day("2026-10-07"), day("2026-10-07"), e.now, r.report); err != nil {
			t.Fatal(err)
		}
	}

	orgs, err := failed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]bool{}
	for _, org := range orgs {
		got[org] = true
	}
	for org, want := range map[uuid.UUID]bool{repaired: false, brokenWindow: true, brokenSample: true, cliOnly: false} {
		if got[org] != want {
			t.Errorf("organization %s failed = %v, want %v", org, got[org], want)
		}
	}
}
