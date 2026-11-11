package reconcile_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// holdLock takes the flock on path the way a local administrator can (`flock <path> sleep infinity`) until the test
// ends.
func holdLock(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // a test temp file
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
}

func markerStartedAt(at time.Time) []byte {
	return []byte(`{"action":"apt-get dist-upgrade","pid":999999,"started_at":"` + at.UTC().Format(time.RFC3339Nano) + `"}`)
}

// captureLogs sends slog's default logger to a buffer until the test ends.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &logs
}

// TestNSSShieldHoldsOnlyFreshMarker (plan M5a amendment 2026-11-11 b, P2): a stopped himmelblaud counts as held iff a
// marker exists whose start is younger than the maximum hold plus the timer grace — 12 minutes, 5 in a development
// build; a marker without a readable start never counts.
func TestNSSShieldHoldsOnlyFreshMarker(t *testing.T) {
	const bound = reconcile.NSSShieldMaxHold + reconcile.NSSShieldTimerGrace
	const devBound = 5 * time.Minute
	for _, tc := range []struct {
		name   string
		dev    bool
		marker func(now time.Time) []byte
		held   bool
	}{
		{"none", false, nil, false},
		{"just written", false, func(now time.Time) []byte { return markerStartedAt(now) }, true},
		{"one second inside the bound", false, func(now time.Time) []byte { return markerStartedAt(now.Add(-bound + time.Second)) }, true},
		{"at the bound", false, func(now time.Time) []byte { return markerStartedAt(now.Add(-bound)) }, false},
		{"past the bound", false, func(now time.Time) []byte { return markerStartedAt(now.Add(-time.Hour)) }, false},
		{"clock stepped back inside the bound", false, func(now time.Time) []byte { return markerStartedAt(now.Add(bound - time.Second)) }, true},
		{"dated past the bound into the future", false, func(now time.Time) []byte { return markerStartedAt(now.Add(bound)) }, false},
		{"development build inside the bound", true, func(now time.Time) []byte { return markerStartedAt(now.Add(-devBound + time.Second)) }, true},
		{"development build at the bound", true, func(now time.Time) []byte { return markerStartedAt(now.Add(-devBound)) }, false},
		{"without a start", false, func(time.Time) []byte { return []byte(`{"action":"apt-get install"}`) }, false},
		{"unreadable", false, func(time.Time) []byte { return []byte("{") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys, shield, clock, _ := shieldFixture(false)
			if tc.dev {
				shield.MaxHold, shield.TimerGrace = 4*time.Minute, time.Minute
			}
			if tc.marker != nil {
				sys.files[reconcile.NSSShieldMarker] = tc.marker(clock.Now())
			}
			if got := shield.Holds("himmelblaud.service"); got != tc.held {
				t.Errorf("Holds = %v, want %v", got, tc.held)
			}
		})
	}
}

// TestLoginReportsStopBehindHeldLock (plan M5a amendment 2026-11-11 b, P2; PDK-990): with the shield lock held by
// another process for ever, a stopped himmelblaud is reported once as tamper.service_stopped unless a fresh marker
// backs the stop; the agent never starts the daemon.
func TestLoginReportsStopBehindHeldLock(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker func(now time.Time) []byte
		report bool
	}{
		{"lock taken, no marker", nil, true},
		{"lock taken, fresh marker", func(now time.Time) []byte { return markerStartedAt(now.Add(-time.Minute)) }, false},
		{"lock taken, marker past the bound", func(now time.Time) []byte { return markerStartedAt(now.Add(-13 * time.Minute)) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys, l, events := loginFixture(t)
			ctx := context.Background()
			r := loginResource(t, loginSpec())
			if res := l.Apply(ctx, r); res.Status != reconcile.Changed {
				t.Fatalf("install %+v", res)
			}
			takeEvents(events)
			now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
			lock := filepath.Join(t.TempDir(), "nss-shield.lock")
			holdLock(t, lock)
			l.Shield = &reconcile.NSSShield{Sys: sys, Events: l.Events, LockFile: lock, Now: func() time.Time { return now }}
			if tc.marker != nil {
				sys.Files[reconcile.NSSShieldMarker] = &fakesys.File{Data: tc.marker(now), Mode: 0o600}
			}
			sys.Units["himmelblaud.service"].Active = false
			sys.TakeCalls()

			for range 2 {
				l.Apply(ctx, r)
			}
			var tamper int
			for _, e := range takeEvents(events) {
				if e.typ == protocol.EventTamperServiceStopped {
					tamper++
				}
			}
			if want := map[bool]int{true: 1, false: 0}[tc.report]; tamper != want {
				t.Errorf("%d tamper.service_stopped, want %d", tamper, want)
			}
			if calls := sys.TakeCalls(); slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "systemctl start") }) ||
				sys.Units["himmelblaud.service"].Active {
				t.Errorf("the agent started himmelblaud behind a held lock: %v", calls)
			}
			if _, ok := sys.Files[reconcile.NSSShieldMarker]; ok != (tc.marker != nil) {
				t.Errorf("marker present %v, want it untouched", ok)
			}
		})
	}
}

// TestNSSShieldWarnsLockHeldHourly (plan M5a amendment 2026-11-11 b, P2): a transaction that cannot get the shield
// lock from another process is deferred as before (pending/dpkg_locked) and logs a Warn with how long the lock has
// been held, at most once an hour; a free lock ends the streak.
func TestNSSShieldWarnsLockHeldHourly(t *testing.T) {
	sys, shield, clock, events := shieldFixture(true)
	shield.LockFile, shield.HoldWait = filepath.Join(t.TempDir(), "nss-shield.lock"), 10*time.Millisecond
	logs := captureLogs(t)
	const warning = "the himmelblaud shield lock is held by another process"
	f, err := os.OpenFile(shield.LockFile, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // a test temp file
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	deferred := func() {
		t.Helper()
		out, _, err := shield.Run(context.Background(), "apt-get install", func() (string, int, error) {
			t.Error("the transaction ran without the shield lock held by another process")
			return "", 0, nil
		})
		if !errors.Is(err, reconcile.ErrNSSShieldBusy) || !strings.Contains(out, "Could not get lock") {
			t.Errorf("Run behind a held lock = %q %v", out, err)
		}
	}
	for _, step := range []time.Duration{0, 30 * time.Minute, 29 * time.Minute, time.Minute, 10 * time.Minute} {
		clock.advance(step)
		deferred()
	}
	if got := strings.Count(logs.String(), warning); got != 2 {
		t.Fatalf("%d warnings over 70 minutes, want 2:\n%s", got, logs)
	}
	if !strings.Contains(logs.String(), "held_for=0s") || !strings.Contains(logs.String(), "held_for=1h0m0s") {
		t.Errorf("warnings do not say how long the lock is held:\n%s", logs)
	}
	if len(*events) != 0 || !sys.isActive("himmelblaud.service") {
		t.Errorf("events %v, himmelblaud %v: a deferred transaction reported or held", *events, sys.isActive("himmelblaud.service"))
	}

	_ = f.Close()
	if _, _, err := shield.Run(context.Background(), "apt-get install", func() (string, int, error) { return "", 0, nil }); err != nil {
		t.Fatalf("Run with the lock free: %v", err)
	}
	holdLock(t, shield.LockFile)
	logs.Reset()
	deferred()
	if !strings.Contains(logs.String(), warning) {
		t.Errorf("a new streak after the lock was free does not warn at once:\n%s", logs)
	}
}

// TestNSSShieldWithoutLockFile (plan M5a amendment 2026-11-11 b, P3; PDK-991): when the shield lock file cannot be
// opened, the live marker of another process's hold is never finished: no start of himmelblaud, no recovered event,
// the marker and the records kept; the transaction runs without a hold and is reported once as hold_failed. Recover
// and the per-pass check only log.
func TestNSSShieldWithoutLockFile(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "another hold stopped himmelblaud", true: "himmelblaud running"}[active], func(t *testing.T) {
			sys, shield, clock, events := shieldFixture(active)
			shield.LockFile = filepath.Join(t.TempDir(), "missing", "nss-shield.lock")
			logs := captureLogs(t)
			marker := markerStartedAt(clock.Now().Add(-time.Minute))
			records := []byte(`[{"action":"apt-get dist-upgrade","duration_s":3,"outcome":"restored"}]`)
			sys.files[reconcile.NSSShieldMarker] = marker
			sys.files[reconcile.NSSShieldReport] = records
			ctx := context.Background()

			if shield.Pending(ctx) {
				t.Error("Pending without the shield lock")
			}
			shield.Recover(ctx)
			if !strings.Contains(logs.String(), "shield lock unavailable") {
				t.Errorf("Recover without the shield lock does not log:\n%s", logs)
			}
			ran := false
			if _, _, err := shield.Run(ctx, "apt-get install", func() (string, int, error) { ran = true; return "", 0, nil }); err != nil || !ran {
				t.Fatalf("Run without the shield lock: ran %v, %v", ran, err)
			}
			calls, timer, _ := sys.snapshot()
			if len(calls) != 0 || timer || sys.isActive("himmelblaud.service") != active {
				t.Errorf("calls %v, timer %v, himmelblaud %v: the shield acted without the lock", calls, timer, sys.isActive("himmelblaud.service"))
			}
			if string(sys.files[reconcile.NSSShieldMarker]) != string(marker) || string(sys.files[reconcile.NSSShieldReport]) != string(records) {
				t.Errorf("marker %s, records %s: changed without the lock", sys.files[reconcile.NSSShieldMarker], sys.files[reconcile.NSSShieldReport])
			}
			if ev := shieldEvent(t, *events); ev.Action != "apt-get install" || ev.Outcome != protocol.NSSShieldHoldFailed ||
				!strings.Contains(ev.Error, "shield lock") {
				t.Errorf("event %+v, want one hold_failed with the lock error", ev)
			}
		})
	}
}

// TestLoginRestartWithoutLockFile (plan M5a amendment 2026-11-11 b, P3; Review 1 of PDK-990): a configuration change
// on an agent that cannot open the shield lock file does not restart himmelblaud, which could cut into another
// process's hold; the restart stays pending for a later pass and the missing lock is logged.
func TestLoginRestartWithoutLockFile(t *testing.T) {
	sys, l, events := loginFixture(t)
	ctx := context.Background()
	l.Apply(ctx, loginResource(t, loginSpec()))
	takeEvents(events)
	l.Shield = &reconcile.NSSShield{Sys: sys, Events: l.Events, LockFile: filepath.Join(t.TempDir(), "missing", "nss-shield.lock")}
	logs := captureLogs(t)
	sys.TakeCalls()

	spec := loginSpec()
	spec.Himmelblau.EnableHello = false
	r := loginResource(t, spec)
	if res := l.Apply(ctx, r); res.Status == reconcile.Error {
		t.Fatalf("Apply without the shield lock = %+v", res)
	}
	if calls := sys.TakeCalls(); slices.ContainsFunc(calls, func(c string) bool {
		return strings.HasPrefix(c, "systemctl restart") || strings.HasPrefix(c, "systemctl stop himmelblaud")
	}) {
		t.Errorf("himmelblaud stopped or restarted without the shield lock: %v", calls)
	}
	if !sys.Units["himmelblaud.service"].Active {
		t.Error("himmelblaud left stopped")
	}
	if changes, _ := l.Plan(ctx, r); !slices.Contains(changes, "restart himmelblaud") {
		t.Errorf("Plan without the shield lock = %v, want the restart pending", changes)
	}
	if !strings.Contains(logs.String(), "himmelblaud not restarted") {
		t.Errorf("the deferred restart is not logged:\n%s", logs)
	}
}

// appendWhileSending is a device on which `paddockd updates run` appends a record while the agent sends the earlier
// ones: the append happens when the agent reads the records it moved aside (not at its check for a leftover file).
type appendWhileSending struct {
	*shieldSys
	append func()
}

func (a *appendWhileSending) ReadFile(path string) ([]byte, fs.FileInfo, error) {
	data, info, err := a.shieldSys.ReadFile(path)
	if path == reconcile.NSSShieldReport+".sending" && err == nil && a.append != nil {
		a.append()
		a.append = nil
	}
	return data, info, err
}

// TestNSSShieldRecordAppendedWhileSending (Review 1 of PDK-990, finding 3): a record that an updates run without the
// shield lock appends while the agent sends the records is not removed unsent; it goes out in the next pass, and every
// record is emitted exactly once.
func TestNSSShieldRecordAppendedWhileSending(t *testing.T) {
	base, _, _, events := shieldFixture(true)
	sys := &appendWhileSending{shieldSys: base}
	agent := &reconcile.NSSShield{Sys: sys, Events: &reconcile.Events{Emit: func(typ string, data any) {
		b, _ := json.Marshal(data)
		*events = append(*events, event{typ, string(b)})
	}}}
	rec := reconcile.NSSShieldRecorder(base)
	rec.Emit(protocol.EventLoginNSSShield, protocol.LoginNSSShield{Action: "apt-get dist-upgrade", Outcome: protocol.NSSShieldRestored})
	sys.append = func() {
		rec.Emit(protocol.EventLoginNSSShield, protocol.LoginNSSShield{Action: "apt-get dist-upgrade", Outcome: protocol.NSSShieldHoldFailed})
	}

	agent.Recover(context.Background())
	if ev := shieldEvent(t, *events); ev.Outcome != protocol.NSSShieldRestored {
		t.Fatalf("first pass emitted %+v", ev)
	}
	if !agent.Pending(context.Background()) {
		t.Fatal("the record appended while sending is not pending")
	}
	*events = nil
	agent.Recover(context.Background())
	if ev := shieldEvent(t, *events); ev.Outcome != protocol.NSSShieldHoldFailed {
		t.Errorf("second pass emitted %+v", ev)
	}
	if _, _, files := base.snapshot(); files != 0 || agent.Pending(context.Background()) {
		t.Errorf("%d files left, records still pending", files)
	}
}

// TestNSSShieldSendsLeftoverRecords: records moved aside by a pass that died before it removed them are sent by the
// next pass, before the records file, and none is lost.
func TestNSSShieldSendsLeftoverRecords(t *testing.T) {
	sys, agent, _, events := shieldFixture(true)
	sys.files[reconcile.NSSShieldReport+".sending"] = []byte(`[{"action":"dpkg -i","outcome":"restored"}]`)
	sys.files[reconcile.NSSShieldReport] = []byte(`[{"action":"apt-get dist-upgrade","outcome":"restored"}]`)
	agent.Recover(context.Background())
	if ev := shieldEvent(t, *events); ev.Action != "dpkg -i" {
		t.Fatalf("first pass emitted %+v", ev)
	}
	*events = nil
	agent.Recover(context.Background())
	if ev := shieldEvent(t, *events); ev.Action != "apt-get dist-upgrade" {
		t.Errorf("second pass emitted %+v", ev)
	}
}
