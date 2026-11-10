package reconcile_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const shieldTimerLine = "systemd-run --unit=paddock-nss-shield-restore --on-active=720s --timer-property=AccuracySec=1s " +
	"--description=Paddock: start himmelblaud after a package transaction /usr/bin/systemctl start himmelblaud.service himmelblaud-tasks.service"

// shieldSys is the part of a device the shield touches: the Himmelblau units, the safety timer and the marker.
type shieldSys struct {
	mu     sync.Mutex
	active map[string]bool
	timer  bool
	files  map[string][]byte
	calls  []string
	fail   map[string]bool // calls that fail
	// cancelFails makes every call on a cancelled context fail, as a real command would.
	cancelFails bool
}

func newShieldSys(himmelblaud bool) *shieldSys {
	return &shieldSys{active: map[string]bool{"himmelblaud.service": himmelblaud, "himmelblaud-tasks.service": himmelblaud},
		files: map[string][]byte{}, fail: map[string]bool{}}
}

func (s *shieldSys) log(ctx context.Context, line string) bool {
	s.calls = append(s.calls, line)
	return s.fail[line] || (s.cancelFails && ctx.Err() != nil)
}

func (s *shieldSys) ReadFile(path string) ([]byte, fs.FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.files[path]
	if !ok {
		return nil, nil, fs.ErrNotExist
	}
	return data, nil, nil
}

func (s *shieldSys) WriteFileAtomic(path string, data []byte, _ fs.FileMode, _, _ int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log(context.Background(), "write "+path) {
		return errors.New("read-only file system")
	}
	s.files[path] = data
	return nil
}

func (s *shieldSys) Remove(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.files[path]; !ok {
		return fs.ErrNotExist
	}
	s.calls = append(s.calls, "remove "+path)
	delete(s.files, path)
	return nil
}

func (s *shieldSys) Systemctl(ctx context.Context, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if args[0] == "is-active" {
		if s.active[args[1]] {
			return "active\n", 0, nil
		}
		return "inactive\n", 3, nil
	}
	if s.log(ctx, "systemctl "+strings.Join(args, " ")) {
		return "Job failed\n", 1, nil
	}
	switch {
	case args[0] == "start":
		s.active[args[1]] = true
	case args[0] == "stop" && strings.HasPrefix(args[1], reconcile.NSSShieldTimer):
		s.timer = false
	case args[0] == "stop":
		s.active[args[1]] = false
	}
	return "", 0, nil
}

func (s *shieldSys) SystemdRun(ctx context.Context, _ []byte, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log(ctx, "systemd-run "+strings.Join(args, " ")) {
		return "Failed to start transient timer unit\n", 1, nil
	}
	s.timer = true
	return "", 0, nil
}

func (s *shieldSys) isActive(u string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[u]
}

func (s *shieldSys) snapshot() (calls []string, timer bool, files int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls), s.timer, len(s.files)
}

// shieldClock is a clock that a test moves, and the max-hold timer it fires.
type shieldClock struct {
	mu      sync.Mutex
	now     time.Time
	maxHold chan time.Time
}

func (c *shieldClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *shieldClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func shieldFixture(himmelblaud bool) (*shieldSys, *reconcile.NSSShield, *shieldClock, *[]event) {
	sys := newShieldSys(himmelblaud)
	clock := &shieldClock{now: time.Date(2026, 11, 10, 17, 0, 0, 0, time.UTC), maxHold: make(chan time.Time)}
	var events []event
	var mu sync.Mutex
	shield := &reconcile.NSSShield{Sys: sys, Now: clock.Now,
		After: func(time.Duration) <-chan time.Time { return clock.maxHold },
		Events: &reconcile.Events{Emit: func(typ string, data any) {
			b, _ := json.Marshal(data)
			mu.Lock()
			events = append(events, event{typ, string(b)})
			mu.Unlock()
		}}}
	return sys, shield, clock, &events
}

func shieldEvent(t *testing.T, events []event) protocol.LoginNSSShield {
	t.Helper()
	if len(events) != 1 || events[0].typ != protocol.EventLoginNSSShield {
		t.Fatalf("events %v, want exactly one login.nss_shield", events)
	}
	var ev protocol.LoginNSSShield
	if err := json.Unmarshal([]byte(events[0].data), &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// wantHeld are the calls of one hold that restored the daemon: marker, stale timer cleared, timer armed, stop; then
// both daemons started and the timer cancelled.
var wantHeld = []string{
	"write " + reconcile.NSSShieldMarker,
	"systemctl stop paddock-nss-shield-restore.timer", "systemctl reset-failed paddock-nss-shield-restore.timer",
	"systemctl stop paddock-nss-shield-restore.service", "systemctl reset-failed paddock-nss-shield-restore.service",
	shieldTimerLine,
	"systemctl stop himmelblaud.service",
	"systemctl start himmelblaud.service", "systemctl start himmelblaud-tasks.service",
	"systemctl stop paddock-nss-shield-restore.timer", "systemctl reset-failed paddock-nss-shield-restore.timer",
	"systemctl stop paddock-nss-shield-restore.service", "systemctl reset-failed paddock-nss-shield-restore.service",
	"remove " + reconcile.NSSShieldMarker,
}

// TestNSSShieldHoldsAroundTransaction (PDK-983, decisions §45): himmelblaud is stopped while the transaction runs, with
// the marker written and the safety timer armed first, and started again afterwards; the timer is cancelled, the
// marker removed, and exactly one login.nss_shield reports the action, the duration and the outcome.
func TestNSSShieldHoldsAroundTransaction(t *testing.T) {
	sys, shield, clock, events := shieldFixture(true)
	var during struct {
		active, held, timer, marker bool
	}
	out, exit, err := shield.Run(context.Background(), "apt-get install", func() (string, int, error) {
		during.active, during.held = sys.isActive("himmelblaud.service"), shield.Holds("himmelblaud.service")
		_, during.timer, _ = sys.snapshot()
		_, _, err := sys.ReadFile(reconcile.NSSShieldMarker)
		during.marker = err == nil
		clock.advance(42 * time.Second)
		return "Setting up flatpak", 0, nil
	})
	if out != "Setting up flatpak" || exit != 0 || err != nil {
		t.Fatalf("Run = %q %d %v", out, exit, err)
	}
	if during.active || !during.held || !during.timer || !during.marker {
		t.Errorf("during the transaction: %+v, want himmelblaud stopped and held, timer armed, marker written", during)
	}
	calls, timer, files := sys.snapshot()
	if !slices.Equal(calls, wantHeld) {
		t.Errorf("calls\n%s\nwant\n%s", strings.Join(calls, "\n"), strings.Join(wantHeld, "\n"))
	}
	if !sys.isActive("himmelblaud.service") || !sys.isActive("himmelblaud-tasks.service") || timer || files != 0 || shield.Holds("himmelblaud.service") {
		t.Errorf("after: himmelblaud %v, tasks %v, timer %v, files %d, held %v", sys.isActive("himmelblaud.service"),
			sys.isActive("himmelblaud-tasks.service"), timer, files, shield.Holds("himmelblaud.service"))
	}
	if ev := shieldEvent(t, *events); ev != (protocol.LoginNSSShield{Action: "apt-get install", DurationS: 42, Outcome: protocol.NSSShieldRestored}) {
		t.Errorf("event %+v", ev)
	}
}

// TestNSSShieldRestoresOnEveryPath: a failed transaction, a panic and a cancelled context all start himmelblaud again
// and report the hold once; the transaction's own result reaches the caller unchanged.
func TestNSSShieldRestoresOnEveryPath(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		sys, shield, _, events := shieldFixture(true)
		_, exit, err := shield.Run(context.Background(), "apt-get install", func() (string, int, error) {
			return "E: Sub-process /usr/bin/dpkg returned an error code (1)", 100, nil
		})
		if exit != 100 || err != nil {
			t.Errorf("Run = %d %v, want the transaction's exit 100", exit, err)
		}
		if !sys.isActive("himmelblaud.service") || shieldEvent(t, *events).Outcome != protocol.NSSShieldRestored {
			t.Errorf("not restored: %v", *events)
		}
	})
	t.Run("panic", func(t *testing.T) {
		sys, shield, _, events := shieldFixture(true)
		func() {
			defer func() {
				if r := recover(); r != "boom" {
					t.Errorf("recovered %v, want the transaction's panic to propagate", r)
				}
			}()
			_, _, _ = shield.Run(context.Background(), "dpkg -i", func() (string, int, error) { panic("boom") })
		}()
		if !sys.isActive("himmelblaud.service") || shieldEvent(t, *events).Outcome != protocol.NSSShieldRestored {
			t.Errorf("not restored after a panic: %v", *events)
		}
		if _, timer, files := sys.snapshot(); timer || files != 0 {
			t.Errorf("timer %v, marker files %d after a panic", timer, files)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		sys, shield, _, events := shieldFixture(true)
		sys.cancelFails = true
		ctx, cancel := context.WithCancel(context.Background())
		_, _, err := shield.Run(ctx, "apt-get install", func() (string, int, error) {
			cancel()
			return "", -1, context.Canceled
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run error %v", err)
		}
		if !sys.isActive("himmelblaud.service") || shieldEvent(t, *events).Outcome != protocol.NSSShieldRestored {
			t.Errorf("not restored after the context was cancelled: %v", *events)
		}
	})
}

// TestNSSShieldMaxHold: a transaction that outlasts the maximum hold gets himmelblaud back while it still runs; the
// hold is reported once, with outcome max_hold, when the transaction ends.
func TestNSSShieldMaxHold(t *testing.T) {
	sys, shield, clock, events := shieldFixture(true)
	var activeAfterMaxHold bool
	_, _, _ = shield.Run(context.Background(), "apt-get install", func() (string, int, error) {
		clock.advance(reconcile.NSSShieldMaxHold)
		clock.maxHold <- clock.Now()
		deadline := time.Now().Add(5 * time.Second)
		for !sys.isActive("himmelblaud.service") && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		activeAfterMaxHold = sys.isActive("himmelblaud.service")
		if len(*events) != 0 {
			t.Errorf("reported before the transaction ended: %v", *events)
		}
		clock.advance(time.Minute)
		return "", 0, nil
	})
	if !activeAfterMaxHold {
		t.Error("himmelblaud not started at the maximum hold while the transaction ran")
	}
	if ev := shieldEvent(t, *events); ev.Outcome != protocol.NSSShieldMaxHold || ev.DurationS != 660 {
		t.Errorf("event %+v, want max_hold after 660 s", ev)
	}
	calls, _, _ := sys.snapshot()
	if n := len(slices.DeleteFunc(calls, func(c string) bool { return c != "systemctl start himmelblaud.service" })); n != 1 {
		t.Errorf("himmelblaud started %d times, want once", n)
	}
}

// TestNSSShieldSkipsInactive: a device without a running himmelblaud (not enrolled with an identity, or the daemon
// down for another reason) runs the transaction as it is: nothing is stopped, started or reported.
func TestNSSShieldSkipsInactive(t *testing.T) {
	sys, shield, _, events := shieldFixture(false)
	ran := false
	_, _, _ = shield.Run(context.Background(), "apt-get install", func() (string, int, error) { ran = true; return "", 0, nil })
	if calls, timer, _ := sys.snapshot(); !ran || len(calls) != 0 || timer || len(*events) != 0 || sys.isActive("himmelblaud.service") {
		t.Errorf("ran %v, calls %v, timer %v, events %v", ran, calls, timer, *events)
	}
}

// TestNSSShieldRestoreFailed: when himmelblaud does not start again, the hold is reported as restore_failed with the
// error and the safety timer stays armed to retry.
func TestNSSShieldRestoreFailed(t *testing.T) {
	sys, shield, _, events := shieldFixture(true)
	sys.fail["systemctl start himmelblaud.service"] = true
	_, _, _ = shield.Run(context.Background(), "apt-get install", func() (string, int, error) { return "", 0, nil })
	ev := shieldEvent(t, *events)
	if ev.Outcome != protocol.NSSShieldRestoreFailed || !strings.Contains(ev.Error, "start himmelblaud.service") {
		t.Errorf("event %+v", ev)
	}
	if _, timer, _ := sys.snapshot(); !timer {
		t.Error("safety timer cancelled although himmelblaud did not start")
	}
}

// TestNSSShieldHoldFailed: without a safety timer the daemon is never stopped; the transaction runs with himmelblaud
// running and the failed hold is reported once.
func TestNSSShieldHoldFailed(t *testing.T) {
	sys, shield, _, events := shieldFixture(true)
	sys.fail[shieldTimerLine] = true
	activeDuring := false
	_, _, _ = shield.Run(context.Background(), "apt-get install", func() (string, int, error) {
		activeDuring = sys.isActive("himmelblaud.service")
		return "", 0, nil
	})
	calls, _, files := sys.snapshot()
	if !activeDuring || slices.Contains(calls, "systemctl stop himmelblaud.service") || files != 0 {
		t.Errorf("active %v, calls %v, marker files %d", activeDuring, calls, files)
	}
	if ev := shieldEvent(t, *events); ev.Outcome != protocol.NSSShieldHoldFailed || ev.Error == "" {
		t.Errorf("event %+v", ev)
	}
}

// TestNSSShieldRecover: an agent start that finds the marker of a hold its predecessor did not end starts himmelblaud,
// cancels the safety timer and reports the hold once as recovered; without a marker it does nothing, so a himmelblaud
// someone else stopped stays stopped (and the watch reports it).
func TestNSSShieldRecover(t *testing.T) {
	sys, shield, clock, events := shieldFixture(false)
	shield.Recover(context.Background())
	if calls, _, _ := sys.snapshot(); len(calls) != 0 || len(*events) != 0 || sys.isActive("himmelblaud.service") {
		t.Fatalf("without a marker: calls %v, events %v", calls, *events)
	}
	sys.files[reconcile.NSSShieldMarker] = []byte(`{"action":"dpkg -i","started_at":"` + clock.Now().Add(-3*time.Minute).Format(time.RFC3339) + `"}`)
	sys.timer = true
	shield.Recover(context.Background())
	if !sys.isActive("himmelblaud.service") || !sys.isActive("himmelblaud-tasks.service") {
		t.Error("himmelblaud not started")
	}
	if _, timer, files := sys.snapshot(); timer || files != 0 {
		t.Errorf("timer %v, marker files %d", timer, files)
	}
	if ev := shieldEvent(t, *events); ev != (protocol.LoginNSSShield{Action: "dpkg -i", DurationS: 180, Outcome: protocol.NSSShieldRecovered}) {
		t.Errorf("event %+v", ev)
	}
}

// shieldedSys records whether himmelblaud ran during each apt-get and dpkg call.
type shieldedSys struct {
	*fakesys.System
	shield *shieldSys
	seen   []string
}

func (s *shieldedSys) record(tool string, args []string) {
	state := "running"
	if !s.shield.isActive("himmelblaud.service") {
		state = "held"
	}
	s.seen = append(s.seen, tool+" "+strings.Join(args, " ")+": "+state)
}

func (s *shieldedSys) AptGet(ctx context.Context, args ...string) (string, int, error) {
	s.record("apt-get", args)
	return "", 0, nil
}

func (s *shieldedSys) Dpkg(ctx context.Context, args ...string) (string, int, error) {
	s.record("dpkg", args)
	return "", 0, nil
}

// TestShieldedTransactions: only apt-get and dpkg calls that run maintainer scripts are held; package list updates,
// simulations, downloads and queries run with himmelblaud.
func TestShieldedTransactions(t *testing.T) {
	ss, shield, _, events := shieldFixture(true)
	inner := &shieldedSys{System: fakesys.New(), shield: ss}
	sys := reconcile.Shielded{System: inner, Shield: shield}
	ctx := context.Background()
	for _, args := range [][]string{
		{"update", "-q"}, {"-s", "install", "flatpak"}, {"install", "--download-only", "flatpak"},
		{"install", "-y", "-q", "--no-remove", "--", "flatpak"}, {"remove", "-y", "nano"}, {"dist-upgrade", "-y"},
	} {
		_, _, _ = sys.AptGet(ctx, args...)
	}
	for _, args := range [][]string{{"-l", "nano"}, {"--configure", "-a"}, {"-i", "/var/lib/paddock/packages/x.deb"}} {
		_, _, _ = sys.Dpkg(ctx, args...)
	}
	want := []string{
		"apt-get update -q: running", "apt-get -s install flatpak: running", "apt-get install --download-only flatpak: running",
		"apt-get install -y -q --no-remove -- flatpak: held", "apt-get remove -y nano: held", "apt-get dist-upgrade -y: held",
		"dpkg -l nano: running", "dpkg --configure -a: held", "dpkg -i /var/lib/paddock/packages/x.deb: held",
	}
	if !slices.Equal(inner.seen, want) {
		t.Errorf("seen\n%s\nwant\n%s", strings.Join(inner.seen, "\n"), strings.Join(want, "\n"))
	}
	var actions []string
	for _, e := range *events {
		var ev protocol.LoginNSSShield
		_ = json.Unmarshal([]byte(e.data), &ev)
		actions = append(actions, ev.Action)
	}
	if want := []string{"apt-get install", "apt-get remove", "apt-get dist-upgrade", "dpkg --configure", "dpkg -i"}; !slices.Equal(actions, want) {
		t.Errorf("reported %v, want one event per held transaction %v", actions, want)
	}
}

// TestLoginReportsForeignDaemonStop (decisions §45, protected area 4): the login reconciler reports himmelblaud
// stopped by someone else once per stop as tamper.service_stopped and never starts it; a stop by the agent's own
// shield is not reported.
func TestLoginReportsForeignDaemonStop(t *testing.T) {
	sys, l, events := loginFixture(t)
	ctx := context.Background()
	r := loginResource(t, loginSpec())
	if res := l.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("install %+v", res)
	}
	takeEvents(events)
	sys.TakeCalls()
	timer := "systemd-run --unit=paddock-nss-shield-restore --on-active=720s --timer-property=AccuracySec=1s " +
		"--description=Paddock: start himmelblaud after a package transaction /usr/bin/systemctl start himmelblaud.service himmelblaud-tasks.service"
	sys.FlatpakScript = map[string]fakesys.OutputReply{timer: {}}
	shield := &reconcile.NSSShield{Sys: sys, Events: l.Events}
	l.Shield = shield

	_, _, _ = shield.Run(ctx, "apt-get install", func() (string, int, error) {
		if sys.Units["himmelblaud.service"].Active {
			t.Error("himmelblaud not stopped during the transaction")
		}
		if changes, err := l.Plan(ctx, r); len(changes) != 0 || err != nil {
			t.Errorf("Plan during the own hold = %v %v", changes, err)
		}
		if res := l.Apply(ctx, r); res.Status != reconcile.OK {
			t.Errorf("Apply during the own hold = %+v", res)
		}
		return "", 0, nil
	})
	if got := takeEvents(events); len(got) != 1 || got[0].typ != protocol.EventLoginNSSShield {
		t.Fatalf("events of the own hold %v, want only login.nss_shield", got)
	}

	sys.Units["himmelblaud.service"].Active = false
	if changes, _ := l.Plan(ctx, r); !slices.Equal(changes, []string{"report himmelblaud.service inactive"}) {
		t.Errorf("Plan after a foreign stop = %v", changes)
	}
	sys.TakeCalls()
	for range 2 {
		if res := l.Apply(ctx, r); res.Status != reconcile.OK {
			t.Errorf("Apply after a foreign stop = %+v", res)
		}
	}
	if got := takeEvents(events); !slices.Equal(got, []event{{protocol.EventTamperServiceStopped, `{"unit":"himmelblaud.service","state":"inactive"}`}}) {
		t.Errorf("events of a foreign stop %v, want one tamper.service_stopped", got)
	}
	if calls := sys.TakeCalls(); len(calls) != 0 || sys.Units["himmelblaud.service"].Active {
		t.Errorf("the agent acted on a foreign stop: %v", calls)
	}

	sys.Units["himmelblaud.service"].Active = true
	if changes, _ := l.Plan(ctx, r); !slices.Equal(changes, []string{"clear himmelblaud.service"}) {
		t.Errorf("Plan after the daemon runs again = %v", changes)
	}
	l.Apply(ctx, r)
	sys.Units["himmelblaud.service"].Active = false
	l.Apply(ctx, r)
	if got := takeEvents(events); len(got) != 1 || got[0].typ != protocol.EventTamperServiceStopped {
		t.Errorf("events of a second foreign stop %v, want it reported again", got)
	}
}
