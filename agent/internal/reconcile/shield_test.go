package reconcile_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

func (s *shieldSys) ReadDir(dir string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for p := range s.files {
		if d, name := path.Split(p); d == dir+"/" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, fs.ErrNotExist
	}
	slices.Sort(names)
	return names, nil
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
	var m struct {
		Action   string `json:"action"`
		Reported bool   `json:"reported"`
	}
	if data, _, err := sys.ReadFile(reconcile.NSSShieldMarker); err != nil || json.Unmarshal(data, &m) != nil || !m.Reported || m.Action != "apt-get install" {
		t.Fatalf("marker after a failed restore: %s %v, want it kept as reported", data, err)
	}
	if !shield.Holds("himmelblaud.service") {
		t.Error("a failed restore of the agent's own hold is not its own hold any more")
	}

	// The next attempts retry the start; the hold is not reported again, and the marker goes once the start works.
	shield.Recover(context.Background())
	if len(*events) != 1 {
		t.Errorf("a retry that failed again reported again: %v", *events)
	}
	delete(sys.fail, "systemctl start himmelblaud.service")
	shield.Recover(context.Background())
	if _, _, files := sys.snapshot(); files != 0 || len(*events) != 1 || !sys.isActive("himmelblaud.service") {
		t.Errorf("after a successful retry: marker files %d, events %v, himmelblaud %v", files, *events, sys.isActive("himmelblaud.service"))
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

// TestNSSShieldStopFails: when the stop itself fails, the daemon is started again, the marker removed, and the
// transaction runs with himmelblaud running; the hold is reported once as hold_failed.
func TestNSSShieldStopFails(t *testing.T) {
	sys, shield, _, events := shieldFixture(true)
	sys.fail["systemctl stop himmelblaud.service"] = true
	ran := false
	_, _, _ = shield.Run(context.Background(), "apt-get install", func() (string, int, error) { ran = true; return "", 0, nil })
	_, timer, files := sys.snapshot()
	if !ran || timer || files != 0 || !sys.isActive("himmelblaud.service") {
		t.Errorf("ran %v, timer %v, marker files %d, himmelblaud %v", ran, timer, files, sys.isActive("himmelblaud.service"))
	}
	if ev := shieldEvent(t, *events); ev.Outcome != protocol.NSSShieldHoldFailed || !strings.Contains(ev.Error, "stop himmelblaud.service") {
		t.Errorf("event %+v", ev)
	}
}

// TestNSSShieldSerializes: two transactions at the same time are held one after the other, never overlapping.
func TestNSSShieldSerializes(t *testing.T) {
	sys, shield, _, events := shieldFixture(true)
	shield.LockFile = filepath.Join(t.TempDir(), "nss-shield.lock")
	var mu sync.Mutex
	running, overlap := 0, false
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, _, _ = shield.Run(context.Background(), "apt-get install", func() (string, int, error) {
				mu.Lock()
				running++
				overlap = overlap || running > 1
				mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				mu.Lock()
				running--
				mu.Unlock()
				return "", 0, nil
			})
		})
	}
	wg.Wait()
	if overlap || len(*events) != 2 || !sys.isActive("himmelblaud.service") {
		t.Errorf("overlap %v, events %v, himmelblaud %v", overlap, *events, sys.isActive("himmelblaud.service"))
	}
}

// TestNSSShieldWaitsForDpkg (review M4): while another process holds the dpkg frontend lock, himmelblaud is not
// stopped; a lock that frees within LockWait lets the hold start, one that stays held defers the transaction with
// apt's lock message, so that the software reconciler retries it (pending/dpkg_locked).
func TestNSSShieldWaitsForDpkg(t *testing.T) {
	_, shield, _, events := shieldFixture(true)
	shield.LockWait = 600 * time.Millisecond
	var probes atomic.Int32
	shield.DpkgBusy = func() bool { return probes.Add(1) <= 2 }
	ran := false
	if _, _, err := shield.Run(context.Background(), "apt-get install", func() (string, int, error) { ran = true; return "", 0, nil }); err != nil || !ran {
		t.Fatalf("lock freed within the wait: ran %v, %v", ran, err)
	}
	if shieldEvent(t, *events).Outcome != protocol.NSSShieldRestored {
		t.Errorf("events %v", *events)
	}

	sys, shield, _, events := shieldFixture(true)
	shield.LockWait = 300 * time.Millisecond
	shield.DpkgBusy = func() bool { return true }
	ran = false
	out, exit, err := shield.Run(context.Background(), "apt-get install", func() (string, int, error) { ran = true; return "", 0, nil })
	if ran || !errors.Is(err, reconcile.ErrNSSShieldBusy) || exit != 100 || !strings.HasPrefix(out, "E: Could not get lock") {
		t.Errorf("lock held past the wait: ran %v, %q %d %v", ran, out, exit, err)
	}
	if calls, _, _ := sys.snapshot(); len(calls) != 0 || len(*events) != 0 || !sys.isActive("himmelblaud.service") {
		t.Errorf("himmelblaud touched behind a held dpkg lock: %v %v", calls, *events)
	}
}

// TestNSSShieldAcrossProcesses (plan M5a N6): a hold of `paddockd updates run` (another shield on the same lock file)
// is Paddock's own: Holds is true while its lock is taken, the agent's transaction waits for the lock (and is deferred
// past HoldWait), Recover with the lock taken recovers nothing, and the run's record reaches the agent's events once.
func TestNSSShieldAcrossProcesses(t *testing.T) {
	sys, agent, clock, events := shieldFixture(true)
	lock := filepath.Join(t.TempDir(), "nss-shield.lock")
	agent.LockFile, agent.HoldWait = lock, 300*time.Millisecond
	updates := &reconcile.NSSShield{Sys: sys, LockFile: lock, Now: clock.Now, Events: reconcile.NSSShieldRecorder(sys)}

	held, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = updates.Run(context.Background(), "apt-get dist-upgrade", func() (string, int, error) {
			close(held)
			<-finish
			return "", 0, nil
		})
	}()
	<-held
	// A fresh shield of the agent sees the other process's hold by its lock alone.
	if fresh := (&reconcile.NSSShield{Sys: newShieldSys(true), LockFile: lock}); !fresh.Holds("himmelblaud.service") {
		t.Error("the shield lock of another process's hold is not seen as Paddock's own hold")
	}
	if _, _, err := agent.Run(context.Background(), "apt-get install", func() (string, int, error) {
		t.Error("the agent's transaction ran inside another process's hold")
		return "", 0, nil
	}); !errors.Is(err, reconcile.ErrNSSShieldBusy) {
		t.Errorf("agent Run during the updates run's hold: %v", err)
	}
	agent.Recover(context.Background())
	if sys.isActive("himmelblaud.service") || len(*events) != 0 {
		t.Errorf("the agent ended another process's hold: himmelblaud %v, events %v", sys.isActive("himmelblaud.service"), *events)
	}
	close(finish)
	<-done
	if !agent.Pending(context.Background()) {
		t.Error("the updates run's record is not pending for the agent")
	}
	agent.Recover(context.Background())
	if ev := shieldEvent(t, *events); ev.Action != "apt-get dist-upgrade" || ev.Outcome != protocol.NSSShieldRestored {
		t.Errorf("emitted record %+v", ev)
	}
	if agent.Pending(context.Background()) || agent.Holds("himmelblaud.service") {
		t.Error("record or marker left after the agent emitted the record")
	}
}

// TestNSSShieldWaitsForOtherHold (plan M5a N6.2): a transaction that finds another process's hold waits for its lock
// and holds afterwards.
func TestNSSShieldWaitsForOtherHold(t *testing.T) {
	sys, agent, clock, events := shieldFixture(true)
	lock := filepath.Join(t.TempDir(), "nss-shield.lock")
	agent.LockFile = lock
	updates := &reconcile.NSSShield{Sys: sys, LockFile: lock, Now: clock.Now, Events: reconcile.NSSShieldRecorder(sys)}
	held, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = updates.Run(context.Background(), "apt-get dist-upgrade", func() (string, int, error) {
			close(held)
			time.Sleep(300 * time.Millisecond)
			return "", 0, nil
		})
	}()
	<-held
	heldAfter := false
	if _, _, err := agent.Run(context.Background(), "apt-get install", func() (string, int, error) {
		heldAfter = !sys.isActive("himmelblaud.service")
		return "", 0, nil
	}); err != nil || !heldAfter {
		t.Errorf("the waiting transaction: %v, held %v", err, heldAfter)
	}
	<-done
	agent.Recover(context.Background())
	var actions []string
	for _, e := range *events {
		var ev protocol.LoginNSSShield
		_ = json.Unmarshal([]byte(e.data), &ev)
		actions = append(actions, ev.Action)
	}
	if !slices.Equal(actions, []string{"apt-get install", "apt-get dist-upgrade"}) {
		t.Errorf("events %v, want the agent's hold and the run's record", actions)
	}
}

// TestNSSShieldRecords (plan M5a N6.4): the records of the updates run form one array of at most 16 entries; the
// agent emits each as login.nss_shield and removes the file.
func TestNSSShieldRecords(t *testing.T) {
	sys, agent, _, events := shieldFixture(true)
	rec := reconcile.NSSShieldRecorder(sys)
	for i := range 18 {
		rec.Emit(protocol.EventLoginNSSShield, protocol.LoginNSSShield{Action: "apt-get dist-upgrade", DurationS: int64(i), Outcome: "restored"})
	}
	agent.Recover(context.Background())
	if len(*events) != 16 {
		t.Fatalf("%d events, want the newest 16", len(*events))
	}
	var first protocol.LoginNSSShield
	_ = json.Unmarshal([]byte((*events)[0].data), &first)
	if first.DurationS != 2 {
		t.Errorf("oldest kept record %+v, want the third", first)
	}
	if _, _, err := sys.ReadFile(reconcile.NSSShieldReport); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("record file left: %v", err)
	}
}

// TestNSSShieldRecoverDeadHolder: a marker whose holder died (no process holds the lock) is finished by Recover, even
// when the hold was another process's.
func TestNSSShieldRecoverDeadHolder(t *testing.T) {
	sys, shield, _, events := shieldFixture(false)
	shield.LockFile = filepath.Join(t.TempDir(), "nss-shield.lock")
	sys.files[reconcile.NSSShieldMarker] = []byte(`{"action":"apt-get dist-upgrade","pid":` + "999999" + `}`)
	if !shield.Pending(context.Background()) {
		t.Fatal("a hold without holder is not pending")
	}
	shield.Recover(context.Background())
	if !sys.isActive("himmelblaud.service") || shieldEvent(t, *events).Outcome != protocol.NSSShieldRecovered {
		t.Errorf("himmelblaud %v, events %v", sys.isActive("himmelblaud.service"), *events)
	}
}

// holdDuringShow is a device on which a hold starts while the login reconciler reads himmelblaud's state: the hold's
// marker is written and the daemon stopped just before systemctl show answers.
type holdDuringShow struct {
	*fakesys.System
	armed bool
}

func (h *holdDuringShow) Systemctl(ctx context.Context, args ...string) (string, int, error) {
	if h.armed && args[0] == "show" {
		h.armed = false
		h.Files[reconcile.NSSShieldMarker] = &fakesys.File{Data: []byte(`{"action":"apt-get install"}`), Mode: 0o600}
		h.Units["himmelblaud.service"].Active = false
	}
	return h.System.Systemctl(ctx, args...)
}

// TestLoginHoldBetweenReads (review M1): a hold that starts between the login reconciler's check of the shield and its
// read of the daemon's state is the agent's own, not tampering.
func TestLoginHoldBetweenReads(t *testing.T) {
	fs, l, events := loginFixture(t)
	ctx := context.Background()
	r := loginResource(t, loginSpec())
	l.Apply(ctx, r)
	takeEvents(events)
	sys := &holdDuringShow{System: fs}
	l.Sys = sys
	l.Shield = &reconcile.NSSShield{Sys: sys, Events: l.Events}
	sys.armed = true
	if changes, _ := l.Plan(ctx, r); slices.ContainsFunc(changes, func(c string) bool { return strings.HasPrefix(c, "report") }) {
		t.Errorf("Plan reports the own hold: %v", changes)
	}
	fs.Units["himmelblaud.service"].Active = true
	delete(fs.Files, reconcile.NSSShieldMarker)
	sys.armed = true
	l.Apply(ctx, r)
	for _, e := range takeEvents(events) {
		if e.typ == protocol.EventTamperServiceStopped {
			t.Errorf("Apply reported the own hold as tampering: %v", e)
		}
	}
}

// TestLoginRestartWaitsForHold (review M3): a configuration change while another hold runs (here of a second shield on
// the same lock, as `paddockd updates run` takes it) does not restart himmelblaud into that hold and does not fail;
// the restart follows once the hold ended.
func TestLoginRestartWaitsForHold(t *testing.T) {
	sys, l, events := loginFixture(t)
	ctx := context.Background()
	l.Apply(ctx, loginResource(t, loginSpec()))
	takeEvents(events)
	sys.FlatpakScript = map[string]fakesys.OutputReply{shieldTimerLine: {}}
	lock := filepath.Join(t.TempDir(), "nss-shield.lock")
	l.Shield = &reconcile.NSSShield{Sys: sys, Events: l.Events, LockFile: lock, LockWait: 200 * time.Millisecond}
	other := &reconcile.NSSShield{Sys: sys, LockFile: lock}
	held, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = other.Run(ctx, "apt-get dist-upgrade", func() (string, int, error) { close(held); <-finish; return "", 0, nil })
	}()
	<-held
	sys.TakeCalls()

	spec := loginSpec()
	spec.Himmelblau.EnableHello = false
	r := loginResource(t, spec)
	if res := l.Apply(ctx, r); res.Status == reconcile.Error {
		t.Fatalf("Apply during another hold = %+v", res)
	}
	for _, e := range takeEvents(events) {
		if e.typ == protocol.EventLoginApplyFailed || e.typ == protocol.EventTamperServiceStopped {
			t.Errorf("event during another hold: %v", e)
		}
	}
	if slices.ContainsFunc(sys.TakeCalls(), func(c string) bool { return strings.HasPrefix(c, "systemctl restart") }) {
		t.Error("himmelblaud restarted inside another process's hold")
	}
	if changes, _ := l.Plan(ctx, r); !slices.Contains(changes, "restart himmelblaud") {
		t.Errorf("Plan while the restart is deferred = %v", changes)
	}

	close(finish)
	<-done
	l.Apply(ctx, r)
	if calls := sys.TakeCalls(); !slices.Contains(calls, "systemctl restart himmelblaud.service") {
		t.Errorf("no restart after the hold ended: %v", calls)
	}
	if changes, _ := l.Plan(ctx, r); len(changes) != 0 {
		t.Errorf("Plan after the deferred restart = %v", changes)
	}
}
