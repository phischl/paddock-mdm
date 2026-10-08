package osupdates

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const distUpgrade = `Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages have been kept back:
  linux-generic linux-headers-generic
The following packages will be upgraded:
  curl libcurl4t64 openssl
3 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.
Need to get 2,345 kB of archives.
`

func TestParseDistUpgrade(t *testing.T) {
	n, held := ParseDistUpgrade(distUpgrade)
	if n != 3 || !slices.Equal(held, []string{"linux-generic", "linux-headers-generic"}) {
		t.Fatalf("upgraded %d, held back %v", n, held)
	}
	if n, held := ParseDistUpgrade("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"); n != 0 || held == nil || len(held) != 0 {
		t.Fatalf("nothing to do: %d %v", n, held)
	}
}

func TestRunRegular(t *testing.T) {
	var calls []string
	clock := time.Date(2026, 10, 10, 4, 0, 0, 0, time.UTC)
	now := func() time.Time { clock = clock.Add(time.Minute); return clock }
	apt := func(_ context.Context, timeout time.Duration, args ...string) (string, int, error) {
		calls = append(calls, strings.Join(args, " "))
		if timeout <= 0 || timeout > RunLimit {
			t.Errorf("timeout %s", timeout)
		}
		if args[len(args)-1] == "dist-upgrade" {
			return distUpgrade, 0, nil
		}
		return "", 0, nil
	}
	r := RunRegular(context.Background(), apt, noDpkg, now, func() bool { return true })
	if r.Kind != protocol.UpdatesKindRegular || r.Result != protocol.UpdatesResultOK || r.Upgraded != 3 || len(r.HeldBack) != 2 ||
		!r.RebootRequired || !r.FinishedAt.After(r.StartedAt) {
		t.Fatalf("%+v", r)
	}
	want := []string{"-o DPkg::Lock::Timeout=600 -q update",
		"-o DPkg::Lock::Timeout=600 -y -q -o Dpkg::Options::=--force-confold dist-upgrade"}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls %q", calls)
	}
}

func noDpkg(context.Context, time.Duration, ...string) (string, int, error) { return "", 0, nil }

// TestRunRegularRecoversDpkgAndIgnoresCancellation (review 1): a cancelled context does not stop apt, and an
// interrupted installation is finished with dpkg --configure -a before the run is retried.
func TestRunRegularRecoversDpkgAndIgnoresCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	interrupted := true
	var calls []string
	apt := func(ctx context.Context, _ time.Duration, args ...string) (string, int, error) {
		if ctx.Err() != nil {
			t.Error("apt ran with a cancelled context")
		}
		calls = append(calls, args[len(args)-1])
		if interrupted {
			return "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem.\n", 100, nil
		}
		return distUpgrade, 0, nil
	}
	dpkg := func(_ context.Context, _ time.Duration, args ...string) (string, int, error) {
		calls = append(calls, "dpkg "+strings.Join(args, " "))
		interrupted = false
		return "", 0, nil
	}
	r := RunRegular(ctx, apt, dpkg, time.Now, func() bool { return false })
	if r.Result != protocol.UpdatesResultOK || r.Upgraded != 3 || !slices.Equal(calls, []string{"update", "dpkg --configure -a", "update", "dist-upgrade"}) {
		t.Fatalf("%+v %q", r, calls)
	}
}

func TestRunRegularFailures(t *testing.T) {
	now := time.Now
	failing := func(_ context.Context, _ time.Duration, args ...string) (string, int, error) {
		return "E: Failed to fetch http://archive.ubuntu.com/ubuntu\n", 100, nil
	}
	if r := RunRegular(context.Background(), failing, noDpkg, now, func() bool { return false }); r.Result != protocol.UpdatesResultFailed ||
		!strings.Contains(r.Error, "apt-get update: exit 100: E: Failed to fetch") {
		t.Fatalf("%+v", r)
	}
	timeout := func(_ context.Context, _ time.Duration, args ...string) (string, int, error) {
		if args[len(args)-1] == "dist-upgrade" {
			return "", -1, fmt.Errorf("apt-get: %w", context.DeadlineExceeded)
		}
		return "", 0, nil
	}
	if r := RunRegular(context.Background(), timeout, noDpkg, now, func() bool { return false }); r.Result != protocol.UpdatesResultTimeout {
		t.Fatalf("%+v", r)
	}
	long := func(context.Context, time.Duration, ...string) (string, int, error) {
		return strings.Repeat("x", 1000), 1, nil
	}
	if r := RunRegular(context.Background(), long, noDpkg, now, func() bool { return false }); len(r.Error) > maxError {
		t.Fatalf("error of %d bytes", len(r.Error))
	}
}

func TestParseUnattendedLog(t *testing.T) {
	log := `2026-10-07 03:14:01,100 INFO Starting unattended upgrades script
2026-10-07 03:14:02,000 ERROR Old run failed
2026-10-08 03:21:07,512 INFO Starting unattended upgrades script
2026-10-08 03:21:07,513 INFO Allowed origins are: o=Ubuntu,a=noble-security
2026-10-08 03:21:07,513 INFO Initial blacklist: ^openssl$
2026-10-08 03:21:09,001 INFO Packages that will be upgraded: libssl3t64 curl
2026-10-08 03:21:30,800 INFO All upgrades installed
`
	r, ok := ParseUnattendedLog([]byte(log))
	want := time.Date(2026, 10, 8, 3, 21, 7, 512e6, time.Local).UTC()
	if !ok || r.Kind != protocol.UpdatesKindSecurity || !r.StartedAt.Equal(want) || r.Upgraded != 2 || r.Result != protocol.UpdatesResultOK {
		t.Fatalf("%+v %v", r, ok)
	}
	r, _ = ParseUnattendedLog([]byte(log + "2026-10-08 03:21:31,000 ERROR dpkg returned an error\n"))
	if r.Result != protocol.UpdatesResultFailed || r.Error != "dpkg returned an error" {
		t.Fatalf("%+v", r)
	}
	if _, ok := ParseUnattendedLog([]byte("garbage\n")); ok {
		t.Fatal("run in a log without one")
	}
}

func TestParseUnitRun(t *testing.T) {
	u, ok := ParseUnitRun("ExecMainStartTimestamp=@1791442900\nExecMainExitTimestamp=@1791443000\nResult=success\n")
	if !ok || u.Result != "success" || u.Exited.Unix() != 1791443000 || u.Started.Unix() != 1791442900 {
		t.Fatalf("%+v %v", u, ok)
	}
	if _, ok := ParseUnitRun("ExecMainStartTimestamp=\nExecMainExitTimestamp=\nResult=success\n"); ok {
		t.Fatal("a unit that never ran")
	}
}

// TestSecurityRun: only a log run that began during the unit's run counts; an older one in the log does not.
func TestSecurityRun(t *testing.T) {
	start := time.Date(2026, 10, 8, 3, 20, 0, 0, time.Local)
	log := []byte(start.Add(-5*24*time.Hour).Format("2006-01-02 15:04:05") + ",000 INFO Starting unattended upgrades script\n" +
		start.Add(-5*24*time.Hour).Format("2006-01-02 15:04:05") + ",500 INFO Packages that will be upgraded: a b c\n")
	unit := UnitRun{Started: start.UTC(), Exited: start.Add(time.Minute).UTC(), Result: "success"}
	if r := SecurityRun(unit, log, true); r.Upgraded != 0 || !r.StartedAt.Equal(unit.Started) || !r.FinishedAt.Equal(unit.Exited) ||
		!r.RebootRequired || r.Result != protocol.UpdatesResultOK {
		t.Fatalf("stale log run attributed: %+v", r)
	}
	log = append(log, []byte(start.Format("2006-01-02 15:04:05")+",100 INFO Starting unattended upgrades script\n"+
		start.Format("2006-01-02 15:04:05")+",500 INFO Packages that will be upgraded: libssl3t64\n")...)
	if r := SecurityRun(unit, log, false); r.Upgraded != 1 {
		t.Fatalf("current log run: %+v", r)
	}
	unit.Result = "exit-code"
	if r := SecurityRun(unit, nil, false); r.Result != protocol.UpdatesResultFailed || r.Error != "apt-daily-upgrade.service: exit-code" {
		t.Fatalf("failed unit: %+v", r)
	}
}

func TestResultRoundTrip(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	if r, err := ReadResult(l); r != nil || err != nil {
		t.Fatalf("no result: %v %v", r, err)
	}
	in := protocol.UpdatesRun{Kind: protocol.UpdatesKindRegular, Upgraded: 4, HeldBack: []string{}, Result: protocol.UpdatesResultOK,
		FinishedAt: time.Now().UTC().Truncate(time.Second)}
	if err := WriteResult(l, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadResult(l)
	if err != nil || out.Upgraded != 4 || !out.FinishedAt.Equal(in.FinishedAt) {
		t.Fatalf("%+v %v", out, err)
	}
	if RebootRequired(l) {
		t.Fatal("reboot required without the marker")
	}
}
