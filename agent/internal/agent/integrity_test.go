package agent

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the md5sums of the fake dpkg database
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/integrity"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// integritySys knows no unit and reports installed exactly the packages in installed.
type integritySys struct{ installed map[string]bool }

func (integritySys) Systemctl(context.Context, ...string) (string, int, error) {
	return "LoadState=not-found\n", 0, nil
}

func (s integritySys) Output(_ context.Context, _ string, args ...string) ([]byte, error) {
	if s.installed[args[len(args)-1]] {
		return []byte("installed"), nil
	}
	return nil, errors.New("dpkg-query: exit 1")
}

// withIntegrity gives the agent an integrity check on its test root and a device with slot A active, as New wires it
// on a device; it returns the agent New made.
func withIntegrity(t *testing.T, a *Agent, installed ...string) *Agent {
	t.Helper()
	l := a.d.Layout
	if _, err := os.Lstat(filepath.Join(l.Slots(), "current")); errors.Is(err, os.ErrNotExist) {
		writeFile(t, filepath.Join(l.Slots(), "A", "paddockd"), "agent v1")
		if err := os.Symlink("A", filepath.Join(l.Slots(), "current")); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(l.Join("/usr/bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/opt/paddock/agent/current/paddockd", l.Join("/usr/bin/paddockd")); err != nil {
			t.Fatal(err)
		}
	}
	sys := integritySys{installed: map[string]bool{}}
	for _, p := range installed {
		sys.installed[p] = true
	}
	c := integrity.New(l, sys)
	c.DpkgBusy = func() bool { return false }
	c.Sleep = func(time.Duration) {}
	a.d.Integrity = c
	b, err := New(a.d)
	if err != nil {
		t.Fatal(err)
	}
	// Some fixtures hold their bundle in memory only.
	b.current = a.current
	return b
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // test files
		t.Fatal(err)
	}
}

// tampered returns the files of every device.tamper_protected_file_changed, spooled or delivered.
func tampered(t *testing.T, a *Agent, g *testgw.Gateway) []string {
	t.Helper()
	var files []string
	events := spooled(t, a)
	if g != nil {
		events = append(events, eventsOf(g, protocol.EventTamperProtectedFileChanged)...)
	}
	for _, e := range events {
		if e.Type == protocol.EventTamperProtectedFileChanged {
			files = append(files, eventData(t, e)["file"].(string))
		}
	}
	return files
}

// ticks runs n integrity passes and fails on a report.
func ticks(t *testing.T, a *Agent, g *testgw.Gateway, n int) {
	t.Helper()
	for range n {
		a.tickIntegrity(context.Background())
		if files := tampered(t, a, g); len(files) != 0 {
			t.Fatalf("reported %v, want nothing", files)
		}
	}
}

// TestIntegrityAgentUpdate: a regular update and a regular rollback move the baseline without a report (ADR 0056).
func TestIntegrityAgentUpdate(t *testing.T) {
	for _, tc := range []struct{ outcome, slot string }{{update.OutcomeUpdated, "B"}, {update.OutcomeRolledBack, "A"}} {
		t.Run(tc.outcome, func(t *testing.T) {
			g := testgw.New(t)
			a := withIntegrity(t, newAgent(t, g))
			a.d.Supervisor = func() (int, error) { return 1, nil }
			a.d.Signal = func(int) error { return nil }
			ticks(t, a, g, 1)
			offer(g, "9.1.0", []byte("agent v2"))
			a.Cycle(context.Background())
			if !update.Pending(a.d.Layout) {
				t.Fatal("not staged")
			}
			ticks(t, a, g, 1)
			// The supervisor installs slot B, switches, and decides.
			writeFile(t, filepath.Join(a.d.Layout.Slots(), "B", "paddockd"), "agent v2")
			if err := os.Remove(a.d.Layout.UpdateRequest()); err != nil {
				t.Fatal(err)
			}
			replaceLink(t, tc.slot, filepath.Join(a.d.Layout.Slots(), "current"))
			ticks(t, a, g, 1)
			res, _ := json.Marshal(update.Result{Version: "9.1.0", FromVersion: "1.0.0", Outcome: tc.outcome, At: time.Now().UTC()})
			writeFile(t, a.d.Layout.UpdateResult(), string(res))
			ticks(t, a, g, 1)
			g.Mu.Lock()
			g.Checkin.AgentUpdate = nil
			g.Mu.Unlock()
			a.Cycle(context.Background())
			if a.st.ReportedUpdateAt == nil {
				t.Fatal("result not processed")
			}
			ticks(t, a, g, 3)
			// A later manual switch is reported once, also across a restart.
			other := map[string]string{"A": "B", "B": "A"}[tc.slot]
			replaceLink(t, other, filepath.Join(a.d.Layout.Slots(), "current"))
			a.tickIntegrity(context.Background())
			a.tickIntegrity(context.Background())
			if files := tampered(t, a, g); !slices.Equal(files, []string{"/opt/paddock/agent/current"}) {
				t.Fatalf("reported %v", files)
			}
			b := withIntegrity(t, a)
			b.tickIntegrity(context.Background())
			if files := tampered(t, b, g); len(files) != 1 {
				t.Fatalf("after the restart: %v", files)
			}
		})
	}
}

// TestIntegrityForgedUpdateResult (plan M5a R16): a request and a result for a release the agent never staged, written
// together with a switch of current, raise update_result_unstaged once, and the next pass reports the slots.
func TestIntegrityForgedUpdateResult(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	writeFile(t, filepath.Join(a.d.Layout.Slots(), "B", "paddockd"), "agent v0")
	a = withIntegrity(t, a)
	ticks(t, a, g, 1)
	writeFile(t, a.d.Layout.UpdateRequest(), `{"version":"9.1.0"}`)
	writeFile(t, filepath.Join(a.d.Layout.Slots(), "B", "paddockd"), "agent other")
	replaceLink(t, "B", filepath.Join(a.d.Layout.Slots(), "current"))
	if err := os.Remove(a.d.Layout.UpdateRequest()); err != nil {
		t.Fatal(err)
	}
	res, _ := json.Marshal(update.Result{Version: "9.1.0", FromVersion: "1.0.0", Outcome: update.OutcomeSignatureInvalid,
		At: time.Now().UTC()})
	writeFile(t, a.d.Layout.UpdateResult(), string(res))
	a.Cycle(context.Background())
	if a.st.ReportedUpdateAt == nil {
		t.Fatal("result not processed")
	}
	for range 3 {
		a.tickIntegrity(context.Background())
	}
	var got []string
	events := append(spooled(t, a), eventsOf(g, protocol.EventTamperProtectedFileChanged)...)
	for _, e := range events {
		if e.Type == protocol.EventTamperProtectedFileChanged {
			d := eventData(t, e)
			reason, _ := d["reason"].(string)
			got = append(got, d["file"].(string)+" "+reason)
		}
	}
	slices.Sort(got)
	want := []string{"/opt/paddock/agent/B/paddockd ", "/opt/paddock/agent/current ",
		integrity.UpdateResultFile + " " + protocol.TamperReasonUpdateResultUnstaged}
	if !slices.Equal(got, want) {
		t.Fatalf("reported %q, want %q", got, want)
	}
}

func replaceLink(t *testing.T, target, path string) {
	t.Helper()
	_ = os.Remove(path + ".new")
	if err := os.Symlink(target, path+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

// TestIntegritySupervisorRollback: the files the upgrade helper copies back are no change once the result is
// processed; a later foreign change is.
func TestIntegritySupervisorRollback(t *testing.T) {
	for _, outcome := range []string{protocol.SupervisorOutcomeRolledBack, protocol.SupervisorOutcomeRolledBackUnreachable,
		protocol.SupervisorOutcomeInstallFailed} {
		t.Run(outcome, func(t *testing.T) {
			g := testgw.New(t)
			a := withIntegrity(t, newAgent(t, g), supervisorpkg.Package)
			l := a.d.Layout
			install := func(content string) {
				var sums strings.Builder
				for _, f := range []string{supervisorpkg.Binary, supervisorpkg.UnitFile} {
					writeFile(t, l.Join(f), content+f)
					sum := md5.Sum([]byte(content + f)) //nolint:gosec // dpkg's format
					sums.WriteString(hex.EncodeToString(sum[:]) + "  " + strings.TrimPrefix(f, "/") + "\n")
				}
				writeFile(t, l.Join("/var/lib/dpkg/info/paddock-supervisor.md5sums"), sums.String())
			}
			install("v1")
			ticks(t, a, nil, 1)
			// handleSupervisorPackage records the files before it launches the upgrade (TestIntegritySupervisorCapture).
			if err := integrity.RecordSupervisorPre(l, runtime.GOARCH, "2.0.0"); err != nil {
				t.Fatal(err)
			}
			install("v2")
			writeFile(t, l.Join(supervisorpkg.Binary), "v1"+supervisorpkg.Binary)
			writeFile(t, l.Join(supervisorpkg.UnitFile), "v1"+supervisorpkg.UnitFile)
			if err := supervisorpkg.WriteResult(l, supervisorpkg.Result{Version: "2.0.0", FromVersion: "1.0.0", Outcome: outcome,
				At: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
			ticks(t, a, nil, 1)
			a.reportSupervisorUpgrade()
			ticks(t, a, nil, 3)
			writeFile(t, l.Join(supervisorpkg.Binary), "foreign")
			a.tickIntegrity(context.Background())
			if files := tampered(t, a, nil); !slices.Equal(files, []string{supervisorpkg.Binary}) {
				t.Fatalf("reported %v", files)
			}
		})
	}
}

// TestIntegrityOwnWrites: the revocation trust on first use and the in-place encryption's preparation, abort and
// cleanup retry write their files without a report.
func TestIntegrityOwnWrites(t *testing.T) {
	t.Run("revocation trust on first use", func(t *testing.T) {
		g := testgw.New(t)
		a := withIntegrity(t, newAgent(t, g))
		ticks(t, a, g, 1)
		a.applyRevocation(&bundle.Bundle{Revocation: &bundle.Revocation{Keys: []bundle.SigningKey{revocationKey(1)}}})
		if _, err := os.Stat(a.d.Layout.RevokeTrust()); err != nil {
			t.Fatal(err)
		}
		ticks(t, a, g, 3)
	})
	params := `{"conversion_id":"` + testConversionID + `"}`
	prepared := func(t *testing.T) *Agent {
		t.Helper()
		a, _, _ := convAgent(t)
		a = withIntegrity(t, a)
		ticks(t, a, nil, 1)
		a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
		runWorker(t, a)
		if _, err := os.Stat(a.d.Layout.DiskSetupConfig()); err != nil || a.st.Conversion.Phase != state.ConversionPrepared {
			t.Fatalf("not prepared: %v", err)
		}
		_ = os.Remove(a.d.Layout.Spool())
		ticks(t, a, nil, 2)
		return a
	}
	t.Run("abort command", func(t *testing.T) {
		a := prepared(t)
		if status, _ := a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-a", params)); status != protocol.CommandSucceeded {
			t.Fatal(status)
		}
		if _, err := os.Stat(a.d.Layout.DiskSetupConfig()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("disk-setup.json: %v", err)
		}
		_ = os.Remove(a.d.Layout.Spool())
		ticks(t, a, nil, 3)
	})
	t.Run("abort request", func(t *testing.T) {
		a := prepared(t)
		req, _ := json.Marshal(encrypt.AbortRequest{Nonce: "n1", ConversionID: testConversionID, By: "operator", RequestedAt: a.d.Now()})
		writeFile(t, a.d.Layout.EncryptAbortRequest(), string(req))
		a.handleAbortRequest(context.Background())
		if _, err := os.Stat(a.d.Layout.DiskSetupConfig()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("disk-setup.json: %v", err)
		}
		_ = os.Remove(a.d.Layout.Spool())
		ticks(t, a, nil, 3)
	})
	t.Run("cleanup retry", func(t *testing.T) {
		a := prepared(t)
		a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
		a.tickConversion(context.Background())
		// While the worker owns the file, a pass leaves it alone.
		ticks(t, a, nil, 1)
		runWorker(t, a)
		if _, err := os.Stat(a.d.Layout.DiskSetupConfig()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("disk-setup.json: %v", err)
		}
		_ = os.Remove(a.d.Layout.Spool())
		ticks(t, a, nil, 3)
	})
}

// TestIntegrityNotEnrolled: a device that is not active is not checked.
func TestIntegrityNotEnrolled(t *testing.T) {
	g := testgw.New(t)
	a := withIntegrity(t, newAgent(t, g))
	a.st.Status = state.StatusPending
	a.tickIntegrity(context.Background())
	if _, err := os.Stat(a.d.Layout.Integrity()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checked a pending device: %v", err)
	}
}

// TestIntegritySkipsDiskSetupWhileConverting: while the conversion worker runs, disk-setup.json is its file until it
// returns and syncs the baseline.
func TestIntegritySkipsDiskSetupWhileConverting(t *testing.T) {
	g := testgw.New(t)
	a := withIntegrity(t, newAgent(t, g))
	ticks(t, a, g, 1)
	a.conversionBusy = true
	writeFile(t, a.d.Layout.DiskSetupConfig(), "{}")
	ticks(t, a, g, 2)
	a.syncIntegrity(a.d.Layout.DiskSetupConfig())
	a.conversionBusy = false
	ticks(t, a, g, 2)
}

// preparedIntegrity is a device whose in-place encryption is prepared, with the integrity baseline recorded.
func preparedIntegrity(t *testing.T) *Agent {
	t.Helper()
	a, _, _ := convAgent(t)
	a = withIntegrity(t, a)
	ticks(t, a, nil, 1)
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", `{"conversion_id":"`+testConversionID+`"}`))
	runWorker(t, a)
	if _, err := os.Stat(a.d.Layout.DiskSetupConfig()); err != nil || a.st.Conversion.Phase != state.ConversionPrepared {
		t.Fatalf("not prepared: %v", err)
	}
	_ = os.Remove(a.d.Layout.Spool())
	ticks(t, a, nil, 2)
	return a
}

// TestIntegrityRefusedAbortKeepsHandEdit (plan M5a R8, T1): a refused abort request and a refused abort command do
// not move the baseline, so a prior hand edit of disk-setup.json is reported once.
func TestIntegrityRefusedAbortKeepsHandEdit(t *testing.T) {
	a := preparedIntegrity(t)
	writeFile(t, a.d.Layout.DiskSetupConfig(), `{"hand":"edit"}`)
	req, _ := json.Marshal(encrypt.AbortRequest{Nonce: "n1", ConversionID: "c-unknown", By: "operator", RequestedAt: a.d.Now()})
	writeFile(t, a.d.Layout.EncryptAbortRequest(), string(req))
	a.handleAbortRequest(context.Background())
	if status, _ := a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-a",
		`{"conversion_id":"c-unknown"}`)); status != protocol.CommandFailed {
		t.Fatal(status)
	}
	for range 3 {
		a.tickIntegrity(context.Background())
		if files := tampered(t, a, nil); !slices.Equal(files, []string{"/etc/paddock/disk-setup.json"}) {
			t.Fatalf("reported %v", files)
		}
	}
}

// breakBaseline makes integrity.json unreadable (a directory) until the returned func restores it.
func breakBaseline(t *testing.T, a *Agent) func() {
	t.Helper()
	path := a.d.Layout.Integrity()
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".saved", path); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIntegrityFailedSyncDeferred (plan M5a R7.1, T7): Paddock's own write whose sync failed is taken as the baseline
// by the next pass instead of being reported.
func TestIntegrityFailedSyncDeferred(t *testing.T) {
	a := preparedIntegrity(t)
	restore := breakBaseline(t, a)
	writeFile(t, a.d.Layout.DiskSetupConfig(), `{"written":"by Paddock"}`)
	a.syncIntegrity(a.d.Layout.DiskSetupConfig())
	restore()
	ticks(t, a, nil, 3)
	writeFile(t, a.d.Layout.DiskSetupConfig(), `{"hand":"edit"}`)
	a.tickIntegrity(context.Background())
	if files := tampered(t, a, nil); !slices.Equal(files, []string{"/etc/paddock/disk-setup.json"}) {
		t.Fatalf("reported %v", files)
	}
}

// holdIntegrityLock holds integrity.lock from a second open file description until the returned func releases it.
func holdIntegrityLock(t *testing.T, a *Agent) func() {
	t.Helper()
	f, err := os.OpenFile(a.d.Layout.IntegrityLock(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // a file descriptor fits an int
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return func() { _ = f.Close() }
}

// updatedTo stages version as the agent does and installs it as the supervisor does: into slot, current switched,
// the request removed and the result written at at.
func updatedTo(t *testing.T, a *Agent, g *testgw.Gateway, version, slot string, at time.Time) {
	t.Helper()
	offer(g, version, []byte("agent "+version))
	a.Cycle(context.Background())
	if !update.Pending(a.d.Layout) {
		t.Fatal("not staged")
	}
	g.Mu.Lock()
	g.Checkin.AgentUpdate = nil
	g.Mu.Unlock()
	writeFile(t, filepath.Join(a.d.Layout.Slots(), slot, "paddockd"), "agent "+version)
	if err := os.Remove(a.d.Layout.UpdateRequest()); err != nil {
		t.Fatal(err)
	}
	replaceLink(t, slot, filepath.Join(a.d.Layout.Slots(), "current"))
	res, _ := json.Marshal(update.Result{Version: version, FromVersion: "1.0.0", Outcome: update.OutcomeUpdated, At: at})
	writeFile(t, a.d.Layout.UpdateResult(), string(res))
}

func updateEvents(t *testing.T, a *Agent) int {
	t.Helper()
	n := 0
	for _, e := range spooled(t, a) {
		if e.Type == protocol.EventAgentUpdated {
			n++
		}
	}
	return n
}

// TestIntegrityUpdateResultWaitsForTheBaseline (plan M5a R7.2, R7.3, T6): while integrity.lock is held the update
// result is neither reported nor marked processed; afterwards it is reported once and a later update raises no
// tamper event. Past StateBound the result is reported without the bookkeeping.
func TestIntegrityUpdateResultWaitsForTheBaseline(t *testing.T) {
	setup := func(t *testing.T) (*Agent, *testgw.Gateway, *time.Time) {
		g := testgw.New(t)
		a := newAgent(t, g)
		now := time.Now().UTC()
		a.d.Now = func() time.Time { return now }
		a = withIntegrity(t, a)
		a.d.Supervisor = func() (int, error) { return 1, nil }
		a.d.Signal = func(int) error { return nil }
		ticks(t, a, g, 1)
		return a, g, &now
	}
	t.Run("lock released", func(t *testing.T) {
		a, g, now := setup(t)
		updatedTo(t, a, g, "9.1.0", "B", now.Add(time.Minute))
		release := holdIntegrityLock(t, a)
		a.reportUpdate()
		if a.st.ReportedUpdateAt != nil || updateEvents(t, a) != 0 {
			t.Fatalf("reported while the baseline could not move: %v", a.st.ReportedUpdateAt)
		}
		release()
		a.reportUpdate()
		a.reportUpdate()
		if a.st.ReportedUpdateAt == nil || updateEvents(t, a) != 1 {
			t.Fatalf("reported at %v with %d events", a.st.ReportedUpdateAt, updateEvents(t, a))
		}
		ticks(t, a, g, 2)
		updatedTo(t, a, g, "9.2.0", "A", now.Add(time.Hour))
		a.reportUpdate()
		ticks(t, a, g, 2)
	})
	t.Run("past the bound", func(t *testing.T) {
		a, g, now := setup(t)
		updatedTo(t, a, g, "9.1.0", "B", now.Add(time.Minute))
		holdIntegrityLock(t, a)
		a.reportUpdate()
		*now = now.Add(integrity.StateBound)
		a.reportUpdate()
		if a.st.ReportedUpdateAt == nil || updateEvents(t, a) != 1 {
			t.Fatalf("not reported past the bound: %v", a.st.ReportedUpdateAt)
		}
	})
}

// TestIntegritySupervisorCapture (plan M5a R10, R7.2, T8): the agent records the supervisor files before it launches
// the upgrade, so a regular rollback raises no event; while the record fails nothing is launched.
func TestIntegritySupervisorCapture(t *testing.T) {
	a, _, launched := supervisorAgent(t, "")
	a = withIntegrity(t, a, supervisorpkg.Package)
	l := a.d.Layout
	install := func(content string) {
		var sums strings.Builder
		for _, f := range []string{supervisorpkg.Binary, supervisorpkg.UnitFile} {
			writeFile(t, l.Join(f), content+f)
			sum := md5.Sum([]byte(content + f)) //nolint:gosec // dpkg's format
			sums.WriteString(hex.EncodeToString(sum[:]) + "  " + strings.TrimPrefix(f, "/") + "\n")
		}
		writeFile(t, l.Join("/var/lib/dpkg/info/paddock-supervisor.md5sums"), sums.String())
	}
	install("v1")
	ticks(t, a, nil, 1)
	restore := breakBaseline(t, a)
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("launched without the record: %v", *launched)
	}
	restore()
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 1 {
		t.Fatalf("launched %v", *launched)
	}
	install("v2")
	writeFile(t, l.Join(supervisorpkg.Binary), "v1"+supervisorpkg.Binary)
	writeFile(t, l.Join(supervisorpkg.UnitFile), "v1"+supervisorpkg.UnitFile)
	if err := os.Remove(l.SupervisorUpgrade()); err != nil {
		t.Fatal(err)
	}
	if err := supervisorpkg.WriteResult(l, supervisorpkg.Result{Version: buildinfo.Version, FromVersion: "0.0.0~alpha.1",
		Outcome: protocol.SupervisorOutcomeRolledBack, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	a.reportSupervisorUpgrade()
	ticks(t, a, nil, 3)
}

// TestIntegrityBaselineReset (plan M5a R14, T15): a fresh device is established silently; a deleted baseline on an
// established device is reported once as baseline_reset.
func TestIntegrityBaselineReset(t *testing.T) {
	g := testgw.New(t)
	a := withIntegrity(t, newAgent(t, g))
	ticks(t, a, g, 1)
	if a.st.IntegrityEstablishedAt == nil {
		t.Fatal("not established after the first pass")
	}
	if err := os.Remove(a.d.Layout.Integrity()); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		a.tickIntegrity(context.Background())
	}
	var reasons []string
	for _, e := range append(spooled(t, a), eventsOf(g, protocol.EventTamperProtectedFileChanged)...) {
		if e.Type == protocol.EventTamperProtectedFileChanged {
			d := eventData(t, e)
			reasons = append(reasons, d["file"].(string)+"#"+d["reason"].(string))
		}
	}
	if want := "/var/lib/paddock/state/integrity.json#" + protocol.TamperReasonBaselineReset; !slices.Equal(reasons, []string{want}) {
		t.Fatalf("reported %v", reasons)
	}
}

// TestIntegritySuspensionInState (plan M5a R15.3, T17): the suspensions are saved to state.json and a restarted agent
// continues them.
func TestIntegritySuspensionInState(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	now := time.Now()
	a.d.Now = func() time.Time { return now }
	a = withIntegrity(t, a)
	ticks(t, a, g, 1)
	writeFile(t, a.d.Layout.Probation(), "{}")
	ticks(t, a, g, 1)
	now = now.Add(a.d.Config.DriftInterval)
	s, err := state.Load(a.d.Layout.State())
	if err != nil || s.IntegritySuspended["slots"].File != "/var/lib/paddock/state/probation.json" {
		t.Fatalf("saved %v, %v", s.IntegritySuspended, err)
	}
	b := withIntegrity(t, a)
	b.st = s
	ticks(t, b, g, 1)
	if s := b.st.IntegritySuspended["slots"]; s.Observed == 0 {
		t.Fatalf("the restarted agent started the suspension anew: %+v", s)
	}
}

// TestIntegrityIntervalCapped (plan M5a R15.5, T18): a drift interval above an hour runs the check hourly with one
// Warn, and a pass runs at agent start.
func TestIntegrityIntervalCapped(t *testing.T) {
	if got := integrity.Interval(365 * 24 * time.Hour); got != time.Hour {
		t.Fatalf("interval %v", got)
	}
	g := testgw.New(t)
	g.Checkin.NextCheckinS = 3600
	a := newAgent(t, g)
	a.d.Config.DriftInterval = 24 * time.Hour
	a = withIntegrity(t, a)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	if got := a.integrityInterval(); got != time.Hour || !strings.Contains(logs.String(), "level=WARN") {
		slog.SetDefault(prev)
		t.Fatalf("interval %v, log %q", got, logs.String())
	}
	slog.SetDefault(prev)
	a.d.Config.DriftInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitWithin(t, servedAtOnce, func() bool {
		_, err := os.Stat(a.d.Layout.Integrity())
		return err == nil
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// unreadableOnce makes a device file unreadable until the returned func restores it; root reads it anyway.
func unreadableOnce(t *testing.T, path string) func() {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIntegrityHooksReturnReadErrors (plan M5a R15.1, T21): a hook that cannot read a file fails, so the flow waits for
// it or defers the file, and nothing is reported afterwards.
func TestIntegrityHooksReturnReadErrors(t *testing.T) {
	t.Run("UpdateResult", func(t *testing.T) {
		g := testgw.New(t)
		a := newAgent(t, g)
		a = withIntegrity(t, a)
		a.d.Supervisor = func() (int, error) { return 1, nil }
		a.d.Signal = func(int) error { return nil }
		ticks(t, a, g, 1)
		updatedTo(t, a, g, "9.1.0", "B", time.Now().UTC())
		restore := unreadableOnce(t, filepath.Join(a.d.Layout.Slots(), "B", "paddockd"))
		a.reportUpdate()
		restore()
		if a.st.ReportedUpdateAt != nil || updateEvents(t, a) != 0 {
			t.Fatal("reported without moving the baseline")
		}
		a.reportUpdate()
		if a.st.ReportedUpdateAt == nil || updateEvents(t, a) != 1 {
			t.Fatal("not reported at the next tick")
		}
		ticks(t, a, g, 3)
	})
	t.Run("RecordSupervisorPre and SupervisorResult", func(t *testing.T) {
		a, _, launched := supervisorAgent(t, "")
		a = withIntegrity(t, a, supervisorpkg.Package)
		l := a.d.Layout
		install := func(content string) {
			var sums strings.Builder
			for _, f := range []string{supervisorpkg.Binary, supervisorpkg.UnitFile} {
				writeFile(t, l.Join(f), content+f)
				sum := md5.Sum([]byte(content + f)) //nolint:gosec // dpkg's format
				sums.WriteString(hex.EncodeToString(sum[:]) + "  " + strings.TrimPrefix(f, "/") + "\n")
			}
			writeFile(t, l.Join("/var/lib/dpkg/info/paddock-supervisor.md5sums"), sums.String())
		}
		install("v1")
		ticks(t, a, nil, 1)
		restore := unreadableOnce(t, l.Join(supervisorpkg.Binary))
		a.handleSupervisorPackage(context.Background())
		restore()
		a.handleSupervisorPackage(context.Background())
		if len(*launched) != 1 {
			t.Fatalf("launched %v", *launched)
		}
		install("v2")
		writeFile(t, l.Join(supervisorpkg.Binary), "v1"+supervisorpkg.Binary)
		writeFile(t, l.Join(supervisorpkg.UnitFile), "v1"+supervisorpkg.UnitFile)
		if err := os.Remove(l.SupervisorUpgrade()); err != nil {
			t.Fatal(err)
		}
		if err := supervisorpkg.WriteResult(l, supervisorpkg.Result{Version: buildinfo.Version, FromVersion: "0.0.0~alpha.1",
			Outcome: protocol.SupervisorOutcomeRolledBack, At: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		restore = unreadableOnce(t, l.Join(supervisorpkg.UnitFile))
		a.reportSupervisorUpgrade()
		restore()
		if a.st.ReportedSupervisorUpgradeAt != nil {
			t.Fatal("processed without the exception")
		}
		a.reportSupervisorUpgrade()
		ticks(t, a, nil, 3)
	})
	t.Run("SyncFiles", func(t *testing.T) {
		a := preparedIntegrity(t)
		writeFile(t, a.d.Layout.DiskSetupConfig(), `{"written":"by Paddock"}`)
		restore := unreadableOnce(t, a.d.Layout.DiskSetupConfig())
		a.syncIntegrity(a.d.Layout.DiskSetupConfig())
		restore()
		ticks(t, a, nil, 3)
	})
}
