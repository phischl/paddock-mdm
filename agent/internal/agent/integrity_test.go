package agent

import (
	"context"
	"crypto/md5" //nolint:gosec // the md5sums of the fake dpkg database
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
