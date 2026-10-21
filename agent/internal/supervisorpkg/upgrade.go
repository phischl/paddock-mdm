package supervisorpkg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// System is the device port of the upgrade helper (reconcile.OS on a device, fakesys in tests).
type System interface {
	ReadFile(path string) ([]byte, fs.FileInfo, error)
	WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error
	Systemctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// Dpkg runs dpkg non-interactively in a process group of its own, killed with the group after 15 minutes.
	Dpkg(ctx context.Context, args ...string) (output string, exit int, err error)
}

// Upgrader is `paddockd supervisor-upgrade`: it runs inside the transient unit, so the supervisor's restart by the
// package's postinst, which stops the agent that started it, does not stop it.
type Upgrader struct {
	Sys    System
	Layout paths.Layout
	Now    func() time.Time
	// Sleep waits d or until ctx ends.
	Sleep func(ctx context.Context, d time.Duration) error
	// Poll is the interval of the check-in wait; Wait and Hold are CheckinWait and Stable on a device.
	Poll, Wait, Hold time.Duration
}

// backups are the supervisor's files the helper copies before dpkg and restores on a rollback.
func (u *Upgrader) backups() [][2]string {
	return [][2]string{{Binary, filepath.Join(BackupDir, "paddock-supervisor")}, {UnitFile, filepath.Join(BackupDir, Service)}}
}

// Run installs the staged package deb and returns the result it wrote: updated when the agent checked in after the
// installation and the supervisor kept running; install_failed when the backup or dpkg failed (the backup is restored
// only if the supervisor is not active afterwards); rolled_back when the check-in did not come within Wait: the backup
// is copied back and the supervisor restarted. A rollback while the new supervisor ran stable and the agent's
// check-ins failed to reach the server is rolled_back_unreachable: the version is retried later (design contract 8).
func (u *Upgrader) Run(ctx context.Context, deb, from string) Result {
	version, err := VersionOf(deb)
	if err != nil {
		version = ""
	}
	r := Result{Version: version, FromVersion: from, Outcome: u.install(ctx, deb)}
	r.At = u.Now().UTC()
	if err := WriteResult(u.Layout, r); err != nil {
		slog.ErrorContext(ctx, "writing the supervisor upgrade result failed", "error", err)
	}
	if err := os.Remove(deb); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.WarnContext(ctx, "removing the supervisor package failed", "error", err)
	}
	slog.InfoContext(ctx, "supervisor upgrade finished", "version", r.Version, "from_version", r.FromVersion, "outcome", r.Outcome)
	return r
}

func (u *Upgrader) install(ctx context.Context, deb string) string {
	for _, b := range u.backups() {
		if err := u.copy(b[0], b[1]); err != nil {
			slog.ErrorContext(ctx, "backing up the supervisor failed; not installing", "error", err)
			return protocol.SupervisorOutcomeInstallFailed
		}
	}
	out, exit, err := u.Sys.Dpkg(ctx, "-i", deb)
	if err != nil || exit != 0 {
		if pid, active := u.supervisor(ctx); !active || pid == "" {
			u.restore(ctx)
		}
		if err == nil && strings.Contains(out, "locked by another process") {
			// Another package run (apt, or the in-place encryption's initrd work, plan M8e amendment 2026-10-21 item 16)
			// holds dpkg's lock: nothing was installed, the agent tries again later.
			slog.WarnContext(ctx, "dpkg is locked by another package run; the supervisor upgrade waits", "output", lastLines(out))
			return OutcomeDeferred
		}
		slog.ErrorContext(ctx, "installing the supervisor package failed", "exit", exit, "error", err, "output", lastLines(out))
		return protocol.SupervisorOutcomeInstallFailed
	}
	updated, unreachable := u.wait(ctx, u.Now())
	if updated {
		return protocol.SupervisorOutcomeUpdated
	}
	slog.ErrorContext(ctx, "the agent did not check in after the supervisor upgrade; restoring the previous supervisor",
		"server_unreachable", unreachable)
	u.restore(ctx)
	if unreachable {
		return protocol.SupervisorOutcomeRolledBackUnreachable
	}
	return protocol.SupervisorOutcomeRolledBack
}

// wait reports whether the agent checked in after installed and the supervisor then kept one PID for Hold, within
// Wait. The check-in mark holds the time of the check-in (agent.checkedIn). When it did not, unreachable reports
// whether only the server was missing: the supervisor kept one PID for Hold and the agent's check-ins after installed
// failed to reach the server.
func (u *Upgrader) wait(ctx context.Context, installed time.Time) (updated, unreachable bool) {
	deadline := installed.Add(u.Wait)
	var stablePID, supPID string
	var since, supSince time.Time
	for {
		now := u.Now()
		pid, active := u.supervisor(ctx)
		switch {
		case !active || pid == "":
			supPID = ""
		case pid != supPID:
			supPID, supSince = pid, now
		}
		switch {
		case !active || pid == "" || !u.markedAfter(u.Layout.LastCheckin(), installed):
			stablePID = ""
		case pid != stablePID:
			stablePID, since = pid, now
		case now.Sub(since) >= u.Hold:
			return true, false
		}
		if !now.Before(deadline) {
			return false, supPID != "" && now.Sub(supSince) >= u.Hold && u.markedAfter(u.Layout.LastCheckinFailed(), installed)
		}
		if err := u.Sleep(ctx, u.Poll); err != nil {
			return false, false
		}
	}
}

// markedAfter reports whether a time mark file (LastCheckin, LastCheckinFailed) holds a time after t.
func (u *Upgrader) markedAfter(file string, t time.Time) bool {
	data, err := os.ReadFile(file) //nolint:gosec // path of the agent layout
	if err != nil {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	return err == nil && at.After(t)
}

// supervisor returns the main PID of the supervisor's unit and whether it is active.
func (u *Upgrader) supervisor(ctx context.Context) (pid string, active bool) {
	out, _, err := u.Sys.Systemctl(ctx, "show", "-p", "MainPID", "-p", "ActiveState", Service)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "MainPID":
			if v != "0" {
				pid = v
			}
		case "ActiveState":
			active = v == "active"
		}
	}
	return pid, active
}

// restore copies the backup back, reloads systemd and restarts the supervisor. Every step is attempted.
func (u *Upgrader) restore(ctx context.Context) {
	for _, b := range u.backups() {
		if err := u.copy(b[1], b[0]); err != nil {
			slog.ErrorContext(ctx, "restoring the supervisor failed", "file", b[0], "error", err)
		}
	}
	for _, args := range [][]string{{"daemon-reload"}, {"restart", Service}} {
		if out, exit, err := u.Sys.Systemctl(ctx, args...); err != nil || exit != 0 {
			slog.ErrorContext(ctx, "systemctl failed", "args", args, "exit", exit, "error", err, "output", lastLines(out))
		}
	}
}

func (u *Upgrader) copy(from, to string) error {
	data, info, err := u.Sys.ReadFile(from)
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("%s is not a regular file", from)
	}
	return u.Sys.WriteFileAtomic(to, data, info.Mode().Perm(), 0, 0)
}

func lastLines(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return strings.Join(lines, "\n")
}
