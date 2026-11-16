// Package integrity is the agent-side baseline of Paddock's own device components (ADR 0056, option C; plan M5a
// amendment 2026-11-16, part C): each drift pass compares the agent slots and current, the files of Paddock's dpkg
// packages and fleetd, the agent-written configuration files and the drop-ins of Paddock's units with a baseline,
// and reports each change once as device.tamper_protected_file_changed. It only reads: it never restores, stops or
// rewrites anything on the device (design contract 8), and only Paddock's own regular paths move the baseline.
package integrity

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/update"
)

// agentLink is the symlink of paddock-agent and its expected target (plan M5a C2).
const (
	agentLink   = "/usr/bin/paddockd"
	agentTarget = "/opt/paddock/agent/current/paddockd"
)

// warnEvery bounds the Warn lines per object (plan M5a C9).
const warnEvery = time.Hour

// System is what the check asks the device: systemd for the units' files and dpkg for a package's status.
type System interface {
	Systemctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Checker runs the integrity check of the drift pass. It keeps the hash cache and the Warn throttle in memory, so
// every file is hashed anew after an agent start; it is used by the agent's loop only.
type Checker struct {
	Layout paths.Layout
	Sys    System
	// DpkgBusy reports a held dpkg lock, tested with F_GETLK only: taking dpkg's locks would make apt fail.
	DpkgBusy func() bool
	Arch     string
	// Emit spools device.tamper_protected_file_changed for a device path.
	Emit  func(file string)
	Now   func() time.Time
	Sleep func(time.Duration) // between polls of integrity.lock; nil is time.Sleep

	hash   hasher
	warned map[string]time.Time
}

// New returns the check of a device.
func New(l paths.Layout, sys System) *Checker {
	frontend := reconcile.FrontendLockBusy(l.Join(reconcile.DpkgFrontendLock))
	database := reconcile.FrontendLockBusy(l.Join("/var/lib/dpkg/lock"))
	return &Checker{Layout: l, Sys: sys, Arch: runtime.GOARCH, Now: time.Now,
		DpkgBusy: func() bool { return frontend() || database() }}
}

// Pass is what the agent knows of its own flows at a pass.
type Pass struct {
	// ReportedUpdateAt and ReportedSupervisorAt are the times of the last processed update and supervisor upgrade
	// results (state.json).
	ReportedUpdateAt     *time.Time
	ReportedSupervisorAt *time.Time
	// SkipFiles are agent-written files (layout paths) a running Paddock writer may change before its sync: the
	// conversion worker writes and removes disk-setup.json minutes before it returns.
	SkipFiles []string
}

// Check runs one pass. Errors are logged and skip their object; nothing blocks longer than LockWait.
func (c *Checker) Check(ctx context.Context, p Pass) {
	if c.hash.cache == nil {
		c.hash.cache = map[string]cached{}
	}
	quiet := c.quiescent(p.ReportedUpdateAt)
	supervisorBusy := c.supervisorBusy(p.ReportedSupervisorAt)
	var changed []string
	err := newStore(c.Layout, c.Sleep).update(func(b *Baseline) {
		obs := map[string]observed{}
		var fresh []string
		if quiet {
			fresh = append(fresh, c.checkSlots(b, obs)...)
		}
		fresh = append(fresh, c.checkFiles(b, p.SkipFiles, obs)...)
		if v, err := linkValue(c.Layout, agentLink); err != nil {
			c.warn(agentLink, "reading the paddockd link failed", err)
		} else {
			obs[agentLink] = observed{value: v, expected: v == agentTarget}
		}
		c.checkPackages(ctx, b, supervisorBusy, obs)
		unitsComplete := c.checkUnits(ctx, obs)
		if len(fresh) > 0 {
			slices.Sort(fresh)
			slog.Info("integrity baseline initialized", "paths", fresh)
		}
		changed = mark(b, obs, unitsComplete)
	})
	if err != nil {
		c.warn("baseline", "the integrity check skipped this pass", err)
		return
	}
	for _, f := range changed {
		slog.Warn("a protected Paddock file changed outside Paddock", "file", f)
		if c.Emit != nil {
			c.Emit(f)
		}
	}
}

// mark applies the once-per-change rule (plan M5a C8) and returns the paths to report. A foreign unit file that is
// gone again is expected absent; its mark is dropped only when every unit was checked.
func mark(b *Baseline, obs map[string]observed, unitsComplete bool) []string {
	var changed []string
	for p, o := range obs {
		r, reported := b.Reported[p]
		switch {
		case o.expected:
			delete(b.Reported, p)
		case !reported || r != o.value:
			b.Reported[p] = o.value
			changed = append(changed, p)
		}
	}
	if unitsComplete {
		for p, r := range b.Reported {
			if _, seen := obs[p]; !seen && strings.HasPrefix(r, "present:") {
				delete(b.Reported, p)
			}
		}
	}
	slices.Sort(changed)
	return changed
}

// checkSlots observes both slots and current while the update is quiescent (plan M5a C4) and returns the paths it
// initialized. A value equal to the staged release is a result still to come: the supervisor writes the slot,
// removes the request and only then writes the result, so a pass may fall in between.
func (c *Checker) checkSlots(b *Baseline, obs map[string]observed) []string {
	s, err := c.hash.slots(c.Layout)
	if err != nil {
		c.warn("slots", "reading the agent slots failed", err)
		return nil
	}
	var fresh []string
	for p, v := range s {
		exp, ok := b.Expected[p]
		switch {
		case !ok:
			b.expect(p, v)
			fresh = append(fresh, p)
		case b.Staged != nil && (v == b.Staged.SHA256 || p == current && s[slotPath(v)] == b.Staged.SHA256):
		default:
			obs[p] = observed{value: v, expected: v == exp}
		}
	}
	return fresh
}

// checkFiles observes the agent-written configuration files (plan M5a C7) and returns the paths it initialized.
func (c *Checker) checkFiles(b *Baseline, skip []string, obs map[string]observed) []string {
	l := c.Layout
	var fresh []string
	for _, full := range []string{l.AgentConfig(), l.Trust(), l.RevokeTrust(), l.DiskSetupConfig()} {
		if slices.Contains(skip, full) {
			continue
		}
		p := devicePath(l, full)
		v, err := c.hash.value(l, p)
		if err != nil {
			c.warn(p, "hashing an agent-written file failed", err)
			continue
		}
		exp, ok := b.Expected[p]
		if !ok {
			b.expect(p, v)
			fresh = append(fresh, p)
			continue
		}
		obs[p] = observed{value: v, expected: v == exp}
	}
	return fresh
}

// quiescent reports that no agent update runs: no request, no probation, and no unprocessed result (plan M5a C4).
func (c *Checker) quiescent(reportedAt *time.Time) bool {
	if update.Pending(c.Layout) {
		return false
	}
	if _, err := os.Lstat(c.Layout.Probation()); !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	r, err := update.ReadResult(c.Layout)
	if err != nil {
		return false
	}
	return r == nil || reportedAt != nil && reportedAt.Equal(r.At)
}

// supervisorBusy reports a supervisor upgrade that runs or whose result is not processed (plan M5a C2).
func (c *Checker) supervisorBusy(reportedAt *time.Time) bool {
	if _, err := os.Lstat(c.Layout.SupervisorUpgrade()); !errors.Is(err, fs.ErrNotExist) {
		return true
	}
	r, err := supervisorpkg.ReadResult(c.Layout)
	if err != nil {
		return true
	}
	return r != nil && (reportedAt == nil || !reportedAt.Equal(r.At))
}

// warn logs an error of an object at most once per warnEvery (plan M5a C9).
func (c *Checker) warn(object, msg string, err error) {
	now := c.Now()
	if last, ok := c.warned[object]; ok && now.Sub(last) < warnEvery {
		return
	}
	if c.warned == nil {
		c.warned = map[string]time.Time{}
	}
	c.warned[object] = now
	slog.Warn(msg, "object", object, "error", err)
}
