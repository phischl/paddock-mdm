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
	"maps"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// agentLink is the symlink of paddock-agent and its expected target (plan M5a C2); slotsDir is the file param of a
// failed slot read (R3).
const (
	agentLink   = "/usr/bin/paddockd"
	agentTarget = "/opt/paddock/agent/current/paddockd"
	slotsDir    = "/opt/paddock/agent"
)

// warnEvery bounds the Warn lines per object (plan M5a C9).
const warnEvery = time.Hour

// System is what the check asks the device: systemd for the units' files and dpkg for a package's status.
type System interface {
	Systemctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// integrityFile is the device path of the baseline, the file param of its own causes and of a reset (plan M5a R3).
const integrityFile = "/var/lib/paddock/state/integrity.json"

// Checker runs the integrity check of the drift pass. It keeps the hash cache, the Warn throttle and the suspension
// state in memory, so every file is hashed anew after an agent start; Check is used by the agent's loop only, Defer
// by any goroutine.
type Checker struct {
	Layout paths.Layout
	Sys    System
	// DpkgBusy reports a held dpkg lock, tested with F_GETLK only: taking dpkg's locks would make apt fail.
	DpkgBusy func() bool
	Arch     string
	// Emit spools device.tamper_protected_file_changed for a device path; reason is "" for a change (plan M5a R5).
	Emit  func(file, reason string)
	Now   func() time.Time
	Sleep func(time.Duration) // between polls of integrity.lock; nil is time.Sleep

	hash          hasher
	warned        map[string]time.Time
	suspended     map[string]Suspension // nil until the first Check seeds it from Pass.Suspended
	resetReported bool

	mu       sync.Mutex
	deferred map[string]uint64 // device path → token of its latest Defer
	deferSeq uint64
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
	// Interval is the check's interval (Interval); a gap between passes counts as at most two of it (plan M5a R4).
	Interval time.Duration
	// Established is whether a pass on this device ever saved a baseline with the slots (plan M5a R14).
	Established bool
	// Suspended is the agent state's suspensions; the first Check of the process takes them (plan M5a R15.3).
	Suspended map[string]Suspension
}

// Result is what a pass hands back to the agent state.
type Result struct {
	// Established is true after a save of a baseline that holds current (plan M5a R14).
	Established bool
	// Suspended is the suspensions after the pass; the agent saves them when SuspendedChanged (R15.3).
	Suspended        map[string]Suspension
	SuspendedChanged bool
}

// Defer marks agent-written files (layout paths) whose sync failed after Paddock's own write: a later pass takes
// their observed value as the baseline instead of comparing it (plan M5a R7.1).
func (c *Checker) Defer(files ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deferred == nil {
		c.deferred = map[string]uint64{}
	}
	for _, f := range files {
		c.deferSeq++
		c.deferred[devicePath(c.Layout, f)] = c.deferSeq
	}
}

func (c *Checker) deferredNow() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.deferred)
}

// snapshot is what a pass observed without the lock (plan M5a R1).
type snapshot struct {
	slots          map[string]string   // nil: the slots are not judged in this pass
	files          map[string]string   // agent-written files
	obs            map[string]observed // judged without the baseline: the paddockd link and foreign unit files
	pkgFiles       map[string]pkgFile
	supervisorSums map[string]string // the md5sums of a completely observed supervisor package
	unitsComplete  bool
	deferred       map[string]uint64 // the deferred paths when the observation started
	applied        map[string]uint64 // the deferred paths the baseline took
	blocked        blockers
}

// Check runs one pass: it observes without integrity.lock, then classifies and saves under it, then reports
// (plan M5a R1). Errors are logged and block their object or the pass; an object blocked past its bound is reported
// once (R4, R15).
func (c *Checker) Check(ctx context.Context, p Pass) Result {
	if c.hash.cache == nil {
		c.hash.cache = map[string]cached{}
	}
	if c.suspended == nil {
		c.suspended = maps.Clone(p.Suspended)
		if c.suspended == nil {
			c.suspended = map[string]Suspension{}
		}
	}
	before := maps.Clone(c.suspended)
	now := c.Now()
	gen0 := peekGeneration(c.Layout)
	s := c.observe(ctx, p)
	var changed []string
	var raced, resetDue, established bool
	err := newStore(c.Layout, c.Sleep).update(func(b *Baseline) bool {
		if b.Generation != gen0 {
			raced = true
			return false
		}
		changed = c.classify(b, s, p.Established, now)
		resetDue, b.Reset = b.Reset != nil, nil
		b.CheckedAt = now.UTC()
		_, established = b.Expected[current]
		return true
	})
	// The baseline's blockers in the order of plan M5a R15.2: lock, read, write, raced.
	switch {
	case err == nil && raced:
		s.blocked.block(objBaseline, 3, integrityFile)
	case errors.Is(err, errBaselineWrite):
		c.warn("baseline", "the integrity check could not save this pass", err)
		s.blocked.block(objBaseline, 2, integrityFile)
	case errors.Is(err, errBaselineRead):
		c.warn("baseline", "the integrity check skipped this pass", err)
		s.blocked.block(objBaseline, 1, integrityFile)
	case err != nil:
		c.warn("baseline", "the integrity check skipped this pass", err)
		s.blocked.block(objBaseline, 0, devicePath(c.Layout, c.Layout.IntegrityLock()))
	}
	saved := err == nil && !raced
	report := c.track(s.blocked, saved, now, p.Interval)
	if saved {
		c.forgetApplied(s.applied)
		for _, f := range changed {
			slog.Warn("a protected Paddock file changed outside Paddock", "file", f)
			c.emit(f, "")
		}
	}
	if resetDue && !c.resetReported {
		c.emit(integrityFile, protocol.TamperReasonBaselineReset)
		c.resetReported = true
	}
	if saved {
		c.resetReported = false
	}
	// Objects blocked by the same file (dpkg's lock blocks every package) report it once.
	slices.Sort(report)
	for _, f := range slices.Compact(report) {
		slog.Warn("the integrity check is suspended past its bound", "file", f)
		c.emit(f, protocol.TamperReasonCheckSuspended)
	}
	return Result{Established: established && saved, Suspended: maps.Clone(c.suspended),
		SuspendedChanged: !maps.Equal(before, c.suspended)}
}

func (c *Checker) emit(file, reason string) {
	if c.Emit != nil {
		c.Emit(file, reason)
	}
}

// forgetApplied ends the deferral of the paths the saved baseline took, unless they were deferred again meanwhile.
func (c *Checker) forgetApplied(applied map[string]uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, tok := range applied {
		if c.deferred[p] == tok {
			delete(c.deferred, p)
		}
	}
}

// observe evaluates the flow conditions and hashes every checked path, without the lock (plan M5a R1).
func (c *Checker) observe(ctx context.Context, p Pass) *snapshot {
	s := &snapshot{files: map[string]string{}, obs: map[string]observed{}, pkgFiles: map[string]pkgFile{},
		deferred: c.deferredNow(), applied: map[string]uint64{}, blocked: blockers{}}
	if c.quiescent(p.ReportedUpdateAt, s.blocked) {
		if v, err := c.hash.slots(c.Layout); err != nil {
			c.warn("slots", "reading the agent slots failed", err)
			s.blocked.block(objSlots, 4, slotsDir)
		} else {
			s.slots = v
		}
	}
	c.observeFiles(p.SkipFiles, s)
	if v, err := linkValue(c.Layout, agentLink); err != nil {
		c.warn(agentLink, "reading the paddockd link failed", err)
		s.blocked.block("file:"+agentLink, 1, agentLink)
	} else {
		s.obs[agentLink] = observed{value: v, expected: v == agentTarget}
	}
	c.observePackages(ctx, s, c.supervisorBusy(p.ReportedSupervisorAt, s.blocked))
	c.observeUnits(ctx, s)
	return s
}

// classify judges the snapshot against the baseline under the lock and returns the paths to report (plan M5a R1).
func (c *Checker) classify(b *Baseline, s *snapshot, established bool, now time.Time) []string {
	obs := maps.Clone(s.obs)
	_, hadCurrent := b.Expected[current]
	var fresh []string
	// A value equal to the staged release is a result still to come: the supervisor writes the slot, removes the
	// request and only then writes the result, so a pass may fall in between (C4).
	for p, v := range s.slots {
		exp, ok := b.Expected[p]
		switch {
		case !ok:
			b.expect(p, v)
			fresh = append(fresh, p)
		case v != exp && b.Staged != nil && (v == b.Staged.SHA256 || p == current && s.slots[slotPath(v)] == b.Staged.SHA256):
			s.blocked.block(objSlots, 3, p)
		default:
			obs[p] = observed{value: v, expected: v == exp}
		}
	}
	deferred := c.deferredNow()
	for p, v := range s.files {
		exp, ok := b.Expected[p]
		if tok, isDeferred := deferred[p]; isDeferred {
			// A path deferred after the observation started is taken by a later pass, whose snapshot follows the write.
			if s.deferred[p] == tok {
				b.expect(p, v)
				s.applied[p] = tok
			}
			continue
		}
		if !ok {
			b.expect(p, v)
			fresh = append(fresh, p)
			continue
		}
		obs[p] = observed{value: v, expected: v == exp}
	}
	for p, f := range s.pkgFiles {
		obs[p] = observed{value: f.sha, expected: f.md5 == f.entry || excepted(b, p, f.entry, f.sha)}
	}
	if s.supervisorSums != nil {
		b.Exceptions = slices.DeleteFunc(b.Exceptions, func(e Exception) bool { return s.supervisorSums[e.Path] != e.MD5 })
	}
	// The slots are recorded by trust on first use on an established device: that is a reset of the baseline (R14).
	if established && !hadCurrent && b.Reset == nil && slices.Contains(fresh, current) {
		b.Reset = &Reset{Kind: "missing", At: now.UTC()}
		slog.Warn("the integrity baseline lost the agent slots; it is recorded anew")
	}
	if len(fresh) > 0 {
		slices.Sort(fresh)
		slog.Info("integrity baseline initialized", "paths", fresh)
	}
	return mark(b, obs, s.unitsComplete)
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

// observeFiles hashes the agent-written configuration files (plan M5a C7). A file a running writer owns is skipped
// and suspends its check (R3 conversion).
func (c *Checker) observeFiles(skip []string, s *snapshot) {
	l := c.Layout
	for _, full := range []string{l.AgentConfig(), l.Trust(), l.RevokeTrust(), l.DiskSetupConfig()} {
		p := devicePath(l, full)
		if slices.Contains(skip, full) {
			s.blocked.block("file:"+p, 0, p)
			continue
		}
		v, err := c.hash.value(l, p)
		if err != nil {
			c.warn(p, "hashing an agent-written file failed", err)
			s.blocked.block("file:"+p, 1, p)
			continue
		}
		s.files[p] = v
	}
}

// quiescent reports that no agent update runs: no request, no probation, and no unprocessed result (plan M5a C4).
// Each condition that holds blocks the slots (R15.2).
func (c *Checker) quiescent(reportedAt *time.Time, bl blockers) bool {
	l := c.Layout
	quiet := true
	if update.Pending(l) {
		bl.block(objSlots, 0, devicePath(l, l.UpdateRequest()))
		quiet = false
	}
	if _, err := os.Lstat(l.Probation()); !errors.Is(err, fs.ErrNotExist) {
		bl.block(objSlots, 1, devicePath(l, l.Probation()))
		quiet = false
	}
	if r, err := update.ReadResult(l); err != nil || r != nil && (reportedAt == nil || !reportedAt.Equal(r.At)) {
		bl.block(objSlots, 2, devicePath(l, l.UpdateResult()))
		quiet = false
	}
	return quiet
}

// supervisorBusy reports a supervisor upgrade that runs or whose result is not processed (plan M5a C2); each
// condition that holds blocks the supervisor package (R15.2).
func (c *Checker) supervisorBusy(reportedAt *time.Time, bl blockers) bool {
	l := c.Layout
	busy := false
	if _, err := os.Lstat(l.SupervisorUpgrade()); !errors.Is(err, fs.ErrNotExist) {
		bl.block("package:"+supervisorPackage, 0, devicePath(l, l.SupervisorUpgrade()))
		busy = true
	}
	if r, err := supervisorpkg.ReadResult(l); err != nil || r != nil && (reportedAt == nil || !reportedAt.Equal(r.At)) {
		bl.block("package:"+supervisorPackage, 1, devicePath(l, l.SupervisorUpgradeResult()))
		busy = true
	}
	return busy
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
