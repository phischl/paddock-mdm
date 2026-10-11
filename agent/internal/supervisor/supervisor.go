// Package supervisor is paddock-supervisor (plan M2b decisions 15 and 16, design contract 1–5): it runs
// /opt/paddock/agent/current/paddockd as its child and restarts it with back-off, and it alone installs agent
// releases: signature check with the compiled-in release key, copy into the inactive A/B slot, self-test, one
// symlink flip, probation and automatic rollback. It is deliberately small, so it never needs an update itself.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/pkg/semver"
)

// Outcomes written to update-result.json (shared contract with agent/internal/update).
const (
	outcomeUpdated          = "updated"
	outcomeSelfTestFailed   = "self_test_failed"
	outcomeRolledBack       = "rolled_back"
	outcomeSignatureInvalid = "signature_invalid"
	outcomeDowngradeRefused = "downgrade_refused"
)

// Config are the paths and timings of a supervisor.
type Config struct {
	Slots        string // directory with A, B and the symlink current
	Staging      string // staging directory with request.json and <version>/paddockd(.minisig)
	Result       string // update-result.json
	ProbationLog string // probation.json
	LastCheckin  string // touched by the agent after every check-in
	PublicKey    *minisign.PublicKey
	Probation    time.Duration
	SelfTest     time.Duration // self-test timeout
	Tick         time.Duration // watchdog and probation check interval
	MaxBackoff   time.Duration
	Notify       func(state string)     // sd_notify
	Now          func() time.Time       // clock of the probation; nil is time.Now (tests inject one)
	Sleep        func(time.Duration)    // waits between rollback flip attempts; nil is time.Sleep (tests inject one)
	SyncDir      func(dir string) error // syncs slots after a flip, staging before a drop or a result; nil is fsync (tests inject failures)
	SyncFile     func(*os.File) error   // syncs a state file before its rename and its directory after; nil is fsync (tests inject failures)
}

// rollbackAttempts bounds the attempts to flip current back to the previous slot; the waits between them double from
// rollbackRetryWait. With the waits (3.75 s), five flips and stopping the agent (up to 10 s) the blocked loop stays
// far below the systemd watchdog (WatchdogSec=60), which it cannot pet meanwhile.
const (
	rollbackAttempts  = 5
	rollbackRetryWait = 250 * time.Millisecond
)

// probation is a switch under observation; it is persisted so that a restarted supervisor resumes it.
type probation struct {
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	FromSlot    string    `json:"from_slot"`
	ToSlot      string    `json:"to_slot"`
	SwitchedAt  time.Time `json:"switched_at"`
	// RollingBack marks a rollback whose flip to FromSlot happened but is not known to be durable; its result waits.
	RollingBack bool `json:"rolling_back,omitempty"`
	// Outcome and DecidedAt are the decided result, recorded and synced before update-result.json is written. The
	// removal of the log that follows is not synced, so a log that comes back after a power loss carries the result
	// already written, and a restart writes it again unchanged instead of deciding anew (PDK-058).
	Outcome   string    `json:"outcome,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	deadline  time.Time
	exits     int
	markKept  bool // the check-in mark could not be removed, so it cannot prove a check-in of the new agent
	unsynced  bool // the switch to ToSlot is not known to be durable, so it must be confirmed before "updated"
	passed    bool // healthy at the deadline; only the confirmation of the switch is outstanding
}

type selfTest struct {
	version, slot string
	err           error
}

// Supervisor runs the agent. All fields are owned by the goroutine that calls Run.
type Supervisor struct {
	cfg       Config
	child     *exec.Cmd
	exited    chan error
	started   time.Time
	backoff   time.Duration
	restart   <-chan time.Time
	probation *probation
	// rolledBack is a rollback that waits for a durable flip back before it reports rolled_back (PDK-045).
	rolledBack *probation
	testing    bool
	tested     chan selfTest
}

// New creates a supervisor.
func New(cfg Config) *Supervisor {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	if cfg.SyncDir == nil {
		cfg.SyncDir = syncDir
	}
	if cfg.SyncFile == nil {
		cfg.SyncFile = syncFile
	}
	return &Supervisor{cfg: cfg, exited: make(chan error, 1), tested: make(chan selfTest, 1), backoff: time.Second}
}

// Run supervises the agent until ctx ends; usr1 delivers update requests from the agent. It ignores SIGHUP for the
// whole process, so every agent it starts inherits SIGHUP as ignored until the agent installs its own handler.
func (s *Supervisor) Run(ctx context.Context, usr1 <-chan os.Signal) {
	// finish asks the agent to check in with SIGHUP, also right after restartChild, before the new agent can have
	// installed a handler; with the default action that ends it. Only an inherited SIG_IGN covers the agent's whole
	// start from exec on (the Go runtime keeps it until signal.Notify); a lost request is harmless, because the agent
	// checks in at start (PDK-035).
	signal.Ignore(syscall.SIGHUP)
	s.resumeProbation()
	s.start()
	s.cfg.Notify("READY=1")
	s.resumeRequest(ctx)
	tick := time.NewTicker(s.cfg.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.stop()
			return
		case err := <-s.exited:
			s.onExit(err)
		case <-s.restart:
			s.restart = nil
			s.start()
		case <-usr1:
			s.onRequest(ctx)
		case r := <-s.tested:
			s.onSelfTest(r)
		case <-tick.C:
			// Petting the watchdog from this loop proves that the loop is responsive.
			s.cfg.Notify("WATCHDOG=1")
			s.checkProbation()
		}
	}
}

func (s *Supervisor) current() string { return filepath.Join(s.cfg.Slots, "current") }

func (s *Supervisor) start() {
	cmd := exec.Command(filepath.Join(s.current(), "paddockd"), "run") //nolint:gosec // fixed path below /opt/paddock
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	s.started = time.Now()
	if err := cmd.Start(); err != nil {
		slog.Error("starting the agent failed", "error", err)
		s.exited <- err
		return
	}
	s.child = cmd
	go func() { s.exited <- cmd.Wait() }()
}

// stop terminates the child (SIGTERM, SIGKILL after 10 s) and consumes its exit.
func (s *Supervisor) stop() {
	if s.child == nil {
		return
	}
	_ = s.child.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		_ = s.child.Process.Kill()
		<-s.exited
	}
	s.child = nil
}

func (s *Supervisor) onExit(err error) {
	s.child = nil
	slog.Warn("agent exited", "error", err)
	// A passed probation only waits for its switch to become durable; the release proved healthy and stays.
	if s.probation != nil && !s.probation.passed {
		if s.probation.exits++; s.probation.exits >= 3 {
			s.rollback("crash loop")
			return
		}
	}
	if time.Since(s.started) >= time.Minute {
		s.backoff = time.Second
	}
	slog.Info("restarting the agent", "in", s.backoff)
	s.restart = time.After(s.backoff)
	s.backoff = min(2*s.backoff, s.cfg.MaxBackoff)
}

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// onRequest verifies a staged release and starts its self-test in the inactive slot.
func (s *Supervisor) onRequest(ctx context.Context) {
	if s.testing || s.probation != nil || s.rolledBack != nil {
		slog.Warn("update request ignored: an update is in progress")
		return
	}
	var req struct{ Version string }
	data, err := os.ReadFile(filepath.Join(s.cfg.Staging, "request.json"))
	if err == nil {
		err = json.Unmarshal(data, &req)
	}
	if err != nil || !versionPattern.MatchString(req.Version) {
		slog.Error("invalid update request", "error", err, "version", req.Version)
		s.cleanup("")
		return
	}
	dir := filepath.Join(s.cfg.Staging, req.Version)
	from := s.version(s.current())
	bin, err := os.ReadFile(filepath.Join(dir, "paddockd")) //nolint:gosec // version validated above
	if err != nil || !s.verify(bin, filepath.Join(dir, "paddockd.minisig"), req.Version) {
		slog.Error("release signature invalid or not for this version and architecture; update refused", "version", req.Version, "error", err)
		s.finish(req.Version, from, outcomeSignatureInvalid)
		return
	}
	// An active agent that cannot report its version has failed; any signed release may replace it.
	if versionPattern.MatchString(from) && semver.Compare(req.Version, from) <= 0 {
		slog.Error("release is not newer than the active agent; downgrade refused", "version", req.Version, "active", from)
		s.finish(req.Version, from, outcomeDowngradeRefused)
		return
	}
	slot := s.inactiveSlot()
	if err := install(bin, filepath.Join(s.cfg.Slots, slot, "paddockd")); err != nil {
		slog.Error("installing the release into the inactive slot failed", "slot", slot, "error", err)
		s.finish(req.Version, from, outcomeSelfTestFailed)
		return
	}
	s.testing = true
	go func() {
		s.tested <- selfTest{version: req.Version, slot: slot, err: s.runSelfTest(ctx, slot, req.Version)}
	}()
}

// verify checks the signature of bin, which covers its trusted comment, and that the comment names version and this
// architecture (plan M4b.1 decision 11).
func (s *Supervisor) verify(bin []byte, sigPath, version string) bool {
	raw, err := os.ReadFile(sigPath) //nolint:gosec // path below the staging directory
	if err != nil || s.cfg.PublicKey == nil || !minisign.Verify(*s.cfg.PublicKey, bin, raw) {
		return false
	}
	var sig minisign.Signature
	if sig.UnmarshalText(raw) != nil {
		return false
	}
	v, arch, ok := releasesig.Parse(sig.TrustedComment)
	return ok && v == version && arch == runtime.GOARCH
}

// runSelfTest runs `<slot>/paddockd self-test` and checks that the binary is the requested version.
func (s *Supervisor) runSelfTest(ctx context.Context, slot, version string) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.SelfTest)
	defer cancel()
	bin := filepath.Join(s.cfg.Slots, slot, "paddockd")
	out, err := exec.CommandContext(ctx, bin, "self-test").CombinedOutput() //nolint:gosec // our slot
	if err != nil {
		return fmt.Errorf("self-test: %w: %s", err, out)
	}
	if got := s.version(filepath.Join(s.cfg.Slots, slot)); got != version {
		return fmt.Errorf("the release reports version %q, not %q", got, version)
	}
	return nil
}

// onSelfTest switches to the tested slot or reports the failure.
func (s *Supervisor) onSelfTest(r selfTest) {
	s.testing = false
	from := s.version(s.current())
	if r.err != nil {
		slog.Error("release failed its self-test; not switching", "version", r.version, "error", r.err)
		s.finish(r.version, from, outcomeSelfTestFailed)
		return
	}
	p := &probation{Version: r.version, FromVersion: from, FromSlot: s.activeSlot(), ToSlot: r.slot, SwitchedAt: s.cfg.Now()}
	err := writeJSON(s.cfg.ProbationLog, p, s.cfg.SyncFile)
	if err == nil {
		err = flip(s.cfg.Slots, r.slot, s.cfg.SyncDir)
	}
	// A failed directory sync after the rename leaves current on the new slot: the synced probation log stays, so the
	// probation runs and a restart re-checks current against it; "updated" waits until the switch is durable.
	if err != nil && s.activeSlot() != r.slot {
		slog.Error("switching slots failed", "error", err)
		_ = os.Remove(s.cfg.ProbationLog)
		s.finish(r.version, from, outcomeSelfTestFailed)
		return
	}
	if err != nil {
		slog.Warn("switched slots, but syncing the slot directory failed", "slot", r.slot, "error", err)
		p.unsynced = true
	}
	slog.Info("switched to the new agent version; probation started", "version", r.version, "slot", r.slot, "probation", s.cfg.Probation)
	p.deadline = p.SwitchedAt.Add(s.cfg.Probation)
	s.probation = p
	s.stop()
	p.markKept = s.forgetCheckin() != nil
	s.restartChild()
}

// forgetCheckin removes the check-in mark while no agent runs, so that only an agent started after the switch can set
// it again. Comparing the mark's mtime with the switch time cannot decide this: the kernel stamps files with its
// coarse clock, up to one tick behind time.Now, so a check-in right after the switch can carry an older mtime.
func (s *Supervisor) forgetCheckin() error {
	if err := os.Remove(s.cfg.LastCheckin); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("removing the check-in mark failed", "error", err)
		return fmt.Errorf("removing the check-in mark: %w", err)
	}
	return nil
}

// checkProbation ends a probation at its deadline: healthy is a running child that checked in after the switch, i.e.
// set the check-in mark that forgetCheckin removed before the child started.
func (s *Supervisor) checkProbation() {
	if s.rolledBack != nil {
		s.confirmRollback()
		return
	}
	p := s.probation
	if p == nil {
		return
	}
	if !p.passed {
		// A mark that survived the switch would pass an agent that never checks in; without proof, fail safe at once.
		if p.markKept {
			s.rollback("check-in mark could not be cleared")
			return
		}
		if s.cfg.Now().Before(p.deadline) {
			return
		}
		if _, err := os.Stat(s.cfg.LastCheckin); s.child == nil || err != nil {
			s.rollback("not healthy at the end of the probation")
			return
		}
		p.passed = true
	}
	if p.unsynced && !s.confirmFlip(p.ToSlot) {
		return
	}
	slog.Info("probation passed", "version", p.Version)
	s.probation = nil
	s.conclude(p, outcomeUpdated)
}

// rollback flips back to the previous slot and restarts the old agent. It reports rolled_back only if current then
// points at the previous slot; otherwise the new agent keeps running and the release counts as failed on this device.
// A flip back whose directory sync failed reports nothing yet: the probation log, marked RollingBack and synced, stays
// until confirmRollback has made the flip durable, so a restart after a lost flip still finds the probation.
func (s *Supervisor) rollback(reason string) {
	p := s.probation
	s.probation = nil
	slog.Error("rolling back", "version", p.Version, "to_version", p.FromVersion, "reason", reason)
	durable, err := s.flipBack(p.FromSlot)
	if err == nil && !durable {
		p.RollingBack = true
		if werr := writeJSON(s.cfg.ProbationLog, p, s.cfg.SyncFile); werr != nil {
			// The log written at the switch still names ToSlot, so a restart resumes the probation or drops it, and
			// reports nothing in either case.
			slog.Error("marking the probation log as rolling back failed", "error", werr)
		}
		s.rolledBack = p
		s.restartChild()
		slog.Warn("rolled back; the result waits until the flip back is durable", "version", p.Version, "slot", p.FromSlot)
		return
	}
	s.restartChild()
	if err != nil {
		slog.Error("rollback failed: current still points at the new agent", "version", p.Version, "active_slot", s.activeSlot(),
			"previous_slot", p.FromSlot, "attempts", rollbackAttempts, "error", err)
		s.conclude(p, outcomeSelfTestFailed)
		return
	}
	s.conclude(p, outcomeRolledBack)
}

// flipBack points current at slot, retrying with back-off. It succeeds exactly when current then points at slot: a
// failed directory sync after the rename leaves the flip done but not durable (durable false), a rename that failed
// leaves it undone. It does not retry a failed sync: on Linux an fsync after an I/O error can succeed although the
// change was lost, so only confirmFlip, a new rename followed by a successful sync, makes the flip durable.
func (s *Supervisor) flipBack(slot string) (durable bool, err error) {
	wait := rollbackRetryWait
	for attempt := 1; ; attempt++ {
		err := flip(s.cfg.Slots, slot, s.cfg.SyncDir)
		if s.activeSlot() == slot {
			if err != nil {
				slog.Warn("flipped back, but syncing the slot directory failed", "slot", slot, "error", err)
			}
			return err == nil, nil
		}
		if err == nil {
			err = fmt.Errorf("current does not point at slot %s after the flip", slot)
		}
		if attempt == rollbackAttempts {
			return false, err
		}
		slog.Warn("flipping back failed; retrying", "slot", slot, "attempt", attempt, "in", wait, "error", err)
		s.cfg.Sleep(wait)
		wait *= 2
	}
}

// confirmRollback reports a rollback once its flip back is durable.
func (s *Supervisor) confirmRollback() {
	p := s.rolledBack
	if !s.confirmFlip(p.FromSlot) {
		return
	}
	s.rolledBack = nil
	s.conclude(p, outcomeRolledBack)
}

// confirmFlip makes current -> slot durable while current already points at slot: it renames a new symlink over
// current and syncs the slot directory. The new rename is a change of its own, so a successful sync proves it durable,
// unlike a sync retried after a failure. It reports false, and leaves current alone, if that is not proven.
func (s *Supervisor) confirmFlip(slot string) bool {
	if active := s.activeSlot(); active != slot {
		slog.Error("cannot confirm the slot flip: current points elsewhere", "slot", slot, "active_slot", active)
		return false
	}
	if err := flip(s.cfg.Slots, slot, s.cfg.SyncDir); err != nil {
		slog.Warn("the slot flip is not durable yet; the update result waits", "slot", slot, "error", err)
		return false
	}
	return true
}

func (s *Supervisor) restartChild() {
	s.stop()
	s.restart = nil
	s.backoff = time.Second
	s.start()
}

// conclude ends the probation p with outcome. It records the outcome in the probation log before it reports it, so
// that the probation ends in exactly one result even if a power loss brings the removed log back (PDK-058).
func (s *Supervisor) conclude(p *probation, outcome string) {
	p.Outcome, p.DecidedAt = outcome, time.Now().UTC()
	err := writeJSON(s.cfg.ProbationLog, p, s.cfg.SyncFile)
	if err != nil {
		// The result is the device's only report of the probation, so it is written all the same; only a power loss
		// before the log's removal is durable can then let a restart decide again.
		slog.Error("recording the outcome in the probation log failed", "error", err)
	}
	s.report(p, err == nil)
}

// report writes the result of p and removes the probation log once the result is written. If writing the result
// fails and the log holds the recorded outcome (recorded), the log stays, so the next start writes the same result
// again (PDK-063). Without a recorded outcome the log is removed all the same: a failed write may still have put the
// result in place (its last step, the directory sync, follows the rename), and a log without an outcome would let the
// next start run the probation again and contradict that result; a lost result is the lesser evil. The same result
// written twice is reported once: the agent turns a result into an event once per "at" (agent.reportUpdate), and the
// server counts an outcome once per device and release.
func (s *Supervisor) report(p *probation, recorded bool) {
	if s.finishAt(p.Version, p.FromVersion, p.Outcome, p.DecidedAt) != nil && recorded {
		return
	}
	_ = os.Remove(s.cfg.ProbationLog)
}

// finish cleans the staging directory, writes the update result and asks the agent to check in (SIGHUP).
func (s *Supervisor) finish(version, from, outcome string) {
	_ = s.finishAt(version, from, outcome, time.Now().UTC())
}

// finishAt is finish with the result time at; it returns the error of writing the result. The removal of the request
// is synced before the result is written, so a power loss cannot bring the request back once its result exists: a
// restart would process it again (resumeRequest) and report the release a second time. If the sync fails, the result
// is written all the same; resumeRequest then still recognises the request by the result that names its release.
func (s *Supervisor) finishAt(version, from, outcome string, at time.Time) error {
	s.cleanup(version)
	if err := s.cfg.SyncDir(s.cfg.Staging); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("syncing the staging directory failed", "error", err)
	}
	res := map[string]any{"version": version, "from_version": from, "outcome": outcome, "at": at}
	err := writeJSON(s.cfg.Result, res, s.cfg.SyncFile)
	if err != nil {
		slog.Error("writing the update result failed", "error", err)
	}
	if s.child != nil {
		_ = s.child.Process.Signal(syscall.SIGHUP)
	}
	return err
}

func (s *Supervisor) cleanup(version string) {
	_ = os.Remove(filepath.Join(s.cfg.Staging, "request.json"))
	if version != "" {
		_ = os.RemoveAll(filepath.Join(s.cfg.Staging, version))
	}
}

// resumeProbation continues a probation that a restarted supervisor (or device) interrupted.
func (s *Supervisor) resumeProbation() {
	var p probation
	data, err := os.ReadFile(s.cfg.ProbationLog)
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, &p); err != nil {
		// Without the log's content the release and the slots are unknown, so no result could be true; the staged
		// release directory stays, because its version is unknown too.
		slog.Error("dropping an unreadable probation log", "error", err)
		s.dropProbation("")
		return
	}
	if p.Outcome != "" {
		slog.Info("the probation already ended; writing its result again", "version", p.Version, "outcome", p.Outcome)
		s.report(&p, true)
		return
	}
	if p.RollingBack && s.activeSlot() == p.FromSlot {
		s.rolledBack = &p
		slog.Info("resuming a rollback that waits for a durable flip back", "version", p.Version)
		return
	}
	// A rollback flip lost with the power leaves current on ToSlot: the probation runs again and decides anew.
	if s.activeSlot() != p.ToSlot {
		// The flip never happened, or a rollback flip back survived whose log could not be marked rolling_back; on disk
		// the two look the same. No result is reported: rolled_back for a switch lost with the power would count the
		// release as failed in the rollout and block it on this device, while without a result the agent stages the
		// release again and its next probation reports. A current on neither slot proves nothing either way.
		slog.Warn("dropping the probation log: current points at neither the new nor a rolled-back slot", "version", p.Version,
			"active_slot", s.activeSlot(), "to_slot", p.ToSlot)
		s.dropProbation(p.Version)
		return
	}
	p.RollingBack = false
	// The previous supervisor may have seen the switch's sync fail; only a confirmed flip may end in "updated".
	p.unsynced = true
	p.SwitchedAt = s.cfg.Now()
	p.deadline = p.SwitchedAt.Add(s.cfg.Probation)
	s.probation = &p
	// Rolling back here would start the old agent before Run starts the current one; checkProbation does it.
	p.markKept = s.forgetCheckin() != nil
	slog.Info("resuming probation", "version", p.Version)
}

// resumeRequest processes an update request that a restarted supervisor (or device) interrupted before the switch,
// during verification or self-test, or whose SIGUSR1 never arrived (PDK-061). Without a probation log nothing was
// reported for it yet, and the agent does not signal again while the request keeps update.Pending true, so the
// request is processed as SIGUSR1 would: signature, version and self-test are checked anew from the staged files,
// and it ends in exactly one result or a switch with its own probation. A request whose release the existing result
// already names outlived that result through a power loss; it is removed instead, because processing it again would
// report the release a second time.
func (s *Supervisor) resumeRequest(ctx context.Context) {
	if s.probation != nil || s.rolledBack != nil {
		return
	}
	var req, res struct{ Version string }
	data, err := os.ReadFile(filepath.Join(s.cfg.Staging, "request.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err == nil && json.Unmarshal(data, &req) == nil && versionPattern.MatchString(req.Version) {
		if data, err := os.ReadFile(s.cfg.Result); err == nil && json.Unmarshal(data, &res) == nil && res.Version == req.Version {
			slog.Warn("removing an update request whose result was already written", "version", req.Version)
			s.cleanup(req.Version)
			return
		}
	}
	slog.Info("processing an update request left from before the restart", "version", req.Version)
	s.onRequest(ctx)
}

// dropProbation gives up a probation that cannot be resumed. A request left behind keeps update.Pending true, so the
// agent would never stage another release (PDK-060). The removal of the request is therefore synced before the log
// is removed: a power loss can bring back the log with or without the request, never the request alone, and the next
// start drops a log that came back again. If the sync fails, the log stays for that retry.
func (s *Supervisor) dropProbation(version string) {
	s.cleanup(version)
	// A staging directory that does not exist holds no request that a power loss could bring back.
	if err := s.cfg.SyncDir(s.cfg.Staging); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("syncing the staging directory failed; the probation log stays until the next start", "error", err)
		return
	}
	_ = os.Remove(s.cfg.ProbationLog)
}

func (s *Supervisor) activeSlot() string {
	target, err := os.Readlink(s.current())
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func (s *Supervisor) inactiveSlot() string {
	if s.activeSlot() == "A" {
		return "B"
	}
	return "A"
}

// version runs `<dir>/paddockd version`.
func (s *Supervisor) version(dir string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(dir, "paddockd"), "version").Output() //nolint:gosec // our slot
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// flip points current at slot with one atomic rename of a new symlink and syncs slots with sync.
func flip(slots, slot string, sync func(string) error) error {
	tmp := filepath.Join(slots, ".current.tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(slot, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(slots, "current")); err != nil {
		return err
	}
	return sync(slots)
}

// install copies bin to path atomically (0755).
func install(bin []byte, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // slot directories are 0755
		return err
	}
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // executable
	if err != nil {
		return err
	}
	_, err = f.Write(bin)
	err = errors.Join(err, f.Sync(), f.Close())
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// writeJSON replaces path with v atomically. It syncs the content with sync before the rename: a new file renamed into
// place unsynced can come back empty after a power loss, and an empty probation log is dropped (PDK-059). It syncs the
// directory after the rename with sync as well, so an error returned at that step leaves path already replaced.
func writeJSON(path string, v any, sync func(*os.File) error) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // our own state files
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	err = errors.Join(err, sync(f), f.Close())
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirWith(filepath.Dir(path), sync)
}

func syncFile(f *os.File) error { return f.Sync() }

func syncDir(dir string) error { return syncDirWith(dir, syncFile) }

func syncDirWith(dir string, sync func(*os.File) error) error {
	d, err := os.Open(dir) //nolint:gosec // our own directories
	if err != nil {
		return err
	}
	return errors.Join(sync(d), d.Close())
}
