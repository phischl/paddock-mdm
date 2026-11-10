package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// NSSShieldMarker records a hold that is not finished: himmelblaud was stopped by a Paddock process (the agent or
// `paddockd updates run`) and not yet started again, or starting it failed. While it exists the hold is Paddock's own,
// never tampering; the agent finishes it when no process holds the shield lock any more (decisions §45, §47).
const NSSShieldMarker = "/var/lib/paddock/state/nss-shield.json"

// NSSShieldReport is the JSON array of the login.nss_shield records of `paddockd updates run`, which has no event
// spool; the agent emits and removes them (plan M5a N6.4). It keeps at most nssShieldMaxRecords, the oldest dropped.
const NSSShieldReport = "/var/lib/paddock/state/nss-shield-report.json"

const nssShieldMaxRecords = 16

// NSSShieldLock is the lock file whose exclusive flock a hold keeps from before its check of the daemon until its
// marker is gone, across the agent and `paddockd updates run` (plan M5a N6.2): the lock, not the marker, says that a
// hold is in progress.
const NSSShieldLock = "/var/lib/paddock/state/nss-shield.lock"

// DpkgFrontendLock is dpkg's frontend lock: a process that holds it is running a package operation.
const DpkgFrontendLock = "/var/lib/dpkg/lock-frontend"

// NSSShieldTimer is the transient systemd timer that starts himmelblaud when no Paddock process does: the safety net
// that does not depend on the agent (decisions §45).
const NSSShieldTimer = "paddock-nss-shield-restore"

// Hold times of the agent's shield. A hold that reaches NSSShieldMaxHold ends while the transaction still runs; the
// safety timer fires NSSShieldTimerGrace later, so that normally the holder restores first and the timer is cancelled.
// NSSShieldLockWait bounds the wait for the dpkg frontend lock before a hold and the wait of a restart for a hold;
// NSSShieldHoldWait the wait of a transaction for another hold, which lasts as long as that transaction at most.
const (
	NSSShieldMaxHold    = 10 * time.Minute
	NSSShieldTimerGrace = 2 * time.Minute
	NSSShieldLockWait   = 2 * time.Minute
	NSSShieldHoldWait   = PackageTimeout
)

// ErrNSSShieldBusy is a transaction not started because another package operation held the dpkg lock past LockWait or
// another hold the shield lock past HoldWait: himmelblaud is not stopped behind it, and the caller retries later.
var ErrNSSShieldBusy = errors.New("another package operation is running; himmelblaud not held")

// nssShieldBusyOutput is the output of a transaction ErrNSSShieldBusy skipped, in apt's words, so that callers that
// read apt's output see a held dpkg lock (pending/dpkg_locked).
const nssShieldBusyOutput = "E: Could not get lock " + DpkgFrontendLock + ": another package operation is running " +
	"(Paddock does not stop himmelblaud behind it)\n"

// nssShieldUnit is the daemon whose NSS answers the shield suppresses; restore starts the tasks daemon with it
// because systemd may stop it along with the daemon.
var nssShieldUnit = himmelblauUnits[0]

// shieldRestoreTimeout bounds the restore, which runs on a context of its own: a cancelled transaction still
// restores.
const shieldRestoreTimeout = 2 * time.Minute

// shieldPoll is the interval of the waits for the shield lock and the dpkg lock.
const shieldPoll = 250 * time.Millisecond

// shieldSys is what the shield needs of the system.
type shieldSys interface {
	ReadFile(path string) ([]byte, fs.FileInfo, error)
	WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error
	Remove(path string) error
	Systemctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	SystemdRun(ctx context.Context, stdin []byte, args ...string) (output string, exit int, err error)
}

// NSSShield holds himmelblaud stopped around Paddock's own package transactions (PDK-983, decisions §45 and §47).
// Himmelblau 4.0.8's NSS module answers getpwnam for every unknown name with a synthetic directory user while the
// daemon runs, so adduser and useradd in a maintainer script refuse to create a system user ("already exists"). While
// the daemon is stopped, new logins and screen unlocks of directory users wait, and directory users may not resolve
// through NSS; sessions are not ended.
//
// One hold runs at a time on a device: the in-process semaphore and the flock on LockFile serialize the agent's
// transactions and those of `paddockd updates run`. A hold waits for the dpkg frontend lock before it stops the
// daemon, restores it on every path (success, error, panic, cancelled context), at the latest after MaxHold, and
// reports exactly one login.nss_shield. A transient timer started before the stop restores it if the holder dies; the
// marker lets the agent finish such a hold, and a failed restore, later.
type NSSShield struct {
	Sys    shieldSys
	Events *Events
	// MaxHold, TimerGrace, LockWait and HoldWait default to NSSShieldMaxHold, NSSShieldTimerGrace, NSSShieldLockWait
	// and NSSShieldHoldWait.
	MaxHold, TimerGrace, LockWait, HoldWait time.Duration
	// LockFile is the device path of NSSShieldLock (root included); "" serializes within the process only.
	LockFile string
	// DpkgBusy reports whether another process holds the dpkg frontend lock (FrontendLockBusy); nil: never.
	DpkgBusy func() bool
	// Now and After are the clock (nil: time.Now, time.After).
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time

	sem     chan struct{}
	semOnce sync.Once
	mu      sync.Mutex
	holding bool
}

type shieldMarker struct {
	Action    string    `json:"action"`
	StartedAt time.Time `json:"started_at"`
	PID       int       `json:"pid"`
	// Reported is set when the hold was reported (restore_failed) and only the restore is left.
	Reported bool `json:"reported,omitempty"`
}

func (s *NSSShield) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *NSSShield) after(d time.Duration) <-chan time.Time {
	if s.After != nil {
		return s.After(d)
	}
	return time.After(d)
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (s *NSSShield) maxHold() time.Duration  { return orDefault(s.MaxHold, NSSShieldMaxHold) }
func (s *NSSShield) lockWait() time.Duration { return orDefault(s.LockWait, NSSShieldLockWait) }
func (s *NSSShield) holdWait() time.Duration { return orDefault(s.HoldWait, NSSShieldHoldWait) }

// Holds reports whether unit is stopped by one of Paddock's own holds: the shield lock is taken (a hold of this or
// another process is in progress) or the marker exists (a hold whose holder died or whose restore failed, which
// Recover finishes). The login reconciler never reports such a stop as tampering (plan M5a N6.3).
func (s *NSSShield) Holds(unit string) bool {
	if s == nil || !slices.Contains(himmelblauUnits, unit) {
		return false
	}
	s.mu.Lock()
	holding := s.holding
	s.mu.Unlock()
	return holding || s.markerExists() || (s.LockFile != "" && lockTaken(s.LockFile))
}

func (s *NSSShield) markerExists() bool {
	data, _, err := s.Sys.ReadFile(NSSShieldMarker)
	return err == nil && data != nil
}

func (s *NSSShield) setHolding(v bool) {
	s.mu.Lock()
	s.holding = v
	s.mu.Unlock()
}

// acquire takes the semaphore and the shield lock within wait (both are tried at once first); ok is false when
// another hold kept them that long.
func (s *NSSShield) acquire(ctx context.Context, wait time.Duration) (release func(), ok bool, err error) {
	s.semOnce.Do(func() { s.sem = make(chan struct{}, 1) })
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	select {
	case s.sem <- struct{}{}:
	default:
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-deadline.C:
			return nil, false, nil
		}
	}
	unlock := func() {}
	if s.LockFile != "" {
		f, err := lockFile(ctx, s.LockFile, deadline.C)
		switch {
		case errors.Is(err, errLockTimeout):
			<-s.sem
			return nil, false, nil
		case err != nil && ctx.Err() != nil:
			<-s.sem
			return nil, false, ctx.Err()
		case err != nil:
			// Without the lock file, holds in this process are still serialized; another process's hold shows as an
			// inactive himmelblaud and its transaction runs without a hold of its own.
			slog.WarnContext(ctx, "shield lock unavailable; serializing within the process only", "error", err)
		default:
			unlock = func() { _ = f.Close() }
		}
	}
	return func() { unlock(); <-s.sem }, true, nil
}

// tryAcquire takes the semaphore and the shield lock if both are free now.
func (s *NSSShield) tryAcquire(ctx context.Context) (release func(), ok bool) {
	release, ok, _ = s.acquire(ctx, 0)
	return release, ok
}

// waitDpkg waits until no other process holds the dpkg frontend lock, at most LockWait.
func (s *NSSShield) waitDpkg(ctx context.Context) (bool, error) {
	if s.DpkgBusy == nil {
		return true, nil
	}
	deadline := time.Now().Add(s.lockWait())
	for s.DpkgBusy() {
		if !time.Now().Before(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(shieldPoll):
		}
	}
	return true, nil
}

// Run runs one package transaction. While himmelblaud is active, it is held stopped around run; otherwise run runs
// as it is (a device without Himmelblau, or with the daemon down for another reason, which the shield never starts).
// When another package operation keeps the dpkg lock or another hold keeps the shield lock past LockWait, run does not
// run: the result is apt's lock message with ErrNSSShieldBusy.
func (s *NSSShield) Run(ctx context.Context, action string, run func() (string, int, error)) (string, int, error) {
	if s == nil {
		return run()
	}
	release, ok, err := s.acquire(ctx, s.holdWait())
	if err != nil {
		return "", -1, err
	}
	if !ok {
		slog.WarnContext(ctx, "another himmelblaud hold outlasted the wait; transaction deferred", "action", action)
		return nssShieldBusyOutput, 100, ErrNSSShieldBusy
	}
	defer release()
	// A marker under the lock is a hold whose holder died: it is finished and reported before a new hold writes its
	// own marker over it (plan M5a N4); `paddockd updates run` never calls Recover.
	s.finishStale(ctx)

	if out, _, err := s.Sys.Systemctl(ctx, "is-active", nssShieldUnit); err != nil || firstLine(out) != "active" {
		return run()
	}
	if free, err := s.waitDpkg(ctx); err != nil {
		return "", -1, err
	} else if !free {
		slog.WarnContext(ctx, "the dpkg lock stays held; transaction deferred without stopping himmelblaud", "action", action)
		return nssShieldBusyOutput, 100, ErrNSSShieldBusy
	}
	start := s.now()
	if err := s.hold(ctx, action, start); err != nil {
		slog.ErrorContext(ctx, "himmelblaud not held for a package transaction", "action", action, "error", err)
		s.report(action, 0, protocol.NSSShieldHoldFailed, err)
		return run()
	}

	var (
		once       sync.Once
		outcome    string
		restoreErr error
	)
	restore := func(o string) {
		once.Do(func() {
			outcome = o
			restoreErr = s.restore(ctx)
		})
	}
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-done:
		case <-s.after(s.maxHold()):
			slog.WarnContext(ctx, "package transaction outlasted the maximum hold; starting himmelblaud while it runs",
				"action", action, "max_hold", s.maxHold())
			restore(protocol.NSSShieldMaxHold)
		}
	}()
	// Deferred, so that a panic in run restores the daemon and reports the hold before it unwinds further.
	defer func() {
		close(done)
		<-exited
		restore(protocol.NSSShieldRestored)
		if restoreErr != nil {
			outcome = protocol.NSSShieldRestoreFailed
		}
		s.report(action, s.now().Sub(start), outcome, restoreErr)
		s.settle(shieldMarker{Action: action, StartedAt: start.UTC(), PID: os.Getpid()}, restoreErr)
	}()
	return run()
}

// hold arms the safety net and stops himmelblaud: marker first, then the timer, then the stop, so that every state
// a crash can leave behind is restored by the timer or by the agent. A step that fails undoes the earlier ones.
func (s *NSSShield) hold(ctx context.Context, action string, start time.Time) error {
	m := shieldMarker{Action: action, StartedAt: start.UTC(), PID: os.Getpid()}
	if err := s.writeMarker(m); err != nil {
		return err
	}
	s.cancelTimer(ctx)
	delay := strconv.FormatInt(int64((s.maxHold()+orDefault(s.TimerGrace, NSSShieldTimerGrace))/time.Second), 10) + "s"
	if out, exit, err := s.Sys.SystemdRun(ctx, nil, "--unit="+NSSShieldTimer, "--on-active="+delay,
		"--timer-property=AccuracySec=1s", "--description=Paddock: start himmelblaud after a package transaction",
		"/usr/bin/systemctl", "start", himmelblauUnits[0], himmelblauUnits[1]); err != nil || exit != 0 {
		return errors.Join(commandError("arm the safety timer", out, exit, err), s.Sys.Remove(NSSShieldMarker))
	}
	s.setHolding(true)
	if out, exit, err := s.Sys.Systemctl(ctx, "stop", nssShieldUnit); err != nil || exit != 0 {
		stopErr := commandError("stop "+nssShieldUnit, out, exit, err)
		if restoreErr := s.restore(ctx); restoreErr != nil {
			// The marker stays, so that the agent retries the start; Run reports this hold as hold_failed, so the
			// retry does not report it again.
			m.Reported = true
			return errors.Join(stopErr, restoreErr, s.writeMarker(m))
		}
		return errors.Join(stopErr, s.Sys.Remove(NSSShieldMarker))
	}
	return nil
}

func (s *NSSShield) writeMarker(m shieldMarker) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode the shield marker: %w", err)
	}
	if err := s.Sys.WriteFileAtomic(NSSShieldMarker, data, 0o600, 0, 0); err != nil {
		return fmt.Errorf("write the shield marker: %w", err)
	}
	return nil
}

// settle ends a reported hold: the marker goes when the daemon runs again, and stays as reported when it does not, so
// that the agent retries the start without reporting the hold again.
func (s *NSSShield) settle(m shieldMarker, restoreErr error) {
	if restoreErr == nil {
		if err := s.Sys.Remove(NSSShieldMarker); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Error("removing the shield marker failed", "error", err)
		}
		return
	}
	m.Reported = true
	if err := s.writeMarker(m); err != nil {
		slog.Error("keeping the shield marker failed", "error", err)
	}
}

// restore starts the Himmelblau daemons again and, when they started, cancels the safety timer; when they did not,
// the timer stays armed and retries.
func (s *NSSShield) restore(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shieldRestoreTimeout)
	defer cancel()
	defer s.setHolding(false)
	var errs []error
	for _, u := range himmelblauUnits {
		if out, exit, err := s.Sys.Systemctl(ctx, "start", u); err != nil || exit != 0 {
			errs = append(errs, commandError("start "+u, out, exit, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.cancelTimer(ctx)
	return nil
}

// commandError describes a failed command: its error, or its exit status and first output line.
func commandError(what, out string, exit int, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s: exit %d: %s", what, exit, firstLine(out))
}

// cancelTimer stops the safety timer and forgets its units; a timer that does not exist is no error.
func (s *NSSShield) cancelTimer(ctx context.Context) {
	for _, u := range []string{NSSShieldTimer + ".timer", NSSShieldTimer + ".service"} {
		_, _, _ = s.Sys.Systemctl(ctx, "stop", u)
		_, _, _ = s.Sys.Systemctl(ctx, "reset-failed", u)
	}
}

// report emits the one login.nss_shield of a hold.
func (s *NSSShield) report(action string, held time.Duration, outcome string, err error) {
	ev := protocol.LoginNSSShield{Action: action, DurationS: int64(held.Round(time.Second) / time.Second), Outcome: outcome}
	if err != nil {
		ev.Error = err.Error()
		slog.Error("himmelblaud shield", "action", action, "outcome", outcome, "held", held, "error", err)
	} else {
		slog.Info("himmelblaud shield", "action", action, "outcome", outcome, "held", held)
	}
	s.Events.emit(protocol.EventLoginNSSShield, ev)
}

// Pending reports whether Recover has work: records of `paddockd updates run`, or a marker while no process holds the
// shield lock.
func (s *NSSShield) Pending(ctx context.Context) bool {
	if s == nil {
		return false
	}
	if data, _, err := s.Sys.ReadFile(NSSShieldReport); err == nil && data != nil {
		return true
	}
	if !s.markerExists() {
		return false
	}
	release, ok := s.tryAcquire(ctx)
	if ok {
		release()
	}
	return ok
}

// Recover finishes what no hold in progress owns, under the shield lock taken without waiting (plan M5a N3.2, N6.3):
// a taken lock means a hold of this or another process is in progress, and nothing is touched. A marker is a hold
// whose holder died, or whose start failed: the Himmelblau daemons are started (the safety timer may have done so),
// the hold is reported once (recovered, or restore_failed while the start fails) and the marker is kept until the
// start succeeds. Then the records of `paddockd updates run` are emitted and removed. Without a marker a stopped
// himmelblaud is left alone: the login reconciler reports it as tampering.
func (s *NSSShield) Recover(ctx context.Context) {
	if s == nil {
		return
	}
	release, ok := s.tryAcquire(ctx)
	if !ok {
		return
	}
	defer release()
	s.finishStale(ctx)
	s.sendRecords(ctx)
}

func (s *NSSShield) finishStale(ctx context.Context) {
	data, _, err := s.Sys.ReadFile(NSSShieldMarker)
	switch {
	case errors.Is(err, fs.ErrNotExist) || (err == nil && data == nil):
		return
	case err != nil:
		slog.WarnContext(ctx, "reading the shield marker failed", "error", err)
		return
	}
	var m shieldMarker
	if err := json.Unmarshal(data, &m); err != nil {
		slog.WarnContext(ctx, "unreadable shield marker; restoring himmelblaud", "error", err)
	}
	held := time.Duration(0)
	if !m.StartedAt.IsZero() {
		held = max(s.now().Sub(m.StartedAt), 0)
	}
	restoreErr := s.restore(ctx)
	switch {
	case restoreErr == nil && !m.Reported:
		s.report(m.Action, held, protocol.NSSShieldRecovered, nil)
	case restoreErr == nil:
		slog.InfoContext(ctx, "himmelblaud started after a failed restore", "action", m.Action)
	case !m.Reported:
		s.report(m.Action, held, protocol.NSSShieldRestoreFailed, restoreErr)
	default:
		slog.WarnContext(ctx, "starting himmelblaud still fails", "action", m.Action, "error", restoreErr)
	}
	s.settle(m, restoreErr)
}

// readRecords returns the records of NSSShieldReport; a missing file has none.
func (s *NSSShield) readRecords() ([]protocol.LoginNSSShield, error) {
	data, _, err := s.Sys.ReadFile(NSSShieldReport)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && data == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", NSSShieldReport, err)
	}
	var records []protocol.LoginNSSShield
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode %s: %w", NSSShieldReport, err)
	}
	return records, nil
}

// sendRecords emits the records of `paddockd updates run` as login.nss_shield and removes the file.
func (s *NSSShield) sendRecords(ctx context.Context) {
	records, err := s.readRecords()
	if err != nil {
		slog.WarnContext(ctx, "dropping unreadable shield records", "error", err)
	}
	if n := len(records) - nssShieldMaxRecords; n > 0 {
		slog.WarnContext(ctx, "dropping the oldest shield records", "dropped", n)
		records = records[n:]
	}
	for _, r := range records {
		s.Events.emit(protocol.EventLoginNSSShield, r)
	}
	if rmErr := s.Sys.Remove(NSSShieldReport); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		slog.WarnContext(ctx, "removing the shield records failed", "error", rmErr)
	}
}

// NSSShieldRecorder returns the Events of `paddockd updates run`, which has no event spool: each login.nss_shield is
// appended to NSSShieldReport (under the shield lock, which the hold keeps while it reports) for the agent to emit.
func NSSShieldRecorder(sys shieldSys) *Events {
	shield := &NSSShield{Sys: sys}
	return &Events{Emit: func(typ string, data any) {
		ev, ok := data.(protocol.LoginNSSShield)
		if !ok {
			return
		}
		records, err := shield.readRecords()
		if err != nil {
			slog.Error("replacing unreadable shield records", "error", err)
		}
		records = append(records, ev)
		records = records[max(len(records)-nssShieldMaxRecords, 0):]
		b, err := json.Marshal(records)
		if err == nil {
			err = sys.WriteFileAtomic(NSSShieldReport, b, 0o600, 0, 0)
		}
		if err != nil {
			slog.Error("storing the shield record failed", "type", typ, "error", err)
		}
	}}
}

// Exclusive runs fn while no hold runs, waiting at most LockWait; ran is false when a hold kept the lock that long.
// The login reconciler restarts himmelblaud this way, so that a restart never cuts into a hold.
func (s *NSSShield) Exclusive(ctx context.Context, fn func() error) (ran bool, err error) {
	if s == nil {
		return true, fn()
	}
	release, ok, err := s.acquire(ctx, s.lockWait())
	if err != nil || !ok {
		return false, err
	}
	defer release()
	return true, fn()
}

// aptTransactionVerbs are the apt-get commands that run dpkg; everything else (update, download, a simulation) runs
// without the shield.
var aptTransactionVerbs = []string{"install", "reinstall", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade",
	"autoremove", "autopurge"}

// aptNoAct are the apt-get options that make a command change nothing.
var aptNoAct = []string{"-s", "--simulate", "--just-print", "--dry-run", "--recon", "--no-act", "-d", "--download-only"}

// dpkgTransactionActions are the dpkg actions that run maintainer scripts.
var dpkgTransactionActions = []string{"-i", "--install", "--unpack", "--configure", "-r", "--remove", "-P", "--purge",
	"--triggers-only"}

// AptTransaction returns the action of an apt-get call that changes packages, "" for one that does not.
func AptTransaction(args []string) string {
	if slices.ContainsFunc(args, func(a string) bool { return slices.Contains(aptNoAct, a) }) {
		return ""
	}
	for _, a := range args {
		if slices.Contains(aptTransactionVerbs, a) {
			return "apt-get " + a
		}
	}
	return ""
}

// DpkgTransaction returns the action of a dpkg call that runs maintainer scripts, "" for a query.
func DpkgTransaction(args []string) string {
	for _, a := range args {
		if slices.Contains(dpkgTransactionActions, a) {
			return "dpkg " + a
		}
	}
	return ""
}

// Shielded is a System whose package transactions run under an NSSShield; every other call goes to the System as
// it is.
type Shielded struct {
	System
	Shield *NSSShield
}

// AptGet implements System.
func (s Shielded) AptGet(ctx context.Context, args ...string) (string, int, error) {
	action := AptTransaction(args)
	if action == "" {
		return s.System.AptGet(ctx, args...)
	}
	return s.Shield.Run(ctx, action, func() (string, int, error) { return s.System.AptGet(ctx, args...) })
}

// Dpkg implements System.
func (s Shielded) Dpkg(ctx context.Context, args ...string) (string, int, error) {
	action := DpkgTransaction(args)
	if action == "" {
		return s.System.Dpkg(ctx, args...)
	}
	return s.Shield.Run(ctx, action, func() (string, int, error) { return s.System.Dpkg(ctx, args...) })
}
