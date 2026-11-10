package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// NSSShieldMarker records a hold in progress: himmelblaud was stopped by the agent and not yet started again. The
// agent's next start finds it after a crash and restores the daemon (decisions §45).
const NSSShieldMarker = "/var/lib/paddock/state/nss-shield.json"

// NSSShieldTimer is the transient systemd timer that starts himmelblaud when the agent does not: the safety net that
// does not depend on the agent (decisions §45).
const NSSShieldTimer = "paddock-nss-shield-restore"

// Hold times of the shield. A hold that reaches NSSShieldMaxHold ends while the transaction still runs; the safety
// timer fires NSSShieldTimerGrace later, so that normally the agent restores first and the timer is cancelled.
const (
	NSSShieldMaxHold    = 10 * time.Minute
	NSSShieldTimerGrace = 2 * time.Minute
)

// nssShieldUnit is the daemon whose NSS answers the shield suppresses; restore starts the tasks daemon with it
// because systemd may stop it along with the daemon.
var nssShieldUnit = himmelblauUnits[0]

// shieldRestoreTimeout bounds the restore, which runs on a context of its own: a cancelled transaction still
// restores.
const shieldRestoreTimeout = 2 * time.Minute

// shieldSys is what the shield needs of the system.
type shieldSys interface {
	ReadFile(path string) ([]byte, fs.FileInfo, error)
	WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error
	Remove(path string) error
	Systemctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	SystemdRun(ctx context.Context, stdin []byte, args ...string) (output string, exit int, err error)
}

// NSSShield holds himmelblaud stopped around the agent's own package transactions (PDK-983, decisions §45).
// Himmelblau 4.0.8's NSS module answers getpwnam for every unknown name with a synthetic directory user while the
// daemon runs, so adduser and useradd in a maintainer script refuse to create a system user ("already exists"). With
// the daemon stopped, NSS falls back to Himmelblau's cache and running sessions continue; new logins and screen
// unlocks wait until the daemon is back.
//
// One transaction is held at a time. Every hold restores the daemon on every path (success, error, panic, cancelled
// context), at the latest after MaxHold, and reports exactly one login.nss_shield. A transient timer started before
// the stop restores it if the agent dies; the marker lets the next agent start report and finish such a hold.
type NSSShield struct {
	Sys    shieldSys
	Events *Events
	// MaxHold and TimerGrace default to NSSShieldMaxHold and NSSShieldTimerGrace.
	MaxHold, TimerGrace time.Duration
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

func (s *NSSShield) maxHold() time.Duration {
	if s.MaxHold > 0 {
		return s.MaxHold
	}
	return NSSShieldMaxHold
}

func (s *NSSShield) timerGrace() time.Duration {
	if s.TimerGrace > 0 {
		return s.TimerGrace
	}
	return NSSShieldTimerGrace
}

// Holds reports whether unit is stopped by a hold in progress, so that the login reconciler does not report it as
// tampering.
func (s *NSSShield) Holds(unit string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holding && slices.Contains(himmelblauUnits, unit)
}

func (s *NSSShield) setHolding(v bool) {
	s.mu.Lock()
	s.holding = v
	s.mu.Unlock()
}

// Run runs one package transaction. While himmelblaud is active, it is held stopped around run; otherwise run runs
// as it is (a device without Himmelblau, or with the daemon down for another reason, which the shield never starts).
func (s *NSSShield) Run(ctx context.Context, action string, run func() (string, int, error)) (string, int, error) {
	if s == nil {
		return run()
	}
	s.semOnce.Do(func() { s.sem = make(chan struct{}, 1) })
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return "", -1, ctx.Err()
	}
	defer func() { <-s.sem }()

	if out, _, err := s.Sys.Systemctl(ctx, "is-active", nssShieldUnit); err != nil || firstLine(out) != "active" {
		return run()
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
	}()
	return run()
}

// hold arms the safety net and stops himmelblaud: marker first, then the timer, then the stop, so that every state
// a crash can leave behind is restored by the timer or by the next agent start. A step that fails undoes the earlier
// ones.
func (s *NSSShield) hold(ctx context.Context, action string, start time.Time) error {
	marker, err := json.Marshal(shieldMarker{Action: action, StartedAt: start.UTC()})
	if err != nil {
		return fmt.Errorf("encode the shield marker: %w", err)
	}
	if err := s.Sys.WriteFileAtomic(NSSShieldMarker, marker, 0o600, 0, 0); err != nil {
		return fmt.Errorf("write the shield marker: %w", err)
	}
	s.cancelTimer(ctx)
	delay := strconv.FormatInt(int64((s.maxHold()+s.timerGrace())/time.Second), 10) + "s"
	if out, exit, err := s.Sys.SystemdRun(ctx, nil, "--unit="+NSSShieldTimer, "--on-active="+delay,
		"--timer-property=AccuracySec=1s", "--description=Paddock: start himmelblaud after a package transaction",
		"/usr/bin/systemctl", "start", himmelblauUnits[0], himmelblauUnits[1]); err != nil || exit != 0 {
		return errors.Join(commandError("arm the safety timer", out, exit, err), s.Sys.Remove(NSSShieldMarker))
	}
	s.setHolding(true)
	if out, exit, err := s.Sys.Systemctl(ctx, "stop", nssShieldUnit); err != nil || exit != 0 {
		return errors.Join(commandError("stop "+nssShieldUnit, out, exit, err), s.restore(ctx), s.Sys.Remove(NSSShieldMarker))
	}
	return nil
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

// report emits the one login.nss_shield of a hold and removes its marker.
func (s *NSSShield) report(action string, held time.Duration, outcome string, err error) {
	ev := protocol.LoginNSSShield{Action: action, DurationS: int64(held.Round(time.Second) / time.Second), Outcome: outcome}
	if err != nil {
		ev.Error = err.Error()
		slog.Error("himmelblaud shield", "action", action, "outcome", outcome, "held", held, "error", err)
	} else {
		slog.Info("himmelblaud shield", "action", action, "outcome", outcome, "held", held)
	}
	s.Events.emit(protocol.EventLoginNSSShield, ev)
	if rmErr := s.Sys.Remove(NSSShieldMarker); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		slog.Error("removing the shield marker failed", "error", rmErr)
	}
}

// Recover finishes a hold the agent did not end itself (it died during a transaction): it starts the Himmelblau
// daemons, which the safety timer may already have done, and reports the hold. Only a hold of the agent's own is
// restored: without the marker, a stopped himmelblaud is left alone and reported by the watch.
func (s *NSSShield) Recover(ctx context.Context) {
	if s == nil {
		return
	}
	data, _, err := s.Sys.ReadFile(NSSShieldMarker)
	if err != nil || data == nil {
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
	outcome := protocol.NSSShieldRecovered
	restoreErr := s.restore(ctx)
	if restoreErr != nil {
		outcome = protocol.NSSShieldRestoreFailed
	}
	s.report(m.Action, held, outcome, restoreErr)
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

// aptTransaction returns the action of an apt-get call that changes packages, "" for one that does not.
func aptTransaction(args []string) string {
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

// dpkgTransaction returns the action of a dpkg call that runs maintainer scripts, "" for a query.
func dpkgTransaction(args []string) string {
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
	action := aptTransaction(args)
	if action == "" {
		return s.System.AptGet(ctx, args...)
	}
	return s.Shield.Run(ctx, action, func() (string, int, error) { return s.System.AptGet(ctx, args...) })
}

// Dpkg implements System.
func (s Shielded) Dpkg(ctx context.Context, args ...string) (string, int, error) {
	action := dpkgTransaction(args)
	if action == "" {
		return s.System.Dpkg(ctx, args...)
	}
	return s.Shield.Run(ctx, action, func() (string, int, error) { return s.System.Dpkg(ctx, args...) })
}
