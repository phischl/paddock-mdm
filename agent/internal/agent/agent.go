// Package agent is the run loop of `paddockd run` (plan M2b decisions 8, 9, 11–13): periodic and event-triggered
// check-ins with back-off, bundle apply, drift correction and the event spool. It never locks, wipes, reboots or
// blocks logins; without a server it keeps the last applied bundle and keeps spooling.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/apply"
	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/enroll"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/agent/internal/localadmin"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/spool"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Deps are the dependencies of the run loop.
type Deps struct {
	Layout  paths.Layout
	Config  config.Agent
	Trust   bundle.Trust
	Key     identity.Key
	Client  *client.Client
	Health  *health.State
	Applier *apply.Applier
	// Inventory is the fleetd reconciler of Applier; New lets the update policy gate its upgrades (plan M8d decision 23).
	Inventory *reconcile.Inventory
	// Commands executes the commands of check-ins; nil means the handlers of this build (commands.Handlers).
	Commands *commands.Executor
	// Events receives the device events of the reconcilers; New connects it to the spool.
	Events *reconcile.Events
	// Sys is the device for the session tracking (plan M3b decision 11); nil disables it.
	Sys reconcile.System
	// Accounts is the device for the managed local administrator (plan M4a decision 15); nil disables it.
	Accounts localadmin.System
	// LUKS runs the LUKS tools of the root volume (plan M4b decision 8); nil disables the luks reconciler.
	LUKS luks.Tools
	// Encrypt is the device the in-place encryption reads and changes (plan M8e); nil reports no eligibility and
	// refuses encrypt_disk.
	Encrypt encrypt.Host
	// EncryptModule is the embedded dracut module of the in-place encryption (plan M8e §6.4); nil refuses encrypt_disk.
	EncryptModule fs.FS
	// FollowLogins sends the PAM session openings of the device until ctx ends (journal); nil: none.
	FollowLogins func(ctx context.Context, out chan<- localadmin.Login)
	Spool        *spool.Spool    // nil: the agent's own spool below Layout
	Triggers     <-chan struct{} // immediate check-in requests (network up, resume, SIGHUP)
	// Revoke hands a revocation envelope to paddock-revoke and returns its refusal reason ("" when it executed);
	// nil runs the installed paddock-revoke (plan M4c decision 11).
	Revoke func(ctx context.Context, envelope []byte) (refused string, err error)
	// SelfLock runs the stored self-lock token with paddock-revoke after elapsed (the dead man's switch); nil runs the
	// installed paddock-revoke.
	SelfLock func(ctx context.Context, envelope []byte, elapsed time.Duration) (refused string, err error)
	// RevokeCapabilities returns what the installed paddock-revoke understands (`paddock-revoke capabilities`); nil
	// runs the installed paddock-revoke.
	RevokeCapabilities func(ctx context.Context) ([]string, error)
	// Uptime returns the time since boot including suspend and the boot ID; nil reads /proc.
	Uptime func() (time.Duration, string, error)
	// Notify shows a desktop notification on the user sessions; nil shows none.
	Notify func(ctx context.Context, msg string)
	// Supervisor returns the PID of paddock-supervisor and Signal sends it SIGUSR1 (tests replace both).
	Supervisor func() (int, error)
	Signal     func(pid int) error
	// RunUnit runs systemd-run to start a transient unit (the supervisor upgrade, plan M8d decision 31); nil runs it.
	RunUnit func(ctx context.Context, name string, args ...string) error
	// Executable is the running binary the uninstall copies (tests); "" asks the OS.
	Executable string
	// NoExec reports whether the file system holding a directory is mounted noexec; nil asks statfs.
	NoExec func(dir string) (bool, error)
	// SupervisorVersion runs `paddock-supervisor version`; nil runs the installed supervisor ("" when it is not
	// installed).
	SupervisorVersion func(ctx context.Context) (string, error)
	// Download fetches a package from the package store with at most limit bytes; nil uses Client.Download.
	Download func(ctx context.Context, url string, limit int64) ([]byte, error)
	Now      func() time.Time
	// Monotonic measures durations within the process, unaffected by wall-clock steps (tests set it apart from Now to
	// step the wall clock); nil uses Now, whose time.Now readings carry the monotonic clock.
	Monotonic func() time.Time
	Rand      func() float64 // uniform in [0, 1)
	// Sleep waits d or until ctx ends; nil waits.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Agent is the run loop. All state is owned by the goroutine that calls Run.
type Agent struct {
	d           Deps
	st          state.State
	current     *bundle.Bundle // last applied bundle (drift loop)
	failures    int
	lastAttempt time.Time
	localAdmin  *localadmin.Manager
	luks        *reconcile.LUKS
	// ticketAccepted is set by a check-in that accepted a time ticket: the loop restarts the dead man's switch ticks
	// from it, so that the count reaches each lead time at a tick, not up to a tick later (gate R6).
	ticketAccepted bool
	// installJobs feeds the install worker, installDone returns its results to the loop (plan M5b decision 7).
	installJobs chan installJob
	installDone chan installDone
	// updateRequested is whether the last check-in's offer was requested by an administrator (plan M8d decision 23):
	// under the manual policy it allows the fleetd and supervisor upgrades of that check-in.
	updateRequested bool
	// policySkipped is the last offered version the manual policy declined, so that it is logged once per version.
	policySkipped string
	// supervisorSkipped is the last supervisor package version and reason not installed, logged once.
	supervisorSkipped string
	// markerSeen is the first sighting of the current supervisor-upgrade.json (supervisorMarker).
	markerSeen markerSeen
	// conversionJobs feeds the conversion worker (plan M8e decision 12); conversionCalls carries its reads and changes
	// of the state to the loop; conversionBusy is set while a preparation is queued or runs.
	conversionJobs  chan struct{}
	conversionCalls chan func()
	conversionBusy  bool
	// helperRunning is whether the background reencryption's unit was running at the last full pass (plan M8e decision
	// 22); helperNoExecLogged and helperLimitLogged log a launch that cannot happen once per start.
	helperRunning bool
	// enrollmentDeferred is health.disk.conversion.enrollment_deferred as the last full pass found it (plan M8e
	// amendment 2026-10-22, item 22); reencryptLogged logs stop condition S15 once per start; noticeCheckAt is when the
	// completed notice may read the header again.
	enrollmentDeferred string
	reencryptLogged    bool
	noticeCheckAt      time.Time
	// initrdFailures and initrdRetryAt are the backoff of the converted disk's initrd work and of a cleanup;
	// finishCancel cancels a regeneration the worker runs, at a revocation hand-over (PDK-374).
	initrdFailures int
	initrdRetryAt  time.Time
	finishCancel   context.CancelFunc
	// bootConverted is a boot result ok seen since the start: this boot opened the converted disk through the module,
	// so no "not LUKS" answer leads to a cleanup until the next start (amendment 2026-10-21, item 13).
	bootConverted bool
	// neutralizeReported and restoreReported are the reasons of the last disk.conversion_neutralize_failed and
	// disk.conversion_unlock_restore_failed emitted since the start; "" after a disarm or reinstall that succeeded
	// (reportOnce, PDK-482). They are accessed on the run loop.
	neutralizeReported string
	restoreReported    string
	// helperLaunched is a helper this start launched or saw running whose end the agent has not recorded yet: an end
	// without a result counts as a failed run.
	helperLaunched     bool
	helperNoExecLogged bool
	helperLimitLogged  bool
}

// Load reads configuration, trust anchor, identity and state from the layout.
func Load(l paths.Layout) (Deps, error) {
	cfg, err := config.LoadAgent(l.AgentConfig())
	if err != nil {
		return Deps{}, err
	}
	trust, err := config.LoadTrust(l.Trust())
	if err != nil {
		return Deps{}, err
	}
	key, err := identity.Load(l.IdentityKey())
	if err != nil {
		return Deps{}, err
	}
	c, err := client.New(cfg.ServerURL, cfg.Proxy, key)
	if err != nil {
		return Deps{}, err
	}
	managed, err := reconcile.LoadManaged(l.Managed())
	if err != nil {
		return Deps{}, err
	}
	sys := reconcile.OS{Root: l.Root}
	events := &reconcile.Events{}
	inventory := &reconcile.Inventory{Sys: sys, Events: events, Download: c.Download, BundlesURL: BundlesURL(cfg.ServerURL)}
	d := Deps{
		Layout: l, Config: cfg, Trust: trust, Key: key, Client: c, Events: events, Sys: sys, Accounts: sys, Inventory: inventory,
		Applier: apply.New(sys, managed, events).WithInventory(inventory),
	}
	if l.Root == "" || l.Root == "/" {
		d.FollowLogins = localadmin.FollowJournal
		d.LUKS = luks.OS{}
		d.Encrypt = encrypt.OS{}
		d.EncryptModule = encrypt.Module()
		d.Notify = func(ctx context.Context, msg string) { notifySessions(ctx, sys.Loginctl, runTool, msg) }
	}
	return d, nil
}

// New creates the run loop. It writes nothing: `paddockd plan` uses it from a second process, so the start-time
// work runs in Run.
func New(d Deps) (*Agent, error) {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Rand == nil {
		d.Rand = rand.Float64 //nolint:gosec // jitter, not a secret
	}
	if d.Health == nil {
		d.Health = health.NewState(buildinfo.Version)
	}

	st, err := state.Load(d.Layout.State())
	if err != nil {
		return nil, err
	}
	a := &Agent{d: d, st: st, installJobs: make(chan installJob, installQueue), installDone: make(chan installDone, installQueue),
		conversionJobs: make(chan struct{}, 1), conversionCalls: make(chan func())}
	if d.Inventory != nil {
		d.Inventory.UpdatesAllowed = a.updatesAllowed
	}
	a.localAdmin = &localadmin.Manager{Sys: d.Accounts, Escrow: escrowClient{a}, State: &a.st.LocalAdmin, Save: a.persist,
		Emit: a.event, Result: a.commandResult, Now: d.Now}
	if d.LUKS != nil {
		a.luks = a.luksReconciler()
	}
	if a.d.Commands == nil {
		a.d.Commands = commands.New(commands.Handlers(map[string]commands.Handler{
			command.TypeRotateAdminPassword: a.rotateCommand,
			command.TypeDeleteSelfLock:      a.deleteSelfLock,
			command.TypeInstallNow:          a.installNowCommand,
			command.TypeUninstall:           a.uninstallCommand,
			command.TypeEncryptDisk:         a.encryptDiskCommand,
			command.TypeEncryptDiskAbort:    a.encryptDiskAbortCommand,
		}), d.Now)
	}
	if a.d.Spool == nil {
		a.d.Spool = a.newSpool()
	}
	if a.d.Events != nil {
		a.d.Events.Emit = a.event
	}
	if a.d.Revoke == nil {
		a.d.Revoke = func(ctx context.Context, envelope []byte) (string, error) {
			return runRevoke(ctx, a.d.Layout.RevokeBinary(), envelope)
		}
	}
	if a.d.SelfLock == nil {
		a.d.SelfLock = func(ctx context.Context, envelope []byte, elapsed time.Duration) (string, error) {
			return runRevoke(ctx, a.d.Layout.RevokeBinary(), envelope, "--elapsed-seconds", strconv.FormatInt(int64(elapsed/time.Second), 10))
		}
	}
	if a.d.RevokeCapabilities == nil {
		a.d.RevokeCapabilities = func(ctx context.Context) ([]string, error) {
			return revokeCapabilities(ctx, a.d.Layout.RevokeBinary())
		}
	}
	if a.d.Uptime == nil {
		a.d.Uptime = procUptime
	}
	if a.d.Supervisor == nil {
		a.d.Supervisor = func() (int, error) { return update.SupervisorPID(a.d.Layout) }
	}
	if a.d.Signal == nil {
		a.d.Signal = update.Notify
	}
	if a.d.RunUnit == nil {
		a.d.RunUnit = runUnit
	}
	if a.d.NoExec == nil {
		a.d.NoExec = noexec
	}
	if a.d.SupervisorVersion == nil {
		a.d.SupervisorVersion = func(ctx context.Context) (string, error) { return supervisorVersion(ctx, a.d.Layout) }
	}
	if a.d.Sleep == nil {
		a.d.Sleep = sleepCtx
	}
	if a.d.Download == nil && a.d.Client != nil {
		a.d.Download = a.d.Client.Download
	}
	a.refreshHealth()
	a.loadCurrent()
	return a, nil
}

// Run serves the health socket and runs the check-in loop until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	// Here and not in New: New also serves `paddockd plan`, a second process that could remove a release the daemon
	// is staging before its request.json exists (PDK-075) or report the daemon's running install_now as interrupted
	// and race its state writes (PDK-081).
	a.sweepStaging()
	a.reportInterruptedInstalls()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := health.Serve(ctx, a.d.Layout.Socket(), a.d.Health); err != nil {
			slog.ErrorContext(ctx, "health socket failed", "error", err)
		}
	}()
	defer wg.Wait()
	if err := a.waitActive(ctx); err != nil {
		return err
	}
	if a.d.Sys != nil {
		// Not waited for: an installation in progress outlives the run loop (runInstalls).
		go a.runInstalls(ctx)
	}
	// Before the worker starts: the I2 check of plan M8e §14.10 decides before a preparation is re-queued.
	a.startConversion(ctx)
	if a.d.Encrypt != nil {
		// Not waited for, like the install worker: a running apt-get or dracut outlives the run loop.
		go a.runConversions(ctx)
	}
	logins := make(chan localadmin.Login, 16)
	if a.d.FollowLogins != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.d.FollowLogins(ctx, logins)
		}()
	}
	return a.loop(ctx, logins)
}

func (a *Agent) loop(ctx context.Context, logins <-chan localadmin.Login) error {
	next := time.NewTimer(0) // check in at start
	defer next.Stop()
	localAdmin := time.NewTicker(localadmin.PollInterval)
	defer localAdmin.Stop()
	drift := time.NewTicker(a.d.Config.DriftInterval)
	defer drift.Stop()
	sessionPoll := time.NewTicker(SessionPoll)
	defer sessionPoll.Stop()
	dms := time.NewTicker(DMSTick)
	defer dms.Stop()
	nextAt := a.d.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-drift.C:
			a.drift(ctx)
			a.tickLUKS(ctx, true)
			a.tickConversion(ctx)
			a.reportUpdateRuns(ctx)
		case d := <-a.installDone:
			a.finishInstall(d)
		case fn := <-a.conversionCalls:
			fn()
		case <-sessionPoll.C:
			a.trackSessions(ctx)
			a.tickConversionSessions(ctx)
		case <-dms.C:
			a.tickDMS(ctx)
		case <-localAdmin.C:
			a.tickLocalAdmin(ctx)
			a.tickLUKS(ctx, false)
		case l := <-logins:
			a.localAdminLogin(l)
		case <-a.d.Triggers:
			if at := triggered(a.d.Now(), a.lastAttempt, a.d.Rand()); at.Before(nextAt) {
				nextAt = at
				next.Reset(at.Sub(a.d.Now()))
			}
		case <-next.C:
			d := a.Cycle(ctx)
			nextAt = a.d.Now().Add(d)
			next.Reset(d)
			if a.ticketAccepted {
				a.ticketAccepted = false
				dms.Reset(DMSTick)
			}
			a.tickLocalAdmin(ctx)
			a.tickLUKS(ctx, true)
			a.tickConversion(ctx)
		}
	}
}

// waitActive returns once the device is active; while the enrollment is pending it polls the enrollment status.
func (a *Agent) waitActive(ctx context.Context) error {
	delay := enroll.FirstPoll
	for a.st.Status != state.StatusActive {
		switch {
		case a.st.Status == state.StatusRejected:
			slog.WarnContext(ctx, "the enrollment of this device was rejected; the agent stays idle")
		case a.st.EnrollmentID == "":
			slog.InfoContext(ctx, "device not enrolled; waiting for `paddockd enroll`")
		default:
			if _, err := enroll.Poll(ctx, a.d.Layout, a.d.Client, &a.st); err != nil {
				slog.WarnContext(ctx, "enrollment status unavailable", "error", err)
			}
			a.refreshHealth()
			if a.st.Status == state.StatusActive {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(2*delay, enroll.MaxPoll)
		if st, err := state.Load(a.d.Layout.State()); err == nil && st.EnrollmentID != a.st.EnrollmentID {
			a.st = st // `paddockd enroll` ran meanwhile
		}
	}
	return nil
}

// Cycle runs one check-in and returns the time until the next one.
func (a *Agent) Cycle(ctx context.Context) time.Duration {
	a.lastAttempt = a.d.Now()
	resp, err := a.d.Client.Checkin(ctx, a.st.DeviceID, a.st.Seq, a.checkinRequest(ctx))
	if err != nil {
		a.failures++
		var retryAfter time.Duration
		var apiErr *client.APIError
		if errors.As(err, &apiErr) {
			retryAfter = apiErr.RetryAfter
		}
		d := afterFailure(a.failures, a.d.Rand(), retryAfter)
		slog.WarnContext(ctx, "check-in failed", "error", err, "failures", a.failures, "retry_in", d.Round(time.Second))
		if !errors.As(err, &apiErr) || apiErr.Status == http.StatusBadGateway || apiErr.Status == http.StatusServiceUnavailable ||
			apiErr.Status == http.StatusGatewayTimeout {
			a.markCheckinFailed()
		}
		a.setError(fmt.Sprintf("check-in: %v", err))
		return d
	}
	a.failures = 0
	if err := a.checkedIn(resp); err != nil {
		slog.ErrorContext(ctx, "storing check-in state failed", "error", err)
		a.setError(err.Error())
	} else {
		a.setError("")
	}
	a.reportUpdate()
	a.reportSupervisorUpgrade()
	a.handleBundle(ctx, resp.Bundle)
	a.ticketAccepted = a.acceptTicket(resp.TimeTicket) || a.ticketAccepted
	a.handleCommands(ctx, resp.Commands)
	a.handleUpdate(ctx, resp.AgentUpdate)
	a.handleSupervisorPackage(ctx)
	a.flush(ctx)
	a.postResults(ctx)
	a.launchUninstall(ctx)
	a.clearUpdateResult()
	a.clearSupervisorResult()
	return afterSuccess(resp.NextCheckinS, a.d.Rand())
}

// checkinRequest carries the health report, which includes the device's sudo flavor (shown on the device detail) and a
// pending reboot.
func (a *Agent) checkinRequest(ctx context.Context) protocol.CheckinRequest {
	a.refreshSudoFlavor(ctx)
	a.refreshRebootRequired()
	a.refreshRevokeCapabilities(ctx)
	a.refreshComponents(ctx)
	a.refreshHostname(ctx)
	health, err := json.Marshal(a.d.Health.Report())
	if err != nil {
		health = nil
	}
	return protocol.CheckinRequest{
		AppliedBundleVersion: a.st.AppliedBundleVersion, AgentVersion: buildinfo.Version,
		SchemaVersions: apply.SchemaVersions, EventSeqHigh: a.st.EventSeq, Arch: runtime.GOARCH, Health: health,
	}
}

// refreshHostname reports the kernel (transient) hostname in the health report (plan M8h decision 8): the server
// keeps it as the device's reported hostname. A failed read keeps the last value.
func (a *Agent) refreshHostname(ctx context.Context) {
	name, err := os.Hostname()
	if err != nil {
		slog.DebugContext(ctx, "hostname unknown", "error", err)
		return
	}
	a.d.Health.Update(func(r *health.Report) { r.Hostname = name })
}

// refreshSudoFlavor detects the active sudo implementation for the health report; a failed detection keeps the last
// value.
func (a *Agent) refreshSudoFlavor(ctx context.Context) {
	if a.d.Sys == nil {
		return
	}
	flavor, _, err := reconcile.SudoFlavor(ctx, a.d.Sys)
	if err != nil {
		slog.DebugContext(ctx, "sudo flavor unknown", "error", err)
		return
	}
	a.d.Health.Update(func(r *health.Report) { r.SudoFlavor = string(flavor) })
}

// checkedIn persists the new sequence number first (clone detection depends on it) and marks the check-in for the
// supervisor's probation.
func (a *Agent) checkedIn(resp protocol.CheckinResponse) error {
	now := a.d.Now().UTC()
	a.st.Seq, a.st.LastCheckinAt = resp.Seq, &now
	if err := state.Save(a.d.Layout.State(), a.st); err != nil {
		return err
	}
	a.refreshHealth()
	return fsutil.WriteFile(a.d.Layout.LastCheckin(), []byte(now.Format(time.RFC3339Nano)+"\n"), 0o644, 0o755)
}

// markCheckinFailed records a check-in that did not reach the server, for the supervisor upgrade helper (design
// contract 8). A failure to write it is logged only: the helper then counts a rollback as permanent, never the reverse.
func (a *Agent) markCheckinFailed() {
	at := a.d.Now().UTC().Format(time.RFC3339Nano) + "\n"
	if err := fsutil.WriteFile(a.d.Layout.LastCheckinFailed(), []byte(at), 0o644, 0o755); err != nil {
		slog.Warn("recording the failed check-in failed", "error", err)
	}
}

func (a *Agent) setError(msg string) {
	a.d.Health.Update(func(r *health.Report) {
		r.LastError = msg
		if r.Status != health.StatusNotEnrolled {
			r.Status = health.StatusOK
			if msg != "" {
				r.Status = health.StatusDegraded
			}
		}
	})
}

func (a *Agent) refreshHealth() {
	a.d.Health.Update(func(r *health.Report) {
		r.LastCheckinAt, r.LastBundleVersion = a.st.LastCheckinAt, a.st.AppliedBundleVersion
		if a.st.Status == state.StatusActive && r.Status == health.StatusNotEnrolled {
			r.Status = health.StatusOK
		}
	})
}

// State returns a copy of the agent state (tests).
func (a *Agent) State() state.State { return a.st }
