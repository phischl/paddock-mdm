// Package agent is the run loop of `paddockd run` (plan M2b decisions 8, 9, 11–13): periodic and event-triggered
// check-ins with back-off, bundle apply, drift correction and the event spool. It never locks, wipes, reboots or
// blocks logins; without a server it keeps the last applied bundle and keeps spooling.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/apply"
	"github.com/paddock-mdm/paddock/agent/internal/buildinfo"
	"github.com/paddock-mdm/paddock/agent/internal/client"
	"github.com/paddock-mdm/paddock/agent/internal/config"
	"github.com/paddock-mdm/paddock/agent/internal/enroll"
	"github.com/paddock-mdm/paddock/agent/internal/fsutil"
	"github.com/paddock-mdm/paddock/agent/internal/health"
	"github.com/paddock-mdm/paddock/agent/internal/identity"
	"github.com/paddock-mdm/paddock/agent/internal/paths"
	"github.com/paddock-mdm/paddock/agent/internal/reconcile"
	"github.com/paddock-mdm/paddock/agent/internal/spool"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/agent/internal/update"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
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
	// Events receives the device events of the reconcilers; New connects it to the spool.
	Events *reconcile.Events
	// Sys is the device for the session tracking (plan M3b decision 11); nil disables it.
	Sys      reconcile.System
	Spool    *spool.Spool    // nil: the agent's own spool below Layout
	Triggers <-chan struct{} // immediate check-in requests (network up, resume, SIGHUP)
	// Supervisor returns the PID of paddock-supervisor and Signal sends it SIGUSR1 (tests replace both).
	Supervisor func() (int, error)
	Signal     func(pid int) error
	Now        func() time.Time
	Rand       func() float64 // uniform in [0, 1)
}

// Agent is the run loop. All state is owned by the goroutine that calls Run.
type Agent struct {
	d           Deps
	st          state.State
	current     *bundle.Bundle // last applied bundle (drift loop)
	failures    int
	lastAttempt time.Time
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
	return Deps{
		Layout: l, Config: cfg, Trust: trust, Key: key, Client: c, Applier: apply.New(sys, managed, events), Events: events,
		Sys: sys,
	}, nil
}

// New creates the run loop.
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
	a := &Agent{d: d, st: st}
	if a.d.Spool == nil {
		a.d.Spool = a.newSpool()
	}
	if a.d.Events != nil {
		a.d.Events.Emit = a.event
	}
	if a.d.Supervisor == nil {
		a.d.Supervisor = func() (int, error) { return update.SupervisorPID(a.d.Layout) }
	}
	if a.d.Signal == nil {
		a.d.Signal = update.Notify
	}
	a.refreshHealth()
	a.loadCurrent()
	return a, nil
}

// Run serves the health socket and runs the check-in loop until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
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
	return a.loop(ctx)
}

func (a *Agent) loop(ctx context.Context) error {
	next := time.NewTimer(0) // check in at start
	defer next.Stop()
	drift := time.NewTicker(a.d.Config.DriftInterval)
	defer drift.Stop()
	sessionPoll := time.NewTicker(SessionPoll)
	defer sessionPoll.Stop()
	nextAt := a.d.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-drift.C:
			a.drift(ctx)
		case <-sessionPoll.C:
			a.trackSessions(ctx)
		case <-a.d.Triggers:
			if at := triggered(a.d.Now(), a.lastAttempt, a.d.Rand()); at.Before(nextAt) {
				nextAt = at
				next.Reset(at.Sub(a.d.Now()))
			}
		case <-next.C:
			d := a.Cycle(ctx)
			nextAt = a.d.Now().Add(d)
			next.Reset(d)
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
	a.handleBundle(ctx, resp.Bundle)
	a.handleUpdate(ctx, resp.AgentUpdate)
	a.flush(ctx)
	a.clearUpdateResult()
	return afterSuccess(resp.NextCheckinS, a.d.Rand())
}

// checkinRequest carries the health report, which includes the device's sudo flavor (shown on the device detail).
func (a *Agent) checkinRequest(ctx context.Context) protocol.CheckinRequest {
	a.refreshSudoFlavor(ctx)
	health, err := json.Marshal(a.d.Health.Report())
	if err != nil {
		health = nil
	}
	return protocol.CheckinRequest{
		AppliedBundleVersion: a.st.AppliedBundleVersion, AgentVersion: buildinfo.Version,
		SchemaVersions: acceptedSchemas, EventSeqHigh: a.st.EventSeq, Arch: runtime.GOARCH, Health: health,
	}
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
