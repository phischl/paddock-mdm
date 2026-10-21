package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// supervisorWaitPoll is how often the conversion worker looks again while a supervisor upgrade runs (plan M8e
// decision 37).
const supervisorWaitPoll = 30 * time.Second

// uuidPattern is a canonical UUID, the form of a conversion ID.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// conversionID decodes the params of encrypt_disk and encrypt_disk_abort; "" when they carry no valid conversion ID.
func conversionID(params json.RawMessage) string {
	var p command.EncryptDiskParams
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || !uuidPattern.MatchString(p.ConversionID) {
		return ""
	}
	return p.ConversionID
}

// encryptDiskCommand accepts encrypt_disk (plan M8e decision 12): it refuses while a revocation was handed over within
// 24 hours, while an uninstall is pending and when the device is not eligible; otherwise it records the conversion as
// preparing and queues the preparation on the conversion worker.
func (a *Agent) encryptDiskCommand(ctx context.Context, c *command.Command) (string, map[string]any) {
	refuse := func(reason string, reasons []string) (string, map[string]any) {
		r := map[string]any{"accepted": false, "reason": reason}
		if len(reasons) > 0 {
			r["reasons"] = reasons
		}
		return protocol.CommandFailed, r
	}
	id := conversionID(c.Params)
	if id == "" {
		return refuse("invalid_params", nil)
	}
	now := a.d.Now()
	for _, at := range a.st.HandedRevocations {
		if now.Sub(at) < revocationWindow {
			return refuse("revocation_pending", nil)
		}
	}
	if a.st.PendingUninstall != nil {
		return refuse("uninstall_pending", nil)
	}
	if a.d.Encrypt == nil || a.d.EncryptModule == nil {
		slog.ErrorContext(ctx, "encrypt_disk refused: this agent cannot convert the disk (no device access or no dracut module)")
		return refuse(encrypt.ReasonNotEligible, nil)
	}
	if prev := a.st.Conversion; prev != nil {
		switch {
		case prev.CleanupPending:
			return refuse(encrypt.ReasonNotEligible, []string{encrypt.ReasonCleanupPending})
		case prev.Phase != state.ConversionCancelled && prev.Phase != state.ConversionFailed:
			return refuse(encrypt.ReasonNotEligible, []string{encrypt.ReasonAlreadyEncrypted})
		}
	}
	l := encrypt.Preflight(ctx, a.d.Encrypt, a.d.Layout.Root, false)
	if !l.Eligible {
		return refuse(encrypt.ReasonNotEligible, l.Reasons)
	}
	if disk := a.d.Health.Report().Disk; disk != nil && disk.State != protocol.DiskNotEncrypted {
		return refuse(encrypt.ReasonNotEligible, []string{encrypt.ReasonAlreadyEncrypted})
	}
	a.st.Conversion = &state.DiskConversion{ID: id, CommandID: c.CommandID, Phase: state.ConversionPreparing, RequestedAt: now.UTC()}
	_ = a.persist()
	a.queueConversion()
	slog.InfoContext(ctx, "in-place encryption accepted; preparing", "conversion_id", id)
	return protocol.CommandSucceeded, map[string]any{"accepted": true}
}

// encryptDiskAbortCommand handles encrypt_disk_abort (plan M8e decision 27): a prepared conversion is aborted at once,
// a preparing one by the worker before its next step (the result follows then), any other phase is refused.
func (a *Agent) encryptDiskAbortCommand(ctx context.Context, c *command.Command) (string, map[string]any) {
	refuse := func(reason string) (string, map[string]any) {
		return protocol.CommandFailed, map[string]any{"aborted": false, "reason": reason}
	}
	id := conversionID(c.Params)
	if id == "" {
		return refuse("invalid_params")
	}
	conv := a.st.Conversion
	if conv == nil || conv.ID != id {
		return refuse(encrypt.ReasonUnknownConversion)
	}
	switch conv.Phase {
	case state.ConversionPreparing:
		conv.AbortRequested, conv.AbortCommandID = true, c.CommandID
		_ = a.persist()
		return commands.Deferred, nil
	case state.ConversionPrepared:
		if a.d.Encrypt == nil {
			return refuse(encrypt.ReasonNotAbortable)
		}
		// Without ctx's cancel, as on the worker: an agent stop must not kill dracut --regenerate-all halfway.
		if aborted, reason := encrypt.Abort(context.WithoutCancel(ctx), a.d.Encrypt, a.d.Layout, a.directStore(), id, encrypt.ByAdmin,
			false); !aborted {
			return refuse(reason)
		}
		return protocol.CommandSucceeded, map[string]any{"aborted": true}
	}
	return refuse(encrypt.ReasonNotAbortable)
}

// queueConversion queues a job of the conversion worker — the preparation or the cleanup retry; a job already queued
// covers it.
func (a *Agent) queueConversion() {
	select {
	case a.conversionJobs <- struct{}{}:
		a.conversionBusy = true
	default:
	}
}

// startConversion runs at the agent's start, before anything else of the conversion: the I2 check (an adopted
// conversion drops its preparation, plan M8e §14.10), the answer to an abort a restart interrupted, and the re-queue of
// a preparation (decision 13).
func (a *Agent) startConversion(ctx context.Context) {
	if a.d.Encrypt == nil || a.st.Conversion == nil {
		return
	}
	a.adoptConversion(ctx)
	a.answerAbort()
	if a.st.Conversion.Phase == state.ConversionPreparing {
		a.queueConversion()
	}
}

// adoptConversion is the I2 check of plan M8e §14.10 for a conversion that is not encrypting yet: when its partition
// is LUKS the disk converted at a boot, and the conversion is adopted as encrypting — a queued preparation is dropped,
// a pending cleanup ends, disk.conversion_started is emitted. The boot result, the reinstall of a removed module and
// the background phase are plan M8e decision 18 onwards (PDK-245). It reports whether it adopted.
func (a *Agent) adoptConversion(ctx context.Context) bool {
	c := a.st.Conversion
	if c == nil || c.Phase == state.ConversionEncrypting || c.Phase == state.ConversionCompleted {
		return false
	}
	isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, c.Partition)
	if !ok || !isLUKS {
		return false
	}
	select {
	case <-a.conversionJobs:
		a.conversionBusy = false
	default:
	}
	now := a.d.Now().UTC()
	slog.WarnContext(ctx, "the root partition carries the conversion's LUKS header; adopting the conversion", "conversion_id", c.ID,
		"phase", c.Phase)
	c.Phase, c.StartedAt, c.CleanupPending, c.AbortRequested, c.Notified = state.ConversionEncrypting, &now, false, false, nil
	c.FailureStage, c.FailureReason = "", ""
	a.event(protocol.EventDiskConversionStarted, map[string]any{"conversion_id": c.ID, "volume": c.LUKSUUID, "init_result": "unknown"})
	a.answerAbort()
	a.saveState()
	return true
}

// answerAbort posts the result of an encrypt_disk_abort the worker has handled: aborted when the conversion is
// cancelled, not_abortable when it went on (adopted).
func (a *Agent) answerAbort() {
	c := a.st.Conversion
	if c == nil || c.AbortCommandID == "" || c.Phase == state.ConversionPreparing {
		return
	}
	result := map[string]any{"aborted": true}
	status := protocol.CommandSucceeded
	if c.Phase != state.ConversionCancelled {
		result, status = map[string]any{"aborted": false, "reason": encrypt.ReasonNotAbortable}, protocol.CommandFailed
	}
	a.st.CommandResults = append(a.st.CommandResults, state.CommandResult{CommandID: c.AbortCommandID, Status: status,
		Result: commands.Encode(result)})
	c.AbortCommandID = ""
	a.saveState()
}

// tickConversion is the conversion's part of every full pass: the I2 check, then the retry of an unfinished cleanup
// (invariant I3) or of a preparation without a worker job (a transient tool error, or a failure whose save failed),
// queued on the conversion worker: dracut may run for LongTimeout and must not stall the run loop. A preparing
// conversion thus never waits for the next start, and an abort deferred meanwhile is answered by the worker.
func (a *Agent) tickConversion(ctx context.Context) {
	c := a.st.Conversion
	if a.d.Encrypt == nil || c == nil || a.adoptConversion(ctx) || a.conversionBusy {
		return
	}
	if c.CleanupPending || c.Phase == state.ConversionPreparing {
		a.queueConversion()
	}
}

// tickConversionSessions runs at every session poll: the operator's abort request and the restart notification.
func (a *Agent) tickConversionSessions(ctx context.Context) {
	a.handleAbortRequest(ctx)
	c := a.st.Conversion
	if a.d.Encrypt == nil || c == nil || c.Phase != state.ConversionPrepared {
		return
	}
	mode := encrypt.DefaultUnlockMode
	if plan, err := encrypt.ReadPlan(a.d.Layout); err == nil && plan != nil {
		mode = plan.UnlockMode
	}
	if c.Notified == nil {
		c.Notified = map[string]time.Time{}
	}
	if encrypt.NotifyRestart(ctx, a.d.Encrypt, a.d.Layout.Root, mode, c.Notified, a.d.Now()) {
		a.saveState()
	}
}

// handleAbortRequest answers `paddockd encrypt-abort` (plan M8e decision 14 as corrected on 2026-10-21): the agent
// claims the request, answers running, aborts like encrypt_disk_abort with by operator — a prepared conversion only —
// and answers with the outcome.
func (a *Agent) handleAbortRequest(ctx context.Context) {
	req, err := encrypt.ClaimAbortRequest(a.d.Layout, a.d.Now())
	if err != nil {
		slog.WarnContext(ctx, "encrypt-abort request not handled", "error", err)
		return
	}
	if req == nil {
		return
	}
	if err := encrypt.WriteAbortResponse(a.d.Layout, encrypt.AbortResponse{Nonce: req.Nonce, State: encrypt.AbortRunning}); err != nil {
		slog.ErrorContext(ctx, "answering the encrypt-abort request failed", "error", err)
	}
	aborted, reason := false, encrypt.ReasonUnknownConversion
	if a.d.Encrypt != nil {
		// Without ctx's cancel, as on the worker: an agent stop must not kill dracut --regenerate-all halfway.
		aborted, reason = encrypt.Abort(context.WithoutCancel(ctx), a.d.Encrypt, a.d.Layout, a.directStore(), req.ConversionID,
			encrypt.ByOperator, false)
	}
	slog.InfoContext(ctx, "encrypt-abort request handled", "aborted", aborted, "reason", reason)
	if err := encrypt.WriteAbortResponse(a.d.Layout, encrypt.AbortResponse{Nonce: req.Nonce, State: encrypt.AbortDone,
		Aborted: aborted, Reason: reason}); err != nil {
		slog.ErrorContext(ctx, "answering the encrypt-abort request failed", "error", err)
	}
}

// conversionPending is the uninstall refusal of plan M8e decision 36: a conversion whose initrd still carries the
// module and the key, an unfinished cleanup, or a root volume with an unfinished reencryption (whatever the state).
func (a *Agent) conversionPending(ctx context.Context) bool {
	if c := a.st.Conversion; c != nil {
		if c.CleanupPending {
			return true
		}
		if !c.InitrdRegenerated && c.Phase != state.ConversionCancelled && !a.failedWhileUnencrypted(ctx, c) {
			return true
		}
	}
	return a.rootReencrypting(ctx)
}

// failedWhileUnencrypted: failed at stage preflight, prepare or init with the partition not LUKS.
func (a *Agent) failedWhileUnencrypted(ctx context.Context, c *state.DiskConversion) bool {
	if c.Phase != state.ConversionFailed || (c.FailureStage != state.StagePreflight && c.FailureStage != state.StagePrepare &&
		c.FailureStage != state.StageInit) || a.d.Encrypt == nil {
		return false
	}
	isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, c.Partition)
	return ok && !isLUKS
}

// rootReencrypting reports whether the root volume's LUKS2 metadata carries a reencrypt keyslot.
func (a *Agent) rootReencrypting(ctx context.Context) bool {
	if a.d.LUKS == nil {
		return false
	}
	vol, err := luks.Root(ctx, a.d.LUKS)
	if err != nil {
		if !errors.Is(err, luks.ErrNotEncrypted) {
			slog.WarnContext(ctx, "root volume unknown for the uninstall check", "error", err)
		}
		return false
	}
	md, err := luks.Dump(ctx, a.d.LUKS, vol.Device)
	if err != nil {
		slog.WarnContext(ctx, "LUKS metadata unreadable for the uninstall check", "error", err)
		return false
	}
	return md.Reencrypting()
}

// runConversions is the conversion worker (plan M8e decision 12, the install worker's pattern): it prepares a
// conversion that is preparing, or retries its unfinished cleanup. Every read and change of the agent state goes
// through the run loop (onLoop). The tools run without ctx's cancel: apt-get stopped halfway leaves dpkg broken; a
// stopped agent re-queues the preparation at its next start.
func (a *Agent) runConversions(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.conversionJobs:
		}
		var p *encrypt.Preparer
		partition, cleanup := "", false
		if a.onLoop(ctx, func() {
			switch c := a.st.Conversion; {
			case c != nil && c.Phase == state.ConversionPreparing:
				p = a.preparer(ctx)
			case c != nil && c.CleanupPending:
				partition, cleanup = c.Partition, true
			}
		}) != nil {
			return
		}
		if cleanup {
			a.retryCleanup(ctx, partition)
		}
		outcome := encrypt.Stopped
		if p != nil {
			outcome = p.Prepare(context.WithoutCancel(ctx))
		}
		if a.onLoop(ctx, func() {
			a.conversionBusy = false
			if p != nil && outcome == encrypt.Stopped {
				// A preparation that stopped because the partition is LUKS already (the disk converted at a boot) is adopted
				// now rather than at the next full pass (invariant I2).
				a.adoptConversion(ctx)
				a.refuseUnrunAbort()
			}
			a.answerAbort()
		}) != nil {
			return
		}
		if p != nil {
			slog.InfoContext(ctx, "in-place encryption preparation ended", "outcome", outcome)
		}
	}
}

// retryCleanup is the I3 retry of an unfinished cleanup on the worker — never while the partition is LUKS or its header
// cannot be checked (invariant I1).
func (a *Agent) retryCleanup(ctx context.Context, partition string) {
	if isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, partition); isLUKS || !ok {
		return
	}
	encrypt.RunCleanup(context.WithoutCancel(ctx), a.d.Encrypt, a.d.Layout, a.loopStore(ctx))
}

// refuseUnrunAbort answers an abort the worker could not run (Abort refused while the run loop is alive): the deferred
// encrypt_disk_abort is answered not_abortable (decision 27) and the preparation is queued again, so that the
// conversion does not stay preparing without a worker and hold supervisor upgrades back (decision 37).
func (a *Agent) refuseUnrunAbort() {
	c := a.st.Conversion
	if c == nil || c.Phase != state.ConversionPreparing || !c.AbortRequested {
		return
	}
	if c.AbortCommandID != "" {
		a.st.CommandResults = append(a.st.CommandResults, state.CommandResult{CommandID: c.AbortCommandID,
			Status: protocol.CommandFailed, Result: commands.Encode(map[string]any{"aborted": false, "reason": encrypt.ReasonNotAbortable})})
	}
	c.AbortRequested, c.AbortCommandID = false, ""
	a.saveState()
	a.queueConversion()
}

// preparer builds the preparation from the applied bundle; it runs on the loop.
func (a *Agent) preparer(ctx context.Context) *encrypt.Preparer {
	p := &encrypt.Preparer{Sys: a.d.Encrypt, Layout: a.d.Layout, Escrow: loopEscrow{a: a, ctx: ctx}, Keys: a.bundleKeys(),
		State: a.loopStore(ctx), Module: a.d.EncryptModule, Now: a.d.Now,
		Hold:  func(context.Context) error { return a.holdForSupervisor(ctx) },
		Sleep: func(_ context.Context, d time.Duration) error { return a.d.Sleep(ctx, d) }}
	if a.current != nil {
		p.Disk = a.current.Disk
	}
	return p
}

// holdForSupervisor returns once no supervisor upgrade runs (plan M8e decision 37): it waits while
// supervisor-upgrade.json exists, at most supervisorpkg.StaleAfter from the marker's start (its mtime when it is
// unreadable).
func (a *Agent) holdForSupervisor(ctx context.Context) error {
	logged := false
	for {
		marker, err := supervisorpkg.ReadMarker(a.d.Layout)
		var started time.Time
		switch {
		case marker != nil:
			started = marker.StartedAt
		case err == nil:
			return nil
		default:
			info, serr := os.Stat(a.d.Layout.SupervisorUpgrade())
			if serr != nil {
				return nil //nolint:nilerr // no marker to wait for
			}
			started = info.ModTime()
		}
		if a.d.Now().Sub(started) >= supervisorpkg.StaleAfter {
			return nil
		}
		if !logged {
			slog.InfoContext(ctx, "in-place encryption preparation waits for the running supervisor upgrade")
			logged = true
		}
		if err := a.d.Sleep(ctx, supervisorWaitPoll); err != nil {
			return err
		}
	}
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// onLoop runs fn on the run loop and waits for it; it fails once ctx ended (the loop is gone).
func (a *Agent) onLoop(ctx context.Context, fn func()) error {
	done := make(chan struct{})
	select {
	case a.conversionCalls <- func() { fn(); close(done) }:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// agentStore is the agent state as encrypt.Store; run executes on the owner of the state.
type agentStore struct {
	a   *Agent
	run func(fn func()) error
}

// directStore is the Store for code that runs on the loop already.
func (a *Agent) directStore() agentStore {
	return agentStore{a: a, run: func(fn func()) error { fn(); return nil }}
}

// loopStore is the Store of the conversion worker.
func (a *Agent) loopStore(ctx context.Context) agentStore {
	return agentStore{a: a, run: func(fn func()) error { return a.onLoop(ctx, fn) }}
}

func (s agentStore) Conversion() (state.DiskConversion, bool) {
	var c state.DiskConversion
	ok := false
	if err := s.run(func() {
		if s.a.st.Conversion != nil {
			c, ok = *s.a.st.Conversion, true
		}
	}); err != nil {
		return c, false
	}
	return c, ok
}

func (s agentStore) Update(fn func(c *state.DiskConversion, l *state.LUKS)) error {
	return s.Transition(func(c *state.DiskConversion, l *state.LUKS) *encrypt.Event {
		fn(c, l)
		return nil
	})
}

// Transition implements encrypt.Store: the change, its save and its event run in one call on the owner of the state;
// a failed save restores the state as it was (fn changes fields, never maps or slices in place).
func (s agentStore) Transition(fn func(c *state.DiskConversion, l *state.LUKS) *encrypt.Event) error {
	var err error
	if rerr := s.run(func() {
		c := s.a.st.Conversion
		if c == nil {
			err = errors.New("no conversion")
			return
		}
		oldConv, oldLUKS := *c, s.a.st.LUKS
		oldConv.Notified = maps.Clone(c.Notified)
		ev := fn(c, &s.a.st.LUKS)
		if err = s.a.persist(); err != nil {
			*c, s.a.st.LUKS = oldConv, oldLUKS
			return
		}
		if ev != nil {
			s.a.event(ev.Type, ev.Data)
		}
	}); rerr != nil {
		return rerr
	}
	return err
}

// loopEscrow is the escrow client of the conversion worker: the device API calls read the agent state (device ID,
// sequence number), so they run on the loop.
type loopEscrow struct {
	a   *Agent
	ctx context.Context
}

func (e loopEscrow) Upload(ctx context.Context, req escrow.Request) error {
	var err error
	if lerr := e.a.onLoop(e.ctx, func() { err = escrowClient{e.a}.Upload(ctx, req) }); lerr != nil {
		return lerr
	}
	return err
}

func (e loopEscrow) Status(ctx context.Context, escrowID string) (string, error) {
	var status string
	var err error
	if lerr := e.a.onLoop(e.ctx, func() { status, err = escrowClient{e.a}.Status(ctx, escrowID) }); lerr != nil {
		return "", lerr
	}
	return status, err
}
