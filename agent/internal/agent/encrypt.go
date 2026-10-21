package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
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
		// Without ctx's cancel, as on the worker: an agent stop must not kill an initrd rebuild halfway.
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

// startConversion runs at the agent's start, before anything else of the conversion: the removal of temporary initrds
// a killed regeneration left (PDK-375), the I2 check (an adopted
// conversion drops its preparation, plan M8e §14.10), the answer to an abort a restart interrupted, the reset of the
// background phase's failure count (decision 22: three relaunches per boot), and the re-queue of a preparation
// (decision 13) or of the converted disk's initrd work (decisions 18, 20 and 52).
func (a *Agent) startConversion(ctx context.Context) {
	if a.d.Encrypt == nil {
		return
	}
	if err := encrypt.RemoveStaleTemps(a.d.Encrypt, a.d.Layout); err != nil {
		slog.InfoContext(ctx, "temporary initrds of an interrupted regeneration not removed", "error", err)
	}
	if a.st.Conversion == nil {
		return
	}
	a.adoptConversion(ctx)
	a.answerAbort()
	c := a.st.Conversion
	if c.ResumeFailures != 0 {
		c.ResumeFailures = 0
		a.saveState()
	}
	if c.Phase == state.ConversionPreparing || converted(c) && !c.InitrdRegenerated && !a.conversionRevoked() {
		a.queueConversion()
	}
}

// converted reports whether the conversion's disk carries the LUKS header: encrypting or completed.
func converted(c *state.DiskConversion) bool {
	return c.Phase == state.ConversionEncrypting || c.Phase == state.ConversionCompleted
}

// adoptConversion is the I2 check of plan M8e §14.10 and decision 18 while the device holds a conversion: it reads
// the init step's result and lets the disk decide. A LUKS partition adopts a conversion that is not encrypting yet —
// a queued preparation is dropped, a pending cleanup ends, disk.conversion_started is emitted with the init step's
// result, and an unlock path a cleanup had removed is marked for its reinstall before anything else runs
// (ModuleRestorePending). A partition that is not LUKS after a failed or skipped init step fails the conversion at
// stage init and starts the cleanup of invariant I3 (initFailed). The result file is removed once acted on; while
// the header cannot be checked it stays for the next pass. It reports whether it adopted.
func (a *Agent) adoptConversion(ctx context.Context) bool {
	c := a.st.Conversion
	if c == nil {
		return false
	}
	boot, err := encrypt.ReadBootResult(a.d.Layout)
	if err != nil {
		slog.WarnContext(ctx, "the result of the init step is unreadable", "error", err)
	}
	// Before any look at the disk: this boot opened the converted disk through the module, so no "not LUKS" answer
	// leads to a cleanup until the next start (amendment 2026-10-21, item 13).
	a.bootConverted = a.bootConverted || boot != nil && boot.Status == encrypt.BootOK
	if converted(c) {
		a.notConverted(ctx, boot)
		a.dropBootResult(ctx, boot)
		return false
	}
	isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, encrypt.DiskOf(*c))
	if !ok {
		return false
	}
	if !isLUKS {
		a.initFailed(ctx, boot)
		return false
	}
	select {
	case <-a.conversionJobs:
		a.conversionBusy = false
	default:
	}
	now := a.d.Now().UTC()
	slog.WarnContext(ctx, "the root partition carries the conversion's LUKS header; adopting the conversion", "conversion_id", c.ID,
		"phase", c.Phase, "init_result", boot.InitResult())
	c.Phase, c.StartedAt, c.CleanupPending, c.CleanupError, c.AbortRequested, c.Notified = state.ConversionEncrypting, &now, false, "",
		false, nil
	c.PackagesBusySince = nil
	c.FailureStage, c.FailureReason = "", ""
	c.ModuleRestorePending = encrypt.ModuleMissing(a.d.Layout)
	data := map[string]any{"conversion_id": c.ID, "volume": c.LUKSUUID, "init_result": boot.InitResult()}
	if boot != nil && boot.Seconds >= 0 {
		data["init_s"] = boot.Seconds
	}
	a.event(protocol.EventDiskConversionStarted, data)
	a.answerAbort()
	a.saveState()
	a.dropBootResult(ctx, boot)
	return true
}

// initFailed handles the init step's result on a partition that is not LUKS (plan M8e decision 18): a failed or
// skipped init step fails a conversion waiting for its restart at stage init and starts the cleanup of invariant I3 —
// CleanupPending, retried by the worker at every full pass. A conversion in another phase (a stale initrd ran during
// an unfinished cleanup) keeps its phase; its cleanup goes on. Without a result nothing changes: the device has not
// restarted yet, or it booted from an initrd without the module.
func (a *Agent) initFailed(ctx context.Context, boot *encrypt.BootResult) {
	c := a.st.Conversion
	if boot == nil {
		return
	}
	defer a.dropBootResult(ctx, boot)
	if !boot.Failed() || (c.Phase != state.ConversionPreparing && c.Phase != state.ConversionPrepared) {
		slog.WarnContext(ctx, "the init step's result does not change the conversion", "conversion_id", c.ID, "phase", c.Phase,
			"init_result", boot.InitResult())
		return
	}
	select {
	case <-a.conversionJobs:
		a.conversionBusy = false
	default:
	}
	reason := boot.FailureReason()
	slog.WarnContext(ctx, "the init step did not convert the disk; the conversion failed", "conversion_id", c.ID, "reason", reason)
	c.Phase, c.FailureStage, c.FailureReason, c.CleanupPending, c.CleanupError, c.Notified = state.ConversionFailed, state.StageInit,
		reason, true, "", nil
	c.PackagesBusySince = nil
	a.event(protocol.EventDiskConversionFailed, map[string]any{"conversion_id": c.ID, "stage": state.StageInit, "reason": reason,
		"volume": c.LUKSUUID})
	a.answerAbort()
	a.saveState()
}

// notConverted is I2 for a conversion the state calls encrypting or completed (amendment 2026-10-21, items 11 and
// 13): when the partition is not LUKS on all of IsLUKS's evidence and the header cannot be dumped either, so that no
// single wrong answer starts a cleanup on a converted disk, the conversion fails at stage init with reason not_luks
// and the cleanup of invariant I3 runs on the worker. A boot result ok says the disk converted: never a cleanup then.
func (a *Agent) notConverted(ctx context.Context, boot *encrypt.BootResult) {
	c := a.st.Conversion
	if a.bootConverted {
		return
	}
	if isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, encrypt.DiskOf(*c)); !ok || isLUKS {
		return
	}
	if _, err := luks.Dump(ctx, encrypt.LUKSTools(a.d.Encrypt), c.Partition); err == nil {
		return
	}
	slog.ErrorContext(ctx, "the state says the disk converted, but the partition is not LUKS; the conversion failed",
		"conversion_id", c.ID, "phase", c.Phase)
	c.Phase, c.FailureStage, c.FailureReason, c.CleanupPending, c.CleanupError = state.ConversionFailed, state.StageInit,
		reasonNotLUKS, true, ""
	a.event(protocol.EventDiskConversionFailed, map[string]any{"conversion_id": c.ID, "stage": state.StageInit,
		"reason": reasonNotLUKS, "volume": c.LUKSUUID})
	a.saveState()
}

// reasonNotLUKS fails a conversion whose state says converted on a partition without a LUKS header.
const reasonNotLUKS = "not_luks"

// dropBootResult removes the init step's result once the agent acted on it.
func (a *Agent) dropBootResult(ctx context.Context, boot *encrypt.BootResult) {
	if boot == nil {
		return
	}
	if err := encrypt.RemoveBootResult(a.d.Layout); err != nil {
		slog.WarnContext(ctx, "removing the init step's result failed", "error", err)
	}
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

// tickConversion is the conversion's part of every full pass: the I2 check, then, on a converted disk, the background
// phase and the initrd work (tickConverted), else the retry of an unfinished cleanup (invariant I3) or of a
// preparation without a worker job (a transient tool error, or a failure whose save failed), queued on the conversion
// worker: dracut may run for LongTimeout and must not stall the run loop. A preparing conversion thus never waits for
// the next start, and an abort deferred meanwhile is answered by the worker.
func (a *Agent) tickConversion(ctx context.Context) {
	if a.d.Encrypt == nil || a.st.Conversion == nil {
		return
	}
	a.adoptConversion(ctx)
	c := a.st.Conversion
	if converted(c) {
		a.tickConverted(ctx)
		return
	}
	if a.conversionBusy {
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
		// Without ctx's cancel, as on the worker: an agent stop must not kill an initrd rebuild halfway.
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
	isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, encrypt.DiskOf(*c))
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
// conversion that is preparing, retries its unfinished cleanup, or does the initrd work of a converted disk
// (finishConversion). Every read and change of the agent state goes
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
		var conv state.DiskConversion
		var disk encrypt.Disk
		var finishCtx context.Context
		cleanup, finish, due := false, false, false
		if a.onLoop(ctx, func() {
			// No initrd work while a supervisor upgrade runs: its rollback restarts the supervisor and kills the agent and
			// its dracut (review 7, X1; amendment 2026-10-21, items 17 and 18). The next full pass retries, without a
			// backoff.
			due = !a.d.Now().Before(a.initrdRetryAt) && !a.supervisorMarkerFresh()
			switch c := a.st.Conversion; {
			case c != nil && c.Phase == state.ConversionPreparing:
				p = a.preparer(ctx)
			case c != nil && c.CleanupPending && !a.bootConverted:
				disk, cleanup = encrypt.DiskOf(*c), due
			case c != nil && converted(c) && !c.InitrdRegenerated && !a.conversionRevoked():
				conv, finish = *c, true
				// A revocation hand-over cancels the regeneration (handRevocations; PDK-374).
				finishCtx, a.finishCancel = context.WithCancel(context.WithoutCancel(ctx))
			}
		}) != nil {
			return
		}
		attempted, succeeded := false, false
		var workErr error
		if cleanup {
			attempted, succeeded, workErr = a.retryCleanup(ctx, disk)
		}
		if finish {
			attempted, succeeded, workErr = a.finishConversion(finishCtx, conv, due)
		}
		outcome := encrypt.Stopped
		if p != nil {
			outcome = p.Prepare(context.WithoutCancel(ctx))
		}
		if a.onLoop(ctx, func() {
			a.conversionBusy = false
			if a.finishCancel != nil {
				a.finishCancel()
				a.finishCancel = nil
			}
			if attempted {
				a.initrdAttempt(succeeded)
				a.recordInitrdIssue(workErr)
			}
			if finish && succeeded && a.st.Conversion != nil && a.st.Conversion.InitrdRegenerated {
				// The replaced initrds' freed blocks on /boot may still hold the conversion key until its keyslot is
				// wiped (RR-71): the luks pass that wipes it runs now, on the loop like every pass, not at the next one.
				a.tickLUKS(ctx, true)
			}
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

// finishConversion is the initrd work of a converted disk on the worker, while the initrd was not regenerated yet: the
// re-arm of the boot PIN dialogue while no TPM keyslot exists (plan M8e decision 52), the reinstall of an unlock path a
// cleanup had removed (decision 18), and, once a TPM keyslot exists, the initrd regeneration (decision 20). Nothing
// runs unless the partition is LUKS (invariant I1). A failure is logged; the next full pass queues the work again.
func (a *Agent) finishConversion(fctx context.Context, c state.DiskConversion, due bool) (attempted, succeeded bool, err error) {
	// Only the regeneration follows fctx (a revocation hand-over); the reinstall, which brings the unlock path back,
	// runs to its end.
	ctx := context.WithoutCancel(fctx)
	if isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, encrypt.DiskOf(c)); !isLUKS || !ok {
		return false, false, nil
	}
	md, err := luks.Dump(ctx, encrypt.LUKSTools(a.d.Encrypt), c.Partition)
	if err != nil {
		slog.WarnContext(ctx, "the converted volume's keyslots are unreadable; retrying at the next full pass", "error", err)
	}
	tpm := err == nil && encrypt.HasTPMKeyslot(md)
	if a.revokedSince(ctx) {
		return false, false, nil
	}
	if err == nil && !tpm {
		if armed, err := encrypt.RearmDiskSetup(a.d.Layout); err != nil {
			slog.ErrorContext(ctx, "re-arming the boot PIN dialogue failed", "error", err)
		} else if armed {
			slog.InfoContext(ctx, "the boot PIN is not set yet; the next start asks for it again", "conversion_id", c.ID)
		}
	}
	store := a.loopStore(ctx)
	if !due {
		return false, false, nil
	}
	if c.ModuleRestorePending {
		if err := encrypt.RestoreModule(ctx, a.d.Encrypt, a.d.Layout, a.d.EncryptModule); err != nil {
			slog.ErrorContext(ctx, "reinstalling the unlock path of the converted disk failed; retrying later", "conversion_id", c.ID,
				"error", err)
			return !errors.Is(err, encrypt.ErrPackagesBusy), false, err
		}
		if err := store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.ModuleRestorePending = false }); err != nil {
			slog.ErrorContext(ctx, "recording the reinstalled unlock path failed", "error", err)
			return true, false, nil
		}
		slog.InfoContext(ctx, "the unlock path of the converted disk is reinstalled in every initrd", "conversion_id", c.ID)
	}
	if !tpm {
		return c.ModuleRestorePending, true, nil
	}
	if a.revokedSince(ctx) {
		return false, false, nil
	}
	if err := encrypt.RegenerateInitrd(fctx, a.d.Encrypt, a.d.Layout, c.Mapping, c.LUKSUUID, c.Phase == state.ConversionCompleted); err != nil {
		slog.ErrorContext(ctx, "regenerating the initrd for the TPM unlock failed; retrying later", "conversion_id", c.ID, "error", err)
		return !errors.Is(err, encrypt.ErrPackagesBusy), false, err
	}
	if a.revokedSince(ctx) {
		return true, false, nil
	}
	if err := store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.InitrdRegenerated = true }); err != nil {
		slog.ErrorContext(ctx, "recording the regenerated initrd failed; retrying later", "error", err)
		return true, false, nil
	}
	slog.InfoContext(ctx, "initrd regenerated: the disk unlocks through the TPM, the conversion key left /boot", "conversion_id", c.ID)
	return true, true, nil
}

// revokedSince asks the run loop whether a revocation was handed over since the worker took its job (amendment
// 2026-10-21, item 10); a gone loop counts as revoked, so that nothing changes on a guess.
func (a *Agent) revokedSince(ctx context.Context) bool {
	revoked := true
	if a.onLoop(ctx, func() { revoked = a.conversionRevoked() }) != nil {
		return true
	}
	return revoked
}

// retryCleanup is the I3 retry of an unfinished cleanup on the worker — never while the partition is LUKS or its header
// cannot be checked (invariant I1).
func (a *Agent) retryCleanup(ctx context.Context, disk encrypt.Disk) (attempted, succeeded bool, err error) {
	if isLUKS, ok := encrypt.IsLUKS(ctx, a.d.Encrypt, a.d.Layout, disk); isLUKS || !ok {
		return false, false, nil
	}
	done, err := encrypt.RunCleanup(context.WithoutCancel(ctx), a.d.Encrypt, a.d.Layout, a.loopStore(ctx))
	// A package run holding dpkg's locks is no failure of the cleanup: it is retried at the next pass, not backed off.
	return !errors.Is(err, encrypt.ErrPackagesBusy), done, err
}

// Backoff of the initrd work (amendment 2026-10-21, items 16 and 17): every failed cleanup, reinstall or regeneration
// doubles the wait before the next attempt, so that a device whose initrds never pass does not hold dpkg's locks at
// every full pass. A package run holding the locks is no failure: the next pass tries again.
const (
	initrdRetryFirst = 5 * time.Minute
	initrdRetryMax   = 6 * time.Hour
)

// recordInitrdIssue keeps why the initrd work cannot go on in the conversion's state for the health (amendment
// 2026-10-21, item 19): boot_space_low with the bytes needed and free, kernel_not_buildable, no_bootable_kernel,
// key_material_hardlinked or key_material_shared_bootable; any other outcome clears
// it. It runs on the loop.
func (a *Agent) recordInitrdIssue(err error) {
	c := a.st.Conversion
	if c == nil {
		return
	}
	issue, needed, free, kernel := "", int64(0), int64(0), ""
	var space *encrypt.BootSpaceError
	var notBuildable *encrypt.KernelNotBuildableError
	var hardlinked *encrypt.KeyMaterialHardlinkedError
	var shared *encrypt.KeySharedBootableError
	switch {
	case errors.As(err, &shared):
		issue, kernel = encrypt.IssueKeyMaterialSharedBootable, shared.Kernel
	case errors.As(err, &hardlinked):
		issue = encrypt.IssueKeyMaterialHardlinked
	case errors.As(err, &space):
		issue, needed, free = encrypt.IssueBootSpaceLow, space.Needed, space.Free
	case errors.As(err, &notBuildable):
		issue, kernel = encrypt.IssueKernelNotBuildable, notBuildable.Version
	case errors.Is(err, encrypt.ErrNoBootableKernel):
		issue = encrypt.IssueNoBootableKernel
	case c.InitrdIssue == encrypt.IssueOrphanInitrdRemoved:
		return // reported once, until the conversion ends
	}
	if c.InitrdIssue == issue && c.BootSpaceNeeded == needed && c.BootSpaceFree == free && c.InitrdIssueKernel == kernel {
		return
	}
	c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = issue, needed, free, kernel
	a.saveState()
}

// initrdAttempt records the outcome of an attempt of the initrd work; it runs on the loop.
func (a *Agent) initrdAttempt(succeeded bool) {
	if succeeded {
		a.initrdFailures, a.initrdRetryAt = 0, time.Time{}
		return
	}
	a.initrdFailures++
	wait := initrdRetryMax
	if a.initrdFailures <= 10 {
		wait = min(initrdRetryFirst<<(a.initrdFailures-1), initrdRetryMax)
	}
	a.initrdRetryAt = a.d.Now().Add(wait)
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
		State: a.loopStore(ctx), Module: a.d.EncryptModule, TestHooks: buildinfo.Dev, Now: a.d.Now,
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
		if !a.supervisorMarkerFresh() {
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

// supervisorMarkerFresh reports whether supervisor-upgrade.json exists and is younger than supervisorpkg.StaleAfter
// from the marker's start (its mtime when it is unreadable).
func (a *Agent) supervisorMarkerFresh() bool {
	marker, err := supervisorpkg.ReadMarker(a.d.Layout)
	var started time.Time
	switch {
	case marker != nil:
		started = marker.StartedAt
	case err == nil:
		return false
	default:
		info, serr := os.Stat(a.d.Layout.SupervisorUpgrade())
		if serr != nil {
			return false
		}
		started = info.ModTime()
	}
	return a.d.Now().Sub(started) < supervisorpkg.StaleAfter
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

// The background reencryption helper (plan M8e decision 21, §14.3 decision 30).
const (
	resumeUnitName = "paddock-encrypt-resume"
	// resumeSlot is the agent's current slot the helper runs from; resumeBinary is the helper systemd starts.
	resumeSlot   = "/opt/paddock/agent/current"
	resumeBinary = resumeSlot + "/paddockd"
	// maxResumeFailures is how many failed results a boot relaunches the helper after (decision 22).
	maxResumeFailures = 3
	// helperStopWait bounds the stop of the helper before a revocation hand-over (§14.5 decision 39).
	helperStopWait = 60 * time.Second
	helperStopPoll = time.Second
)

// tickConverted is the full pass of a converted disk (plan M8e decisions 20 to 22): the helper's result, the helper's
// launch while encrypting, the initrd work on the worker while the initrd was not regenerated, and the end of the
// conversion.
func (a *Agent) tickConverted(ctx context.Context) {
	a.recordResumeResult(ctx)
	c := a.st.Conversion
	if c.Phase == state.ConversionEncrypting {
		a.tickResume(ctx)
	}
	// After a revocation hand-over the keyslots may be erased: no PIN re-arm or rebuild for a locked disk.
	if !c.InitrdRegenerated && !a.conversionBusy && !a.conversionRevoked() {
		a.queueConversion()
	}
	a.clearConversion(ctx)
}

// recordResumeResult reads result.json (plan M8e decision 22): completed ends the background phase — only
// progress.json and result.json are removed (invariant I1) — and failed counts a failure of this boot; the phase
// stays encrypting, the header stays recoverable. Each is recorded with its event once.
func (a *Agent) recordResumeResult(ctx context.Context) {
	r, err := encrypt.ReadResult(a.d.Layout)
	if err != nil {
		slog.ErrorContext(ctx, "the result of the background reencryption is unreadable; it is discarded", "error", err)
		if err := encrypt.RemoveResult(a.d.Layout); err != nil {
			slog.ErrorContext(ctx, "removing the result of the background reencryption failed", "error", err)
		}
		return
	}
	if r == nil {
		return
	}
	a.helperLaunched = false
	encrypting := a.st.Conversion.Phase == state.ConversionEncrypting && !a.conversionRevoked()
	switch {
	case r.Outcome == encrypt.OutcomeCompleted && encrypting:
		if !a.completeConversion(ctx, r) {
			return
		}
	case r.Outcome == encrypt.OutcomeFailed && encrypting:
		if !a.resumeFailed(ctx, r.Reason) {
			return
		}
		a.helperLaunched = false
		if err := encrypt.RemoveResult(a.d.Layout); err != nil {
			slog.ErrorContext(ctx, "removing the result of the background reencryption failed", "error", err)
		}
		return
	}
	if err := encrypt.RemoveProgress(a.d.Layout); err != nil {
		slog.ErrorContext(ctx, "removing the progress of the background reencryption failed", "error", err)
	}
}

// reasonNoResult is a helper run that ended without a result (killed, or its result could not be written).
const reasonNoResult = "resume_no_result"

// resumeFailed records a failed run of the helper (decision 22): one failure of this start toward
// maxResumeFailures, reported with stage resume; the phase stays encrypting. It reports whether the state was saved.
func (a *Agent) resumeFailed(ctx context.Context, reason string) bool {
	if err := a.directStore().Transition(func(c *state.DiskConversion, _ *state.LUKS) *encrypt.Event {
		c.ResumeFailures++
		return &encrypt.Event{Type: protocol.EventDiskConversionFailed, Data: map[string]any{"conversion_id": c.ID,
			"stage": state.StageResume, "reason": reason, "volume": c.LUKSUUID}}
	}); err != nil {
		slog.ErrorContext(ctx, "recording the failed background reencryption failed", "error", err)
		return false
	}
	slog.WarnContext(ctx, "the background reencryption failed", "reason", reason, "failures", a.st.Conversion.ResumeFailures)
	return true
}

// completeConversion records the end of the background phase; r is nil when the helper left no result (the
// reencryption finished without it). It reports whether the state was saved.
func (a *Agent) completeConversion(ctx context.Context, r *encrypt.Result) bool {
	now := a.d.Now().UTC()
	if err := a.directStore().Transition(func(c *state.DiskConversion, _ *state.LUKS) *encrypt.Event {
		data := map[string]any{"conversion_id": c.ID, "volume": c.LUKSUUID, "data_bytes": c.DataBytes}
		at := now
		if r != nil {
			if r.DataBytes > 0 {
				data["data_bytes"] = r.DataBytes
			}
			data["duration_s"] = r.DurationS
			if !r.FinishedAt.IsZero() {
				at = r.FinishedAt.UTC()
			}
		}
		c.Phase, c.CompletedAt = state.ConversionCompleted, &at
		return &encrypt.Event{Type: protocol.EventDiskConversionCompleted, Data: data}
	}); err != nil {
		slog.ErrorContext(ctx, "recording the completed reencryption failed", "error", err)
		return false
	}
	slog.InfoContext(ctx, "the background reencryption completed", "conversion_id", a.st.Conversion.ID)
	return true
}

// tickResume launches the helper of the background phase (plan M8e decision 21) while the disk carries the reencrypt
// keyslot and its unit is not running — not before an unlock path a cleanup removed is reinstalled (decision 18),
// not after maxResumeFailures failed results of this boot (decision 22), not while a revocation handed over within
// 24 hours may run (§14.5 decision 39), and only from a slot that is not mounted noexec (§14.3 decision 30). A disk
// without the reencrypt keyslot and without a result completed without the helper.
func (a *Agent) tickResume(ctx context.Context) {
	c := a.st.Conversion
	running, known := a.helperActive(ctx)
	if a.helperRunning = running; running {
		// Only a unit seen running counts as launched: an unknown answer must not turn into a failure (review 2, m5).
		a.helperLaunched = a.helperLaunched || known
		return
	}
	if a.helperLaunched {
		// The helper ended since the last pass; a result it wrote meanwhile is recorded first.
		a.recordResumeResult(ctx)
		if a.helperLaunched {
			a.helperLaunched = false
			if !a.conversionRevoked() && !a.resumeFailed(ctx, reasonNoResult) {
				return
			}
		}
		if a.st.Conversion.Phase != state.ConversionEncrypting {
			return
		}
	}
	md, err := luks.Dump(ctx, encrypt.LUKSTools(a.d.Encrypt), c.Partition)
	if err != nil {
		slog.WarnContext(ctx, "the converted volume's keyslots are unreadable; the helper is not launched", "error", err)
		return
	}
	if !md.Reencrypting() {
		if a.conversionRevoked() {
			// A Lock erased the keyslots, or will: that is no completion.
			return
		}
		a.recordResumeResult(ctx)
		if a.st.Conversion.Phase == state.ConversionEncrypting && a.completeConversion(ctx, nil) {
			if err := encrypt.RemoveProgress(a.d.Layout); err != nil {
				slog.ErrorContext(ctx, "removing the progress of the background reencryption failed", "error", err)
			}
		}
		return
	}
	switch {
	case c.ModuleRestorePending:
		return
	case c.ResumeFailures >= maxResumeFailures:
		if !a.helperLimitLogged {
			slog.ErrorContext(ctx, "the background reencryption failed too often; it resumes after the next start",
				"failures", c.ResumeFailures)
			a.helperLimitLogged = true
		}
		return
	case a.conversionRevoked():
		return
	}
	dir, err := filepath.EvalSymlinks(a.d.Layout.Join(resumeSlot))
	noexec := false
	if err == nil {
		noexec, err = a.d.NoExec(dir)
	}
	if err != nil || noexec {
		if !a.helperNoExecLogged {
			slog.ErrorContext(ctx, "the background reencryption helper cannot run from the agent's slot", "dir", dir, "noexec", noexec,
				"error", err)
			a.helperNoExecLogged = true
		}
		return
	}
	if err := a.d.RunUnit(ctx, "systemd-run", "--unit", resumeUnitName, "--collect", "--no-block", "--property=KillMode=mixed",
		"--property=Nice=10", "--property=IOSchedulingClass=idle", resumeBinary, "encrypt-resume", "--partition", c.Partition); err != nil {
		slog.WarnContext(ctx, "launching the background reencryption failed; retrying at the next full pass", "error", err)
		return
	}
	a.helperRunning, a.helperLaunched = true, true
	slog.InfoContext(ctx, "background reencryption launched", "conversion_id", c.ID)
}

// conversionRevoked reports whether a revocation was handed to paddock-revoke after the conversion started encrypting
// (amendment 2026-10-21, item 10): the conversion is terminal on the device then — no relaunch of the helper, no
// completion, no PIN re-arm or rebuild — until its state is cleared. RevokedAt records it at the hand-over; the
// comparison with HandedRevocations covers a hand-over recorded before this agent version.
func (a *Agent) conversionRevoked() bool {
	c := a.st.Conversion
	if c == nil || c.StartedAt == nil {
		return false
	}
	if c.RevokedAt != nil {
		return true
	}
	for _, at := range a.st.HandedRevocations {
		if !at.Before(*c.StartedAt) {
			return true
		}
	}
	return false
}

// helperActive reports whether the helper's unit runs (or starts or stops). Only "inactive" or "failed" on stdout say
// it does not; any other answer — a systemctl that fails, empty output (no bus), a state systemd adds later — is
// unknown (known false) and counts as running, so that no second helper is launched and no run is counted failed on a
// guess (amendment 2026-10-21, item 14).
func (a *Agent) helperActive(ctx context.Context) (running, known bool) {
	out, _, _, err := a.d.Encrypt.Command(ctx, "systemctl", "is-active", encrypt.ResumeUnit)
	if err != nil {
		slog.WarnContext(ctx, "the state of the background reencryption is unknown", "error", err)
		return true, false
	}
	switch unit := strings.TrimSpace(out); {
	case unitStopped(unit):
		return false, true
	case unitRunning(unit):
		return true, true
	default:
		slog.WarnContext(ctx, "the state of the background reencryption is unknown", "is-active", unit)
		return true, false
	}
}

// unitRunning reports whether a systemctl is-active answer is a unit that runs, starts or stops.
func unitRunning(state string) bool {
	switch state {
	case "active", "activating", "deactivating", "reloading", "refreshing":
		return true
	}
	return false
}

// unitStopped reports whether a systemctl is-active answer says the unit does not run.
func unitStopped(state string) bool { return state == "inactive" || state == "failed" }

// stopResumeHelper stops the background reencryption before a revocation is handed over (plan M8e §14.5 decision 39):
// SIGTERM is safe for cryptsetup reencrypt. It waits at most helperStopWait for the unit to leave active; a missing
// unit is no error. The caller hands over in any case: the Lock always wins over the helper.
func (a *Agent) stopResumeHelper(ctx context.Context) {
	if a.d.Encrypt == nil {
		return
	}
	if _, stderr, exit, err := a.d.Encrypt.Command(ctx, "systemctl", "stop", "--no-block", encrypt.ResumeUnit); err != nil ||
		(exit != 0 && exit != 5) {
		slog.WarnContext(ctx, "stopping the background reencryption failed", "exit", exit, "error", err, "stderr", strings.TrimSpace(stderr))
	}
	deadline := a.d.Now().Add(helperStopWait)
	for {
		out, _, _, err := a.d.Encrypt.Command(ctx, "systemctl", "is-active", encrypt.ResumeUnit)
		unit := strings.TrimSpace(out)
		if err == nil && unitStopped(unit) {
			a.helperRunning = false
			return
		}
		if !a.d.Now().Before(deadline) {
			slog.WarnContext(ctx, "the background reencryption did not stop in time; handing the revocation over anyway", "unit", unit,
				"error", err)
			return
		}
		if err := a.d.Sleep(ctx, helperStopPoll); err != nil {
			return
		}
	}
}

// clearConversion ends a conversion (plan M8e decision 22): once the initrd was regenerated and the disk reports
// compliant or escrow_pending after completed, the state is cleared; decision 3's hold has ended with the regeneration.
func (a *Agent) clearConversion(ctx context.Context) {
	c := a.st.Conversion
	if c == nil || c.Phase != state.ConversionCompleted || !c.InitrdRegenerated || c.CleanupPending {
		return
	}
	disk := a.d.Health.Report().Disk
	if disk == nil || (disk.State != protocol.DiskCompliant && disk.State != protocol.DiskEscrowPending) {
		return
	}
	// plan.json stays while a regeneration during encrypting left it for the helper (decision 21).
	if err := os.Remove(a.d.Layout.EncryptPlan()); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.ErrorContext(ctx, "removing the conversion plan failed; retrying at the next full pass", "error", err)
		return
	}
	slog.InfoContext(ctx, "in-place encryption finished", "conversion_id", c.ID, "disk", disk.State)
	a.st.Conversion = nil
	a.saveState()
}

// conversionHealth is the conversion's part of health.disk (plan M8e decisions 22 and 52): the phase, key_on_boot from
// prepared until the initrd was regenerated, and while encrypting the progress of progress.json, paused with
// helper_not_running while the helper's unit does not run.
func (a *Agent) conversionHealth() *protocol.DiskConversion {
	c := a.st.Conversion
	if c == nil {
		return nil
	}
	h := &protocol.DiskConversion{Phase: c.Phase, Layout: c.Layout, DataBytes: c.DataBytes,
		KeyOnBoot: !c.InitrdRegenerated && (c.Phase == state.ConversionPrepared || converted(c))}
	if c.CleanupPending {
		h.CleanupError = c.CleanupError
	}
	h.InitrdIssue, h.BootSpaceNeeded, h.BootSpaceFree, h.InitrdIssueKernel = c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree,
		c.InitrdIssueKernel
	if c.Phase == state.ConversionPreparing && c.PackagesBusySince != nil {
		at := *c.PackagesBusySince
		h.PausedReason, h.PausedSince = encrypt.PausedPackagesBusy, &at
	}
	if c.Phase != state.ConversionEncrypting {
		return h
	}
	p, err := encrypt.ReadProgress(a.d.Layout)
	if err != nil {
		slog.Warn("the progress of the background reencryption is unreadable", "error", err)
	}
	if p != nil {
		h.DoneBytes, h.ETASeconds, h.PausedReason = p.DoneBytes, p.ETASeconds, p.PausedReason
		if p.DataBytes > 0 {
			h.DataBytes = p.DataBytes
		}
		at := p.UpdatedAt
		h.UpdatedAt = &at
	}
	if !a.helperRunning {
		h.PausedReason = encrypt.PausedHelperNotRunning
	}
	return h
}
