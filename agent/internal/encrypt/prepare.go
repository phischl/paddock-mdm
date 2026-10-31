package encrypt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// The dracut files of a conversion (plan M8e decisions 13 and 15).
const (
	// ModuleDir is the module the embedded files are written to.
	ModuleDir = "/usr/lib/dracut/modules.d/99paddock-encrypt"
	// ModuleConf adds the module to every initrd dracut builds while plan.env exists.
	ModuleConf = "/etc/dracut.conf.d/91-paddock-encrypt.conf"
	// TPM2Conf is the dracut configuration of the autoinstall (plan M4b), written when absent.
	TPM2Conf   = "/etc/dracut.conf.d/90-paddock-tpm2.conf"
	moduleName = "paddock-encrypt"
)

// moduleConf is the content of ModuleConf.
const moduleConf = "add_dracutmodules+=\" " + moduleName + " \"\n"

// tpm2Conf is the content of TPM2Conf: exactly the three lines of the 24.04 autoinstall template.
const tpm2Conf = "# Paddock: unlock LUKS with systemd-cryptsetup and TPM2+PIN (plan M4b)\nhostonly=\"yes\"\n" +
	"add_dracutmodules+=\" systemd crypt tpm2-tss lvm \"\n"

// Timing of the preparation: the escrow is polled like the luks reconciler's (reconcile.LUKSPollInterval and
// LUKSEscrowWait); apt-get install and dracut are bounded like every package run (reconcile.PackageTimeout).
const (
	EscrowPoll  = 30 * time.Second
	EscrowWait  = 15 * time.Minute
	LongTimeout = 15 * time.Minute
)

// Defaults of the disk setup when the applied bundle carries no disk policy (plan M8e decision 13 step 2).
const (
	DefaultBootPINMinLength = 8
	DefaultUnlockMode       = bundle.UnlockModeTPMPIN
)

// Failure reasons of the preparation (plan M8e decision 13, §14.4), a closed set besides the first stderr line of a
// tool. The ones with a colon carry a list after it.
const (
	ReasonNotEligible          = "not_eligible"
	ReasonEscrowNotStored      = "escrow_not_stored"
	ReasonDracutInstallFailed  = "dracut_install_failed"
	ReasonDracutRemoves        = "dracut_removes"
	ReasonDracutRemovedDiffers = "dracut_removed_differs"
	ReasonInitrdIncomplete     = "initrd_incomplete"
)

// dracutRemovable is the allow list of packages installing dracut may remove (plan M8e decision 33).
var dracutRemovable = []string{"brltty", "initramfs-tools", "initramfs-tools-bin", "initramfs-tools-core"}

// recoveryAlphabet is systemd-cryptenroll's modhex alphabet of recovery keys.
const recoveryAlphabet = "cbdefghijklnrtuv"

// Escrow uploads escrows of the device and polls their status (device API).
type Escrow interface {
	Upload(ctx context.Context, req escrow.Request) error
	Status(ctx context.Context, escrowID string) (string, error)
}

// Outcome is how a preparation ended.
type Outcome int

// Outcomes of Prepare.
const (
	// Stopped: ctx ended, or the conversion is gone or no longer preparing (adopted); the next start re-queues it.
	Stopped Outcome = iota
	Prepared
	Failed
	// Aborted: an encrypt_disk_abort was received while preparing (decision 27); the conversion is cancelled.
	Aborted
)

// Preparer prepares the device for the conversion at its next restart (plan M8e decision 13).
type Preparer struct {
	Sys    Host
	Layout paths.Layout
	Escrow Escrow
	// Keys and Disk are the applied bundle's: the escrow key and the disk policy.
	Keys  *bundle.Keys
	Disk  *bundle.DiskSpec
	State Store
	// Module is the embedded dracut module (agent/internal/encrypt/dracut); its files are written as they are.
	Module fs.FS
	// TestHooks writes the marker that lets the init script honour the test delays (plan M8e decision 19); only a
	// dev build (buildinfo.Dev) sets it.
	TestHooks bool
	// ReportNeutralize receives the outcome of the disarm of an abort requested while preparing (Abort) and of a
	// failed preparation (fail); nil reports a failure itself.
	ReportNeutralize NeutralizeReport
	// Hold returns once no supervisor upgrade runs (plan M8e decision 37); nil holds nothing.
	Hold  func(ctx context.Context) error
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// layout is the preflight of step 1, used by step 2 in the same run.
	layout *Layout
}

// failure is a step that failed with a reason of the closed set.
type failure struct{ reason string }

func (f *failure) Error() string { return f.reason }

// TransientRetries is how many passes a preparation is retried after a transient tool error before it fails: dpkg
// that cannot answer during unattended-upgrades or a dracut run that failed once must not end a conversion for good.
const TransientRetries = 3

// transient is a tool error outside the closed set of reasons; the preparation is retried at the next full pass.
type transient struct{ err error }

func (t *transient) Error() string { return t.err.Error() }
func (t *transient) Unwrap() error { return t.err }

// errBusy is a step that waits for a package run holding dpkg's locks: the next full pass runs it again, and the wait
// counts toward no retry (an apt run may hold the locks for many minutes).
var errBusy = errors.New("a package run holds the dpkg lock")

// errWait is a step that waits for room in /boot or a buildable kernel: the next full pass runs it again, and the wait
// counts toward no retry; unlike errBusy it is no wait for dpkg's locks (review 10, M6).
var errWait = errors.New("the initrd cannot be built yet")

// errStop ends a preparation that the next start re-queues.
var errStop = errors.New("preparation stopped")

// errAbortRequested ends a step that saw an abort requested after the check before it; the abort runs instead.
var errAbortRequested = errors.New("abort requested")

// Prepare runs the steps of decision 13 in order. Every step is idempotent: an agent restarted while preparing runs
// Prepare again and the steps skip what exists. Before every step it waits for a running supervisor upgrade, and an
// abort requested meanwhile runs Abort instead of the step. A transient tool error stops the run until the next full
// pass, at most TransientRetries times. A failing step sets the phase failed with stage prepare and emits
// disk.conversion_failed; once step 7 started (the module files may exist) the cleanup of Abort follows (fail).
func (p *Preparer) Prepare(ctx context.Context) Outcome {
	steps := []func(context.Context, state.DiskConversion) error{p.preflight, p.plan, p.key, p.escrow, p.diskSetup,
		p.dracut, p.module, p.initrd, p.prepared}
	for i, step := range steps {
		if p.Hold != nil {
			if err := p.Hold(ctx); err != nil {
				return Stopped
			}
		}
		c, ok := p.State.Conversion()
		if !ok || c.Phase != state.ConversionPreparing {
			return Stopped
		}
		if c.AbortRequested {
			return p.abort(ctx, c)
		}
		if p.converted(ctx, c) {
			return Stopped
		}
		err := step(ctx, c)
		if err == nil {
			continue
		}
		if errors.Is(err, errAbortRequested) {
			return p.abort(ctx, c)
		}
		if errors.Is(err, errStop) || ctx.Err() != nil {
			return Stopped
		}
		if errors.Is(err, errWait) {
			slog.InfoContext(ctx, "the preparation waits until the initrds can be built", "conversion_id", c.ID, "step", i+1)
			return Stopped
		}
		if errors.Is(err, errBusy) {
			slog.InfoContext(ctx, "the preparation waits for a package run that holds the dpkg lock", "conversion_id", c.ID, "step", i+1)
			if c.PackagesBusySince == nil {
				now := p.Now().UTC()
				if err := p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.PackagesBusySince = &now }); err != nil {
					slog.ErrorContext(ctx, "recording the wait for the dpkg lock failed", "error", err)
				}
			}
			return Stopped
		}
		var t *transient
		if errors.As(err, &t) && c.TransientErrors < TransientRetries {
			return p.retry(ctx, c, i+1, err)
		}
		reason := firstLine(err.Error())
		var f *failure
		if errors.As(err, &f) {
			reason = cut(f.reason)
		}
		return p.fail(ctx, c, i+1, reason)
	}
	return Prepared
}

// converted reports whether the partition of a planned conversion is LUKS or its header cannot be checked: no step
// runs then (invariants I1 and I2) — the disk converted at a boot and the worker adopts the conversion, or the next
// full pass looks again.
func (p *Preparer) converted(ctx context.Context, c state.DiskConversion) bool {
	if c.Partition == "" {
		return false
	}
	luks, ok := IsLUKS(ctx, p.Sys, p.Layout, DiskOf(c))
	if luks || !ok {
		slog.WarnContext(ctx, "the partition is LUKS or its header cannot be checked; the preparation stops", "conversion_id", c.ID,
			"luks", luks)
		return true
	}
	return false
}

// retry counts the transient error of step n and stops; the worker queues the preparation again at the next full
// pass. An abort requested during the step runs instead.
func (p *Preparer) retry(ctx context.Context, c state.DiskConversion, n int, cause error) Outcome {
	slog.WarnContext(ctx, "in-place encryption preparation step failed; retrying at the next full pass", "conversion_id", c.ID,
		"step", n, "retry", c.TransientErrors+1, "error", cause)
	if err := p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.TransientErrors++ }); err != nil {
		slog.ErrorContext(ctx, "recording the retry of the preparation failed", "error", err)
	}
	if cur, ok := p.State.Conversion(); ok && cur.Phase == state.ConversionPreparing && cur.AbortRequested {
		return p.abort(ctx, cur)
	}
	return Stopped
}

// abort runs the abort requested while preparing (decision 27); Stopped when Abort refused, which the caller answers.
func (p *Preparer) abort(ctx context.Context, c state.DiskConversion) Outcome {
	if aborted, _ := Abort(ctx, p.Sys, p.Layout, p.State, c.ID, ByAdmin, true, p.ReportNeutralize); aborted {
		return Aborted
	}
	return Stopped
}

// fail records the failure of step n and, once step 7 started in this or an earlier run, disarms the initrds (Disarm,
// PDK-579) and cleans up under invariant I3.
// It never cleans up a partition that is LUKS (invariants I1 and I2): the disk converted at a boot, so the failure is
// not recorded and the worker adopts the conversion (Stopped). While the header cannot be checked the failure is
// recorded with CleanupPending and the cleanup is left to the retry of a full pass. A failure whose save failed is not
// recorded either (Stopped): the conversion stays preparing and the worker queues it again at the next full pass.
func (p *Preparer) fail(ctx context.Context, c state.DiskConversion, n int, reason string) Outcome {
	slog.WarnContext(ctx, "in-place encryption preparation failed", "conversion_id", c.ID, "step", n, "reason", reason)
	cleanup := n >= 7 || c.ModuleWritten
	runCleanup := cleanup
	if cleanup {
		luks, ok := IsLUKS(ctx, p.Sys, p.Layout, DiskOf(c))
		if luks {
			slog.WarnContext(ctx, "the partition is LUKS already; adopting the conversion instead of cleaning up", "conversion_id", c.ID)
			return Stopped
		}
		runCleanup = ok
	}
	if err := p.State.Transition(func(c *state.DiskConversion, _ *state.LUKS) *Event {
		c.Phase, c.FailureStage, c.FailureReason, c.CleanupPending = state.ConversionFailed, state.StagePrepare, reason, cleanup
		c.CleanupError, c.PackagesBusySince = "", nil
		return &Event{protocol.EventDiskConversionFailed, map[string]any{"conversion_id": c.ID, "stage": state.StagePrepare,
			"reason": reason, "volume": c.LUKSUUID}}
	}); err != nil {
		slog.ErrorContext(ctx, "recording the failed preparation failed; retrying at the next full pass", "error", err)
		// An abort deferred while the step ran is run now rather than answered not_abortable by the worker (decision 27).
		if cur, ok := p.State.Conversion(); ok && cur.Phase == state.ConversionPreparing && cur.AbortRequested {
			return p.abort(ctx, cur)
		}
		return Stopped
	}
	if runCleanup {
		// Before the cleanup, which can fail, be killed or wait for dpkg's locks: an initrd built since step 7 wrote the
		// module still converts the disk at a restart (plan M8e item 18, amendment 2026-10-30, PDK-579).
		neutralize(ctx, p.Sys, p.Layout, p.State, p.ReportNeutralize)
		_, _ = RunCleanup(ctx, p.Sys, p.Layout, p.State) // logged; a later full pass retries
	}
	return Failed
}

// preflight is step 1: the preflight again (decision 2) and dm_crypt (decision 7). It is skipped with step 2 once
// the plan of this conversion exists.
func (p *Preparer) preflight(ctx context.Context, c state.DiskConversion) error {
	if plan, err := ReadPlan(p.Layout); err == nil && plan != nil && plan.ConversionID == c.ID {
		return nil
	}
	l := Preflight(ctx, p.Sys, p.Layout.Root, false)
	reasons := l.Reasons
	if !p.dmCrypt(ctx) {
		reasons = append(slices.Clone(reasons), ReasonDMCryptMissing)
		slices.Sort(reasons)
	}
	if len(reasons) > 0 {
		return &failure{ReasonNotEligible + ":" + strings.Join(reasons, "+")}
	}
	p.layout = &l
	return nil
}

// dmCrypt reports whether the kernel has dm_crypt (/sys/module/dm_crypt, else modprobe dm_crypt).
func (p *Preparer) dmCrypt(ctx context.Context) bool {
	if ok, err := p.Sys.Stat(p.Layout.Join("/sys/module/dm_crypt")); err == nil && ok {
		return true
	}
	_, _, exit, err := p.Sys.Command(ctx, "modprobe", "dm_crypt")
	return err == nil && exit == 0
}

// plan is step 2: the LUKS UUID, the mapping name and the targets, written to plan.json and then recorded in the
// state. A plan of this conversion that exists already is recorded again: a run stopped between the two left the
// state without its partition and LUKS UUID, and invariants I1 and I2 and the escrow's volume need them.
func (p *Preparer) plan(ctx context.Context, c state.DiskConversion) error {
	if existing, err := ReadPlan(p.Layout); err == nil && existing != nil && existing.ConversionID == c.ID {
		if c.Partition == existing.Partition && c.LUKSUUID == existing.LUKSUUID && c.Layout == existing.Layout &&
			c.Mapping == existing.Mapping && c.DataBytes == existing.DataBytes {
			return nil
		}
		return p.recordPlan(*existing)
	}
	l := p.layout
	if l == nil {
		return errors.New("no preflight for the plan")
	}
	luksUUID, err := newUUID()
	if err != nil {
		return err
	}
	mapping, err := p.mapping()
	if err != nil {
		return err
	}
	plan := Plan{ConversionID: c.ID, Layout: l.Kind, Partition: l.Partition, PartUUID: l.PartUUID, LUKSUUID: luksUUID,
		Mapping: mapping, VG: l.VG, LV: l.LV, FSUUID: l.FSUUID, UnlockMode: DefaultUnlockMode,
		BootPINMinLength: DefaultBootPINMinLength, CreatedAt: p.Now().UTC()}
	if p.Disk != nil {
		if p.Disk.UnlockMode != "" {
			plan.UnlockMode = p.Disk.UnlockMode
		}
		if p.Disk.BootPINMinLength > 0 {
			plan.BootPINMinLength = p.Disk.BootPINMinLength
		}
	}
	if err := targets(ctx, p.Sys, &plan); err != nil {
		return err
	}
	if _, err := plan.Env(); err != nil {
		return err
	}
	if err := writePlan(p.Layout, plan); err != nil {
		return err
	}
	return p.recordPlan(plan)
}

// recordPlan copies what the conversion's state keeps of plan into it.
func (p *Preparer) recordPlan(plan Plan) error {
	return p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) {
		c.Layout, c.LUKSUUID, c.Mapping, c.Partition, c.DataBytes = plan.Layout, plan.LUKSUUID, plan.Mapping, plan.Partition, plan.DataBytes
	})
}

// mapping is dm_crypt-<n> with the smallest n whose /dev/mapper/<name> does not exist.
func (p *Preparer) mapping() (string, error) {
	for n := 0; n < 1000; n++ {
		name := "dm_crypt-" + strconv.Itoa(n)
		ok, err := p.Sys.Stat(p.Layout.Join("/dev/mapper/" + name))
		if err != nil {
			return "", err
		}
		if !ok {
			return name, nil
		}
	}
	return "", errors.New("no free dm_crypt mapping name")
}

// key is step 3: the conversion key, 32 random bytes as 64 modhex characters in 8 groups of 8, 0600 without a newline,
// generated only when the file does not exist (decision 13 step 3). An existing key is kept even when its escrow did
// not finish: step 4 escrows it under the next generation, so a rerun never creates a second key.
func (p *Preparer) key(_ context.Context, c state.DiskConversion) error {
	_, err := os.Stat(p.Layout.InstallPassphrase())
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if c.KeyEscrowGeneration > 0 {
		// The stored key is gone: the new one must be escrowed again.
		if err := p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.KeyEscrowGeneration = 0 }); err != nil {
			return err
		}
	}
	key, err := NewConversionKey()
	if err != nil {
		return err
	}
	return fsutil.WriteFile(p.Layout.InstallPassphrase(), []byte(key), 0o600, 0o700)
}

// NewConversionKey returns a conversion key in the systemd-cryptenroll recovery-key format (71 characters).
func NewConversionKey() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	var b strings.Builder
	for i, v := range raw {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(recoveryAlphabet[v>>4])
		b.WriteByte(recoveryAlphabet[v&0x0f])
	}
	return b.String(), nil
}

// escrow is step 4: the conversion key is uploaded as the next recovery key generation of the root volume and the
// step waits until the server stored it. Nothing after it runs before stored. A key the server did not store is
// shredded; the next attempt generates a new one with a new generation.
func (p *Preparer) escrow(ctx context.Context, c state.DiskConversion) error {
	if c.KeyEscrowGeneration > 0 {
		return nil
	}
	if c.LUKSUUID == "" {
		return errors.New("the conversion has no LUKS UUID to escrow its key for")
	}
	pub, version, err := escrowKey(p.Keys)
	if err != nil {
		return p.notStored(ctx, err)
	}
	key, err := os.ReadFile(p.Layout.InstallPassphrase())
	if err != nil {
		return err
	}
	ct, err := escrow.Encrypt(pub, key)
	clear(key)
	if err != nil {
		return p.notStored(ctx, err)
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	var generation int64
	// The generation is recorded before the upload, as the luks reconciler does: a generation that may have reached the
	// server is never offered again.
	if err := p.State.Update(func(_ *state.DiskConversion, l *state.LUKS) {
		generation = l.RecoveryAttempted + 1
		l.RecoveryAttempted = generation
	}); err != nil {
		return err
	}
	// Without Volume: the device API refuses a secret with a header field (plan M8e amendment item 20); the LUKS UUID
	// reaches the server with disk.conversion_prepared.
	if err := p.Escrow.Upload(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindLUKSRecoveryKey, Generation: generation,
		KeyVersion: version, Ciphertext: ct}); err != nil {
		if ctx.Err() != nil {
			return errStop
		}
		return p.notStored(ctx, err)
	}
	deadline := p.Now().Add(EscrowWait)
	for {
		if err := p.Sleep(ctx, EscrowPoll); err != nil {
			return errStop
		}
		status, err := p.Escrow.Status(ctx, id)
		switch {
		case err == nil && status == escrow.StatusStored:
			slog.InfoContext(ctx, "conversion key stored as recovery key", "conversion_id", c.ID, "generation", generation)
			return p.State.Update(func(c *state.DiskConversion, l *state.LUKS) {
				l.RecoveryStored = max(l.RecoveryStored, generation)
				c.KeyEscrowGeneration = generation
			})
		case err == nil && (status == escrow.StatusFailed || status == escrow.StatusRefused):
			return p.notStored(ctx, fmt.Errorf("escrow %s", status))
		case !p.Now().Before(deadline):
			return p.notStored(ctx, errors.New("escrow not stored in time"))
		case err != nil:
			slog.WarnContext(ctx, "escrow status unavailable; polling again", "error", err)
		}
	}
}

// notStored shreds the conversion key and fails step 4.
func (p *Preparer) notStored(ctx context.Context, cause error) error {
	slog.WarnContext(ctx, "conversion key not escrowed", "error", cause)
	if err := shred(p.Layout.InstallPassphrase()); err != nil {
		slog.ErrorContext(ctx, "shredding the conversion key failed", "error", err)
	}
	return &failure{ReasonEscrowNotStored}
}

// diskSetup is step 5: the settings of the first-boot disk setup. Its pending marker is armed only once the
// reencryption completed, because no keyslot can be added before (plan M8e amendment 2026-10-22, item 22).
func (p *Preparer) diskSetup(context.Context, state.DiskConversion) error {
	plan, err := ReadPlan(p.Layout)
	if err != nil || plan == nil {
		return fmt.Errorf("read the plan: %w", err)
	}
	cfg, err := json.Marshal(map[string]any{"boot_pin_min_length": plan.BootPINMinLength, "unlock_mode": plan.UnlockMode})
	if err != nil {
		return err
	}
	return fsutil.WriteFile(p.Layout.DiskSetupConfig(), cfg, 0o644, 0o755)
}

// dracut is step 6 (plan M8e decisions 32 and 33): dracut is installed when dpkg-query reports it not installed,
// after a simulation whose removals must all be in the allow list; what really left must equal the simulation. Then
// the autoinstall's dracut configuration is written when absent.
func (p *Preparer) dracut(ctx context.Context, _ state.DiskConversion) error {
	installed, err := dracutInstalled(ctx, p.Sys)
	if err != nil {
		return &transient{err}
	}
	if !installed {
		if err := p.installDracut(ctx); err != nil {
			return err
		}
	}
	if _, err := os.Stat(p.Layout.Join(TPM2Conf)); errors.Is(err, os.ErrNotExist) {
		return fsutil.WriteFile(p.Layout.Join(TPM2Conf), []byte(tpm2Conf), 0o644, 0o755)
	} else if err != nil {
		return err
	}
	return nil
}

func (p *Preparer) installDracut(ctx context.Context) error {
	simulated, ok := simulateRemovals(ctx, p.Sys)
	if !ok {
		return &failure{ReasonDracutInstallFailed}
	}
	var outside []string
	for _, pkg := range simulated {
		if !slices.Contains(dracutRemovable, pkg) {
			outside = append(outside, pkg)
		}
	}
	if len(outside) > 0 {
		return &failure{ReasonDracutRemoves + ":" + strings.Join(outside, "+")}
	}
	before, err := installedPackages(ctx, p.Sys)
	if err != nil {
		return &transient{err}
	}
	out, stderr, exit, err := p.Sys.CommandWithin(ctx, LongTimeout, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get",
		"install", "-y", "dracut")
	if err != nil || exit != 0 {
		slog.WarnContext(ctx, "installing dracut failed", "exit", exit, "error", err, "stderr", firstLine(stderr),
			"output", lastLine(out))
		return &failure{ReasonDracutInstallFailed}
	}
	after, err := installedPackages(ctx, p.Sys)
	if err != nil {
		return &transient{err}
	}
	var removed []string
	for pkg := range before {
		if !after[pkg] {
			removed = append(removed, pkg)
		}
	}
	if diff := symmetricDifference(removed, simulated); len(diff) > 0 {
		return &failure{ReasonDracutRemovedDiffers + ":" + strings.Join(diff, "+")}
	}
	slog.InfoContext(ctx, "dracut installed for the in-place encryption", "removed", removed)
	return nil
}

// dracutInstalled is the one source of truth for "dracut installed" (plan M8e decision 32): true for the status
// installed, false when dpkg does not know the package (exit 1) or reports it not-installed or config-files (its files
// are removed, as installedPackages counts it). Any other answer is an error: dpkg could not tell, or an upgrade of
// dracut is under way (half-configured, unpacked, triggers-pending …).
func dracutInstalled(ctx context.Context, sys System) (bool, error) {
	out, stderr, exit, err := sys.Command(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}", "dracut")
	if err != nil {
		return false, fmt.Errorf("dpkg-query dracut: %w", err)
	}
	status := strings.TrimSpace(out)
	switch {
	case exit == 1:
		return false, nil
	case exit != 0:
		return false, fmt.Errorf("dpkg-query dracut: exit %d: %s", exit, firstLine(stderr))
	case status == "installed":
		return true, nil
	case status == "not-installed" || status == "config-files":
		return false, nil
	}
	return false, fmt.Errorf("dpkg-query dracut: status %q", cut(status))
}

// installedPackages returns the packages whose dpkg status is installed; a package in state rc is not.
func installedPackages(ctx context.Context, sys System) (map[string]bool, error) {
	out, stderr, exit, err := sys.Command(ctx, "dpkg-query", "-W", "-f=${Package} ${db:Status-Status}\n")
	if err == nil && exit != 0 {
		err = fmt.Errorf("dpkg-query: exit %d: %s", exit, firstLine(stderr))
	}
	if err != nil {
		return nil, err
	}
	pkgs := map[string]bool{}
	for line := range strings.Lines(out) {
		if f := strings.Fields(line); len(f) == 2 && f[1] == "installed" {
			pkgs[f[0]] = true
		}
	}
	return pkgs, nil
}

// symmetricDifference returns the packages in exactly one of a and b, sorted.
func symmetricDifference(a, b []string) []string {
	var diff []string
	for _, p := range a {
		if !slices.Contains(b, p) {
			diff = append(diff, p)
		}
	}
	for _, p := range b {
		if !slices.Contains(a, p) {
			diff = append(diff, p)
		}
	}
	slices.Sort(diff)
	return slices.Compact(diff)
}

// module is step 7: the embedded module files (directory and scripts 0755, others 0644), its dracut configuration,
// plan.env and, in dev builds, test-hooks. ModuleWritten is recorded first: from the first file on, any dracut run (a
// kernel update) may build an initrd with the module, which the cleanup must then verify (invariant I3).
func (p *Preparer) module(_ context.Context, c state.DiskConversion) error {
	plan, err := ReadPlan(p.Layout)
	if err != nil || plan == nil {
		return fmt.Errorf("read the plan: %w", err)
	}
	env, err := plan.Env()
	if err != nil {
		return err
	}
	if !c.ModuleWritten {
		if err := p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.ModuleWritten = true }); err != nil {
			return err
		}
	}
	if err := WriteModule(p.Layout, p.Module); err != nil {
		return err
	}
	if err := fsutil.WriteFile(p.Layout.Join(ModuleConf), []byte(moduleConf), 0o644, 0o755); err != nil {
		return err
	}
	if err := fsutil.WriteFile(p.Layout.EncryptPlanEnv(), env, 0o600, 0o700); err != nil {
		return err
	}
	if p.TestHooks {
		return fsutil.WriteFile(p.Layout.EncryptTestHooks(), nil, 0o600, 0o700)
	}
	return nil
}

// WriteModule writes the files of the embedded module to ModuleDir, replacing what is there.
func WriteModule(l paths.Layout, module fs.FS) error {
	if module == nil {
		return errors.New("this build carries no dracut module")
	}
	entries, err := fs.ReadDir(module, ".")
	if err != nil {
		return err
	}
	dir := l.Join(ModuleDir)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a dracut module directory is 0755 (plan M8e decision 13 step 7)
		return err
	}
	written := 0
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) == ".go" {
			continue
		}
		data, err := fs.ReadFile(module, e.Name())
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if path.Ext(e.Name()) == ".sh" {
			mode = 0o755
		}
		if err := fsutil.WriteFile(filepath.Join(dir, e.Name()), data, mode, 0o755); err != nil {
			return err
		}
		written++
	}
	if written == 0 {
		return errors.New("this build carries no dracut module")
	}
	return nil
}

// initrdFiles are what the running kernel's initrd must list after step 8 (plan M8e decision 13).
var initrdFiles = []string{"etc/paddock/encrypt-plan.env", "etc/paddock/encrypt-key", "usr/lib/systemd/system/paddock-encrypt-init.service"}

// initrdBinaries are the tools the init step runs; lvm only for the lvm layout.
var initrdBinaries = []string{"cryptsetup", "e2fsck", "resize2fs"}

// initrd is step 8: every initrd is rebuilt with the module, the running kernel's is verified, and every initrd is
// made readable by root only (it carries the conversion key).
func (p *Preparer) initrd(ctx context.Context, c state.DiskConversion) error {
	// Under dpkg's locks, as every initrd change of the conversion (amendment 2026-10-21, item 16): a kernel package's
	// dracut run in between could leave the newest initrd without the module. Busy waits for the next pass (errBusy).
	unlock, err := p.Sys.LockPackages()
	if errors.Is(err, ErrPackagesBusy) {
		return errBusy
	}
	if err != nil {
		return &transient{err}
	}
	defer unlock()
	if c.PackagesBusySince != nil {
		// The bookkeeping of the wait never fails the preparation (review 9, m6).
		if err := p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.PackagesBusySince = nil }); err != nil {
			slog.ErrorContext(ctx, "recording the end of the wait for the dpkg lock failed", "error", err)
		}
	}
	// One kernel after the other through a temporary file, with the room in /boot checked (item 19(h)): a full /boot
	// or a killed build never leaves a half-written initrd.
	listers := initrdListers
	err = rebuildInitrds(ctx, p.Sys, p.Layout, func(initrd string) error {
		out, err := listInitrd(ctx, p.Sys, &listers, initrd)
		if err == nil && !complete(out, c.Layout) {
			slog.WarnContext(ctx, "the initrd lacks files of the in-place encryption", "initrd", initrd)
			return errIncomplete
		}
		return err
	})
	var space *BootSpaceError
	var notBuildable *KernelNotBuildableError
	switch {
	case err == nil:
		return p.clearInitrdIssue(c)
	case errors.Is(err, errIncomplete):
		return &failure{ReasonInitrdIncomplete}
	case errors.As(err, &notBuildable):
		slog.WarnContext(ctx, "the preparation waits: a kernel's initrd cannot be built", "kernel", notBuildable.Version)
		if uerr := p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) {
			c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = IssueKernelNotBuildable, 0, 0, notBuildable.Version
		}); uerr != nil {
			slog.ErrorContext(ctx, "recording the kernel that cannot be built failed", "error", uerr)
		}
		return errWait
	case errors.As(err, &space):
		slog.WarnContext(ctx, "the preparation waits for room in /boot", "needed", space.Needed, "free", space.Free)
		if uerr := p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) {
			c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = IssueBootSpaceLow, space.Needed, space.Free, ""
		}); uerr != nil {
			slog.ErrorContext(ctx, "recording the lack of room in /boot failed", "error", uerr)
		}
		return errWait
	}
	return &transient{err}
}

// errIncomplete is a rebuilt initrd that lacks files of the init step.
var errIncomplete = errors.New("the initrd lacks files of the in-place encryption")

// clearInitrdIssue ends a reported lack of room once step 8 passed.
func (p *Preparer) clearInitrdIssue(c state.DiskConversion) error {
	if c.InitrdIssue == "" {
		return nil
	}
	return p.State.Update(func(c *state.DiskConversion, _ *state.LUKS) {
		c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = "", 0, 0, ""
	})
}

// complete reports whether an lsinitrd listing has the files and the binaries of the init step.
func complete(listing, layout string) bool {
	names := map[string]bool{}
	bins := map[string]bool{}
	for line := range strings.Lines(listing) {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		name := f[len(f)-1]
		if len(f) >= 3 && f[len(f)-2] == "->" {
			name = f[len(f)-3]
		}
		names[name] = true
		if strings.Contains(name, "bin/") {
			bins[path.Base(name)] = true
		}
	}
	for _, f := range initrdFiles {
		if !names[f] {
			return false
		}
	}
	want := initrdBinaries
	if layout == KindLVM {
		want = append(slices.Clone(want), "lvm")
	}
	for _, b := range want {
		if !bins[b] {
			return false
		}
	}
	return true
}

// prepared is step 9. An abort requested since the check before this step keeps the phase preparing and runs instead:
// otherwise its deferred command would be answered not_abortable for a conversion that is prepared, and so abortable.
func (p *Preparer) prepared(ctx context.Context, c state.DiskConversion) error {
	now := p.Now().UTC()
	abort := false
	if err := p.State.Transition(func(c *state.DiskConversion, _ *state.LUKS) *Event {
		if abort = c.AbortRequested; abort {
			return nil
		}
		c.Phase, c.PreparedAt, c.PackagesBusySince = state.ConversionPrepared, &now, nil
		return &Event{protocol.EventDiskConversionPrepared, map[string]any{"conversion_id": c.ID, "layout": c.Layout,
			"volume": c.LUKSUUID, "data_bytes": c.DataBytes}}
	}); err != nil {
		return err
	}
	if abort {
		return errAbortRequested
	}
	slog.InfoContext(ctx, "in-place encryption prepared; converting at the next restart", "conversion_id", c.ID)
	return nil
}

// escrowKey is the escrow-wrap key of the bundle.
func escrowKey(keys *bundle.Keys) (*rsa.PublicKey, int, error) {
	if keys == nil || keys.EscrowWrap == nil {
		return nil, 0, errors.New("the escrow key arrives with a newer bundle")
	}
	pub, err := escrow.ParsePublicKey(keys.EscrowWrap.PublicKeyPEM)
	if err != nil {
		return nil, 0, err
	}
	version, err := escrow.KeyVersion(keys.EscrowWrap.KeyID)
	return pub, version, err
}

// newUUID returns a random (version 4) UUID.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// lastLine is the last non-empty line of s, cut at 200 runes.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return cut(lines[len(lines)-1])
}
