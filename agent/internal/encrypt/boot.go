package encrypt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Statuses of the init step's result (plan M8e decision 16).
const (
	BootOK      = "ok"
	BootFailed  = "failed"
	BootSkipped = "skipped"
)

// InitUnknown is init_result without a boot result (plan M8e decision 18).
const InitUnknown = "unknown"

// BootResult is /run/paddock/encrypt-boot.env, the result of the init step at a boot through the module (plan M8e
// decision 16).
type BootResult struct {
	Status, Stage, Reason string
	// Seconds is how long the init step ran; -1 when the file does not say.
	Seconds int64
}

// ReadBootResult reads the init step's result; nil without one. The supervisor's RuntimeDirectory may have removed
// the file before the agent started, so a missing file is no error: the disk decides (invariant I2).
func ReadBootResult(l paths.Layout) (*BootResult, error) {
	raw, err := os.ReadFile(l.EncryptBootResult())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r := &BootResult{Seconds: -1}
	for line := range strings.Lines(string(raw)) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "PADDOCK_BOOT_STATUS":
			r.Status = value
		case "PADDOCK_BOOT_STAGE":
			r.Stage = value
		case "PADDOCK_BOOT_REASON":
			r.Reason = value
		case "PADDOCK_BOOT_SECONDS":
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
				r.Seconds = n
			}
		}
	}
	return r, nil
}

// RemoveBootResult removes the init step's result once the agent acted on it; a missing file is no error.
func RemoveBootResult(l paths.Layout) error {
	if err := os.Remove(l.EncryptBootResult()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// InitResult is the init_result of disk.conversion_started: ok, <stage>:<reason> for a failed or skipped init step,
// unknown without a result (or with a status the script never writes), cut at 200 runes.
func (r *BootResult) InitResult() string {
	switch {
	case r == nil:
		return InitUnknown
	case r.Status == BootOK:
		return BootOK
	case r.Status == BootFailed || r.Status == BootSkipped:
		return cut(r.Stage + ":" + r.Reason)
	}
	return InitUnknown
}

// Failed reports whether the init step failed or skipped: with the partition not LUKS, the conversion failed at stage
// init (plan M8e decision 18).
func (r *BootResult) Failed() bool {
	return r != nil && (r.Status == BootFailed || r.Status == BootSkipped)
}

// FailureReason is the reason of a failed or skipped init step (its status when the script named none), cut at 200
// runes.
func (r *BootResult) FailureReason() string {
	if r.Reason == "" {
		return cut(r.Status)
	}
	return cut(r.Reason)
}

// ModuleMissing reports whether a cleanup removed part of a converted disk's unlock path: the module directory, its
// dracut configuration or plan.env (plan M8e decision 18).
func ModuleMissing(l paths.Layout) bool {
	for _, p := range []string{l.Join(ModuleDir), l.Join(ModuleConf), l.EncryptPlanEnv()} {
		if _, err := os.Stat(p); err != nil {
			return true
		}
	}
	return false
}

// RestoreReason is the reason of disk.conversion_unlock_restore_failed, from the first of the joined errors:
// kernel_not_buildable, no_bootable_kernel, boot_space_low (as for the initrd issue of the health), else the first
// line of that error.
func RestoreReason(err error) string {
	for {
		j, ok := err.(interface{ Unwrap() []error })
		if !ok || len(j.Unwrap()) == 0 {
			break
		}
		err = j.Unwrap()[0]
	}
	var notBuildable *KernelNotBuildableError
	switch {
	case errors.As(err, &notBuildable):
		return IssueKernelNotBuildable
	case errors.Is(err, ErrNoBootableKernel):
		return IssueNoBootableKernel
	}
	return NeutralizeReason(err)
}

// ReportRestoreFailed emits disk.conversion_unlock_restore_failed for err, a failed RestoreModule: until the reinstall
// succeeds, an initrd the disarm of a cancelled conversion neutralized cannot open the converted disk (plan M8e
// amendment 2026-10-30, review 2 of PDK-482, X1). A failure to record the event is logged and returned.
func ReportRestoreFailed(ctx context.Context, store Store, err error) error {
	if terr := store.Transition(func(c *state.DiskConversion, _ *state.LUKS) *Event {
		return &Event{protocol.EventDiskConversionUnlockRestoreFailed, map[string]any{"conversion_id": c.ID,
			"reason": RestoreReason(err)}}
	}); terr != nil {
		slog.ErrorContext(ctx, "reporting the failed reinstall of the unlock path failed", "error", terr)
		return terr
	}
	return nil
}

// RestoreModule reinstalls the unlock path of a converted disk after a cleanup had removed it (plan M8e decision 18,
// invariant I2): the embedded module and its dracut configuration, plan.env rendered from plan.json when it is
// missing, then every bootable kernel's initrd rebuilt into a temporary file and renamed into place (rebuildInitrds).
// It succeeds only when every new initrd carries the module, the key and the plan (invariant I1: a kernel update must
// keep booting the device); each is readable by root only, since it carries the conversion key again.
func RestoreModule(ctx context.Context, sys Host, l paths.Layout, module fs.FS) error {
	plan, err := ReadPlan(l)
	if err == nil && plan == nil {
		err = errors.New("plan.json is missing")
	}
	if err != nil {
		return fmt.Errorf("read the plan: %w", err)
	}
	// Under dpkg's locks (amendment 2026-10-21, item 16): a kernel package's dracut run must not finish after the
	// verification with an initrd built before the module was back.
	unlock, err := sys.LockPackages()
	if err != nil {
		return err
	}
	defer unlock()
	if err := WriteModule(l, module); err != nil {
		return err
	}
	if err := fsutil.WriteFile(l.Join(ModuleConf), []byte(moduleConf), 0o644, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(l.EncryptPlanEnv()); errors.Is(err, os.ErrNotExist) {
		env, err := plan.Env()
		if err != nil {
			return err
		}
		if err := fsutil.WriteFile(l.EncryptPlanEnv(), env, 0o600, 0o700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	listers := initrdListers
	return rebuildInitrds(ctx, sys, l, func(initrd string) error {
		out, err := listInitrd(ctx, sys, &listers, initrd)
		if err == nil && !complete(out, plan.Layout) {
			err = fmt.Errorf("it lacks files of %s", moduleName)
		}
		return err
	})
}
