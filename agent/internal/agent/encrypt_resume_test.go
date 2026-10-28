package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// resumeLaunch is the systemd-run of plan M8e decision 21.
const resumeLaunch = "systemd-run --unit paddock-encrypt-resume --collect --no-block --property=KillMode=mixed --property=Nice=10 " +
	"--property=IOSchedulingClass=idle /opt/paddock/agent/current/paddockd encrypt-resume --partition " + testPartition

// convertedAgent is an agent whose conversion was prepared on the fake device; the device then restarted through
// the module: the partition is LUKS with the conversion key's and the reencrypt keyslot. launches records systemd-run.
func convertedAgent(t *testing.T) (*Agent, *convDevice, *[]string) {
	t.Helper()
	a, _, d := convAgent(t)
	if status, _ := a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1",
		`{"conversion_id":"`+testConversionID+`"}`)); status != protocol.CommandSucceeded {
		t.Fatal("not accepted")
	}
	runWorker(t, a)
	if a.st.Conversion.Phase != state.ConversionPrepared {
		t.Fatalf("not prepared: %+v", a.st.Conversion)
	}
	seqs := map[int64]bool{}
	for _, e := range spooled(t, a) {
		seqs[e.EventSeq] = true
	}
	if err := a.d.Spool.Remove(seqs); err != nil {
		t.Fatal(err)
	}
	d.setLUKS(true)
	slot := d.Path("/opt/paddock/agent/a")
	d.MkdirAll("/opt/paddock/agent/a")
	if err := os.Symlink(slot, d.Path("/opt/paddock/agent/current")); err != nil {
		t.Fatal(err)
	}
	a.d.NoExec = func(dir string) (bool, error) {
		if dir != slot {
			t.Errorf("noexec checked on %s", dir)
		}
		return false, nil
	}
	var launches []string
	a.d.RunUnit = func(_ context.Context, name string, args ...string) error {
		launches = append(launches, strings.Join(append([]string{name}, args...), " "))
		d.set(func(d *convDevice) { d.unit = "active" })
		return nil
	}
	return a, d, &launches
}

// writeBoot writes /run/paddock/encrypt-boot.env as the init script does.
func writeBoot(d *convDevice, status, stage, reason string) {
	d.Write("/run/paddock/encrypt-boot.env", "PADDOCK_BOOT_STATUS="+status+"\nPADDOCK_BOOT_STAGE="+stage+"\nPADDOCK_BOOT_REASON="+reason+
		"\nPADDOCK_BOOT_SECONDS=37\n")
}

// writeResult writes result.json as `paddockd encrypt-resume` does.
func writeResult(t *testing.T, d *convDevice, r encrypt.Result) {
	t.Helper()
	raw, _ := json.Marshal(r)
	d.Write("/var/lib/paddock/encrypt/result.json", string(raw))
}

// eventsOfType are the spooled events of typ.
func eventsOfType(t *testing.T, a *Agent, typ string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, e := range spooled(t, a) {
		if e.Type == typ {
			out = append(out, eventData(t, e))
		}
	}
	return out
}

// TestConversionBootAdopts: plan M8e decision 18 — at the start a LUKS partition adopts the conversion whatever the
// boot result says (ok, a failure after the header, none: the supervisor's RuntimeDirectory may remove it), with the
// result in disk.conversion_started once, and without any cleanup; the boot result is removed.
func TestConversionBootAdopts(t *testing.T) {
	for name, tc := range map[string]struct {
		status, stage, reason string
		initResult            string
	}{
		"ok":                      {status: "ok", stage: "init", initResult: "ok"},
		"failed after the header": {status: "failed", stage: "init", reason: "root_missing", initResult: "init:root_missing"},
		"skipped, header written": {status: "skipped", stage: "init", reason: "on_battery", initResult: "init:on_battery"},
		"no boot result":          {initResult: "unknown"},
		"long reason":             {status: "failed", stage: "open", reason: strings.Repeat("r", 300), initResult: "open:" + strings.Repeat("r", 195)},
	} {
		a, d, _ := convertedAgent(t)
		if tc.status != "" {
			writeBoot(d, tc.status, tc.stage, tc.reason)
		}
		a.startConversion(context.Background())
		c := a.st.Conversion
		if c.Phase != state.ConversionEncrypting || c.StartedAt == nil || c.CleanupPending || c.ModuleRestorePending || c.FailureStage != "" {
			t.Fatalf("%s: conversion %+v", name, c)
		}
		started := eventsOfType(t, a, protocol.EventDiskConversionStarted)
		if len(started) != 1 || started[0]["init_result"] != tc.initResult || started[0]["volume"] != c.LUKSUUID ||
			started[0]["conversion_id"] != testConversionID {
			t.Fatalf("%s: started %+v", name, started)
		}
		if _, ok := started[0]["init_s"]; ok != (tc.status != "") {
			t.Fatalf("%s: init_s %+v", name, started[0])
		}
		if d.Exists("/run/paddock/encrypt-boot.env") || len(eventsOfType(t, a, protocol.EventDiskConversionFailed)) != 0 {
			t.Fatalf("%s: boot result left or failure reported", name)
		}
		for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf, "/var/lib/paddock/encrypt/plan.env",
			"/var/lib/paddock/encrypt/plan.json", "/var/lib/paddock/install-passphrase"} {
			if !d.Exists(p) {
				t.Fatalf("%s: %s removed (I1)", name, p)
			}
		}
		// A later boot through the module (its result ok open) changes nothing and is removed.
		writeBoot(d, "ok", "open", "")
		a.tickConversion(context.Background())
		if len(eventsOfType(t, a, protocol.EventDiskConversionStarted)) != 1 || d.Exists("/run/paddock/encrypt-boot.env") {
			t.Fatalf("%s: a later boot result was acted on", name)
		}
	}
}

// TestConversionBootNotLUKS: plan M8e decision 18 — a failed or skipped init step on a partition that is not LUKS
// fails the conversion at stage init and cleans up under invariant I3 on the worker; without a boot result a prepared
// conversion stays prepared; while the header cannot be checked the boot result is kept for the next pass.
func TestConversionBootNotLUKS(t *testing.T) {
	a, d, _ := convertedAgent(t)
	d.setLUKS(false)
	writeBoot(d, "skipped", "init", "on_battery")
	a.startConversion(context.Background())
	c := a.st.Conversion
	if c.Phase != state.ConversionFailed || c.FailureStage != state.StageInit || c.FailureReason != "on_battery" || !c.CleanupPending {
		t.Fatalf("conversion %+v", c)
	}
	failed := eventsOfType(t, a, protocol.EventDiskConversionFailed)
	if len(failed) != 1 || failed[0]["stage"] != "init" || failed[0]["reason"] != "on_battery" || d.Exists("/run/paddock/encrypt-boot.env") {
		t.Fatalf("failed events %+v", failed)
	}
	if !d.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatal("the key went before the initrds were verified (I3)")
	}
	a.tickConversion(context.Background())
	runWorker(t, a)
	if a.st.Conversion.CleanupPending || d.Exists("/var/lib/paddock/install-passphrase") || d.Exists(encrypt.ModuleDir) ||
		len(eventsOfType(t, a, protocol.EventDiskConversionStarted)) != 0 {
		t.Fatalf("cleanup not done: %+v", a.st.Conversion)
	}

	a, d, _ = convertedAgent(t)
	d.setLUKS(false)
	a.startConversion(context.Background())
	if a.st.Conversion.Phase != state.ConversionPrepared || len(spooled(t, a)) != 0 {
		t.Fatalf("without a boot result: %+v", a.st.Conversion)
	}

	a, d, _ = convertedAgent(t)
	writeBoot(d, "failed", "init", "fsck_8")
	_ = os.Remove(d.Path(testPartition))
	a.startConversion(context.Background())
	if a.st.Conversion.Phase != state.ConversionPrepared || !d.Exists("/run/paddock/encrypt-boot.env") || len(spooled(t, a)) != 0 {
		t.Fatalf("unknown header: %+v", a.st.Conversion)
	}
}

// TestConversionWithoutStateUntouched: plan M8e §14.10 I2 runs only while the device holds a conversion — a LUKS root
// and a boot result on a device without one are never touched.
func TestConversionWithoutStateUntouched(t *testing.T) {
	a, _, d := convAgent(t)
	d.setLUKS(true)
	writeBoot(d, "ok", "init", "")
	a.startConversion(context.Background())
	a.tickConversion(context.Background())
	if a.st.Conversion != nil || len(d.Calls()) != 0 || !d.Exists("/run/paddock/encrypt-boot.env") || len(a.conversionJobs) != 0 {
		t.Fatalf("touched: %v", d.Calls())
	}
}

// TestConversionAdoptsAfterCleanup: the cancelled and failed:prepare rows of plan M8e §14.10 (gate S-IE4) — a stale
// initrd converted the disk while the cleanup had removed the module: the conversion is adopted from cancelled or
// failed, the module, its configuration and plan.env are reinstalled and every initrd rebuilt before the helper
// launches; a failing rebuild is retried at every full pass and the helper waits for it.
func TestConversionAdoptsAfterCleanup(t *testing.T) {
	for _, phase := range []string{state.ConversionCancelled, state.ConversionFailed} {
		a, d, launches := convertedAgent(t)
		a.st.Conversion.Phase, a.st.Conversion.CleanupPending = phase, true
		if phase == state.ConversionFailed {
			a.st.Conversion.FailureStage, a.st.Conversion.FailureReason = state.StagePrepare, "initrd_incomplete"
		}
		for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf} {
			_ = os.RemoveAll(d.Path(p))
		}
		d.set(func(d *convDevice) { d.dracutExit = 1 })
		a.startConversion(context.Background())
		c := a.st.Conversion
		if c.Phase != state.ConversionEncrypting || c.CleanupPending || !c.ModuleRestorePending || c.FailureStage != "" {
			t.Fatalf("%s: not adopted: %+v", phase, c)
		}
		runWorker(t, a)
		if !d.Exists(encrypt.ModuleDir) || !d.Exists(encrypt.ModuleConf) || !a.st.Conversion.ModuleRestorePending {
			t.Fatalf("%s: module not rewritten, or the failed rebuild counted as done", phase)
		}
		a.tickConversion(context.Background())
		if len(*launches) != 0 {
			t.Fatalf("%s: helper launched before the reinstall", phase)
		}
		runWorker(t, a)
		d.set(func(d *convDevice) { d.dracutExit = 0 })
		a.initrdRetryAt = time.Time{} // the backoff after the failed rebuilds has passed
		a.tickConversion(context.Background())
		runWorker(t, a)
		if a.st.Conversion.ModuleRestorePending {
			t.Fatalf("%s: the reinstall did not finish", phase)
		}
		if !initrdCarries(d, testKernel) {
			t.Fatalf("%s: the rebuilt initrd lacks the module", phase)
		}
		a.tickConversion(context.Background())
		if !slices.Equal(*launches, []string{resumeLaunch}) {
			t.Fatalf("%s: launches %v", phase, *launches)
		}
	}
}

// TestConversionResumeLaunch: plan M8e decision 21 and §14.3 decision 30 — the helper is launched while encrypting,
// the reencrypt keyslot exists and its unit is not active; a noexec slot or an error launches nothing, logs once and
// reports helper_not_running.
func TestConversionResumeLaunch(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	a.tickConversion(context.Background())
	if !slices.Equal(*launches, []string{resumeLaunch}) {
		t.Fatalf("launches %v", *launches)
	}
	a.tickConversion(context.Background())
	if len(*launches) != 1 {
		t.Fatal("launched while active")
	}

	for name, noexec := range map[string]func(string) (bool, error){
		"noexec": func(string) (bool, error) { return true, nil },
		"error":  func(string) (bool, error) { return false, errors.New("statfs failed") },
	} {
		a, d, launches = convertedAgent(t)
		a.d.NoExec = noexec
		a.startConversion(context.Background())
		a.tickConversion(context.Background())
		a.tickConversion(context.Background())
		if len(*launches) != 0 || !a.helperNoExecLogged {
			t.Fatalf("%s: launches %v", name, *launches)
		}
		if h := a.conversionHealth(); h.PausedReason != encrypt.PausedHelperNotRunning || h.Phase != state.ConversionEncrypting {
			t.Fatalf("%s: health %+v", name, h)
		}
	}
	_ = d
}

// TestConversionResumeResults: plan M8e decision 22 — a failed result is reported with stage resume, the phase stays
// encrypting and the helper is relaunched, up to 3 failed results per start; the next start relaunches it. A completed
// result completes the conversion and removes only progress.json and result.json (invariant I1).
func TestConversionResumeResults(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	for i := 1; i <= 4; i++ {
		d.set(func(d *convDevice) { d.unit = "inactive" })
		writeResult(t, d, encrypt.Result{Outcome: encrypt.OutcomeFailed, Reason: "resume_exit_5:busy", FinishedAt: time.Now()})
		a.tickConversion(context.Background())
		if c := a.st.Conversion; c.Phase != state.ConversionEncrypting || c.ResumeFailures != min(i, 4) {
			t.Fatalf("failure %d: %+v", i, c)
		}
	}
	failed := eventsOfType(t, a, protocol.EventDiskConversionFailed)
	if len(failed) != 4 || failed[0]["stage"] != "resume" || failed[0]["reason"] != "resume_exit_5:busy" {
		t.Fatalf("failed events %+v", failed)
	}
	// A relaunch after each of the first two failures; the third failed result ends them for this start.
	if len(*launches) != 2 || d.Exists("/var/lib/paddock/encrypt/result.json") {
		t.Fatalf("launches %d", len(*launches))
	}
	if h := a.conversionHealth(); h.PausedReason != encrypt.PausedHelperNotRunning {
		t.Fatalf("health %+v", h)
	}
	a.startConversion(context.Background())
	a.tickConversion(context.Background())
	if a.st.Conversion.ResumeFailures != 0 || len(*launches) != 3 {
		t.Fatalf("not relaunched after the start: %+v", a.st.Conversion)
	}

	d.Write("/var/lib/paddock/encrypt/progress.json", `{"done_bytes":1}`)
	finished := time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC)
	writeResult(t, d, encrypt.Result{Outcome: encrypt.OutcomeCompleted, DataBytes: 40760246272, DurationS: 1800, FinishedAt: finished})
	a.tickConversion(context.Background())
	c := a.st.Conversion
	if c.Phase != state.ConversionCompleted || c.CompletedAt == nil || !c.CompletedAt.Equal(finished) {
		t.Fatalf("conversion %+v", c)
	}
	completed := eventsOfType(t, a, protocol.EventDiskConversionCompleted)
	if len(completed) != 1 || completed[0]["duration_s"] != float64(1800) || completed[0]["data_bytes"] != float64(40760246272) ||
		completed[0]["volume"] != c.LUKSUUID {
		t.Fatalf("completed %+v", completed)
	}
	for _, p := range []string{"/var/lib/paddock/encrypt/progress.json", "/var/lib/paddock/encrypt/result.json"} {
		if d.Exists(p) {
			t.Fatalf("%s left", p)
		}
	}
	for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf, "/var/lib/paddock/encrypt/plan.env",
		"/var/lib/paddock/encrypt/plan.json", "/var/lib/paddock/install-passphrase"} {
		if !d.Exists(p) {
			t.Fatalf("%s removed at completion (I1)", p)
		}
	}
	// A kernel update now still builds the module into the initrd (I1).
	if _, _, _, err := d.CommandWithin(context.Background(), time.Minute, nil, "dracut", "-f", "--regenerate-all"); err != nil {
		t.Fatal(err)
	}
	if !initrdCarries(d, testKernel) {
		t.Fatal("a rebuild after the completion dropped the module")
	}
	if h := a.conversionHealth(); h.Phase != state.ConversionCompleted || !h.KeyOnBoot {
		t.Fatalf("health %+v", h)
	}
}

// TestConversionCompletedWithoutResult: a disk whose reencrypt keyslot is gone while the helper left no result (it
// ended between cryptsetup's exit and its result) completes at the next full pass.
func TestConversionCompletedWithoutResult(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin"} })
	a.tickConversion(context.Background())
	if a.st.Conversion.Phase != state.ConversionCompleted || len(*launches) != 0 ||
		len(eventsOfType(t, a, protocol.EventDiskConversionCompleted)) != 1 {
		t.Fatalf("conversion %+v, launches %v", a.st.Conversion, *launches)
	}
}

// TestConversionHealth: plan M8e decisions 22 and 52 — while encrypting the progress of progress.json, paused
// helper_not_running while the unit does not run; key_on_boot from prepared until the initrd was regenerated.
func TestConversionHealth(t *testing.T) {
	a, d, _ := convertedAgent(t)
	if h := a.conversionHealth(); h.Phase != state.ConversionPrepared || !h.KeyOnBoot {
		t.Fatalf("prepared: %+v", h)
	}
	a.startConversion(context.Background())
	a.tickConversion(context.Background())
	d.Write("/var/lib/paddock/encrypt/progress.json",
		`{"done_bytes":8192,"data_bytes":44040192,"speed_bps":126877696,"eta_s":2520,"paused_reason":"on_battery","updated_at":"2026-10-21T12:00:00Z"}`)
	h := a.conversionHealth()
	if h.Phase != state.ConversionEncrypting || h.DoneBytes != 8192 || h.DataBytes != 44040192 || h.ETASeconds != 2520 ||
		h.PausedReason != encrypt.PausedOnBattery || h.UpdatedAt == nil || !h.KeyOnBoot {
		t.Fatalf("encrypting: %+v", h)
	}
	a.helperRunning = false
	if h := a.conversionHealth(); h.PausedReason != encrypt.PausedHelperNotRunning {
		t.Fatalf("helper not running: %+v", h)
	}
	a.st.Conversion.Phase, a.st.Conversion.InitrdRegenerated = state.ConversionCompleted, true
	if h := a.conversionHealth(); h.KeyOnBoot || h.Phase != state.ConversionCompleted {
		t.Fatalf("regenerated: %+v", h)
	}
	a.st.Conversion = nil
	if a.conversionHealth() != nil {
		t.Fatal("health without a conversion")
	}
}

// TestConversionInitrdRegeneration: plan M8e decisions 20 and 52 — while no TPM keyslot exists (the PIN was skipped)
// the PIN dialogue is re-armed at the start and at every full pass once completed, never while encrypting (amendment
// 2026-10-22, item 22), and nothing of the unlock path changes; once a TPM keyslot exists — while encrypting or
// completed — the crypttab line is written, the module goes, the initrds are rebuilt and verified, the plan files go
// and InitrdRegenerated is set; a failed rebuild keeps plan.env and is retried.
func TestConversionInitrdRegeneration(t *testing.T) {
	for _, phase := range []string{state.ConversionEncrypting, state.ConversionCompleted} {
		a, d, _ := convertedAgent(t)
		a.startConversion(context.Background())
		a.st.Conversion.Phase = phase
		_ = os.Remove(d.Path("/var/lib/paddock/disk-setup-pending"))
		runWorker(t, a)
		armed := phase == state.ConversionCompleted
		if d.Exists("/var/lib/paddock/disk-setup-pending") != armed || a.st.Conversion.InitrdRegenerated || d.Exists("/etc/crypttab") {
			t.Fatalf("%s: re-arm at the start not %v, or regenerated without a TPM keyslot", phase, armed)
		}
		_ = os.Remove(d.Path("/var/lib/paddock/disk-setup-pending"))
		a.tickConversion(context.Background())
		runWorker(t, a)
		if d.Exists("/var/lib/paddock/disk-setup-pending") != armed || !d.Exists(encrypt.ModuleDir) {
			t.Fatalf("%s: re-arm at the full pass not %v", phase, armed)
		}

		// The PIN is set at the next boot; the first rebuild fails.
		d.set(func(d *convDevice) { d.slots[1], d.dracutExit = "tpm2+pin", 1 })
		if phase == state.ConversionCompleted {
			d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin"} })
		}
		_ = os.Remove(d.Path("/var/lib/paddock/disk-setup-pending"))
		a.tickConversion(context.Background())
		runWorker(t, a)
		c := a.st.Conversion
		if c.InitrdRegenerated || !d.Exists("/var/lib/paddock/encrypt/plan.env") || d.Exists("/var/lib/paddock/disk-setup-pending") {
			t.Fatalf("%s: failed rebuild: %+v", phase, c)
		}
		if raw, _ := os.ReadFile(d.Path("/etc/crypttab")); string(raw) != c.Mapping+" UUID="+c.LUKSUUID+" none luks,tpm2-device=auto\n" {
			t.Fatalf("%s: crypttab %q", phase, raw)
		}
		d.set(func(d *convDevice) { d.dracutExit = 0 })
		a.initrdRetryAt = time.Time{} // the backoff after the failed rebuild has passed
		a.tickConversion(context.Background())
		runWorker(t, a)
		if !a.st.Conversion.InitrdRegenerated {
			t.Fatalf("%s: not regenerated: %+v", phase, a.st.Conversion)
		}
		for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf, "/var/lib/paddock/encrypt/plan.env"} {
			if d.Exists(p) {
				t.Fatalf("%s: %s left", phase, p)
			}
		}
		// Review 1, B1: the helper of a conversion still encrypting reads plan.json; it goes with the clearing.
		if d.Exists("/var/lib/paddock/encrypt/plan.json") != (phase == state.ConversionEncrypting) {
			t.Fatalf("%s: plan.json kept %v", phase, d.Exists("/var/lib/paddock/encrypt/plan.json"))
		}
		raw, _ := os.ReadFile(d.Path("/boot/initrd.img-" + testKernel))
		if initrdCarries(d, testKernel) || !d.Exists("/var/lib/paddock/install-passphrase") {
			t.Fatalf("%s: initrd %q, or the key went before the reconciler", phase, raw)
		}
		// No re-arm and no more initrd work once regenerated.
		a.tickConversion(context.Background())
		if len(a.conversionJobs) != 0 || d.Exists("/var/lib/paddock/disk-setup-pending") {
			t.Fatalf("%s: initrd work after the regeneration", phase)
		}
		if h := a.conversionHealth(); h.KeyOnBoot {
			t.Fatalf("%s: key_on_boot after the regeneration", phase)
		}
	}
}

// TestConversionCleared: plan M8e decision 22 — the conversion is cleared once the initrd was regenerated and the disk
// reports compliant or escrow_pending after completed, never before the regeneration.
func TestConversionCleared(t *testing.T) {
	for name, tc := range map[string]struct {
		regenerated bool
		disk        string
		cleared     bool
	}{
		"compliant, not regenerated":      {disk: protocol.DiskCompliant},
		"escrow_pending, not regenerated": {disk: protocol.DiskEscrowPending},
		"tpm_pin_missing":                 {regenerated: true, disk: protocol.DiskTPMPINMissing},
		"escrow_pending":                  {regenerated: true, disk: protocol.DiskEscrowPending, cleared: true},
		"compliant":                       {regenerated: true, disk: protocol.DiskCompliant, cleared: true},
	} {
		a, d, _ := convertedAgent(t)
		a.startConversion(context.Background())
		d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin"} })
		a.st.Conversion.Phase, a.st.Conversion.InitrdRegenerated = state.ConversionCompleted, tc.regenerated
		a.conversionBusy = true
		a.d.Health.Update(func(r *health.Report) { r.Disk = &protocol.DiskHealth{State: tc.disk} })
		a.tickConversion(context.Background())
		if cleared := a.st.Conversion == nil; cleared != tc.cleared || d.Exists("/var/lib/paddock/encrypt/plan.json") == tc.cleared {
			t.Fatalf("%s: cleared %v", name, cleared)
		}
	}
}

// TestRevocationStopsHelper: plan M8e §14.5 decision 39 — the hand-over records the envelope first, then stops the
// helper and waits for it, then hands over; a helper that does not stop within 60 s does not hold the Lock back. The
// conversion is terminal from then on (amendment 2026-10-21, item 10): no relaunch (helper_not_running), also after
// 24 hours and after the hand-over's record was pruned, and no completion.
func TestRevocationStopsHelper(t *testing.T) {
	for _, stuck := range []bool{false, true} {
		a, d, launches := convertedAgent(t)
		a.startConversion(context.Background())
		a.tickConversion(context.Background())
		if len(*launches) != 1 {
			t.Fatal("not launched")
		}
		d.set(func(d *convDevice) { d.stopStuck = stuck })
		now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
		a.d.Now = func() time.Time { return now }
		slept := time.Duration(0)
		a.d.Sleep = func(_ context.Context, dur time.Duration) error {
			now, slept = now.Add(dur), slept+dur
			return nil
		}
		var order []string
		a.d.Revoke = func(context.Context, []byte) (string, error) {
			st, _ := state.Load(a.d.Layout.State())
			order = append(order, "revoke", "recorded:"+boolText(len(st.HandedRevocations) == 1),
				"stopped:"+boolText(d.Count("systemctl stop --no-block "+encrypt.ResumeUnit) == 1))
			return "", nil
		}
		a.handRevocations(context.Background(), []json.RawMessage{revocationEnvelope(t, `{"a":1}`)})
		if !slices.Equal(order, []string{"revoke", "recorded:true", "stopped:true"}) {
			t.Fatalf("stuck %v: order %v", stuck, order)
		}
		if stuck != (slept >= helperStopWait) || (!stuck && slept != 0) {
			t.Fatalf("stuck %v: waited %v", stuck, slept)
		}

		d.set(func(d *convDevice) { d.unit = "inactive" })
		a.tickConversion(context.Background())
		if len(*launches) != 1 || a.conversionHealth().PausedReason != encrypt.PausedHelperNotRunning {
			t.Fatalf("stuck %v: relaunched within 24 h", stuck)
		}
		if a.st.Conversion.RevokedAt == nil {
			t.Fatalf("stuck %v: hand-over not recorded in the conversion", stuck)
		}
		now = now.Add(handoffRetention + revocationWindow)
		a.st.HandedRevocations = nil
		a.tickConversion(context.Background())
		d.set(func(d *convDevice) { d.slots = []string{"password"} })
		a.tickConversion(context.Background())
		if len(*launches) != 1 || a.st.Conversion.Phase != state.ConversionEncrypting {
			t.Fatalf("stuck %v: relaunched or completed after the hand-over: %+v", stuck, a.st.Conversion)
		}
	}
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestConversionStartQueuesInitrdWork: at the start the worker gets the converted disk's initrd work (decision 52's
// re-arm "at every start"), and a slot symlink that cannot be resolved launches nothing.
func TestConversionStartQueuesInitrdWork(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.st.Conversion.Phase = state.ConversionEncrypting
	_ = os.Remove(d.Path("/opt/paddock/agent/current"))
	a.startConversion(context.Background())
	if len(a.conversionJobs) != 1 {
		t.Fatal("no initrd work queued at the start")
	}
	a.tickConversion(context.Background())
	if len(*launches) != 0 || !a.helperNoExecLogged {
		t.Fatalf("launched without a slot: %v", *launches)
	}
	if _, err := os.Lstat(filepath.Join(d.Root, "/opt/paddock/agent/current")); err == nil {
		t.Fatal("slot link still there")
	}
}

// TestConversionBootStaleInitrd: a stale initrd that skipped the conversion during an unfinished cleanup (cancelled or
// failed, CleanupPending, partition not LUKS) changes nothing: no failed event, no change of phase; the boot result is
// removed and the cleanup goes on (amendment 2026-10-21, interpretation 2).
func TestConversionBootStaleInitrd(t *testing.T) {
	for _, phase := range []string{state.ConversionCancelled, state.ConversionFailed} {
		a, d, _ := convertedAgent(t)
		d.setLUKS(false)
		a.st.Conversion.Phase, a.st.Conversion.CleanupPending = phase, true
		writeBoot(d, "skipped", "init", "on_battery")
		a.startConversion(context.Background())
		c := a.st.Conversion
		if c.Phase != phase || !c.CleanupPending || c.FailureStage == state.StageInit || len(spooled(t, a)) != 0 ||
			d.Exists("/run/paddock/encrypt-boot.env") {
			t.Fatalf("%s: %+v, events %v", phase, c, spooled(t, a))
		}
	}
}

// TestConversionInitrdWorkNeedsLUKS: invariant I1 — the initrd work of a converted conversion runs only on a partition
// that is LUKS; while the header cannot be checked nothing of the unlock path changes.
func TestConversionInitrdWorkNeedsLUKS(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	a.st.Conversion.Phase, a.st.Conversion.ModuleRestorePending = state.ConversionCompleted, true
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin"} })
	_ = os.Remove(d.Path(testPartition))
	rebuilds := d.Count("dracut -f --regenerate-all")
	a.queueConversion()
	runWorker(t, a)
	if a.st.Conversion.InitrdRegenerated || d.Exists("/etc/crypttab") || d.Count("dracut -f --regenerate-all") != rebuilds ||
		!d.Exists(encrypt.ModuleDir) {
		t.Fatalf("initrd work on an uncheckable partition: %+v", a.st.Conversion)
	}
}

// TestRevocationStopWaitsWhileStarting: Review 1, N1 — a helper unit that is still activating counts as running: the
// hand-over waits for it up to the bound.
func TestRevocationStopWaitsWhileStarting(t *testing.T) {
	a, d, _ := convertedAgent(t)
	d.set(func(d *convDevice) { d.unit, d.stopStuck = "activating", true })
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	slept := time.Duration(0)
	a.d.Sleep = func(_ context.Context, dur time.Duration) error {
		now, slept = now.Add(dur), slept+dur
		return nil
	}
	a.stopResumeHelper(context.Background())
	if slept < helperStopWait {
		t.Fatalf("waited %v", slept)
	}
}

// TestConversionRegeneratedWhileEncrypting: Review 1, B1 — an initrd regenerated while the reencryption still runs
// (the PIN was set at the conversion boot) leaves the helper its plan: a relaunch after that finds plan.json and the
// reencryption still completes.
func TestConversionRegeneratedWhileEncrypting(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	runWorker(t, a)
	if !a.st.Conversion.InitrdRegenerated || a.st.Conversion.Phase != state.ConversionEncrypting {
		t.Fatalf("not regenerated while encrypting: %+v", a.st.Conversion)
	}
	a.tickConversion(context.Background())
	if len(*launches) != 1 {
		t.Fatalf("launches %v", *launches)
	}
	plan, err := encrypt.ReadPlan(a.d.Layout)
	if err != nil || plan == nil || plan.Partition != testPartition {
		t.Fatalf("the relaunched helper finds no plan: %+v %v", plan, err)
	}
}

// TestConversionNoCompletionAfterRevocation: adversarial review m1 — a disk whose keyslots a Lock erased (no reencrypt
// keyslot left) is not reported completed, and no PIN re-arm or rebuild follows while the hand-over is recent.
func TestConversionNoCompletionAfterRevocation(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	runWorker(t, a)
	a.st.HandedRevocations = map[string]time.Time{"h": a.d.Now()}
	d.set(func(d *convDevice) { d.slots = nil })
	_ = os.Remove(d.Path("/var/lib/paddock/disk-setup-pending"))
	a.tickConversion(context.Background())
	if a.st.Conversion.Phase != state.ConversionEncrypting || len(eventsOfType(t, a, protocol.EventDiskConversionCompleted)) != 0 ||
		len(a.conversionJobs) != 0 || len(*launches) != 0 || d.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatalf("after a Lock: %+v, jobs %d", a.st.Conversion, len(a.conversionJobs))
	}
}

// TestConversionStateEncryptingNotLUKS: adversarial review m3 — a state that says encrypting on a partition without a
// LUKS header (isLuks and luksDump agree) fails at stage init with not_luks and is cleaned up under I3; a header that
// cannot be checked changes nothing.
func TestConversionStateEncryptingNotLUKS(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	runWorker(t, a)
	_ = os.Remove(d.Path(testPartition))
	d.setLUKS(false)
	a.tickConversion(context.Background())
	if a.st.Conversion.Phase != state.ConversionEncrypting {
		t.Fatalf("unknown header: %+v", a.st.Conversion)
	}
	d.Write(testPartition, "")
	a.tickConversion(context.Background())
	c := a.st.Conversion
	if c.Phase != state.ConversionFailed || c.FailureStage != state.StageInit || c.FailureReason != "not_luks" || !c.CleanupPending {
		t.Fatalf("not LUKS: %+v", c)
	}
	if failed := eventsOfType(t, a, protocol.EventDiskConversionFailed); len(failed) != 1 || failed[0]["reason"] != "not_luks" {
		t.Fatalf("events %+v", failed)
	}
	a.tickConversion(context.Background())
	runWorker(t, a)
	if a.st.Conversion.CleanupPending || d.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("cleanup not done: %+v", a.st.Conversion)
	}
}

// TestConversionHelperEndsWithoutResult: adversarial review m3 — a helper that ends without a result (killed, or its
// result could not be written) counts as a failed run toward the limit of three per start.
func TestConversionHelperEndsWithoutResult(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	for i := 1; i <= 4; i++ {
		a.tickConversion(context.Background())
		d.set(func(d *convDevice) { d.unit = "inactive" })
	}
	a.tickConversion(context.Background())
	failed := eventsOfType(t, a, protocol.EventDiskConversionFailed)
	if a.st.Conversion.ResumeFailures != 3 || len(*launches) != 3 || len(failed) != 3 || failed[0]["reason"] != "resume_no_result" {
		t.Fatalf("failures %d, launches %d, events %+v", a.st.Conversion.ResumeFailures, len(*launches), failed)
	}
}

// TestConversionStartAfterRevocation: review 2, m4 — an agent start within 24 hours of a revocation hand-over queues no
// initrd work: no PIN re-arm on a locked disk.
func TestConversionStartAfterRevocation(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	runWorker(t, a)
	a.st.HandedRevocations = map[string]time.Time{"h": a.d.Now()}
	_ = os.Remove(d.Path("/var/lib/paddock/disk-setup-pending"))
	a.startConversion(context.Background())
	if len(a.conversionJobs) != 0 {
		t.Fatal("initrd work queued at the start after a hand-over")
	}
	a.tickConversion(context.Background())
	if len(a.conversionJobs) != 0 || d.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatal("PIN dialogue re-armed after a hand-over")
	}
}

// TestConversionUnitStateUnknown: review 2, m5 — a systemctl that cannot answer is no running helper that ended: the
// next pass that sees the unit inactive records no failed run and launches the helper.
func TestConversionUnitStateUnknown(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	broken := true
	d.NotFound = func(name string) bool { return name == "systemctl" && broken }
	a.tickConversion(context.Background())
	broken = false
	a.tickConversion(context.Background())
	if a.st.Conversion.ResumeFailures != 0 || len(eventsOfType(t, a, protocol.EventDiskConversionFailed)) != 0 || len(*launches) != 1 {
		t.Fatalf("failures %d, launches %v", a.st.Conversion.ResumeFailures, *launches)
	}
}

// TestConversionNotLUKSNeedsBothTools: review 2, m6 — isLuks saying "not LUKS" while the header can still be dumped
// changes nothing: one tool's wrong answer never starts a cleanup on a converted disk.
func TestConversionNotLUKSNeedsBothTools(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	runWorker(t, a)
	d.set(func(d *convDevice) { d.luks, d.headerReadable = false, true })
	a.tickConversion(context.Background())
	if c := a.st.Conversion; c.Phase != state.ConversionEncrypting || c.CleanupPending ||
		len(eventsOfType(t, a, protocol.EventDiskConversionFailed)) != 0 {
		t.Fatalf("conversion %+v", c)
	}
}

// initrdCarries reports whether a kernel's fake initrd carries the module; dracut's command line is no content.
func initrdCarries(d *convDevice, v string) bool {
	raw, _ := os.ReadFile(d.Path("/boot/initrd.img-" + v))
	for line := range strings.Lines(string(raw)) {
		if !strings.HasPrefix(line, "Arguments:") && strings.Contains(line, "paddock-encrypt") {
			return true
		}
	}
	return false
}

// TestNotLUKSNeedsEvidence: adversarial review round 2, B1 (amendment item 13) — a "not LUKS" from isLuks alone never
// fails a converted conversion or cleans up its unlock path: an active mapping (a cloned unencrypted disk behind the
// by-partuuid link), the LUKS UUID's by-uuid link, a PARTUUID that blkid finds on two devices, or a boot result ok each
// keep the conversion, the module and the key.
func TestNotLUKSNeedsEvidence(t *testing.T) {
	for name, set := range map[string]func(a *Agent, d *convDevice){
		"mapping active": func(_ *Agent, d *convDevice) { d.Write("/dev/mapper/dm_crypt-0", "") },
		"by-uuid link":   func(a *Agent, d *convDevice) { d.Write("/dev/disk/by-uuid/"+a.st.Conversion.LUKSUUID, "") },
		"two devices":    func(_ *Agent, d *convDevice) { d.set(func(d *convDevice) { d.partDevices = "/dev/sda3\n/dev/sdb3\n" }) },
		"boot result ok": func(_ *Agent, d *convDevice) { writeBoot(d, "ok", "open", "") },
	} {
		a, d, _ := convertedAgent(t)
		a.startConversion(context.Background())
		runWorker(t, a)
		set(a, d)
		d.setLUKS(false)
		a.tickConversion(context.Background())
		a.tickConversion(context.Background())
		runWorker(t, a)
		c := a.st.Conversion
		if c.Phase != state.ConversionEncrypting || c.CleanupPending || !d.Exists("/var/lib/paddock/install-passphrase") ||
			!d.Exists(encrypt.ModuleDir) || len(eventsOfType(t, a, protocol.EventDiskConversionFailed)) != 0 {
			t.Fatalf("%s: %+v", name, c)
		}
	}

	// A cancelled conversion's cleanup retry waits as well while the mapping is active.
	a, d, _ := convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
	d.setLUKS(false)
	d.Write("/dev/mapper/dm_crypt-0", "")
	d.set(func(d *convDevice) { d.headerReadable = false })
	a.queueConversion()
	runWorker(t, a)
	if !a.st.Conversion.CleanupPending || !d.Exists("/var/lib/paddock/install-passphrase") || !d.Exists(encrypt.ModuleDir) {
		t.Fatalf("cleanup ran on a guess: %+v", a.st.Conversion)
	}
}

// TestRevocationBeforeEncrypting: amendment item 10 — a hand-over before the conversion started encrypting (refused,
// the disk was unencrypted) does not end the conversion: the helper runs.
func TestRevocationBeforeEncrypting(t *testing.T) {
	a, _, launches := convertedAgent(t)
	a.st.HandedRevocations = map[string]time.Time{"h": a.d.Now().Add(-48 * time.Hour)}
	a.startConversion(context.Background())
	a.tickConversion(context.Background())
	if len(*launches) != 1 || a.st.Conversion.RevokedAt != nil {
		t.Fatalf("launches %v, %+v", *launches, a.st.Conversion)
	}
}

// TestConversionUnitStateErrorCountsRunning: review 3, m7 — a systemctl that cannot answer counts as a running helper:
// no second helper is launched on a guess.
func TestConversionUnitStateErrorCountsRunning(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	d.NotFound = func(name string) bool { return name == "systemctl" }
	a.tickConversion(context.Background())
	if len(*launches) != 0 || !a.helperRunning {
		t.Fatalf("launched on an unknown unit state: %v", *launches)
	}
}

// TestConversionUnitStateEmpty: adversarial review round 3, minor (amendment item 14) — a systemctl is-active that
// prints nothing (no bus) is no stopped helper: no failed run, no second launch.
func TestConversionUnitStateEmpty(t *testing.T) {
	a, d, launches := convertedAgent(t)
	a.startConversion(context.Background())
	a.tickConversion(context.Background())
	d.set(func(d *convDevice) { d.unit = "" })
	a.tickConversion(context.Background())
	a.tickConversion(context.Background())
	if len(*launches) != 1 || a.st.Conversion.ResumeFailures != 0 || len(eventsOfType(t, a, protocol.EventDiskConversionFailed)) != 0 {
		t.Fatalf("launches %v, failures %d", *launches, a.st.Conversion.ResumeFailures)
	}
}

// TestRevokedConversionWorker: review 4, M1 (amendment item 10) — initrd work queued before a hand-over does not run
// after it: no PIN re-arm, no rebuild on a disk whose keyslots paddock-revoke erases.
func TestRevokedConversionWorker(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	if len(a.conversionJobs) != 1 {
		t.Fatal("no job queued")
	}
	at := a.d.Now()
	a.st.Conversion.RevokedAt = &at
	_ = os.Remove(d.Path("/var/lib/paddock/disk-setup-pending"))
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	runWorker(t, a)
	if d.Exists("/var/lib/paddock/disk-setup-pending") || a.st.Conversion.InitrdRegenerated || d.Exists("/etc/crypttab") {
		t.Fatalf("initrd work after the hand-over: %+v", a.st.Conversion)
	}
}

// TestRevokedConversionDiscardsResult: review 4, m8 — a result the helper wrote is discarded without an event once the
// conversion is revoked.
func TestRevokedConversionDiscardsResult(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	at := a.d.Now()
	a.st.Conversion.RevokedAt = &at
	writeResult(t, d, encrypt.Result{Outcome: encrypt.OutcomeCompleted, DataBytes: 1, FinishedAt: at})
	a.tickConversion(context.Background())
	if a.st.Conversion.Phase != state.ConversionEncrypting || len(eventsOfType(t, a, protocol.EventDiskConversionCompleted)) != 0 ||
		d.Exists("/var/lib/paddock/encrypt/result.json") {
		t.Fatalf("revoked conversion completed: %+v", a.st.Conversion)
	}
}

// TestRevokedAtRolledBack: review 4, m9 — a hand-over whose save failed is no hand-over: RevokedAt is rolled back with
// the envelope's hash.
func TestRevokedAtRolledBack(t *testing.T) {
	a, _, _ := convertedAgent(t)
	a.startConversion(context.Background())
	if err := os.Remove(a.d.Layout.State()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a.d.Layout.State(), "blocked"), 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	a.d.Revoke = func(context.Context, []byte) (string, error) { called = true; return "", nil }
	a.handRevocations(context.Background(), []json.RawMessage{revocationEnvelope(t, `{"a":1}`)})
	if called || a.st.Conversion.RevokedAt != nil || len(a.st.HandedRevocations) != 0 {
		t.Fatalf("hand-over without a save: called %v, %+v", called, a.st.Conversion)
	}
}

// TestBootOKBlocksCleanup: adversarial review round 4, minor 3 (amendment item 13) — a boot result ok counts before any
// look at the disk: a cancelled conversion with an unfinished cleanup and a "not LUKS" on all evidence still does not
// clean up during this start.
func TestBootOKBlocksCleanup(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
	d.setLUKS(false)
	writeBoot(d, "ok", "init", "")
	a.startConversion(context.Background())
	a.tickConversion(context.Background())
	runWorker(t, a)
	if !a.bootConverted || !a.st.Conversion.CleanupPending || !d.Exists("/var/lib/paddock/install-passphrase") ||
		!d.Exists(encrypt.ModuleDir) {
		t.Fatalf("cleanup after a boot result ok: %+v", a.st.Conversion)
	}
}

// TestInitrdWorkBackoff: final adversarial review, minor 3 (amendment item 16) — a failed regeneration waits
// exponentially longer before the next attempt (the PIN re-arm still runs at every pass), and a success resets it.
func TestInitrdWorkBackoff(t *testing.T) {
	a, d, _ := convertedAgent(t)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots, d.dracutExit = []string{"password", "tpm2+pin", "reencrypt"}, 1 })
	builds := func() int {
		n := 0
		for _, l := range d.Long() {
			if strings.HasPrefix(l, "dracut -f --no-uefi --omit") {
				n++
			}
		}
		return n
	}
	runWorker(t, a)
	if builds() != 1 || !a.initrdRetryAt.Equal(now.Add(initrdRetryFirst)) {
		t.Fatalf("first failure: builds %d, retry at %v", builds(), a.initrdRetryAt)
	}
	a.queueConversion()
	runWorker(t, a)
	if builds() != 1 {
		t.Fatal("retried within the backoff")
	}
	now = now.Add(initrdRetryFirst)
	a.queueConversion()
	runWorker(t, a)
	if builds() != 2 || !a.initrdRetryAt.Equal(now.Add(2*initrdRetryFirst)) {
		t.Fatalf("second failure: builds %d, retry at %v", builds(), a.initrdRetryAt)
	}
	now = now.Add(2 * initrdRetryFirst)
	d.set(func(d *convDevice) { d.dracutExit = 0 })
	a.queueConversion()
	runWorker(t, a)
	if !a.st.Conversion.InitrdRegenerated || a.initrdFailures != 0 || !a.initrdRetryAt.IsZero() {
		t.Fatalf("success: %+v, failures %d", a.st.Conversion, a.initrdFailures)
	}
}

// TestRevocationCancelsRegeneration: PDK-374 — a revocation hand-over during a running regeneration cancels it: the
// initrds and the host stay as they were, and InitrdRegenerated is not set.
func TestRevocationCancelsRegeneration(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runConversions(ctx)
	}()
	handOverAt(t, a, d, "dracut -f --no-uefi --omit paddock-encrypt")
	for {
		select {
		case fn := <-a.conversionCalls:
			fn()
			if !a.conversionBusy {
				cancel()
				<-done
				if a.st.Conversion.InitrdRegenerated || !d.Exists(encrypt.ModuleDir) || !initrdCarries(d, testKernel) ||
					a.st.Conversion.RevokedAt == nil {
					t.Fatalf("regeneration went on after the hand-over: %+v", a.st.Conversion)
				}
				return
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the worker hangs")
		}
	}
}

// handOverAt hands a revocation over on the run loop when the device first runs a command line starting with prefix,
// from the worker's goroutine (the loop serves conversionCalls).
func handOverAt(t *testing.T, a *Agent, d *convDevice, prefix string) {
	t.Helper()
	handed := false
	d.set(func(d *convDevice) {
		d.onLine = func(line string) {
			if handed || !strings.HasPrefix(line, prefix) {
				return
			}
			handed = true
			done := make(chan struct{})
			a.conversionCalls <- func() {
				a.d.Revoke = func(context.Context, []byte) (string, error) { return "", nil }
				a.handRevocations(context.Background(), []json.RawMessage{revocationEnvelope(t, `{"a":1}`)})
				close(done)
			}
			<-done
		}
	})
}

// TestRevocationDuringInitrdWork: review 6, M2 (d) — a hand-over while the worker runs stops the initrd work at its next
// check: no PIN re-arm after the keyslot dump, no regeneration after the reinstall, and no InitrdRegenerated after the
// final verification.
func TestRevocationDuringInitrdWork(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	_ = os.Remove(d.Path("/var/lib/paddock/disk-setup-pending"))
	handOverAt(t, a, d, "cryptsetup luksDump")
	runWorker(t, a)
	if d.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatal("re-armed after the hand-over")
	}

	a, d, _ = convertedAgent(t)
	a.startConversion(context.Background())
	a.st.Conversion.ModuleRestorePending = true
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	handOverAt(t, a, d, "dracut -f --no-uefi /boot/.initrd.img-")
	runWorker(t, a)
	for _, l := range d.Long() {
		if strings.HasPrefix(l, "dracut -f --no-uefi --omit") {
			t.Fatal("regenerated after a hand-over during the reinstall")
		}
	}

	a, d, _ = convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	handOverAt(t, a, d, "lsinitrd -m /boot/initrd.img-")
	runWorker(t, a)
	if a.st.Conversion.InitrdRegenerated {
		t.Fatal("InitrdRegenerated saved after a hand-over during the final verification")
	}
}

// TestInitrdWorkBackoffCleanupAndRestore: review 6, M2 (b) — a failed cleanup and a failed reinstall back off like the
// regeneration; a busy dpkg lock does not (amendment item 17).
func TestInitrdWorkBackoffCleanupAndRestore(t *testing.T) {
	a, d, _ := convertedAgent(t)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
	d.setLUKS(false)
	d.set(func(d *convDevice) { d.dracutExit = 1 })
	before := initrdBuilds(d)
	a.queueConversion()
	runWorker(t, a)
	if !a.initrdRetryAt.Equal(now.Add(initrdRetryFirst)) {
		t.Fatalf("failed cleanup: retry at %v", a.initrdRetryAt)
	}
	a.queueConversion()
	runWorker(t, a)
	if n := initrdBuilds(d) - before; n != 1 {
		t.Fatalf("cleanup retried within the backoff: %d rebuilds", n)
	}

	a, d, _ = convertedAgent(t)
	a.d.Now = func() time.Time { return now }
	a.startConversion(context.Background())
	a.st.Conversion.ModuleRestorePending = true
	d.set(func(d *convDevice) { d.dracutExit = 1 })
	runWorker(t, a)
	if !a.initrdRetryAt.Equal(now.Add(initrdRetryFirst)) {
		t.Fatalf("failed reinstall: retry at %v", a.initrdRetryAt)
	}

	a, d, _ = convertedAgent(t)
	a.d.Now = func() time.Time { return now }
	a.startConversion(context.Background())
	a.st.Conversion.ModuleRestorePending = true
	d.PackagesBusy = true
	runWorker(t, a)
	if !a.initrdRetryAt.IsZero() || a.initrdFailures != 0 {
		t.Fatalf("a busy lock backed off: %v", a.initrdRetryAt)
	}

	a, d, _ = convertedAgent(t)
	a.d.Now = func() time.Time { return now }
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
	d.setLUKS(false)
	d.PackagesBusy = true
	a.queueConversion()
	runWorker(t, a)
	if !a.initrdRetryAt.IsZero() || !a.st.Conversion.CleanupPending {
		t.Fatalf("a busy lock backed the cleanup off: %v", a.initrdRetryAt)
	}
}

// TestStaleTempInitrdsRemoved: PDK-375 — at the start, under dpkg's locks, temporary initrds a killed regeneration left
// are removed; no other file of /boot is touched, and while a package run holds the locks nothing is removed.
func TestStaleTempInitrdsRemoved(t *testing.T) {
	a, d, _ := convertedAgent(t)
	d.Write("/boot/.initrd.img-"+testKernel+".paddock", "half built")
	d.Write("/boot/.initrd.img-"+testKernel+".other", "not ours")
	d.PackagesBusy = true
	a.startConversion(context.Background())
	if !d.Exists("/boot/.initrd.img-" + testKernel + ".paddock") {
		t.Fatal("removed while a package run held the lock")
	}
	d.PackagesBusy = false
	a.startConversion(context.Background())
	if d.Exists("/boot/.initrd.img-"+testKernel+".paddock") || !d.Exists("/boot/.initrd.img-"+testKernel+".other") ||
		!d.Exists("/boot/initrd.img-"+testKernel) || !d.Exists("/boot/vmlinuz-"+testKernel) {
		t.Fatal("wrong files removed")
	}
}

// TestCleanupErrorInHealth: PDK-376 — the reason the last cleanup attempt did not finish is reported with the
// conversion while the cleanup is pending.
func TestCleanupErrorInHealth(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
	d.setLUKS(false)
	d.set(func(d *convDevice) { d.dracutExit = 1 })
	a.queueConversion()
	runWorker(t, a)
	if h := a.conversionHealth(); !strings.Contains(h.CleanupError, "exit 1") {
		t.Fatalf("health %+v", h)
	}
	a.st.Conversion.CleanupPending = false
	if h := a.conversionHealth(); h.CleanupError != "" {
		t.Fatalf("cleanup error without a pending cleanup: %+v", h)
	}
	// A new pending cleanup (an abort) starts without the earlier reason.
	b, bd, _ := convertedAgent(t)
	bd.setLUKS(false)
	b.st.Conversion.CleanupError = "an earlier reason"
	if status, _ := b.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-abort",
		`{"conversion_id":"`+testConversionID+`"}`)); status != protocol.CommandSucceeded {
		t.Fatal("not aborted")
	}
	if b.st.Conversion.CleanupError == "an earlier reason" {
		t.Fatalf("an earlier reason survived the new cleanup: %+v", b.st.Conversion)
	}
}

// TestPackagesBusyInHealth: amendment item 18 — a preparation waiting for a package run reports paused_reason
// packages_busy with the time the wait began.
func TestPackagesBusyInHealth(t *testing.T) {
	a, _, _ := convAgent(t)
	since := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionPreparing, PackagesBusySince: &since}
	if h := a.conversionHealth(); h.PausedReason != encrypt.PausedPackagesBusy || h.PausedSince == nil || !h.PausedSince.Equal(since) {
		t.Fatalf("health %+v", h)
	}
	a.st.Conversion.Phase = state.ConversionPrepared
	if h := a.conversionHealth(); h.PausedReason != "" {
		t.Fatalf("packages_busy outside preparing: %+v", h)
	}
}

// TestInitrdIssueInHealth: PDK-380 and PDK-381 (amendment item 19) — a regeneration without room in /boot reports
// boot_space_low with the bytes needed and free, backs off and is not a failure of the conversion; a cleanup without a
// bootable kernel reports no_bootable_kernel and stays pending; a later success clears the issue.
func TestInitrdIssueInHealth(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	d.Free = 1 << 20
	runWorker(t, a)
	h := a.conversionHealth()
	if h.InitrdIssue != encrypt.IssueBootSpaceLow || h.BootSpaceFree != 1<<20 || h.BootSpaceNeeded < 32<<20 ||
		a.st.Conversion.Phase != state.ConversionEncrypting || a.initrdRetryAt.IsZero() {
		t.Fatalf("health %+v, conversion %+v", h, a.st.Conversion)
	}
	d.Free = 0
	a.initrdRetryAt = time.Time{}
	a.queueConversion()
	runWorker(t, a)
	if h := a.conversionHealth(); h.InitrdIssue != "" || !a.st.Conversion.InitrdRegenerated {
		t.Fatalf("after the room returned: %+v", h)
	}

	a, d, _ = convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
	d.setLUKS(false)
	_ = os.Remove(d.Path("/lib/modules/" + testKernel + "/modules.dep"))
	a.queueConversion()
	runWorker(t, a)
	if h := a.conversionHealth(); h.InitrdIssue != encrypt.IssueNoBootableKernel || !a.st.Conversion.CleanupPending ||
		a.initrdRetryAt.IsZero() {
		t.Fatalf("no bootable kernel: %+v", h)
	}
}

// TestCleanupErrorClearedOnEveryPath: PDK-381 — an earlier cleanup reason goes when the cleanup finishes, at an
// adoption, and when the init step's failure or a not-LUKS disk starts a new cleanup.
func TestCleanupErrorClearedOnEveryPath(t *testing.T) {
	// The cleanup finishes.
	a, d, _ := convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending, a.st.Conversion.CleanupError = state.ConversionCancelled, true, "old"
	d.setLUKS(false)
	a.queueConversion()
	runWorker(t, a)
	if c := a.st.Conversion; c.CleanupPending || c.CleanupError != "" {
		t.Fatalf("done: %+v", c)
	}
	// An adoption.
	a, _, _ = convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending, a.st.Conversion.CleanupError = state.ConversionCancelled, true, "old"
	a.startConversion(context.Background())
	if c := a.st.Conversion; c.Phase != state.ConversionEncrypting || c.CleanupError != "" {
		t.Fatalf("adopted: %+v", c)
	}
	// The init step failed on a disk that is not LUKS.
	a, d, _ = convertedAgent(t)
	a.st.Conversion.CleanupError = "old"
	d.setLUKS(false)
	writeBoot(d, "skipped", "init", "on_battery")
	a.startConversion(context.Background())
	if c := a.st.Conversion; !c.CleanupPending || c.CleanupError != "" {
		t.Fatalf("init failed: %+v", c)
	}
	// A converted state on a disk that is not LUKS.
	a, d, _ = convertedAgent(t)
	a.startConversion(context.Background())
	runWorker(t, a)
	a.st.Conversion.CleanupError = "old"
	d.setLUKS(false)
	a.tickConversion(context.Background())
	if c := a.st.Conversion; c.FailureReason != "not_luks" || c.CleanupError != "" {
		t.Fatalf("not LUKS: %+v", c)
	}
}

// TestInitrdWorkWaitsForSupervisorUpgrade: review 7, X1 (amendment item 17) — while a supervisor upgrade runs (its
// rollback restarts the agent), a pending cleanup and a pending reinstall run no dracut and do not back off; once the
// marker is gone they run.
func TestInitrdWorkWaitsForSupervisorUpgrade(t *testing.T) {
	for _, job := range []string{"cleanup", "reinstall"} {
		a, d, _ := convertedAgent(t)
		if job == "cleanup" {
			a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
			d.setLUKS(false)
		} else {
			a.startConversion(context.Background())
			a.st.Conversion.ModuleRestorePending = true
		}
		d.Write("/var/lib/paddock/state/supervisor-upgrade.json", `{"version":"1.2.0","started_at":"`+
			a.d.Now().UTC().Format(time.RFC3339)+`"}`)
		before := initrdBuilds(d)
		a.queueConversion()
		runWorker(t, a)
		if initrdBuilds(d) != before || !a.initrdRetryAt.IsZero() {
			t.Fatalf("%s: dracut ran during a supervisor upgrade", job)
		}
		if err := os.Remove(a.d.Layout.SupervisorUpgrade()); err != nil {
			t.Fatal(err)
		}
		a.queueConversion()
		runWorker(t, a)
		if initrdBuilds(d) == before {
			t.Fatalf("%s: did not run after the upgrade", job)
		}
	}
}

// TestInitrdWorkBackoffReinstallAndBusyRegeneration: review 7, S5 and S6 — a failed reinstall is not tried again within
// its backoff, and a regeneration that finds dpkg's locks busy does not back off.
func TestInitrdWorkBackoffReinstallAndBusyRegeneration(t *testing.T) {
	a, d, _ := convertedAgent(t)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	a.startConversion(context.Background())
	a.st.Conversion.ModuleRestorePending = true
	d.set(func(d *convDevice) { d.dracutExit = 1 })
	runWorker(t, a)
	before := initrdBuilds(d)
	a.queueConversion()
	runWorker(t, a)
	if initrdBuilds(d) != before {
		t.Fatal("reinstall retried within its backoff")
	}

	a, d, _ = convertedAgent(t)
	a.d.Now = func() time.Time { return now }
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	d.PackagesBusy = true
	runWorker(t, a)
	if !a.initrdRetryAt.IsZero() || a.initrdFailures != 0 || a.st.Conversion.InitrdRegenerated {
		t.Fatalf("a busy regeneration backed off: %v", a.initrdRetryAt)
	}
}

// initrdBuilds counts the dracut runs that rebuild initrds: in place or into temporary files.
func initrdBuilds(d *convDevice) int {
	n := 0
	for _, l := range d.Long() {
		if strings.HasPrefix(l, "dracut -f --regenerate-all") || strings.HasPrefix(l, "dracut -f --no-uefi /boot/.initrd.img-") {
			n++
		}
	}
	return n
}

// TestPreparationResumesAfterUpgrade: amendment item 18 — an agent started anew (a new version after a supervisor or
// agent upgrade) while the preparation waits at step 8 picks it up from plan.json: the plan is kept, and once dpkg's
// locks are free the preparation reaches prepared.
func TestPreparationResumesAfterUpgrade(t *testing.T) {
	a, _, d := convAgent(t)
	d.PackagesBusy = true
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", `{"conversion_id":"`+testConversionID+`"}`))
	runWorker(t, a)
	c := a.st.Conversion
	if c.Phase != state.ConversionPreparing || c.PackagesBusySince == nil {
		t.Fatalf("not waiting at step 8: %+v", c)
	}
	plan, err := encrypt.ReadPlan(a.d.Layout)
	if err != nil || plan == nil {
		t.Fatalf("no plan: %v", err)
	}
	// The new agent: the same state and files, a fresh run loop.
	b := newAgentOn(t, a)
	b.d.Encrypt, b.d.EncryptModule, b.current, b.d.Sleep = a.d.Encrypt, a.d.EncryptModule, a.current, a.d.Sleep
	d.PackagesBusy = false
	b.startConversion(context.Background())
	runWorker(t, b)
	if c := b.st.Conversion; c.Phase != state.ConversionPrepared || c.LUKSUUID != plan.LUKSUUID || c.PackagesBusySince != nil {
		t.Fatalf("not resumed from plan.json: %+v", c)
	}
}

// newAgentOn is a second agent on a's device and layout, as after a restart: it loads the saved state.
func newAgentOn(t *testing.T, a *Agent) *Agent {
	t.Helper()
	b, err := New(a.d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPackagesBusySinceEnds: review 9, M5 (d) — the wait for dpkg's locks ends in the state on every path that leaves
// it: a failure, prepared, an adoption, a failed init step, a revocation hand-over.
func TestPackagesBusySinceEnds(t *testing.T) {
	since := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	waiting := func(t *testing.T) (*Agent, *convDevice) {
		t.Helper()
		a, _, d := convAgent(t)
		d.PackagesBusy = true
		a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", `{"conversion_id":"`+testConversionID+`"}`))
		runWorker(t, a)
		if a.st.Conversion.PackagesBusySince == nil {
			t.Fatal("not waiting")
		}
		d.PackagesBusy = false
		return a, d
	}
	for name, leave := range map[string]func(t *testing.T, a *Agent, d *convDevice){
		"failure": func(t *testing.T, a *Agent, d *convDevice) {
			d.set(func(d *convDevice) { d.dracutExit = 1 })
			a.st.Conversion.TransientErrors = encrypt.TransientRetries
			a.queueConversion()
			runWorker(t, a)
		},
		"prepared": func(t *testing.T, a *Agent, _ *convDevice) {
			a.queueConversion()
			runWorker(t, a)
		},
		"adoption": func(t *testing.T, a *Agent, d *convDevice) {
			d.setLUKS(true)
			a.startConversion(context.Background())
		},
		"init failed": func(t *testing.T, a *Agent, d *convDevice) {
			writeBoot(d, "skipped", "init", "on_battery")
			a.startConversion(context.Background())
		},
		"revocation": func(t *testing.T, a *Agent, _ *convDevice) {
			a.d.Revoke = func(context.Context, []byte) (string, error) { return "", nil }
			a.handRevocations(context.Background(), []json.RawMessage{revocationEnvelope(t, `{"a":1}`)})
		},
	} {
		a, d := waiting(t)
		a.st.Conversion.PackagesBusySince = &since
		leave(t, a, d)
		if c := a.st.Conversion; c.PackagesBusySince != nil {
			t.Fatalf("%s: still waiting: %+v", name, c)
		}
	}
}

// TestReinstallIssueInHealth: review 9, M5 (e) — a reinstall without room in /boot shows boot_space_low in the health.
func TestReinstallIssueInHealth(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	a.st.Conversion.ModuleRestorePending = true
	d.Free = 1 << 20
	runWorker(t, a)
	if h := a.conversionHealth(); h.InitrdIssue != encrypt.IssueBootSpaceLow || h.BootSpaceFree != 1<<20 {
		t.Fatalf("health %+v", h)
	}
}

// TestOrphanInitrdIssueKept: amendment item 19(g) — orphan_initrd_removed is reported once the cleanup removed one and
// stays after the cleanup finished.
func TestOrphanInitrdIssueKept(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.CleanupPending = state.ConversionCancelled, true
	d.setLUKS(false)
	d.Write("/boot/vmlinuz-6.5.0-9-generic", "kernel")
	d.buildInitrd(d.Path("/boot/initrd.img-6.5.0-9-generic"), true)
	a.queueConversion()
	runWorker(t, a)
	if c := a.st.Conversion; c.CleanupPending || c.InitrdIssue != encrypt.IssueOrphanInitrdRemoved || d.Exists("/boot/initrd.img-6.5.0-9-generic") {
		t.Fatalf("conversion %+v", c)
	}
}

// TestKernelNotBuildableInHealth: amendment item 19(k) — a bootable kernel without modules.dep shows
// kernel_not_buildable with its version, and the regeneration stays pending.
func TestKernelNotBuildableInHealth(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	d.Write("/lib/modules/6.8.0-91-generic/modules.dep.bin", "")
	runWorker(t, a)
	if h := a.conversionHealth(); h.InitrdIssue != encrypt.IssueKernelNotBuildable || h.InitrdIssueKernel != "6.8.0-91-generic" ||
		a.st.Conversion.InitrdRegenerated || a.initrdRetryAt.IsZero() {
		t.Fatalf("health %+v", h)
	}
}

// TestKeyMaterialHardlinkedInHealth: amendment item 19, rule B — a temporary initrd with a hard link Paddock does not
// list stays, the regeneration stays pending and the health shows key_material_hardlinked.
func TestKeyMaterialHardlinkedInHealth(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	d.Write("/boot/.initrd.img-6.5.0-9-generic.paddock", "a key-carrying temporary initrd")
	if err := os.Link(d.Path("/boot/.initrd.img-6.5.0-9-generic.paddock"), d.Path("/boot/copy")); err != nil {
		t.Fatal(err)
	}
	runWorker(t, a)
	if h := a.conversionHealth(); h.InitrdIssue != encrypt.IssueKeyMaterialHardlinked || a.st.Conversion.InitrdRegenerated ||
		!d.Exists("/boot/.initrd.img-6.5.0-9-generic.paddock") {
		t.Fatalf("health %+v", h)
	}
}

// TestKeySharedBootableInHealth: amendment item 19, rule B — a bootable kernel's initrd that is a symlink to a
// temporary initrd keeps it: the regeneration stays pending and the health shows key_material_shared_bootable with
// the kernel.
func TestKeySharedBootableInHealth(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	d.Write("/boot/.initrd.img-6.5.0-9-generic.paddock", "a key-carrying temporary initrd")
	_ = os.Remove(d.Path("/boot/initrd.img-" + testKernel))
	if err := os.Symlink(d.Path("/boot/.initrd.img-6.5.0-9-generic.paddock"), d.Path("/boot/initrd.img-"+testKernel)); err != nil {
		t.Fatal(err)
	}
	runWorker(t, a)
	if h := a.conversionHealth(); h.InitrdIssue != encrypt.IssueKeyMaterialSharedBootable || h.InitrdIssueKernel != testKernel ||
		a.st.Conversion.InitrdRegenerated || !d.Exists("/boot/.initrd.img-6.5.0-9-generic.paddock") {
		t.Fatalf("health %+v", h)
	}
}

// TestInitrdIssueFieldsReplaced: PDK-382 — in the worker's initrd work each issue replaces every field of the
// previous one, and neither wait shows packages_busy.
func TestInitrdIssueFieldsReplaced(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	d.Free = 1 << 20
	runWorker(t, a)
	d.Free = 0
	d.Write("/lib/modules/6.8.0-91-generic/modules.dep.bin", "")
	a.initrdRetryAt = time.Time{}
	a.queueConversion()
	runWorker(t, a)
	h := a.conversionHealth()
	if h.InitrdIssue != encrypt.IssueKernelNotBuildable || h.BootSpaceNeeded != 0 || h.BootSpaceFree != 0 ||
		h.PausedReason == encrypt.PausedPackagesBusy {
		t.Fatalf("not buildable after boot space: %+v", h)
	}
	_ = os.Remove(d.Path("/lib/modules/6.8.0-91-generic/modules.dep.bin"))
	d.Free = 1 << 20
	a.initrdRetryAt = time.Time{}
	a.queueConversion()
	runWorker(t, a)
	if h := a.conversionHealth(); h.InitrdIssue != encrypt.IssueBootSpaceLow || h.InitrdIssueKernel != "" {
		t.Fatalf("boot space after not buildable: %+v", h)
	}
}

// desktopSessions gives the fake device one wayland session of uid 1000 (ID 3, *id changes it) and records the
// notifications' systemd-run lines.
func desktopSessions(d *convDevice, id *string) *[]string {
	var runs []string
	inner := d.Handle
	d.Handle = func(line string) (string, int, bool) {
		switch {
		case line == "loginctl list-sessions --no-legend":
			return *id + " 1000 u -\n", 0, true
		case strings.HasPrefix(line, "loginctl show-session"):
			return "Id=" + *id + "\nUser=1000\nName=u\nClass=user\nType=wayland\n", 0, true
		case line == "getent passwd 1000":
			return "u:x:1000:1000::/home/u:/bin/bash\n", 0, true
		case strings.HasPrefix(line, "systemd-run --quiet"):
			runs = append(runs, line)
			return "", 0, true
		}
		return inner(line)
	}
	return &runs
}

// TestEnrollmentAfterCompletion: plan M8e amendment 2026-10-22, item 22 — while encrypting without a TPM keyslot the
// first-boot disk setup is never armed and the health reports enrollment_deferred while the header carries the
// requirement or the reencrypt keyslot; at completed it is armed at the first full pass and re-armed after a removal,
// the health drops the deferral, and the session poll shows the completed notification once per session and 4 hours,
// in German under LANG=de_DE.UTF-8, until a TPM keyslot exists; with a TPM keyslot the marker is never armed.
func TestEnrollmentAfterCompletion(t *testing.T) {
	const marker = "/var/lib/paddock/disk-setup-pending"
	a, d, _ := convertedAgent(t)
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	session := "3"
	runs := desktopSessions(d, &session)
	if h := a.conversionHealth(); h.EnrollmentDeferred != "" {
		t.Fatalf("prepared: %+v", h)
	}
	a.tickConversionSessions(context.Background())
	if len(*runs) != 1 || !strings.Contains((*runs)[0], "Disk encryption is ready — please restart") {
		t.Fatalf("prepared notification: %q", *runs)
	}

	// The conversion boot: the reencrypt keyslot; then the requirement alone while the helper runs.
	a.startConversion(context.Background())
	runWorker(t, a)
	a.tickConversion(context.Background())
	runWorker(t, a)
	if d.Exists(marker) || a.st.Conversion.Phase != state.ConversionEncrypting {
		t.Fatalf("armed while encrypting: %+v", a.st.Conversion)
	}
	if h := a.conversionHealth(); h.EnrollmentDeferred != "reencrypt" {
		t.Fatalf("reencrypt keyslot: %+v", h)
	}
	d.set(func(d *convDevice) { d.slots, d.requirement, d.unit = []string{"password"}, true, "active" })
	a.tickConversion(context.Background())
	runWorker(t, a)
	if h := a.conversionHealth(); h.EnrollmentDeferred != "reencrypt" || d.Exists(marker) {
		t.Fatalf("requirement: %+v", h)
	}
	a.tickConversionSessions(context.Background())
	if len(*runs) != 1 {
		t.Fatalf("notified while encrypting: %q", *runs)
	}

	// Completed: the header is clear, the marker is armed and the session is asked to restart.
	d.set(func(d *convDevice) { d.requirement, d.unit = false, "inactive" })
	a.tickConversion(context.Background())
	runWorker(t, a)
	if a.st.Conversion.Phase != state.ConversionCompleted || !d.Exists(marker) {
		t.Fatalf("completed: %+v, armed %v", a.st.Conversion, d.Exists(marker))
	}
	if h := a.conversionHealth(); h.EnrollmentDeferred != "" {
		t.Fatalf("completed: %+v", h)
	}
	// The completing pass took its report before it read the header: an encrypting value is not reported at completed.
	a.enrollmentDeferred = "reencrypt"
	if h := a.conversionHealth(); h.EnrollmentDeferred != "" {
		t.Fatalf("encrypting value at completed: %+v", h)
	}
	a.enrollmentDeferred = ""
	_ = os.Remove(d.Path(marker))
	a.tickConversion(context.Background())
	runWorker(t, a)
	if !d.Exists(marker) {
		t.Fatal("not re-armed after a removal")
	}
	completed := "Disk encryption completed — please restart"
	a.tickConversionSessions(context.Background())
	a.tickConversionSessions(context.Background())
	if len(*runs) != 2 || !strings.Contains((*runs)[1], completed) {
		t.Fatalf("completed notification: %q", *runs)
	}
	if _, ok := a.st.Conversion.Notified["completed:3"]; !ok {
		t.Fatalf("notified %v", a.st.Conversion.Notified)
	}
	now = now.Add(3 * time.Hour)
	a.tickConversionSessions(context.Background())
	if len(*runs) != 2 {
		t.Fatalf("notified again within 4 hours: %q", *runs)
	}
	now = now.Add(time.Hour)
	a.tickConversionSessions(context.Background())
	session = "8"
	d.Write("/etc/default/locale", "LANG=de_DE.UTF-8\n")
	a.tickConversionSessions(context.Background())
	if len(*runs) != 4 || !strings.Contains((*runs)[2], completed) ||
		!strings.Contains((*runs)[3], "Festplattenverschlüsselung abgeschlossen — bitte neu starten") {
		t.Fatalf("after 4 hours and for a new session: %q", *runs)
	}

	// The PIN is set at the next start: no notification, no re-arm.
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin"} })
	now = now.Add(5 * time.Hour)
	a.tickConversionSessions(context.Background())
	if len(*runs) != 4 {
		t.Fatalf("notified with a TPM keyslot: %q", *runs)
	}
	_ = os.Remove(d.Path(marker))
	a.tickConversion(context.Background())
	runWorker(t, a)
	if d.Exists(marker) || !a.st.Conversion.InitrdRegenerated {
		t.Fatalf("armed with a TPM keyslot, or not regenerated: %+v", a.st.Conversion)
	}
}

// TestEnrollmentNotDeferredWithTPMKeyslot (item 22): a header marked for the reencryption that already carries a TPM
// keyslot reports no enrollment_deferred.
func TestEnrollmentNotDeferredWithTPMKeyslot(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots, d.requirement = []string{"password", "reencrypt", "tpm2"}, true })
	a.tickConversion(context.Background())
	runWorker(t, a)
	if h := a.conversionHealth(); h.Phase != state.ConversionEncrypting || h.EnrollmentDeferred != "" ||
		d.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatalf("health %+v, armed %v", h, d.Exists("/var/lib/paddock/disk-setup-pending"))
	}
}

// TestEnrollmentDeferredAfterCompletion: stop condition S15 of plan M8e amendment 2026-10-22, item 22 — a header
// still marked for the reencryption after the completion reports reencrypt_after_completed, logs one warning per
// start and asks no session to restart, which would only defer again; the header is read again after 4 hours only.
// Once the mark is gone the report ends and the notification follows.
func TestEnrollmentDeferredAfterCompletion(t *testing.T) {
	a, d, _ := convertedAgent(t)
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	session := "3"
	runs := desktopSessions(d, &session)
	a.startConversion(context.Background())
	runWorker(t, a)
	d.set(func(d *convDevice) { d.slots, d.requirement = []string{"password"}, true })
	var logs strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	a.tickConversion(context.Background())
	runWorker(t, a)
	a.tickConversion(context.Background())
	runWorker(t, a)
	slog.SetDefault(prev)
	if a.st.Conversion.Phase != state.ConversionCompleted || !d.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatalf("not completed and armed: %+v", a.st.Conversion)
	}
	if h := a.conversionHealth(); h.EnrollmentDeferred != "reencrypt_after_completed" {
		t.Fatalf("health %+v", h)
	}
	if n := strings.Count(logs.String(), "still marked for reencryption after the completion"); n != 1 {
		t.Fatalf("%d warnings:\n%s", n, logs.String())
	}
	dumps := 0
	inner := d.Handle
	d.Handle = func(line string) (string, int, bool) {
		if strings.HasPrefix(line, "cryptsetup luksDump") {
			dumps++
		}
		return inner(line)
	}
	for range 3 {
		a.tickConversionSessions(context.Background())
	}
	if len(*runs) != 0 || dumps != 1 {
		t.Fatalf("notified %q, header dumps %d", *runs, dumps)
	}
	d.set(func(d *convDevice) { d.requirement = false })
	now = now.Add(4 * time.Hour)
	a.tickConversion(context.Background())
	runWorker(t, a)
	a.tickConversionSessions(context.Background())
	if h := a.conversionHealth(); h.EnrollmentDeferred != "" || len(*runs) != 1 ||
		!strings.Contains((*runs)[0], "Disk encryption completed — please restart") {
		t.Fatalf("health %+v, notified %q", h, *runs)
	}
}

// TestCompletedNoticeUnreadableHeader (item 22): a header that cannot be read shows no completed notification and is
// read again only after 4 hours, not at every session poll.
func TestCompletedNoticeUnreadableHeader(t *testing.T) {
	a, d, _ := convertedAgent(t)
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	session := "3"
	runs := desktopSessions(d, &session)
	a.startConversion(context.Background())
	runWorker(t, a)
	d.set(func(d *convDevice) { d.slots = []string{"password"} })
	a.tickConversion(context.Background())
	runWorker(t, a)
	if a.st.Conversion.Phase != state.ConversionCompleted || !d.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatalf("not completed and armed: %+v", a.st.Conversion)
	}
	dumps := 0
	inner := d.Handle
	d.Handle = func(line string) (string, int, bool) {
		if strings.HasPrefix(line, "cryptsetup luksDump") {
			dumps++
			return "", 1, true
		}
		return inner(line)
	}
	for range 3 {
		a.tickConversionSessions(context.Background())
	}
	if len(*runs) != 0 || dumps != 1 {
		t.Fatalf("notified %q, header dumps %d", *runs, dumps)
	}
	now = now.Add(4 * time.Hour)
	a.tickConversionSessions(context.Background())
	if len(*runs) != 0 || dumps != 2 {
		t.Fatalf("after 4 hours: notified %q, header dumps %d", *runs, dumps)
	}
}

// TestRevocationStopEmptyUnitState: review 5 of PDK-245 (amendment item 14) — a systemctl is-active that prints nothing
// (no bus) is no stopped helper: the hand-over keeps polling until helperStopWait ends and the helper stays marked
// running, because it may still run.
func TestRevocationStopEmptyUnitState(t *testing.T) {
	a, d, _ := convertedAgent(t)
	d.set(func(d *convDevice) { d.unit, d.stopStuck = "", true })
	a.helperRunning = true
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	slept := time.Duration(0)
	a.d.Sleep = func(_ context.Context, dur time.Duration) error {
		now, slept = now.Add(dur), slept+dur
		return nil
	}
	a.stopResumeHelper(context.Background())
	if slept < helperStopWait || !a.helperRunning {
		t.Fatalf("waited %v, helperRunning %v", slept, a.helperRunning)
	}
}
