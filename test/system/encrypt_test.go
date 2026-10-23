package system

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// conversionState is state.conversion of the agent's state.json.
type conversionState struct {
	ID                string `json:"id"`
	Phase             string `json:"phase"`
	LUKSUUID          string `json:"luks_uuid"`
	Mapping           string `json:"mapping"`
	Partition         string `json:"partition"`
	InitrdRegenerated bool   `json:"initrd_regenerated"`
	CleanupPending    bool   `json:"cleanup_pending"`
}

// convState reads the conversion of the agent's state (nil once cleared).
func (w *ieWorld) convState(t *testing.T) *conversionState {
	t.Helper()
	var st struct {
		Conversion *conversionState `json:"conversion"`
	}
	if err := json.Unmarshal([]byte(w.Must("sudo cat /var/lib/paddock/state/state.json")), &st); err != nil {
		t.Fatal(err)
	}
	return st.Conversion
}

// fsBytes is the size of the root file system from its superblock (block count × block size).
func (w *ieWorld) fsBytes(t *testing.T) int64 {
	t.Helper()
	out := w.Must(`sudo dumpe2fs -h "$(findmnt -no SOURCE /)" 2>/dev/null | awk -F: '/^Block count/{c=$2} /^Block size/{s=$2} END{print c*s}'`)
	n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil || n <= 0 {
		t.Fatalf("root file system size %q: %v", out, err)
	}
	return n
}

// fileState reports whether path exists in the guest ("present" or "gone").
func (w *ieWorld) fileState(path string) string {
	w.t.Helper()
	return w.Must("sudo test -e " + path + " && echo present || echo gone")
}

// requireFinalDisk asserts the end state of a conversion: no reencrypt keyslot and no requirement in the header,
// the conversion key gone from the host and from every initrd, every initrd naming the volume in its crypttab, and
// generation 1 (the conversion key) no longer opening the disk while the newest generation does.
func (w *ieWorld) requireFinalDisk(t *testing.T, partition, luksUUID, conversionKey string) {
	t.Helper()
	var md struct {
		Keyslots map[string]struct {
			Type string `json:"type"`
		} `json:"keyslots"`
		Config struct {
			Requirements json.RawMessage `json:"requirements"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(w.Must("sudo cryptsetup luksDump --dump-json-metadata "+partition)), &md); err != nil {
		t.Fatal(err)
	}
	for id, k := range md.Keyslots {
		if k.Type != "luks2" {
			t.Fatalf("keyslot %s of type %s left", id, k.Type)
		}
	}
	if len(md.Config.Requirements) != 0 && string(md.Config.Requirements) != "null" {
		t.Fatalf("the header still has requirements %s", md.Config.Requirements)
	}
	for _, p := range []string{"/var/lib/paddock/install-passphrase", "/var/lib/paddock/encrypt/plan.env", "/var/lib/paddock/encrypt/plan.json"} {
		if w.fileState(p) != "gone" {
			t.Fatalf("%s is still on the device", p)
		}
	}
	w.requireInitrds(t, false, luksUUID)
	if w.Opens(t, conversionKey) {
		t.Fatal("the conversion key (recovery-key generation 1) still opens the disk")
	}
	gen, key := w.newestRecoveryKey(t)
	if gen < 2 || !w.Opens(t, key) {
		t.Fatalf("the newest recovery key (generation %d) does not open the disk", gen)
	}
	if out := w.Must("findmnt -no TARGET /boot"); out != "/boot" {
		t.Fatalf("/boot is not mounted: %q", out)
	}
}

// TestInPlaceEncryptionLVM is gate S-IE1 of plan M8e (§9 as amended by §14.6 decisions 44, 45, 50 and 51 and by
// amendment item 22, the PIN after completion): an unencrypted Ubuntu 26.04 Desktop with the guided LVM layout is
// encrypted in place under tpm_pin. It survives a power cut during the open step of the conversion boot and one in
// the middle of the background reencryption; no boot asks for the PIN while the header is marked for reencryption
// (stop condition S2: no keyslot can be added then). After completion the dialogue comes and the user skips it, so the
// conversion key stays the only unlock path (key_on_boot, the uninstall refused, a manual initrd rebuild keeps the
// module); once the PIN is set the device is compliant and the conversion key no longer opens the disk. It runs only
// with PADDOCK_SYSTEM_VMS=paddock-ie-2604.
func TestInPlaceEncryptionLVM(t *testing.T) {
	w := newIEWorld(t, ieVM2604, "26.04", "unencrypted-lvm.yaml.tmpl")
	w.logEvidence(t, "root reference (PDK-242: the installer's fstab form)", "findmnt --fstab -no SOURCE /; cat /proc/cmdline")
	w.logEvidence(t, "layout", "lsblk -f; sudo lvm pvs --segments --units b -o pv_name,pvseg_start,pvseg_size,lv_name")
	w.logEvidence(t, "LVM devices file and filters on 26.04 (PDK-244 verification c)",
		"sudo lvm config --typeconfig full devices/use_devicesfile; ls -l /etc/lvm/devices/ 2>&1; sudo lvm config --typeconfig diff devices; echo exit=$?")
	w.logEvidence(t, "lsinitrd on the stock initrd (PDK-245 verification)",
		"command -v lsinitrd 3cpio dracut-extractinitrd; sudo lsinitrd /boot/initrd.img-$(uname -r) | head -5; echo exit=$?")
	h := w.waitHealth(t, "eligible with layout lvm", 15*time.Minute, func(h conversionHealth) bool { return h.eligible("lvm") })
	t.Logf("%s: conversion %+v", w.Name, *h.Disk.Conversion)
	sizeBefore := w.fsBytes(t)
	crypttab := w.Must("cat /etc/crypttab 2>/dev/null || echo absent")
	pin := randomDigits(t, 8)

	id := w.requestEncryption(t)
	w.waitHealth(t, "conversion prepared", 15*time.Minute, func(h conversionHealth) bool {
		return h.Disk.Conversion != nil && h.Disk.Conversion.Phase == "prepared"
	})
	shots := w.shots(t, "notification")
	w.requireNotified(t)
	shots()
	w.WaitEvent(t, "device.disk_conversion_prepared", 10*time.Minute, func(p map[string]any) bool {
		return p["conversion_id"] == id && p["layout"] == "lvm"
	})
	if info := w.Disk(); stored(info.RecoveryKeys) != 1 {
		t.Fatalf("recovery keys after the preparation %+v, want generation 1 stored", info.RecoveryKeys)
	}
	gen, conversionKey := w.newestRecoveryKey(t)
	if gen != 1 {
		t.Fatalf("the conversion key is generation %d, want 1", gen)
	}
	w.requireInitrds(t, true, "")
	// By exact path: the listing also names the unit in its initrd.target.wants symlink.
	w.logEvidence(t, "the module's entries in the running kernel's initrd", "sudo lsinitrd /boot/initrd.img-$(uname -r) | grep -e paddock -e cmdline.d")
	listing := w.Must("sudo lsinitrd /boot/initrd.img-$(uname -r)")
	for _, f := range []string{"usr/lib/systemd/system/paddock-encrypt-init.service", "etc/paddock/encrypt-key"} {
		if !regexp.MustCompile(`(?m) ` + regexp.QuoteMeta(f) + `$`).MatchString(listing) {
			t.Fatalf("the running kernel's initrd does not list %s", f)
		}
	}
	if out := w.Must("cat /etc/crypttab 2>/dev/null || echo absent"); out != crypttab {
		t.Fatalf("/etc/crypttab changed at the preparation: %q, was %q", out, crypttab)
	}
	conv := w.convState(t)
	partition := w.partition(t, strings.TrimPrefix(conv.Partition, "/dev/disk/by-partuuid/"))

	// The power is cut while the open step waits, after the header is written: the next boot must recover it.
	w.kernelArg("paddock.encrypt.testdelay=open:60")
	mark := w.rebootRequest(t)
	began := w.waitSerial(t, "paddock-encrypt: ", mark, 10*time.Minute)
	shrunk := w.waitSerial(t, "paddock-encrypt: shrink done", mark, 20*time.Minute)
	initDone := w.waitSerial(t, "paddock-encrypt: init done", mark, 20*time.Minute)
	t.Logf("%s: init step: first line → shrink done %s, → init done %s", w.Name, shrunk.Sub(began).Round(time.Second), initDone.Sub(began).Round(time.Second))
	if initDone.Sub(began) > 10*time.Minute {
		t.Fatalf("stop condition S10: the init step took %s", initDone.Sub(began))
	}
	// Only a delay that really runs makes the power cut land in the open step.
	w.waitSerial(t, "paddock-encrypt: test delay open", mark, time.Minute)
	time.Sleep(10 * time.Second)
	w.powerCut(t, "during the open delay")

	// No PIN dialogue while the reencryption is unfinished (item 22).
	w.LimitDisk(t, ieDiskLimit)
	w.powerOn(t)
	w.waitSerial(t, "paddock-encrypt: header found, opening", 0, 10*time.Minute)
	Until(t, w.Name+" answers SSH on dm-crypt", 10*time.Minute, 5*time.Second, nil, w.sshUp)
	w.requireNoDiskSetup(t)
	w.requireLUKSRoot(t, partition, conv.Mapping)
	w.probeEnrollWhileEncrypting(t, partition)
	w.requireEnrollmentDeferred(t)
	w.requireRootReference(t, conv.Mapping)
	// The key the server escrowed (revealed by an administrator above) belongs to the converted volume.
	if !w.Opens(t, conversionKey) {
		t.Fatal("the escrowed conversion key (recovery-key generation 1) does not open the converted volume")
	}
	w.logBootEvidence(t, "boot 2 (open after the power cut)")
	if out := w.Must("sudo journalctl -b -o cat --no-pager | grep -c 'paddock-encrypt: header found, opening' || true"); out == "0" {
		t.Fatal("no 'header found, opening' in the journal of boot 2")
	}
	started := w.WaitEvent(t, "device.disk_conversion_started", 10*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id })
	t.Logf("%s: disk.conversion_started %v", w.Name, started)
	last := w.requireProgress(t, 0)
	if detail := w.requestUninstall(t, http.StatusConflict); detail != "the in-place encryption is unfinished; wait for its completion" {
		t.Fatalf("uninstall while encrypting: detail %q", detail)
	}
	if c := w.conversion(t); c.Phase != "encrypting" || !c.Active {
		t.Fatalf("conversion while encrypting %+v", c)
	}
	c := w.waitConversion(t, "progress in the API", 10*time.Minute, func(c apiConversion) bool {
		return c.Phase == "encrypting" && c.DoneBytes != nil && *c.DoneBytes > 0 && c.ETASeconds != nil
	})
	t.Logf("%s: API done_bytes %d, eta_s %d", w.Name, *c.DoneBytes, *c.ETASeconds)
	w.dropKernelArg("paddock.encrypt.testdelay=")

	// A power cut in the middle of the background phase must cost nothing but the resume (decision 21).
	last = max(last, w.powerCutMidway(t))
	w.powerOn(t)
	w.waitSerial(t, "paddock-encrypt: header found, opening", 0, 10*time.Minute)
	Until(t, w.Name+" answers SSH on dm-crypt", 10*time.Minute, 5*time.Second, nil, w.sshUp)
	w.requireNoDiskSetup(t)
	w.logBootEvidence(t, "boot 3 (open after the power cut in the background phase)")
	w.requireProgress(t, last)
	w.restartWithDiskLimit(t, diskUnlimited)
	w.WaitEvent(t, "device.disk_conversion_completed", 30*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id })

	// Without a TPM keyslot the conversion key is the only unlock path (invariant I1).
	h = w.waitHealth(t, "tpm_pin_missing with the key on /boot", 10*time.Minute, func(h conversionHealth) bool {
		return h.Disk.State == "tpm_pin_missing" && h.Disk.Conversion != nil && h.Disk.Conversion.KeyOnBoot
	})
	if c := w.waitConversion(t, "completed and active", 5*time.Minute, func(c apiConversion) bool { return c.Phase == "completed" }); !c.Active {
		t.Fatalf("completed conversion with the key on /boot is not active: %+v", c)
	}
	w.requestUninstall(t, http.StatusConflict)
	w.requireInitrds(t, true, "")
	if !slices.Contains(w.Keyslots(t), "password") || !w.Opens(t, conversionKey) {
		t.Fatalf("the conversion key's keyslot is gone before the PIN: %v", w.Keyslots(t))
	}
	if w.fileState("/var/lib/paddock/disk-setup-pending") != "present" {
		t.Fatal("the agent did not arm the disk setup at completion (item 22, decision 52)")
	}
	// A rebuild by anyone keeps the module while the PIN is missing (I1); the first dialogue after completion is skipped.
	w.Must("sudo dracut -f --regenerate-all >/dev/null 2>&1")
	w.rebootRequest(t)
	w.skipDiskSetup(t)
	Until(t, w.Name+" answers SSH after the manual rebuild", 10*time.Minute, 5*time.Second, nil, w.sshUp)
	w.requireLUKSRoot(t, partition, conv.Mapping)
	w.requireInitrds(t, true, "")

	// The dialogue must return by the agent's re-arm alone (decision 52), with no marker set by the test.
	w.rebootRequest(t)
	w.AnswerDiskSetup(t, pin)
	info := w.WaitDisk(t, "compliant", 15*time.Minute, func(i diskInfo) bool { return i.state() == "compliant" })
	if !slices.Equal(info.Tokens, []string{"recovery", "tpm2+pin"}) || stored(info.RecoveryKeys) < 2 || stored(info.Headers) < 1 {
		t.Fatalf("compliant disk %+v", info)
	}
	if h := w.convHealth(); h.Disk.Conversion != nil && h.Disk.Conversion.KeyOnBoot {
		t.Fatal("key_on_boot is still true at compliant")
	}
	if c := w.waitConversion(t, "not active at compliant", 5*time.Minute, func(c apiConversion) bool { return !c.Active }); c.Phase != "completed" {
		t.Fatalf("conversion at compliant %+v", c)
	}
	w.requestUninstall(t, http.StatusOK)
	w.s.Call(t, http.MethodPost, "/api/v1/devices/"+w.ID+"/uninstall/cancel", nil, http.StatusOK)
	w.requireFinalDisk(t, partition, conv.LUKSUUID, conversionKey)
	w.RebootWithPIN(t, pin)
	if after := w.fsBytes(t); sizeBefore-after != 64<<20 {
		t.Fatalf("the root file system shrank by %d bytes (%d → %d), want 64 MiB", sizeBefore-after, sizeBefore, after)
	}
}

// TestInPlaceEncryptionPlain is gate S-IE2 of plan M8e (§9 as amended by §14.6 decision 47): an unencrypted Ubuntu
// 24.04 Desktop with ext4 directly on its root partition, the organization on tpm_only. Part A: the operator's abort
// at the device and the administrator's cancel from the portal after the preparation each leave an unencrypted
// device that boots and is eligible again; a skipped init step (resume= on the kernel command line) fails the
// conversion and its cleanup finishes. Part B: the power is cut during the init delay after the shrink; the next boot
// initialises LUKS2; no boot enrolls the TPM while the reencryption is unfinished (amendment item 22); the first boot
// after completion enrolls it without a dialogue; while a package run holds the dpkg lock the agent defers the initrd
// regeneration, apt refuses, and a kernel installed meanwhile gets a verified initrd; the device ends compliant with
// [recovery, tpm2]. It runs only with PADDOCK_SYSTEM_VMS=paddock-ie-2404.
func TestInPlaceEncryptionPlain(t *testing.T) {
	w := newIEWorldTPMOnly(t, ieVM2404, "24.04")
	w.logEvidence(t, "root reference (PDK-242)", "findmnt --fstab -no SOURCE /; grep -v '^#' /etc/fstab; cat /proc/cmdline")
	h := w.waitHealth(t, "eligible with layout plain", 15*time.Minute, func(h conversionHealth) bool { return h.eligible("plain") })
	t.Logf("%s: conversion %+v", w.Name, *h.Disk.Conversion)
	if c := h.Disk.Conversion; c.Initramfs != "initramfs-tools" || len(c.InitramfsRemoves) == 0 {
		t.Fatalf("a 24.04 Desktop reports initramfs %q removing %v", c.Initramfs, c.InitramfsRemoves)
	}
	pu := w.rootPartUUID(t)

	if !t.Run("hibernation through dracut.conf.d refused", func(t *testing.T) {
		w.Bind(t)
		// Under initramfs-tools the directory does not exist yet; the preflight reads it when it does.
		w.Must(`sudo mkdir -p /etc/dracut.conf.d && echo 'kernel_cmdline="resume=/dev/disk/by-partuuid/` + pu + `"' | sudo tee /etc/dracut.conf.d/99-systest-resume.conf >/dev/null && sudo systemctl restart paddock-supervisor`)
		w.waitHealth(t, "hibernation_configured", 5*time.Minute, func(h conversionHealth) bool {
			return slices.Contains(h.reasons(), "hibernation_configured")
		})
		w.Must("sudo rm /etc/dracut.conf.d/99-systest-resume.conf && sudo systemctl restart paddock-supervisor")
		w.waitHealth(t, "eligible again", 5*time.Minute, func(h conversionHealth) bool { return h.eligible("plain") })
	}) {
		t.FailNow()
	}

	if !t.Run("A1 operator abort", func(t *testing.T) {
		w.Bind(t)
		id := w.requestEncryption(t)
		w.waitPrepared(t, id, "plain")
		if out := w.Must(`dpkg-query -W -f='${db:Status-Status} ' dracut initramfs-tools 2>/dev/null || true`); !strings.HasPrefix(out, "installed") || strings.Contains(out, "installed installed") {
			t.Fatalf("dracut and initramfs-tools after the preparation: %q", out)
		}
		w.logEvidence(t, "packages after the switch", "dpkg -l dracut initramfs-tools brltty 2>&1 | tail -4")
		w.requireInitrds(t, true, "")
		w.Must("sudo paddockd encrypt-abort")
		w.WaitEvent(t, "device.disk_conversion_aborted", 5*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id && p["by"] == "operator" })
		w.waitConversion(t, "cancelled", 5*time.Minute, func(c apiConversion) bool { return c.ID == id && c.Phase == "cancelled" })
		w.waitAbortCleaned(t)
		w.reboot(t)
		w.requireUnencrypted(t)
		w.waitHealth(t, "eligible after the abort", 10*time.Minute, func(h conversionHealth) bool { return h.eligible("plain") })
	}) {
		t.FailNow()
	}

	if !t.Run("A2 portal cancel", func(t *testing.T) {
		w.Bind(t)
		id := w.requestEncryption(t)
		w.waitPrepared(t, id, "plain")
		w.s.StepUp(t)
		var dev apiDevice
		if err := json.Unmarshal(w.s.Call(t, http.MethodPost, "/api/v1/devices/"+w.ID+"/encrypt/cancel",
			map[string]any{"confirm_hostname": w.spec.Name}, http.StatusOK).Body, &dev); err != nil || dev.DiskConversion == nil || dev.DiskConversion.AbortCommandID == nil {
			t.Fatalf("cancel after the preparation: %v %+v", err, dev.DiskConversion)
		}
		abort := *dev.DiskConversion.AbortCommandID
		// The audit event is written asynchronously (outbox, audit writer).
		Until(t, w.Name+": device.encrypt_cancelled with mode abort_sent", 2*time.Minute, 5*time.Second, nil, func() bool {
			p := w.s.Events(t, "device.encrypt_cancelled", w.ID)
			return len(p) > 0 && p[len(p)-1].Params["mode"] == "abort_sent" && p[len(p)-1].Params["conversion_id"] == id
		})
		w.WaitEvent(t, "device.disk_conversion_aborted", 10*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id && p["by"] == "admin" })
		w.waitConversion(t, "cancelled", 5*time.Minute, func(c apiConversion) bool {
			return c.ID == id && c.Phase == "cancelled" && c.AbortCommandStatus != nil && *c.AbortCommandStatus == "succeeded"
		})
		w.requireCommandResult(t, abort, `{"aborted":true}`)
		w.waitAbortCleaned(t)
		if info := w.Disk(); !slices.ContainsFunc(info.RecoveryKeys, func(e diskEscrow) bool { return e.Generation == 1 && e.Status == "stored" }) {
			t.Fatalf("recovery key generation 1 is not listed as stored: %+v", info.RecoveryKeys)
		}
		w.reboot(t)
		w.requireUnencrypted(t)
		w.waitHealth(t, "eligible after the cancel", 10*time.Minute, func(h conversionHealth) bool { return h.eligible("plain") })
	}) {
		t.FailNow()
	}

	if !t.Run("A3 skipped init step, cleanup finishes", func(t *testing.T) {
		w.Bind(t)
		id := w.requestEncryption(t)
		w.waitPrepared(t, id, "plain")
		w.kernelArg("resume=/dev/disk/by-partuuid/" + pu)
		mark := w.rebootRequest(t)
		w.waitSerial(t, "paddock-encrypt: result skipped init resume_set", mark, 15*time.Minute)
		Until(t, w.Name+" answers SSH after the skipped init step", 15*time.Minute, 5*time.Second, nil, w.sshUp)
		w.requireUnencrypted(t)
		w.WaitEvent(t, "device.disk_conversion_failed", 10*time.Minute, func(p map[string]any) bool {
			return p["conversion_id"] == id && p["stage"] == "init" && p["reason"] == "resume_set"
		})
		w.waitAbortCleaned(t)
		w.dropKernelArg("resume=")
		w.reboot(t)
		w.waitHealth(t, "eligible after the failed init step", 10*time.Minute, func(h conversionHealth) bool { return h.eligible("plain") })
	}) {
		t.FailNow()
	}

	t.Run("B power cut after the shrink", func(t *testing.T) {
		w.Bind(t)
		id := w.requestEncryption(t)
		w.waitPrepared(t, id, "plain")
		conv := w.convState(t)
		partition := w.partition(t, strings.TrimPrefix(conv.Partition, "/dev/disk/by-partuuid/"))
		_, conversionKey := w.newestRecoveryKey(t)

		w.kernelArg("paddock.encrypt.testdelay=init:120")
		mark := w.rebootRequest(t)
		began := w.waitSerial(t, "paddock-encrypt: ", mark, 10*time.Minute)
		shrunk := w.waitSerial(t, "paddock-encrypt: shrink done", mark, 20*time.Minute)
		t.Logf("%s: init step to shrink done %s", w.Name, shrunk.Sub(began).Round(time.Second))
		// Only a delay that really runs makes the power cut land between the shrink and the header.
		w.waitSerial(t, "paddock-encrypt: test delay init", mark, time.Minute)
		time.Sleep(10 * time.Second)
		w.powerCut(t, "during the init delay after the shrink")

		w.LimitDisk(t, ieDiskLimit)
		w.powerOn(t)
		w.waitSerial(t, "paddock-encrypt: file system already at target", 0, 15*time.Minute)
		w.waitSerial(t, "paddock-encrypt: init done", 0, 15*time.Minute)
		Until(t, w.Name+" answers SSH on dm-crypt", 15*time.Minute, 5*time.Second, nil, w.sshUp)
		w.requireLUKSRoot(t, partition, conv.Mapping)
		w.requireRootReference(t, conv.Mapping)
		w.logBootEvidence(t, "boot 2 (init after the power cut)")
		// No TPM enrollment while the header is marked for reencryption (stop condition S2, amendment item 22).
		w.requireNoDiskSetup(t)
		w.probeEnrollWhileEncrypting(t, partition)
		w.requireEnrollmentDeferred(t)
		started := w.WaitEvent(t, "device.disk_conversion_started", 10*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id })
		t.Logf("%s: disk.conversion_started %v", w.Name, started)
		// Stop condition S10 from the init step's own timing; this boot includes the 120 s test delay.
		if s, _ := started["init_s"].(float64); s <= 0 || s > (10*time.Minute+120*time.Second).Seconds() {
			t.Fatalf("stop condition S10: init_s %v", started["init_s"])
		}
		w.waitHealth(t, "encrypting", 5*time.Minute, func(h conversionHealth) bool { return h.Disk.State == "encrypting" })

		// An open boot needs no input: the module opens the volume with the key in the initrd.
		w.dropKernelArg("paddock.encrypt.testdelay=")
		w.reboot(t)
		w.requireNoDiskSetup(t)
		w.logBootEvidence(t, "boot 3 (open while encrypting)")
		w.requireProgress(t, 0)
		w.restartWithDiskLimit(t, diskUnlimited)
		w.WaitEvent(t, "device.disk_conversion_completed", 30*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id })
		Until(t, w.Name+": disk setup armed at completion", 10*time.Minute, 10*time.Second, nil, func() bool {
			return w.fileState("/var/lib/paddock/disk-setup-pending") == "present"
		})

		// The first boot after completion enrolls the TPM; a package run holds the dpkg lock while the agent would
		// regenerate the initrds, and a kernel is installed meanwhile (PDK-245 verification items).
		kernel := w.stageKernel(t)
		w.holdDpkgAtBoot(t)
		w.reboot(t)
		if out := w.Must("sudo journalctl -b -u paddock-disk-setup.service --no-pager -o cat"); !strings.Contains(out, "TPM unlock enrolled") {
			t.Fatalf("no TPM-only enrollment at the first boot after completion:\n%s", out)
		}
		w.requireDpkgDeferral(t, id)
		w.installKernelDuringRegeneration(t, kernel, conv.LUKSUUID)
		info := w.WaitDisk(t, "compliant", 15*time.Minute, func(i diskInfo) bool { return i.state() == "compliant" })
		if info.UnlockMode != "tpm_only" || !slices.Equal(info.Tokens, []string{"recovery", "tpm2"}) {
			t.Fatalf("compliant disk %+v", info)
		}
		w.requireFinalDisk(t, partition, conv.LUKSUUID, conversionKey)
		w.reboot(t)
		w.requireRootReference(t, conv.Mapping)
	})
}

// newIEWorldTPMOnly is newIEWorld for the plain layout on 24.04 with the organization's unlock mode tpm_only before
// the device enrolls; tpm_pin is restored when the test ends (plan M8e decision 47: such a gate runs alone).
func newIEWorldTPMOnly(t *testing.T, spec aiSpec, release string) *ieWorld {
	t.Helper()
	if !slices.Contains(strings.Split(os.Getenv("PADDOCK_SYSTEM_VMS"), ","), spec.Name) {
		t.Skip("this in-place encryption gate runs with PADDOCK_SYSTEM_VMS=" + spec.Name)
	}
	s := newStack(t)
	setUnlockMode(t, s, "tpm_only")
	t.Cleanup(func() {
		// The gate runs for an hour; the session it started with has expired by then.
		s.Login(t)
		setUnlockMode(t, s, "tpm_pin")
	})
	return newIEWorld(t, spec, release, "unencrypted-plain.yaml.tmpl")
}

// waitAbortCleaned waits until an abandoned conversion's cleanup finished (invariant I3): no cleanup_pending, the
// conversion key and the plan gone, and no initrd carrying the module.
func (w *ieWorld) waitAbortCleaned(t *testing.T) {
	t.Helper()
	w.waitHealth(t, "cleanup finished", 15*time.Minute, func(h conversionHealth) bool {
		return !slices.Contains(h.reasons(), "cleanup_pending")
	})
	for _, p := range []string{"/var/lib/paddock/install-passphrase", "/var/lib/paddock/encrypt/plan.env", "/usr/lib/dracut/modules.d/99paddock-encrypt",
		"/etc/dracut.conf.d/91-paddock-encrypt.conf", "/var/lib/paddock/disk-setup-pending"} {
		if w.fileState(p) != "gone" {
			t.Fatalf("%s is still there after the cleanup", p)
		}
	}
	w.requireInitrds(t, false, "")
}

// requireCommandResult asserts the result the device reported for command id.
func (w *ieWorld) requireCommandResult(t *testing.T, id, want string) {
	t.Helper()
	var page struct {
		Items []struct {
			ID     string         `json:"id"`
			Status string         `json:"status"`
			Result map[string]any `json:"result"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.s.Call(t, http.MethodGet, "/api/v1/devices/"+w.ID+"/commands?page_size=100", nil, http.StatusOK).Body, &page); err != nil {
		t.Fatal(err)
	}
	for _, c := range page.Items {
		if c.ID == id {
			if got, _ := json.Marshal(c.Result); string(got) != want {
				t.Fatalf("command %s %s: result %s, want %s", id, c.Status, got, want)
			}
			return
		}
	}
	t.Fatalf("command %s not listed", id)
}

// stageKernel downloads, before the conversion, the packages of a kernel that is not installed, so that it can be
// installed while the agent regenerates the initrds; it returns the kernel version.
func (w *ieWorld) stageKernel(t *testing.T) string {
	t.Helper()
	v := w.Must(`apt-cache search --names-only '^linux-image-[0-9.]+-[0-9]+-generic$' | awk '{print $1}' | sed 's/^linux-image-//' | sort -V |` +
		` while read -r v; do dpkg-query -W -f='${db:Status-Status}' "linux-image-$v" 2>/dev/null | grep -q installed || echo "$v"; done | tail -1`)
	if v == "" {
		t.Fatal("no kernel version that is not installed")
	}
	w.Must("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --download-only linux-image-" + v + " linux-modules-" + v + " >/dev/null")
	t.Logf("%s: kernel %s staged", w.Name, v)
	return v
}

// dpkgHold holds apt's locks (the frontend lock, then dpkg's) from early boot until /run/systest-dpkg-held is removed.
const dpkgHold = `import fcntl, os, time
fds = []
for p in ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"):
    fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o640)
    fcntl.lockf(fd, fcntl.LOCK_EX)
    fds.append(fd)
open("/run/systest-dpkg-held", "w").close()
while os.path.exists("/run/systest-dpkg-held"):
    time.sleep(1)
`

// holdDpkgAtBoot installs a unit that holds apt's locks from the next boot on, before the agent starts, for one boot
// (PDK-245 verification: the real dpkg lock during the regeneration of decision 20).
func (w *ieWorld) holdDpkgAtBoot(t *testing.T) {
	t.Helper()
	w.MustIn([]byte(dpkgHold), "sudo tee /root/systest-dpkg-hold.py >/dev/null")
	w.MustIn([]byte(`[Unit]
Description=System test: hold the dpkg lock
Before=paddock-supervisor.service
ConditionPathExists=!/root/systest-dpkg-hold.done

[Service]
Type=simple
ExecStartPre=/bin/touch /root/systest-dpkg-hold.done
ExecStart=/usr/bin/python3 /root/systest-dpkg-hold.py
ExecStartPost=/bin/sh -c 'while [ ! -e /run/systest-dpkg-held ]; do sleep 0.2; done'

[Install]
WantedBy=multi-user.target
`), "sudo tee /etc/systemd/system/systest-dpkg-hold.service >/dev/null && sudo systemctl enable systest-dpkg-hold.service 2>/dev/null")
}

// requireDpkgDeferral asserts, while the unit of holdDpkgAtBoot holds apt's locks, that apt refuses with the lock
// message and the agent defers the initrd regeneration without failing the conversion, then releases the locks.
func (w *ieWorld) requireDpkgDeferral(t *testing.T, conversionID string) {
	t.Helper()
	if out := w.Must("systemctl is-active systest-dpkg-hold.service"); out != "active" {
		t.Fatalf("the dpkg lock holder is %s", out)
	}
	out, err := w.SSH(t.Context(), nil, "sudo DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y hostname 2>&1")
	if err == nil || !strings.Contains(out, "Could not get lock") {
		t.Fatalf("apt-get while the lock is held: %v\n%s", err, out)
	}
	t.Logf("%s: apt while the lock is held:\n%s", w.Name, strings.TrimSpace(out))
	Until(t, w.Name+": the agent defers the regeneration", 5*time.Minute, 5*time.Second, nil, func() bool {
		return w.Must("sudo journalctl -b -u paddock-supervisor --no-pager -o cat | grep -c 'a package run holds the dpkg lock' || true") != "0"
	})
	if c := w.convState(t); c == nil || c.InitrdRegenerated {
		t.Fatalf("the initrd was regenerated while dpkg was locked: %+v", c)
	}
	for _, e := range w.s.Events(t, "device.disk_conversion_failed", w.ID) {
		if e.Params["conversion_id"] == conversionID {
			t.Fatalf("the busy dpkg lock failed the conversion: %v", e.Params)
		}
	}
	w.Must("sudo rm /run/systest-dpkg-held")
	// The holder notices the flag within a second; a package run started before it exits finds the lock still held
	// (S-IE2 run 5).
	Until(t, w.Name+": the dpkg lock holder ended", time.Minute, time.Second, nil, func() bool {
		return w.Must("systemctl is-active systest-dpkg-hold.service || true") != "active"
	})
}

// installKernelDuringRegeneration installs the staged kernel while the agent regenerates the initrds and waits until
// the regeneration is recorded with every installed kernel's initrd verified: the crypttab line, no module, no key.
func (w *ieWorld) installKernelDuringRegeneration(t *testing.T, kernel, luksUUID string) {
	t.Helper()
	w.Must(fmt.Sprintf("sudo systemd-run --quiet --unit systest-kernel --setenv=DEBIAN_FRONTEND=noninteractive /bin/sh -c "+
		"'apt-get install -y linux-image-%s linux-modules-%s > /root/systest-kernel.log 2>&1; echo apt exit=$? >> /root/systest-kernel.log'", kernel, kernel))
	Until(t, w.Name+": kernel installed", 15*time.Minute, 5*time.Second, nil, func() bool {
		return w.Must("systemctl is-active systest-kernel.service || true") != "active"
	})
	if out := w.logEvidence(t, "kernel install during the regeneration", "sudo tail -20 /root/systest-kernel.log"); !strings.Contains(out, "apt exit=0") {
		t.Fatalf("the kernel package was not installed")
	}
	if w.Must("test -f /boot/initrd.img-"+kernel+" && echo yes || echo no") != "yes" {
		t.Fatalf("no initrd for kernel %s", kernel)
	}
	// The package's own initrd must already unlock the disk (I1): the module and the key before the agent's
	// regeneration, or the crypttab line once it ran.
	if i := w.initrds(t)["/boot/initrd.img-"+kernel]; !(i.Module && i.Key) && !strings.Contains(i.Crypttab, luksUUID) {
		t.Fatalf("the new kernel's initrd has no unlock path: %+v", i)
	}
	Until(t, w.Name+": initrd regenerated", 15*time.Minute, 10*time.Second, nil, func() bool {
		c := w.convState(t)
		return c != nil && c.InitrdRegenerated || c == nil
	})
	w.logEvidence(t, "regeneration journal", "sudo journalctl -b -u paddock-supervisor --no-pager -o cat | grep -i -e initrd -e 'dpkg lock' | tail -20")
	w.requireInitrds(t, false, luksUUID)
	if !strings.Contains(w.Must("ls /boot"), "initrd.img-"+kernel) {
		t.Fatal("the new kernel's initrd is gone")
	}
}

// TestInPlaceEncryptionCleanupAdopt is gate S-IE4 of plan M8e (§14.6 decision 53; the cancelled and failed:prepare
// rows of §14.10): an operator abort whose initrd rebuild fails leaves cleanup_pending with the key and the plan on
// the device; an uninstall is refused by the device (conversion_pending) and cancelled by the administrator; a reboot
// converts through the stale initrd, the agent adopts the conversion, reinstalls the module once dracut works again,
// and a kernel-update rebuild keeps the device booting on dm-crypt until it is compliant. It runs only with
// PADDOCK_SYSTEM_VMS=paddock-ie-2404.
func TestInPlaceEncryptionCleanupAdopt(t *testing.T) {
	w := newIEWorldTPMOnly(t, ieVM2404, "24.04")
	w.waitHealth(t, "eligible with layout plain", 15*time.Minute, func(h conversionHealth) bool { return h.eligible("plain") })
	id := w.requestEncryption(t)
	w.waitHealth(t, "conversion prepared", 15*time.Minute, func(h conversionHealth) bool {
		return h.Disk.Conversion != nil && h.Disk.Conversion.Phase == "prepared"
	})
	// The restart notification on 24.04 as well (decision 45; the screenshots are evidence only).
	shots := w.shots(t, "notification")
	w.requireNotified(t)
	shots()
	w.waitPrepared(t, id, "plain")
	conv := w.convState(t)
	partition := w.partition(t, strings.TrimPrefix(conv.Partition, "/dev/disk/by-partuuid/"))
	_, conversionKey := w.newestRecoveryKey(t)

	w.Must("sudo dpkg-divert --add --rename --divert /usr/bin/dracut.real /usr/bin/dracut >/dev/null && printf '#!/bin/sh\\nexit 1\\n' | sudo tee /usr/bin/dracut >/dev/null && sudo chmod 0755 /usr/bin/dracut")
	w.Must("sudo paddockd encrypt-abort")
	w.WaitEvent(t, "device.disk_conversion_aborted", 5*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id && p["by"] == "operator" })
	w.waitConversion(t, "cancelled", 5*time.Minute, func(c apiConversion) bool { return c.ID == id && c.Phase == "cancelled" })
	h := w.waitHealth(t, "cleanup_pending", 5*time.Minute, func(h conversionHealth) bool {
		c := h.Disk.Conversion
		return c != nil && !c.Eligible && slices.Equal(c.Reasons, []string{"cleanup_pending"})
	})
	t.Logf("%s: cleanup_error %q", w.Name, h.Disk.Conversion.CleanupError)
	if w.fileState("/usr/lib/dracut/modules.d/99paddock-encrypt") != "gone" {
		t.Fatal("the module directory is still there")
	}
	for _, p := range []string{"/var/lib/paddock/encrypt/plan.env", "/var/lib/paddock/install-passphrase"} {
		if w.fileState(p) != "present" {
			t.Fatalf("%s is gone before the cleanup finished (I3)", p)
		}
	}
	if out := w.Must("sudo lsinitrd /boot/initrd.img-$(uname -r) | grep -c usr/lib/systemd/system/paddock-encrypt-init.service || true"); out == "0" {
		t.Fatal("the running kernel's initrd lost the module although the rebuild failed")
	}

	// The server accepts the uninstall (the row is cancelled); the device refuses it, which ends the command but not the
	// request: the administrator cancels it (amendment 2026-10-23 to decision 53, the uninstall behaviour of plan M8d).
	res := w.RequestUninstall("leave", nil, http.StatusOK)
	type uninstall struct {
		CommandID     string `json:"command_id"`
		CommandStatus string `json:"command_status"`
	}
	var dev struct {
		Uninstall *uninstall `json:"uninstall"`
	}
	if err := json.Unmarshal(res.Body, &dev); err != nil || dev.Uninstall == nil {
		t.Fatalf("uninstall request: %v %s", err, res.Body)
	}
	w.Checkin()
	Until(t, w.Name+": the device refuses the uninstall", 10*time.Minute, 10*time.Second, w.Checkin, func() bool {
		var d struct {
			Uninstall *uninstall `json:"uninstall"`
		}
		_ = json.Unmarshal(w.s.Call(t, http.MethodGet, "/api/v1/devices/"+w.ID, nil, http.StatusOK).Body, &d)
		return d.Uninstall != nil && d.Uninstall.CommandStatus == "failed"
	})
	w.requireCommandResult(t, dev.Uninstall.CommandID, `{"accepted":false,"reason":"conversion_pending"}`)
	w.s.Call(t, http.MethodPost, "/api/v1/devices/"+w.ID+"/uninstall/cancel", nil, http.StatusOK)
	if u := w.device(t).Uninstall; u != nil {
		t.Fatalf("an uninstall is still open after the cancel: %s", *u)
	}

	// The stale initrd still converts the disk at the next boot; the agent must adopt it (I2).
	w.powerDown(t)
	w.LimitDisk(t, ieDiskLimit)
	w.powerOn(t)
	w.waitSerial(t, "paddock-encrypt: init done", 0, 20*time.Minute)
	Until(t, w.Name+" answers SSH on dm-crypt", 15*time.Minute, 5*time.Second, nil, w.sshUp)
	w.requireLUKSRoot(t, partition, conv.Mapping)
	w.requireRootReference(t, conv.Mapping)
	w.logBootEvidence(t, "conversion through the stale initrd")
	w.requireNoFailedEnrollment(t)
	started := w.WaitEvent(t, "device.disk_conversion_started", 10*time.Minute, func(p map[string]any) bool {
		return p["conversion_id"] == id && p["init_result"] == "ok"
	})
	t.Logf("%s: disk.conversion_started %v (init step of the conversion boot)", w.Name, started)
	if s, _ := started["init_s"].(float64); s <= 0 || s > (10*time.Minute).Seconds() {
		t.Fatalf("stop condition S10: init_s %v", started["init_s"])
	}
	w.waitConversion(t, "adopted", 5*time.Minute, func(c apiConversion) bool { return c.ID == id && c.Phase == "encrypting" })
	w.waitHealth(t, "encrypting", 5*time.Minute, func(h conversionHealth) bool { return h.Disk.State == "encrypting" })
	Until(t, w.Name+": module reinstalled", 5*time.Minute, 5*time.Second, nil, func() bool {
		return w.fileState("/usr/lib/dracut/modules.d/99paddock-encrypt") == "present" && w.fileState("/etc/dracut.conf.d/91-paddock-encrypt.conf") == "present"
	})
	unlockPath := "sudo journalctl -b -u paddock-supervisor --no-pager -o cat | grep -c '%s' || true"
	Until(t, w.Name+": the reinstall fails while dracut is diverted", 10*time.Minute, 10*time.Second, nil, func() bool {
		return w.Must(fmt.Sprintf(unlockPath, "reinstalling the unlock path of the converted disk failed")) != "0"
	})
	// The stale initrd carries the module anyway (I1), so the proof is the failure while diverted, then the agent's
	// success line and initrds newer than the moment the diversion was removed.
	if out := w.Must(fmt.Sprintf(unlockPath, "the unlock path of the converted disk is reinstalled in every initrd")); out != "0" {
		t.Fatalf("the reinstall succeeded while dracut was diverted (%s lines)", out)
	}
	removed := w.Must("date +%s")
	w.Must("sudo rm /usr/bin/dracut && sudo dpkg-divert --remove --rename /usr/bin/dracut >/dev/null && test -x /usr/bin/dracut")
	Until(t, w.Name+": the agent reinstalled the unlock path", 20*time.Minute, 15*time.Second, nil, func() bool {
		return w.Must(fmt.Sprintf(unlockPath, "the unlock path of the converted disk is reinstalled in every initrd")) != "0"
	})
	if stale := w.Must("find /boot -maxdepth 1 -name 'initrd.img-*' -type f ! -newermt @" + removed + " | wc -l"); stale != "0" {
		t.Fatalf("%s initrds were not rebuilt after the diversion was removed", stale)
	}
	for name, i := range w.initrds(t) {
		if !i.Module || !i.Key {
			t.Fatalf("%s lacks the module or the key after the reinstall: %+v", name, i)
		}
	}
	// A kernel update's rebuild by anyone must keep the device booting on dm-crypt (I1).
	w.Must("sudo dracut -f --regenerate-all >/dev/null 2>&1")
	w.reboot(t)
	w.requireLUKSRoot(t, partition, conv.Mapping)
	w.requireNoFailedEnrollment(t)
	w.requireProgress(t, 0)
	w.restartWithDiskLimit(t, diskUnlimited)
	w.WaitEvent(t, "device.disk_conversion_completed", 30*time.Minute, func(p map[string]any) bool { return p["conversion_id"] == id })
	// No keyslot can be added before completion; the first boot after it enrolls the TPM (amendment item 22).
	Until(t, w.Name+": disk setup armed at completion", 10*time.Minute, 10*time.Second, nil, func() bool {
		return w.fileState("/var/lib/paddock/disk-setup-pending") == "present"
	})
	w.reboot(t)
	if out := w.Must("sudo journalctl -b -u paddock-disk-setup.service --no-pager -o cat"); !strings.Contains(out, "TPM unlock enrolled") {
		t.Fatalf("no TPM-only enrollment at the first boot after completion:\n%s", out)
	}
	info := w.WaitDisk(t, "compliant", 15*time.Minute, func(i diskInfo) bool { return i.state() == "compliant" })
	if !slices.Equal(info.Tokens, []string{"recovery", "tpm2"}) {
		t.Fatalf("compliant disk %+v", info)
	}
	w.requireFinalDisk(t, partition, conv.LUKSUUID, conversionKey)
	w.reboot(t)
}
