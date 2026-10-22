package system

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The in-place encryption gates of plan M8e §9 (S-IE1, S-IE2, S-IE4) run on throwaway VMs installed without disk
// encryption from the templates test/vms/virtualbox/autoinstall/unencrypted-*.yaml.tmpl, one gate per run (§14.6).

// ieUser is the throwaway VMs' desktop user; GDM logs it in automatically, so a graphical session exists.
const ieUser = "paddocktest"

// ieDiskLimit is the disk throughput of a throwaway VM while its background reencryption runs: about half an hour
// for its 16 GiB, so that the reencryption is still running at the next boot and the power can be cut between 10 %
// and 90 % (plan M8e decision 44). A gate lifts it with a clean restart once it has seen the progress it asserts.
const ieDiskLimit = "8M"

// ieWorld is the device of an in-place encryption gate on its throwaway VM.
type ieWorld struct {
	*Device
	spec aiSpec
}

// newIEWorld runs only when PADDOCK_SYSTEM_VMS names spec's VM (opt-in, like gate D-AI). It releases this tree's
// packages (retracted when the test ends), installs the throwaway VM from template and the Ubuntu ISO of release,
// installs the packages and enrolls the device; the device is retired and the VM deleted when the test ends. The free
// space of the development host is logged before and after the run.
func newIEWorld(t *testing.T, spec aiSpec, release, template string) *ieWorld {
	t.Helper()
	if !slices.Contains(strings.Split(os.Getenv("PADDOCK_SYSTEM_VMS"), ","), spec.Name) {
		t.Skip("this in-place encryption gate runs with PADDOCK_SYSTEM_VMS=" + spec.Name)
	}
	logFree(t, "before the run")
	t.Cleanup(func() { logFree(t, "after the run") })
	s := newStack(t)
	iso := isoPath(t, release)
	s.releaseThisTree(t)
	userData := renderIETemplate(t, s.root, template, spec.Name)
	vm := buildAIVM(t, s.root, spec, iso, withTestAccess(t, userData, s.root, &VM{dir: filepath.Join(s.root, "test", "vms", "virtualbox")}))
	vm.start(t)
	vm.Must("sudo systemctl mask --now " + aptUnits)
	vm.Must("timeout 600 sh -c 'while systemctl is-active " + aptServices + " | grep -qx \"active\\|activating\"; do sleep 2; done'")
	d := Install(t, s, vm, debDir(s))
	t.Cleanup(func() {
		s.cleanupCall(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/retire", http.StatusOK, http.StatusConflict)
	})
	w := &ieWorld{Device: d, spec: spec}
	if err := os.MkdirAll(w.evidenceDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			w.saveDiagnostics(t)
		}
	})
	return w
}

// evidenceDir is bin/system-evidence/<vm>/, where the screenshots and the diagnostics of a failed gate are kept.
func (w *ieWorld) evidenceDir() string {
	return filepath.Join(w.dir, "..", "..", "..", "bin", "system-evidence", w.Name)
}

// saveDiagnostics keeps, before a failed gate deletes its VM, the agent's journal, its health, the conversion state and
// the serial console in evidenceDir (none of them holds a secret).
func (w *ieWorld) saveDiagnostics(t *testing.T) {
	prefix := filepath.Join(w.evidenceDir(), strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"-failure-")
	for name, command := range map[string]string{
		"journal.txt": "sudo journalctl -b --no-pager -o short-monotonic -u paddock-supervisor -u paddock-disk-setup -u 'paddock-encrypt*' | tail -3000",
		"boots.txt":   "sudo journalctl --list-boots --no-pager; sudo journalctl --no-pager -o short-monotonic | grep -E 'paddock-encrypt|systemd-cryptsetup' | tail -500",
		"health.json": "sudo python3 -c " + shellQuote(healthScript),
		"state.json":  "sudo cat /var/lib/paddock/state/state.json",
		"initrds.txt": "sudo sh -c " + shellQuote(initrdScript) + "; for f in /boot/initrd.img-*; do echo \"== $f\"; sudo lsinitrd \"$f\" | grep -e paddock -e crypttab; done",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		out, err := w.SSH(ctx, nil, command)
		cancel()
		if err != nil {
			out += "\n(" + err.Error() + ")"
		}
		if err := os.WriteFile(prefix+name, []byte(out), 0o644); err != nil {
			t.Logf("diagnostics %s: %v", name, err)
		}
	}
	if err := os.WriteFile(prefix+"serial.log", []byte(w.Serial(t)), 0o644); err != nil {
		t.Logf("diagnostics serial: %v", err)
	}
	t.Logf("%s: diagnostics saved to %s*", w.Name, prefix)
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// logFree logs the free space of the file system that holds the VirtualBox machine folder (the result document
// records it per run).
func logFree(t *testing.T, when string) {
	out, err := run(context.Background(), "df", "-h", "--output=avail,target", os.Getenv("HOME"))
	t.Logf("free space %s: %s %v", when, strings.Join(strings.Fields(out), " "), err)
}

// renderIETemplate renders an unencrypted-*.yaml.tmpl for hostname with ieUser and a random password.
func renderIETemplate(t *testing.T, root, template, hostname string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "test", "vms", "virtualbox", "autoinstall", template))
	if err != nil {
		t.Fatal(err)
	}
	pw := make([]byte, 16)
	_, _ = rand.Read(pw)
	cmd := exec.Command("openssl", "passwd", "-6", "-stdin")
	cmd.Stdin = strings.NewReader(hex.EncodeToString(pw))
	hash, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl passwd: %v", err)
	}
	return []byte(strings.NewReplacer("@@HOSTNAME@@", hostname, "@@USERNAME@@", ieUser,
		"@@PASSWORD_HASH@@", strings.TrimSpace(string(hash))).Replace(string(raw)))
}

// releaseThisTree builds the packages of this tree as a new release and rolls it out to all devices in one wave of a
// day, so that no other release replaces the agent under test; the rollout is retracted (retractRelease) and bin/deb
// rebuilt as version 0.1.0 when the test ends (plan M8e decision 48).
func (s *Stack) releaseThisTree(t *testing.T) {
	t.Helper()
	v := version(9, "ie")
	s.Make(t, "deb", "VERSION="+v, "TAGS=paddock_dev", "REVOKE_TAGS=paddock_revoke_testtarget")
	t.Cleanup(func() { s.Make(t, "deb", "VERSION=0.1.0", "TAGS=paddock_dev", "REVOKE_TAGS=paddock_revoke_testtarget") })
	debs, err := filepath.Glob(filepath.Join(s.root, "bin", "deb", "*.deb"))
	if err != nil || len(debs) != 3 {
		t.Fatalf("packages %v: %v", debs, err)
	}
	args := []string{"--version", v, "--artifact", "amd64=" + filepath.Join(s.root, "bin", "agent", "amd64", "paddockd"),
		"--rollout", "--halt-running", "--waves", "100", "--min-wave-minutes", "1440"}
	for _, deb := range debs {
		args = append(args, "--deb", deb)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentRelease(s.root), args...)
	cmd.Dir = s.root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agentrelease %s: %v\n%s", v, err, out)
	}
	t.Cleanup(func() { retractRelease(t, v) })
}

// start boots the powered-off VM headless and waits for SSH.
func (v *VM) start(t *testing.T) {
	t.Helper()
	v.powerOn(t)
	Until(t, v.Name+" answers SSH", 15*time.Minute, 5*time.Second, nil, v.sshUp)
}

// powerOn boots the powered-off VM headless and clears its serial console file first, so that Serial shows this boot
// only.
func (v *VM) powerOn(t *testing.T) {
	t.Helper()
	if err := os.Truncate(v.serial, 0); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if out, err := run(context.Background(), "VBoxManage", "startvm", v.Name, "--type", "headless"); err != nil {
		t.Fatalf("start %s: %v: %s", v.Name, err, out)
	}
}

// powerDown shuts the guest down cleanly and waits until the VM is powered off.
func (v *VM) powerDown(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	_, _ = v.SSH(ctx, nil, "sudo systemctl poweroff")
	// Polled here rather than with lib.sh wait_vm_state, whose state query fails now and then while the VM shuts down
	// (VM.state retries it; hand test run 3).
	Until(t, v.Name+" powers off", 10*time.Minute, 5*time.Second, nil, func() bool { return v.state(ctx) == "poweroff" })
	// VirtualBox writes the NVRAM after the state says poweroff (README: NVRAM pitfall).
	if out, err := v.lib(ctx, "wait_vm_process_exit "+v.Name); err != nil {
		t.Fatalf("%s: %v: %s", v.Name, err, out)
	}
}

// restartWithDiskLimit shuts the guest down cleanly, sets the disk limit and boots it again until SSH answers; a
// running reencryption is stopped by the shutdown and resumes at the boot.
func (v *VM) restartWithDiskLimit(t *testing.T, limit string) {
	t.Helper()
	v.powerDown(t)
	v.LimitDisk(t, limit)
	v.powerOn(t)
	Until(t, v.Name+" answers SSH", 15*time.Minute, 5*time.Second, nil, v.sshUp)
}

// powerCut switches the VM off hard, as a power cut would.
func (v *VM) powerCut(t *testing.T, what string) {
	t.Helper()
	v.Shot(t, "before-power-cut-"+what)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := v.PowerOff(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: power cut %s", v.Name, what)
}

// rebootRequest asks the guest to reboot and waits until SSH is gone; it returns the length of the serial console
// output before the reboot, for waitSerial.
func (v *VM) rebootRequest(t *testing.T) int {
	t.Helper()
	mark := len(v.Serial(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = v.SSH(ctx, nil, "sudo systemctl reboot")
	v.waitSSHDown(t)
	return mark
}

// reboot reboots the guest and waits for SSH.
func (v *VM) reboot(t *testing.T) {
	t.Helper()
	v.rebootRequest(t)
	Until(t, v.Name+" answers SSH after the reboot", 15*time.Minute, 5*time.Second, nil, v.sshUp)
}

// waitSerial waits until the serial console shows line after the offset from and returns when it appeared.
func (v *VM) waitSerial(t *testing.T, line string, from int, timeout time.Duration) time.Time {
	t.Helper()
	Until(t, v.Name+": console line "+strconv.Quote(line), timeout, time.Second, nil, func() bool {
		out := v.Serial(t)
		if len(out) < from {
			from = 0
		}
		return strings.Contains(out[from:], line)
	})
	return time.Now()
}

// kernelArg adds arg to GRUB_CMDLINE_LINUX of /etc/default/grub and runs update-grub (plan M8e §9: the dev-only test
// delay is set over SSH inside the guest, never by test/vms/virtualbox/*.sh).
func (v *VM) kernelArg(arg string) {
	v.t.Helper()
	v.Must(`sudo sed -i -E 's|^GRUB_CMDLINE_LINUX="(.*)"$|GRUB_CMDLINE_LINUX="\1 ` + arg + `"|' /etc/default/grub && sudo update-grub 2>/dev/null` +
		` && sudo grep -q -- '` + arg + `' /boot/grub/grub.cfg`)
}

// dropKernelArg removes every argument starting with prefix from GRUB_CMDLINE_LINUX and runs update-grub.
func (v *VM) dropKernelArg(prefix string) {
	v.t.Helper()
	v.Must(`sudo sed -i -E '/^GRUB_CMDLINE_LINUX=/ s| ` + regexp.QuoteMeta(prefix) + `[^ "]*||g' /etc/default/grub && sudo update-grub 2>/dev/null` +
		` && ! sudo grep -q -- '` + prefix + `' /boot/grub/grub.cfg`)
}

// conversionHealth is the part of the agent's health report the gates read.
type conversionHealth struct {
	Disk struct {
		State      string   `json:"state"`
		Tokens     []string `json:"tokens"`
		UnlockMode string   `json:"unlock_mode"`
		Conversion *struct {
			Eligible         bool     `json:"eligible"`
			Reasons          []string `json:"reasons"`
			Release          string   `json:"release"`
			Layout           string   `json:"layout"`
			Initramfs        string   `json:"initramfs"`
			InitramfsRemoves []string `json:"initramfs_removes"`
			KeyOnBoot        bool     `json:"key_on_boot"`
			CleanupError     string   `json:"cleanup_error"`
			Phase            string   `json:"phase"`
			DataBytes        int64    `json:"data_bytes"`
			DoneBytes        int64    `json:"done_bytes"`
			ETASeconds       int64    `json:"eta_s"`
			PausedReason     string   `json:"paused_reason"`
			InitrdIssue      string   `json:"initrd_issue"`
		} `json:"conversion"`
	} `json:"disk"`
}

// eligible reports whether the device reports an eligible layout.
func (h conversionHealth) eligible(layout string) bool {
	c := h.Disk.Conversion
	return h.Disk.State == "not_encrypted" && c != nil && c.Eligible && c.Layout == layout
}

// reasons are the preflight reasons the device reports.
func (h conversionHealth) reasons() []string {
	if h.Disk.Conversion == nil {
		return nil
	}
	return h.Disk.Conversion.Reasons
}

// done is the reencryption progress the device reports (0 without one).
func (h conversionHealth) done() (done, total int64) {
	if h.Disk.Conversion == nil {
		return 0, 0
	}
	return h.Disk.Conversion.DoneBytes, h.Disk.Conversion.DataBytes
}

// convHealth reads the agent's health report over SSH (plan M8e decision 44: the gates read the device, not the
// last check-in).
func (w *ieWorld) convHealth() conversionHealth {
	w.t.Helper()
	var h conversionHealth
	if err := json.Unmarshal([]byte(w.Health()), &h); err != nil {
		w.t.Fatalf("health: %v", err)
	}
	return h
}

// waitHealth polls the device's health every 5 s until cond holds.
func (w *ieWorld) waitHealth(t *testing.T, what string, timeout time.Duration, cond func(conversionHealth) bool) conversionHealth {
	t.Helper()
	var h conversionHealth
	Until(t, w.Name+": "+what, timeout, 5*time.Second, nil, func() bool {
		h = w.convHealth()
		return cond(h)
	})
	return h
}

// apiConversion is disk_conversion of GET /api/v1/devices/{id}.
type apiConversion struct {
	ID                 string  `json:"id"`
	Phase              string  `json:"phase"`
	Layout             *string `json:"layout"`
	DoneBytes          *int64  `json:"done_bytes"`
	ETASeconds         *int64  `json:"eta_s"`
	AbortCommandID     *string `json:"abort_command_id"`
	AbortCommandStatus *string `json:"abort_command_status"`
	Active             bool    `json:"active"`
}

// apiDevice is the part of GET /api/v1/devices/{id} the gates read.
type apiDevice struct {
	DiskConversion *apiConversion   `json:"disk_conversion"`
	Uninstall      *json.RawMessage `json:"uninstall"`
}

// device reads the device from the API.
func (w *ieWorld) device(t *testing.T) apiDevice {
	t.Helper()
	var d apiDevice
	if err := json.Unmarshal(w.s.Call(t, http.MethodGet, "/api/v1/devices/"+w.ID, nil, http.StatusOK).Body, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// conversion is the device's latest conversion in the API; it fails the test without one.
func (w *ieWorld) conversion(t *testing.T) apiConversion {
	t.Helper()
	c := w.device(t).DiskConversion
	if c == nil {
		t.Fatal("the device has no conversion")
	}
	return *c
}

// waitConversion waits until the API's conversion satisfies cond, checking in every 65 s.
func (w *ieWorld) waitConversion(t *testing.T, what string, timeout time.Duration, cond func(apiConversion) bool) apiConversion {
	t.Helper()
	var c apiConversion
	last := time.Time{}
	Until(t, w.Name+": "+what, timeout, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			w.Checkin()
			last = time.Now()
		}
	}, func() bool {
		d := w.device(t)
		if d.DiskConversion == nil {
			return false
		}
		c = *d.DiskConversion
		return cond(c)
	})
	return c
}

// requestEncryption waits until the server's last check-in reports the disk eligible (the server checks that report,
// not the device's current one), asks, as alice after a step-up, to encrypt the device in place and returns the
// conversion ID.
func (w *ieWorld) requestEncryption(t *testing.T) string {
	t.Helper()
	w.WaitDisk(t, "eligible in the last check-in", 10*time.Minute, func(i diskInfo) bool {
		return i.state() == "not_encrypted" && i.Conversion != nil && i.Conversion.Eligible
	})
	w.s.StepUp(t)
	var dev apiDevice
	res := w.s.Call(t, http.MethodPost, "/api/v1/devices/"+w.ID+"/encrypt", map[string]any{
		"confirm_hostname": w.spec.Name, "reason": "system gate " + w.run, "backup_confirmed": true,
	}, http.StatusOK)
	if err := json.Unmarshal(res.Body, &dev); err != nil || dev.DiskConversion == nil || dev.DiskConversion.Phase != "requested" {
		t.Fatalf("encrypt request: %v %s", err, res.Body)
	}
	t.Logf("%s: conversion %s requested", w.Name, dev.DiskConversion.ID)
	return dev.DiskConversion.ID
}

// waitPrepared waits until the device reports the conversion prepared and the server recorded
// device.disk_conversion_prepared with layout.
func (w *ieWorld) waitPrepared(t *testing.T, conversionID, layout string) {
	t.Helper()
	w.waitHealth(t, "conversion prepared", 15*time.Minute, func(h conversionHealth) bool {
		return h.Disk.Conversion != nil && h.Disk.Conversion.Phase == "prepared"
	})
	w.WaitEvent(t, "device.disk_conversion_prepared", 10*time.Minute, func(p map[string]any) bool {
		return p["conversion_id"] == conversionID && p["layout"] == layout
	})
}

// initrdInfo tells whether an installed initrd carries the Paddock module and the conversion key, and the crypttab
// it carries (lines joined by ";").
type initrdInfo struct {
	Module, Key bool
	Crypttab    string
}

// initrdScript prints one line per regular /boot/initrd.img-* file: the path, the number of lsinitrd lines naming
// paddock-encrypt (dracut's "Arguments:" line, which may name it in --omit, does not count, plan M8e amendment
// 2026-10-21 item 12), the number naming the conversion key, and the crypttab.
const initrdScript = `for f in /boot/initrd.img-*; do
	[ -f "$f" ] && [ ! -L "$f" ] || continue
	l=$(lsinitrd "$f" | grep -v '^Arguments:')
	printf '%s\t%s\t%s\t%s\n' "$f" "$(printf '%s\n' "$l" | grep -c paddock-encrypt)" \
		"$(printf '%s\n' "$l" | grep -c etc/paddock/encrypt-key)" "$(lsinitrd -f etc/crypttab "$f" 2>/dev/null | tr '\n' ';')"
done
`

// initrds reads every installed initrd of the guest.
func (w *ieWorld) initrds(t *testing.T) map[string]initrdInfo {
	t.Helper()
	out := w.MustIn([]byte(initrdScript), "sudo sh -s")
	res := parseInitrds(out)
	if len(res) == 0 {
		t.Fatalf("no initrd in /boot:\n%s", out)
	}
	t.Logf("%s: initrds %+v", w.Name, res)
	return res
}

// parseInitrds reads the output of initrdScript.
func parseInitrds(out string) map[string]initrdInfo {
	res := map[string]initrdInfo{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(line, "\t", 4)
		if len(f) < 3 || !strings.HasPrefix(f[0], "/boot/") {
			continue
		}
		i := initrdInfo{Module: f[1] != "0", Key: f[2] != "0"}
		if len(f) == 4 {
			i.Crypttab = f[3]
		}
		res[f[0]] = i
	}
	return res
}

// requireInitrds fails unless every installed initrd carries the module and the key (with) or none does and each
// names the LUKS UUID luksUUID in its crypttab (without).
func (w *ieWorld) requireInitrds(t *testing.T, with bool, luksUUID string) {
	t.Helper()
	for name, i := range w.initrds(t) {
		switch {
		case with && (!i.Module || !i.Key):
			t.Fatalf("%s lacks the Paddock module or the conversion key: %+v", name, i)
		case !with && (i.Module || i.Key):
			t.Fatalf("%s still carries the Paddock module or the conversion key: %+v", name, i)
		case !with && luksUUID != "" && !strings.Contains(i.Crypttab, luksUUID):
			t.Fatalf("the crypttab of %s does not name %s: %q", name, luksUUID, i.Crypttab)
		}
	}
}

// partition is the root partition of the plan (the future or present LUKS device), as a /dev path.
func (w *ieWorld) partition(t *testing.T, partUUID string) string {
	t.Helper()
	return w.Must("readlink -f /dev/disk/by-partuuid/" + partUUID)
}

// rootPartUUID is the PARTUUID of the partition that holds the root file system before the conversion (below the
// LV for lvm).
func (w *ieWorld) rootPartUUID(t *testing.T) string {
	t.Helper()
	pu := w.Must(`for d in $(lsblk -nlpso NAME,TYPE "$(findmnt -no SOURCE /)" | awk '$2=="part"{print $1}'); do lsblk -dno PARTUUID "$d"; done | head -1`)
	if pu == "" {
		t.Fatalf("no PARTUUID below the root file system:\n%s", w.Must("lsblk -f"))
	}
	return pu
}

// skipDiskSetup waits for the boot PIN dialogue and skips it (Enter twice without a PIN, plan M8e decision 51). Unlike
// AnswerDiskSetup it does not wait for the marker to go: on a converted device whose PIN is still missing the agent
// re-arms it (decision 52).
func (w *ieWorld) skipDiskSetup(t *testing.T) {
	t.Helper()
	active := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, _ := w.SSH(ctx, nil, "systemctl is-active paddock-disk-setup.service")
		return strings.TrimSpace(out)
	}
	Until(t, w.Name+": disk setup asks for the boot PIN", 10*time.Minute, 3*time.Second, nil, func() bool { return active() == "activating" })
	time.Sleep(3 * time.Second)
	w.Shot(t, "disk-setup-skip")
	w.Type("")
	time.Sleep(2 * time.Second)
	w.Type("")
	Until(t, w.Name+": disk setup skipped", 3*time.Minute, 3*time.Second, nil, func() bool { return active() != "activating" })
	if out := w.Must("sudo journalctl -b -u paddock-disk-setup.service --no-pager -o cat"); !strings.Contains(out, "boot PIN skipped") {
		t.Fatalf("the disk setup was not skipped:\n%s", out)
	}
}

// requireNoDiskSetup asserts that the boot PIN dialogue did not run in this boot (plan M8e amendment item 22: no
// enrollment while the header is marked for reencryption, stop condition S2).
func (w *ieWorld) requireNoDiskSetup(t *testing.T) {
	t.Helper()
	if out := w.Must("systemctl show paddock-disk-setup.service -p ConditionResult --value"); out != "no" {
		t.Fatalf("the disk setup ran while the reencryption is unfinished (ConditionResult=%s):\n%s", out,
			w.Must("sudo journalctl -b -u paddock-disk-setup.service --no-pager -o cat"))
	}
}

// requireNoFailedEnrollment asserts that no enrollment was tried and refused in this boot: a device whose disk-setup
// files outlived an abandoned cleanup (gate S-IE4) must not try while the header is marked for reencryption (stop
// condition S2, amendment item 22).
func (w *ieWorld) requireNoFailedEnrollment(t *testing.T) {
	t.Helper()
	if out := w.Must("sudo journalctl -b -u paddock-disk-setup.service --no-pager -o cat | grep -c 'enrolling the TPM unlock failed' || true"); out != "0" {
		t.Fatalf("the disk setup tried to enroll while the reencryption is unfinished (%s failures)", out)
	}
}

// probeEnrollWhileEncrypting records, as evidence of stop condition S2, whether systemd-cryptenroll can add a TPM
// keyslot while the header is marked for reencryption. It enrolls into a copy of the header on a loop device, so the
// device itself never changes; the outcome is logged, not asserted.
func (w *ieWorld) probeEnrollWhileEncrypting(t *testing.T, partition string) {
	t.Helper()
	w.logEvidence(t, "stop condition S2 probe: systemd-cryptenroll while encrypting (on a header copy)", `sudo sh -c '
d=$(mktemp -d -p /run); l=""
trap "[ -n \"\$l\" ] && losetup -d \$l; rm -rf \$d" EXIT
cryptsetup luksHeaderBackup -q `+partition+` --header-backup-file $d/header
l=$(losetup -f --show $d/header)
cryptsetup luksDump $l | grep -i -e requirements -e reencrypt
systemd-cryptenroll --tpm2-device=auto --unlock-key-file=/var/lib/paddock/install-passphrase $l; echo "systemd-cryptenroll exit=$?"
systemctl --version | head -1; cryptsetup --version'`)
}

// requestUninstall asks to remove Paddock (mode leave) and returns the HTTP status and the problem detail.
func (w *ieWorld) requestUninstall(t *testing.T, status int) string {
	t.Helper()
	res := w.RequestUninstall("leave", nil, status)
	var p struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(res.Body, &p)
	return p.Detail
}

// newestRecoveryKey reveals, as alice after a step-up, the newest stored recovery key of the device and its
// generation (the conversion key is generation 1 until the recovery key enrolled after the conversion is stored,
// plan M8e decision 26).
func (w *ieWorld) newestRecoveryKey(t *testing.T) (generation int, key string) {
	t.Helper()
	w.s.StepUp(t)
	var revealed struct {
		Generation  int    `json:"generation"`
		RecoveryKey string `json:"recovery_key"`
	}
	if err := json.Unmarshal(w.s.Call(t, http.MethodPost, "/api/v1/devices/"+w.ID+"/disk/recovery-key",
		map[string]any{"confirm_hostname": w.spec.Name}, http.StatusOK).Body, &revealed); err != nil || revealed.RecoveryKey == "" {
		t.Fatalf("reveal: %v", err)
	}
	return revealed.Generation, revealed.RecoveryKey
}

// shots takes a screenshot every 2 s for 90 s in the background (plan M8e decision 45: evidence only); wait returns
// when it is done.
func (w *ieWorld) shots(t *testing.T, name string) (wait func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 45 {
			if out, err := run(context.Background(), "VBoxManage", "controlvm", w.Name, "screenshotpng",
				filepath.Join(w.evidenceDir(), fmt.Sprintf("%s-%s-%02d.png",
					strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()), name, i))); err != nil {
				t.Logf("screenshot %s %d: %v: %s", name, i, err, out)
			}
			time.Sleep(2 * time.Second)
		}
		// GNOME hides a banner after seconds; the notification list (Super+V) still shows it.
		if out, err := run(context.Background(), "VBoxManage", "controlvm", w.Name, "keyboardputscancode", "e0", "5b", "2f", "af", "e0", "db"); err != nil {
			t.Logf("open the notification list: %v: %s", err, out)
		}
		time.Sleep(2 * time.Second)
		if out, err := run(context.Background(), "VBoxManage", "controlvm", w.Name, "screenshotpng",
			filepath.Join(w.evidenceDir(), strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"-"+name+"-list.png")); err != nil {
			t.Logf("screenshot %s list: %v: %s", name, err, out)
		}
		_, _ = run(context.Background(), "VBoxManage", "controlvm", w.Name, "keyboardputscancode", "01", "81")
	}()
	return func() { <-done }
}

// requireNotified asserts, within 2 minutes of prepared, one finished paddock-notify unit per graphical session and
// none left running (plan M8e decision 45).
func (w *ieWorld) requireNotified(t *testing.T) {
	t.Helper()
	sessions := strings.Fields(w.Must(`for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
	[ "$(loginctl show-session "$s" -p Class --value)" = user ] || continue
	case "$(loginctl show-session "$s" -p Type --value)" in wayland|x11) echo "$s";; esac
done`))
	if len(sessions) == 0 {
		t.Fatal("no graphical user session: the test user's automatic login did not happen")
	}
	var journal string
	Until(t, w.Name+": one notification per graphical session", 2*time.Minute, 5*time.Second, nil, func() bool {
		journal = w.Must("sudo journalctl -o cat _COMM=systemd --no-pager | grep 'paddock-notify-' || true")
		for _, s := range sessions {
			if n := len(regexp.MustCompile(`paddock-notify-`+regexp.QuoteMeta(s)+`-\d+\.service: Deactivated successfully`).FindAllString(journal, -1)); n != 1 {
				return false
			}
		}
		return true
	})
	if left := w.Must("systemctl list-units --no-legend --all 'paddock-notify-*' | grep -c . || true"); left != "0" {
		t.Fatalf("%s paddock-notify units left:\n%s", left, w.Must("systemctl list-units --all 'paddock-notify-*'"))
	}
	t.Logf("%s: graphical sessions %v notified:\n%s", w.Name, sessions, journal)
}

// requireProgress reads done_bytes from the device twice, 10 s apart, and fails unless it grew; it returns the second
// value.
func (w *ieWorld) requireProgress(t *testing.T, atLeast int64) int64 {
	t.Helper()
	var first, second int64
	Until(t, w.Name+": reencryption progress", 5*time.Minute, 10*time.Second, nil, func() bool {
		h := w.convHealth()
		first = second
		second, _ = h.done()
		return h.Disk.State == "encrypting" && first >= atLeast && second > first
	})
	t.Logf("%s: done_bytes %d → %d", w.Name, first, second)
	return second
}

// powerCutMidway waits until the device reports done_bytes between 10 % and 90 % of data_bytes and cuts the power;
// it returns the last value read (plan M8e decision 44).
func (w *ieWorld) powerCutMidway(t *testing.T) int64 {
	t.Helper()
	var done, total int64
	Until(t, w.Name+": reencryption between 10 % and 90 %", 30*time.Minute, 5*time.Second, nil, func() bool {
		done, total = w.convHealth().done()
		if total > 0 && done*10 > total*9 {
			t.Fatalf("the reencryption passed 90 %% (%d of %d) before the power cut", done, total)
		}
		return total > 0 && done*10 >= total
	})
	w.powerCut(t, fmt.Sprintf("at %d of %d bytes", done, total))
	return done
}

// requireLUKSRoot asserts that the root partition is LUKS and root is mounted from mapping.
func (w *ieWorld) requireLUKSRoot(t *testing.T, partition, mapping string) {
	t.Helper()
	if out := w.Must("lsblk -no FSTYPE " + partition + " | head -1"); out != "crypto_LUKS" {
		t.Fatalf("%s is %q, not crypto_LUKS:\n%s", partition, out, w.Must("lsblk -f"))
	}
	if out := w.Must(`lsblk -nlso NAME "$(findmnt -no SOURCE /)"`); !strings.Contains(out, mapping) {
		t.Fatalf("root is not on %s:\n%s", mapping, out)
	}
}

// requireRootReference asserts that the root reference of /etc/fstab resolves to a device-mapper device on top of the
// LUKS mapping and that root is mounted from that device: the safety argument for accepting UUID= and
// /dev/disk/by-uuid/ (plan M8e amendment item 21) proven on the converted device.
func (w *ieWorld) requireRootReference(t *testing.T, mapping string) {
	t.Helper()
	out := w.Must(`ref=$(findmnt --fstab -no SOURCE /); case $ref in UUID=*) ref=/dev/disk/by-uuid/${ref#UUID=};; esac
echo "$ref"; readlink -f "$ref"; readlink -f "$(findmnt -no SOURCE /)"; lsblk -nlso NAME "$(readlink -f "$ref")"`)
	lines := strings.Split(out, "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[1], "/dev/dm-") || lines[1] != lines[2] || !slices.Contains(lines[3:], mapping) {
		t.Fatalf("the fstab root reference does not resolve to the mounted root on %s:\n%s", mapping, out)
	}
	t.Logf("%s: fstab root %s → %s (mounted root, on %s)", w.Name, lines[0], lines[1], mapping)
}

// requireUnencrypted asserts that no LUKS device exists after a boot.
func (w *ieWorld) requireUnencrypted(t *testing.T) {
	t.Helper()
	if out := w.Must("lsblk -nlo FSTYPE"); strings.Contains(out, "crypto_LUKS") {
		t.Fatalf("a LUKS device exists:\n%s", w.Must("lsblk -f"))
	}
}

// logEvidence runs a diagnostic command and logs its output as evidence for the result document; a failure is
// logged, not fatal.
func (w *ieWorld) logEvidence(t *testing.T, what, command string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := w.SSH(ctx, nil, command)
	t.Logf("%s: evidence %s (%v):\n%s", w.Name, what, err, strings.TrimSpace(out))
	return out
}

// logBootEvidence logs, for the boot that just happened, the init step's journal with monotonic timestamps and the
// order of systemd-fsck-root against the init unit, and fails when dracut's catch-all LUKS rule started a
// systemd-cryptsetup unit for the partition (luks-<uuid>, which would wait at a passphrase prompt; verification items
// of PDK-244: the rd.luks=0 race and the fsck ordering). A screenshot of the console is kept as evidence.
func (w *ieWorld) logBootEvidence(t *testing.T, boot string) {
	t.Helper()
	w.logEvidence(t, boot+" init step journal", "sudo journalctl -b -o short-monotonic --no-pager -u paddock-encrypt-init.service -u systemd-fsck-root.service"+
		" -u 'systemd-cryptsetup@*' -u initrd-root-device.target -u sysroot.mount | tail -80")
	w.logEvidence(t, boot+" encrypt-boot.env", "sudo journalctl -b -o cat --no-pager | grep -E 'paddock-encrypt: (result|run|header|init|shrink|file system|test delay)' | tail -40")
	if out := w.Must("sudo journalctl -b -o cat --no-pager | grep -c 'systemd-cryptsetup@luks-' || true"); out != "0" {
		t.Fatalf("%s: dracut's catch-all LUKS rule started systemd-cryptsetup@luks-* (%s journal lines)", boot, out)
	}
	w.Shot(t, "console-"+strings.Fields(boot)[1])
}
