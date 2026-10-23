package system

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The throwaway VM of gate D-AI (plan M4b §6), built like the test VMs (test/vms/virtualbox/create-vm.sh: EFI, Secure
// Boot, TPM 2.0) but installed from a Paddock autoinstall. It is deleted when the gate ends.
const (
	aiVMName  = "paddock-ai-2604"
	aiSSHPort = "2228"
)

// aiSpec names a throwaway VM and sizes its disk (plan M8e decision 42).
type aiSpec struct {
	Name, SSHPort string
	DiskMB        int
}

// The throwaway VMs: gates D-AI and S-DU1 on paddock-ai-2604, the in-place encryption gates of plan M8e on two
// unencrypted installs. The reencryption writes every sector of the root partition and so grows a dynamic VDI to its
// full size; 16 GiB keep two runs within the development host's headroom (decision 42).
var (
	aiVM     = aiSpec{Name: aiVMName, SSHPort: aiSSHPort, DiskMB: 40960}
	ieVM2604 = aiSpec{Name: "paddock-ie-2604", SSHPort: "2229", DiskMB: 16384}
	ieVM2404 = aiSpec{Name: "paddock-ie-2404", SSHPort: "2230", DiskMB: 16384}
)

// minMachineFolderFree is the free space the VirtualBox machine folder needs before a throwaway VM is created (plan
// M8e decision 42).
const minMachineFolderFree = 24 << 30

// isoPath is the Ubuntu Desktop ISO of release (24.04 or 26.04): PADDOCK_SYSTEM_ISO_2404 or PADDOCK_SYSTEM_ISO_2604,
// by default in ~/Downloads (plan M8e decision 43). A missing file fails the test with the path.
func isoPath(t *testing.T, release string) string {
	t.Helper()
	defaults := map[string]string{"24.04": "ubuntu-24.04.5.1-desktop-amd64.iso", "26.04": "ubuntu-26.04.1-desktop-amd64.iso"}
	iso := os.Getenv("PADDOCK_SYSTEM_ISO_" + strings.ReplaceAll(release, ".", ""))
	if iso == "" {
		home, _ := os.UserHomeDir()
		iso = filepath.Join(home, "Downloads", defaults[release])
	}
	if _, err := os.Stat(iso); err != nil {
		t.Fatalf("Ubuntu %s ISO %s: %v", release, iso, err)
	}
	return iso
}

// withTestAccess adds the test environment to generated user-data, before the Paddock late-commands: the development
// stack's hostnames and Caddy CA (the installer downloads the packages from bundles.paddock.localhost) and SSH access
// for the gate as user paddock, the break-glass account of the development organization (make dev-seed). The
// commands Paddock generated stay unchanged.
func withTestAccess(t *testing.T, userData []byte, root string, vm *VM) []byte {
	t.Helper()
	ca, err := os.ReadFile(filepath.Join(root, "deploy", "compose", ".secrets", "caddy-root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(vm.dir, ".secrets", "id_ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	commands := [][]string{
		{"sh", "-c", `printf '%s\n' "$1" >> /target/etc/hosts`, "sh", guestHosts},
		{"sh", "-c", `printf '%s' "$1" | base64 -d > /target/usr/local/share/ca-certificates/paddock-dev-caddy-root.crt`, "sh",
			base64.StdEncoding.EncodeToString(ca)},
		{"curtin", "in-target", "--target=/target", "--", "update-ca-certificates"},
		{"curtin", "in-target", "--target=/target", "--", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "openssh-server"},
		{"curtin", "in-target", "--target=/target", "--", "systemctl", "enable", "ssh.service"},
		{"curtin", "in-target", "--target=/target", "--", "useradd", "-m", "-s", "/bin/bash", "paddock"},
		{"sh", "-c", `mkdir -p /target/home/paddock/.ssh && printf '%s\n' "$1" > /target/home/paddock/.ssh/authorized_keys`, "sh",
			strings.TrimSpace(string(pub))},
		{"curtin", "in-target", "--target=/target", "--", "chown", "-R", "paddock:paddock", "/home/paddock/.ssh"},
		{"sh", "-c", "echo 'paddock ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/90-paddock && chmod 0440 /target/etc/sudoers.d/90-paddock"},
	}
	var lines strings.Builder
	lines.WriteString("    # Test environment of gate D-AI (not part of the Paddock autoinstall).\n")
	for _, c := range commands {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		lines.WriteString("    - " + string(b) + "\n")
	}
	const marker = "  late-commands:\n"
	if !strings.Contains(string(userData), marker) {
		t.Fatalf("user-data without late-commands:\n%s", userData)
	}
	return []byte(strings.Replace(string(userData), marker, marker+lines.String(), 1))
}

// storagePassphrase is the temporary disk passphrase of generated user-data.
func storagePassphrase(t *testing.T, userData []byte) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^      password: "([A-Za-z0-9]{32,})"$`).FindSubmatch(userData)
	if m == nil {
		t.Fatal("no storage passphrase in the user-data")
	}
	return string(m[1])
}

// buildAIVM remasters the ISO with the user-data as /autoinstall.yaml and the autoinstall kernel argument (like
// create-vm.sh), creates the VM of spec with EFI, Secure Boot and TPM 2.0, runs the installer until it powers off,
// ejects the medium and returns the VM. The VM's first serial port writes to its work directory (VM.Serial), and
// its disk is in the bandwidth group of VM.LimitDisk. The VM and the work directory (it holds the user-data) are
// deleted when the test ends.
func buildAIVM(t *testing.T, root string, spec aiSpec, iso string, userData []byte) *VM {
	t.Helper()
	vm := &VM{Name: spec.Name, port: spec.SSHPort, dir: filepath.Join(root, "test", "vms", "virtualbox"), t: t}
	ctx := context.Background()
	if vm.state(ctx) != "" {
		t.Fatalf("VM %s exists already; delete it first (VBoxManage unregistervm %s --delete)", spec.Name, spec.Name)
	}
	work := filepath.Join(root, "bin", "system-ai", spec.Name)
	vm.serial = filepath.Join(work, "serial.log")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("PADDOCK_SYSTEM_KEEP") != "" {
			t.Logf("PADDOCK_SYSTEM_KEEP: %s and %s left for inspection; delete both yourself", spec.Name, work)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := vm.PowerOff(ctx); err != nil {
			t.Errorf("power off %s: %v", spec.Name, err)
		}
		if out, err := run(ctx, "VBoxManage", "unregistervm", spec.Name, "--delete"); err != nil {
			t.Errorf("delete %s: %v: %s", spec.Name, err, out)
		}
		if err := os.RemoveAll(work); err != nil {
			t.Errorf("remove %s: %v", work, err)
		}
	})
	if err := os.WriteFile(filepath.Join(work, "autoinstall.yaml"), userData, 0o600); err != nil {
		t.Fatal(err)
	}
	must := func(name string, args ...string) string {
		t.Helper()
		out, err := run(ctx, name, args...)
		if err != nil {
			t.Fatalf("%s %s: %v: %s", name, strings.Join(args[:min(len(args), 3)], " "), err, tail([]byte(out)))
		}
		return out
	}
	grubOrig := filepath.Join(work, "grub.cfg.orig")
	_ = os.Remove(grubOrig)
	must("xorriso", "-osirrox", "on", "-indev", iso, "-extract", "/boot/grub/grub.cfg", grubOrig)
	grub, err := os.ReadFile(grubOrig) //nolint:gosec // our work directory
	if err != nil {
		t.Fatal(err)
	}
	patched := regexp.MustCompile(`(?m)^set timeout=.*$`).ReplaceAll(grub, []byte("set timeout=3"))
	first := regexp.MustCompile(`/casper/vmlinuz\s+---`).FindIndex(patched)
	if first == nil {
		t.Fatal("no /casper/vmlinuz entry in grub.cfg")
	}
	patched = append(append(append([]byte{}, patched[:first[0]]...), "/casper/vmlinuz autoinstall ---"...), patched[first[1]:]...)
	if err := os.WriteFile(filepath.Join(work, "grub.cfg"), patched, 0o600); err != nil {
		t.Fatal(err)
	}
	installISO := filepath.Join(work, "install.iso")
	_ = os.Remove(installISO)
	must("xorriso", "-indev", iso, "-outdev", installISO, "-map", filepath.Join(work, "autoinstall.yaml"), "/autoinstall.yaml",
		"-map", filepath.Join(work, "grub.cfg"), "/boot/grub/grub.cfg", "-boot_image", "any", "replay")

	folder := regexp.MustCompile(`(?m)^Default machine folder:\s*(.+)$`).FindStringSubmatch(must("VBoxManage", "list", "systemproperties"))
	if folder == nil {
		t.Fatal("no default machine folder")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(strings.TrimSpace(folder[1]), &fs); err != nil {
		t.Fatalf("free space of the machine folder %s: %v", folder[1], err)
	}
	if free := fs.Bavail * uint64(fs.Bsize); free < minMachineFolderFree {
		t.Fatalf("the machine folder %s has %.1f GiB free; %s needs %d GiB (plan M8e decision 42)", strings.TrimSpace(folder[1]),
			float64(free)/(1<<30), spec.Name, minMachineFolderFree>>30)
	} else {
		t.Logf("%s: %.1f GiB free in the machine folder before the build", spec.Name, float64(free)/(1<<30))
	}
	disk := filepath.Join(strings.TrimSpace(folder[1]), spec.Name, spec.Name+".vdi")
	must("VBoxManage", "createvm", "--name", spec.Name, "--ostype", "Ubuntu_64", "--register")
	must("VBoxManage", "modifyvm", spec.Name, "--firmware=efi", "--tpm-type=2.0", "--cpus=2", "--memory=4096",
		"--graphicscontroller=vmsvga", "--vram=128", "--ioapic=on", "--rtc-use-utc=on", "--audio-enabled=off",
		"--usb-ohci=off", "--usb-ehci=off", "--usb-xhci=off", "--nic1=nat", "--natpf1=ssh,tcp,127.0.0.1,"+spec.SSHPort+",,22",
		// The development stack listens on the host's loopback, which the guest reaches as 10.0.2.2 (like the test VMs).
		"--nat-localhostreachable1=on",
		// The init step of plan M8e logs to the kernel console; a guest that names ttyS0 as its console writes it here,
		// where a gate reads it while no SSH is available.
		"--uart1", "0x3F8", "4", "--uart-mode1", "file", vm.serial,
		"--boot1=disk", "--boot2=dvd", "--boot3=none", "--boot4=none")
	if out, err := vm.lib(ctx, "enroll_secure_boot "+spec.Name); err != nil {
		t.Fatalf("Secure Boot: %v: %s", err, out)
	}
	must("VBoxManage", "createmedium", "disk", "--filename", disk, "--size", fmt.Sprint(spec.DiskMB), "--format", "VDI", "--variant", "Standard")
	must("VBoxManage", "bandwidthctl", spec.Name, "add", diskBandwidthGroup, "--type", "disk", "--limit", diskUnlimited)
	must("VBoxManage", "storagectl", spec.Name, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci", "--portcount", "2", "--bootable", "on")
	must("VBoxManage", "storageattach", spec.Name, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", disk,
		"--nonrotational", "on", "--discard", "on", "--bandwidthgroup", diskBandwidthGroup)
	must("VBoxManage", "storageattach", spec.Name, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", installISO)
	must("VBoxManage", "startvm", spec.Name, "--type", "headless")
	t.Logf("%s: installing from the autoinstall", spec.Name)
	// Polled here rather than with lib.sh wait_vm_state, whose state query fails now and then while the VM shuts down
	// and then ends the wait as a failure (PDK-247 hand test run 4); VM.state retries it.
	started := time.Now()
	deadline := started.Add(2 * time.Hour)
	checked := false
	for vm.state(ctx) != "poweroff" {
		if time.Now().After(deadline) {
			vm.Shot(t, "install")
			t.Fatalf("installation did not finish within 2 hours (%s)", vm.state(ctx))
		}
		// The firmware once hung before the installer started, burning CPU for an hour (PDK-247 hand run 8): a disk
		// still empty and no display after five minutes fail at once.
		if !checked && time.Since(started) > 5*time.Minute {
			checked = true
			fi, err := os.Stat(disk)
			shot, _ := run(ctx, "VBoxManage", "controlvm", spec.Name, "screenshotpng", filepath.Join(work, "install-check.png"))
			if err == nil && fi.Size() < 16<<20 && strings.Contains(shot, "0x0") {
				t.Fatalf("%s: firmware hang at boot, the VM did not start the installer (disk %d bytes, no display)", spec.Name, fi.Size())
			}
		}
		time.Sleep(30 * time.Second)
	}
	if out, err := vm.lib(ctx, "wait_vm_process_exit "+spec.Name); err != nil {
		t.Fatalf("%s: %v: %s", spec.Name, err, out)
	}
	must("VBoxManage", "storageattach", spec.Name, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", "emptydrive")
	return vm
}

// diskBandwidthGroup is the bandwidth group of a throwaway VM's disk. Unlimited during the install, a gate limits it
// so that the background reencryption of a 16 GiB disk lasts long enough to cut the power in its middle.
const (
	diskBandwidthGroup = "disk"
	diskUnlimited      = "100000M"
)

// LimitDisk sets the throughput limit of a throwaway VM's disk (VBoxManage bandwidthctl, e.g. "20M"; diskUnlimited
// lifts it). Set it while the VM is powered off: a change made while it ran did not take effect (PDK-247 hand test).
func (v *VM) LimitDisk(t *testing.T, limit string) {
	t.Helper()
	if out, err := run(context.Background(), "VBoxManage", "bandwidthctl", v.Name, "set", diskBandwidthGroup, "--limit", limit); err != nil {
		t.Fatalf("%s: disk limit %s: %v: %s", v.Name, limit, err, out)
	}
}

// Serial returns what the throwaway VM wrote to its first serial port since its last start.
func (v *VM) Serial(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(v.serial)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("serial console of %s: %v", v.Name, err)
	}
	return string(b)
}

// StartWithPassphrase starts the VM and types passphrase once at the disk prompt, then waits for SSH. Unlike lib.sh
// unlock_and_wait_ssh it never types again: at the first boot SSH comes up late, and a second entry would land in
// the boot PIN dialogue.
func (v *VM) StartWithPassphrase(t *testing.T, passphrase string) {
	t.Helper()
	if out, err := run(context.Background(), "VBoxManage", "startvm", v.Name, "--type", "headless"); err != nil {
		t.Fatalf("start %s: %v: %s", v.Name, err, out)
	}
	time.Sleep(40 * time.Second)
	v.Shot(t, "passphrase-prompt")
	v.Type(passphrase)
	Until(t, v.Name+" answers SSH", 10*time.Minute, 5*time.Second, nil, v.sshUp)
}

// aiDevicesPath lists the devices in state with the throwaway VM's hostname. One state per query keeps the page
// small: the retired devices of earlier runs never push the current one off it.
func aiDevicesPath(state string) string {
	return "/api/v1/devices?q=" + aiVMName + "&state=" + state + "&page_size=100"
}

// tokenDevices are the IDs of the devices of a GET /api/v1/devices page in state that enrolled with the enrollment
// token tokenID.
func tokenDevices(page []byte, tokenID, state string) ([]string, error) {
	var p struct {
		Items []struct {
			ID                string  `json:"id"`
			State             string  `json:"state"`
			EnrollmentTokenID *string `json:"enrollment_token_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(page, &p); err != nil {
		return nil, fmt.Errorf("device page: %w", err)
	}
	var ids []string
	for _, item := range p.Items {
		if item.State == state && item.EnrollmentTokenID != nil && *item.EnrollmentTokenID == tokenID {
			ids = append(ids, item.ID)
		}
	}
	return ids, nil
}

// endVerbs take a device of the run out of use through the product: a pending device can only be rejected, an
// active or a quarantined one is retired; rejected and retired devices are out of use already.
func endVerbs() []struct{ state, verb string } {
	return []struct{ state, verb string }{{"pending", "reject"}, {"active", "retire"}, {"quarantined", "retire"}}
}

// WaitAIDevice waits until the throwaway VM enrolled itself with the enrollment token tokenID and returns its device
// ID. The token, used once per run, tells the VM apart from an earlier run's device with the same hostname
// (PDK-377).
func (s *Stack) WaitAIDevice(t *testing.T, tokenID string) string {
	t.Helper()
	var id string
	Until(t, aiVMName+" enrolls itself", 10*time.Minute, 10*time.Second, nil, func() bool {
		ids, err := tokenDevices(s.Call(t, http.MethodGet, aiDevicesPath("active"), nil, http.StatusOK).Body, tokenID, "active")
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) > 0 {
			id = ids[0]
		}
		return id != ""
	})
	return id
}

// RetireAIDevicesOnCleanup takes every device that enrolled with the enrollment token tokenID out of use when the
// test ends, also after a failure (endVerbs), so that a later run never finds it.
func (s *Stack) RetireAIDevicesOnCleanup(t *testing.T, tokenID string) {
	t.Cleanup(func() {
		for _, e := range endVerbs() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			res, err := s.session().Do(ctx, http.MethodGet, aiDevicesPath(e.state), nil)
			if err == nil && res.Status == http.StatusUnauthorized {
				s.Login(t)
				res, err = s.session().Do(ctx, http.MethodGet, aiDevicesPath(e.state), nil)
			}
			cancel()
			if err != nil || res.Status != http.StatusOK {
				t.Errorf("cleanup: list the %s devices of %s: HTTP %d %v %s", e.state, aiVMName, res.Status, err, res.Body)
				continue
			}
			ids, err := tokenDevices(res.Body, tokenID, e.state)
			if err != nil {
				t.Errorf("cleanup: %v", err)
			}
			for _, id := range ids {
				s.cleanupCall(t, http.MethodPost, "/api/v1/devices/"+id+"/"+e.verb, http.StatusOK)
			}
		}
	})
}
