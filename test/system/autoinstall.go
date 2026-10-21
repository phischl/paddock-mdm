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
	"testing"
	"time"
)

// The throwaway VM of gate D-AI (plan M4b §6), built like the test VMs (test/vms/virtualbox/create-vm.sh: EFI, Secure
// Boot, TPM 2.0) but installed from a Paddock autoinstall. It is deleted when the gate ends.
const (
	aiVMName  = "paddock-ai-2604"
	aiSSHPort = "2228"
)

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
// create-vm.sh), creates the VM with EFI, Secure Boot and TPM 2.0, runs the installer until it powers off, ejects
// the medium and returns the VM. The VM and the work directory (it holds the user-data) are deleted when the test
// ends.
func buildAIVM(t *testing.T, root, iso string, userData []byte) *VM {
	t.Helper()
	vm := &VM{Name: aiVMName, port: aiSSHPort, dir: filepath.Join(root, "test", "vms", "virtualbox"), t: t}
	ctx := context.Background()
	if vm.state(ctx) != "" {
		t.Fatalf("VM %s exists already; delete it first (VBoxManage unregistervm %s --delete)", aiVMName, aiVMName)
	}
	work := filepath.Join(root, "bin", "system-ai")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("PADDOCK_SYSTEM_KEEP") != "" {
			t.Logf("PADDOCK_SYSTEM_KEEP: %s and %s left for inspection; delete both yourself", aiVMName, work)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := vm.PowerOff(ctx); err != nil {
			t.Errorf("power off %s: %v", aiVMName, err)
		}
		if out, err := run(ctx, "VBoxManage", "unregistervm", aiVMName, "--delete"); err != nil {
			t.Errorf("delete %s: %v: %s", aiVMName, err, out)
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
	disk := filepath.Join(strings.TrimSpace(folder[1]), aiVMName, aiVMName+".vdi")
	must("VBoxManage", "createvm", "--name", aiVMName, "--ostype", "Ubuntu_64", "--register")
	must("VBoxManage", "modifyvm", aiVMName, "--firmware=efi", "--tpm-type=2.0", "--cpus=2", "--memory=4096",
		"--graphicscontroller=vmsvga", "--vram=128", "--ioapic=on", "--rtc-use-utc=on", "--audio-enabled=off",
		"--usb-ohci=off", "--usb-ehci=off", "--usb-xhci=off", "--nic1=nat", "--natpf1=ssh,tcp,127.0.0.1,"+aiSSHPort+",,22",
		// The development stack listens on the host's loopback, which the guest reaches as 10.0.2.2 (like the test VMs).
		"--nat-localhostreachable1=on",
		"--boot1=disk", "--boot2=dvd", "--boot3=none", "--boot4=none")
	if out, err := vm.lib(ctx, "enroll_secure_boot "+aiVMName); err != nil {
		t.Fatalf("Secure Boot: %v: %s", err, out)
	}
	must("VBoxManage", "createmedium", "disk", "--filename", disk, "--size", "40960", "--format", "VDI", "--variant", "Standard")
	must("VBoxManage", "storagectl", aiVMName, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci", "--portcount", "2", "--bootable", "on")
	must("VBoxManage", "storageattach", aiVMName, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", disk,
		"--nonrotational", "on", "--discard", "on")
	must("VBoxManage", "storageattach", aiVMName, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", installISO)
	must("VBoxManage", "startvm", aiVMName, "--type", "headless")
	t.Logf("%s: installing from the Paddock autoinstall", aiVMName)
	installCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	if out, err := vm.lib(installCtx, fmt.Sprintf("wait_vm_state %s poweroff %d 30", aiVMName, 2*60*60)); err != nil {
		vm.Shot(t, "install")
		t.Fatalf("installation did not finish: %v: %s", err, out)
	}
	must("VBoxManage", "storageattach", aiVMName, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", "emptydrive")
	return vm
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

// aiDevicesPath lists the active devices with the throwaway VM's hostname.
const aiDevicesPath = "/api/v1/devices?q=" + aiVMName + "&state=active&page_size=100"

// tokenDevices are the IDs of the active devices of a GET /api/v1/devices page that enrolled with the enrollment
// token tokenID.
func tokenDevices(page []byte, tokenID string) ([]string, error) {
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
		if item.State == "active" && item.EnrollmentTokenID != nil && *item.EnrollmentTokenID == tokenID {
			ids = append(ids, item.ID)
		}
	}
	return ids, nil
}

// WaitAIDevice waits until the throwaway VM enrolled itself with the enrollment token tokenID and returns its device
// ID. The token, used once per run, tells the VM apart from an earlier run's device with the same hostname
// (PDK-377).
func (s *Stack) WaitAIDevice(t *testing.T, tokenID string) string {
	t.Helper()
	var id string
	Until(t, aiVMName+" enrolls itself", 10*time.Minute, 10*time.Second, nil, func() bool {
		ids, err := tokenDevices(s.Call(t, http.MethodGet, aiDevicesPath, nil, http.StatusOK).Body, tokenID)
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

// RetireAIDevicesOnCleanup retires, when the test ends and also after a failure, every active device that enrolled
// with the enrollment token tokenID, so that a later run never finds it.
func (s *Stack) RetireAIDevicesOnCleanup(t *testing.T, tokenID string) {
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		res, err := s.session().Do(ctx, http.MethodGet, aiDevicesPath, nil)
		if err == nil && res.Status == http.StatusUnauthorized {
			s.Login(t)
			res, err = s.session().Do(ctx, http.MethodGet, aiDevicesPath, nil)
		}
		if err != nil || res.Status != http.StatusOK {
			t.Errorf("cleanup: list the devices of %s: HTTP %d %v %s", aiVMName, res.Status, err, res.Body)
			return
		}
		ids, err := tokenDevices(res.Body, tokenID)
		if err != nil {
			t.Errorf("cleanup: %v", err)
		}
		for _, id := range ids {
			s.cleanupCall(t, http.MethodPost, "/api/v1/devices/"+id+"/retire", http.StatusOK)
		}
	})
}
