// Package system holds the system tests of plan M2b §3.4: the agent packages on the VirtualBox test VMs
// (test/vms/virtualbox, used through its scripts and never changed) against the running development stack.
package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Snapshot is the clean installation every test starts from and returns to. It is never modified.
const Snapshot = "base-installed"

// sshPorts are the forwarded SSH ports of the test VMs (test/vms/virtualbox/README.md).
var sshPorts = map[string]string{"paddock-u2404": "2224", "paddock-u2604": "2226"}

// VM is one test VM.
type VM struct {
	Name string
	port string
	dir  string // test/vms/virtualbox
	t    *testing.T
}

func newVM(t *testing.T, root, name string) *VM {
	t.Helper()
	port, ok := sshPorts[name]
	if !ok {
		t.Fatalf("unknown VM %s", name)
	}
	return &VM{Name: name, port: port, dir: filepath.Join(root, "test", "vms", "virtualbox"), t: t}
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// lib runs a function of test/vms/virtualbox/lib.sh.
func (v *VM) lib(ctx context.Context, script string) (string, error) {
	return run(ctx, "bash", "-c", "set -euo pipefail; source "+filepath.Join(v.dir, "lib.sh")+"; "+script)
}

func (v *VM) state(ctx context.Context) string {
	out, _ := v.lib(ctx, "vm_state "+v.Name)
	return strings.TrimSpace(out)
}

// PowerOff stops the VM and waits until VirtualBox has written its NVRAM (README: NVRAM pitfall).
func (v *VM) PowerOff(ctx context.Context) error {
	if v.state(ctx) != "poweroff" && v.state(ctx) != "saved" && v.state(ctx) != "aborted" {
		if out, err := run(ctx, "VBoxManage", "controlvm", v.Name, "poweroff"); err != nil {
			return fmt.Errorf("poweroff %s: %v: %s", v.Name, err, out)
		}
	}
	if out, err := v.lib(ctx, "wait_vm_state "+v.Name+" poweroff 300 2 || { [[ $(vm_state "+v.Name+") == aborted ]] && wait_vm_process_exit "+v.Name+"; }"); err != nil {
		return fmt.Errorf("wait for poweroff of %s: %v: %s", v.Name, err, out)
	}
	return nil
}

// Restore powers the VM off and restores the snapshot base-installed.
func (v *VM) Restore(ctx context.Context) error {
	if err := v.PowerOff(ctx); err != nil {
		return err
	}
	if out, err := run(ctx, "VBoxManage", "snapshot", v.Name, "restore", Snapshot); err != nil {
		return fmt.Errorf("restore %s: %v: %s", v.Name, err, out)
	}
	return nil
}

// Start boots the VM with start-vm.sh (types the LUKS passphrase, waits for SSH).
func (v *VM) Start(ctx context.Context) error {
	if out, err := run(ctx, filepath.Join(v.dir, "start-vm.sh"), v.Name); err != nil {
		return fmt.Errorf("start %s: %v: %s", v.Name, err, out)
	}
	return nil
}

// aptUnits run apt on their own; a background apt run competes with the agent's Himmelblau installation for the
// dpkg lock and makes gate timings unpredictable. They are stopped and masked for the duration of a test only (plan
// M4a step 0e): base-installed keeps them, as devices in production do.
const aptUnits = "apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service"

// Fresh restores base-installed, boots, stops and masks aptUnits, and restores base-installed again (powered off)
// when the test ends. With PADDOCK_SYSTEM_KEEP set, a failed test leaves the VM running as it is, for inspection.
func (v *VM) Fresh() {
	v.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	v.t.Cleanup(func() {
		if v.t.Failed() && os.Getenv("PADDOCK_SYSTEM_KEEP") != "" {
			v.t.Logf("PADDOCK_SYSTEM_KEEP: %s left running; restore %s yourself", v.Name, Snapshot)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := v.Restore(ctx); err != nil {
			v.t.Errorf("leaving %s at %s: %v", v.Name, Snapshot, err)
		}
	})
	if err := v.Restore(ctx); err != nil {
		v.t.Fatal(err)
	}
	if err := v.Start(ctx); err != nil {
		v.t.Fatal(err)
	}
	v.Must("sudo systemctl mask --now " + aptUnits)
}

func (v *VM) sshArgs() []string {
	return []string{
		"-i", filepath.Join(v.dir, ".secrets", "id_ed25519"), "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
	}
}

// SSH runs a shell command in the guest as user paddock (passwordless sudo) with optional stdin.
func (v *VM) SSH(ctx context.Context, stdin []byte, command string) (string, error) {
	args := append(v.sshArgs(), "-p", v.port, "paddock@127.0.0.1", command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	return out.String(), err
}

// Must runs a command and fails the test on error.
func (v *VM) Must(command string) string {
	v.t.Helper()
	return v.MustIn(nil, command)
}

// MustIn runs a command with stdin and fails the test on error. SSH connection failures (ssh exit 255 with a
// connection error, e.g. while a package installation restarts sshd) are retried for up to two minutes; a failing
// command is not.
func (v *VM) MustIn(stdin []byte, command string) string {
	v.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		out, err := v.SSH(ctx, stdin, command)
		if err == nil {
			return strings.TrimSpace(out)
		}
		var exit *exec.ExitError
		connection := errors.As(err, &exit) && exit.ExitCode() == 255 && strings.Contains(out, "Connection")
		if !connection || time.Now().After(deadline) {
			v.t.Fatalf("%s: %s: %v\n%s", v.Name, command, err, out)
		}
		v.t.Logf("%s: SSH connection failed (%s), retrying", v.Name, strings.TrimSpace(out))
		time.Sleep(5 * time.Second)
	}
}

// Copy copies a local file into the guest.
func (v *VM) Copy(local, remote string) {
	v.t.Helper()
	data, err := os.ReadFile(local)
	if err != nil {
		v.t.Fatal(err)
	}
	v.MustIn(data, "cat > "+remote)
}

// SetLink switches the VM's network cable (adapter 1) off or on.
func (v *VM) SetLink(on bool) {
	v.t.Helper()
	state := "off"
	if on {
		state = "on"
	}
	if out, err := run(context.Background(), "VBoxManage", "controlvm", v.Name, "setlinkstate1", state); err != nil {
		v.t.Fatalf("setlinkstate1 %s: %v: %s", state, err, out)
	}
}
