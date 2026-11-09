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
	"slices"
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
	// group coordinates this VM with the other VMs of a parallel test (nil: the test drives its VMs itself).
	group *vmGroup
	// serial is the file the first serial port of a throwaway VM writes to (buildAIVM).
	serial string
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

// state returns the VM's state. VBoxManage now and then answers nothing while the other VM of a parallel test is
// changed (snapshot restore, start), so an empty answer is asked again.
func (v *VM) state(ctx context.Context) string {
	for range 5 {
		out, _ := v.lib(ctx, "vm_state "+v.Name)
		if s := strings.TrimSpace(out); s != "" {
			return s
		}
		time.Sleep(2 * time.Second)
	}
	return ""
}

// PowerOff stops the VM and waits until VirtualBox has written its NVRAM (README: NVRAM pitfall).
func (v *VM) PowerOff(ctx context.Context) error {
	if s := v.state(ctx); s != "poweroff" && s != "saved" && s != "aborted" {
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
func (v *VM) Fresh() { v.fresh(false) }

// FreshWithDisk is Fresh with a second, empty 64 MiB disk on SATA port 2: the test target of paddock-revoke (plan M4c
// gate R1). The disk is attached after base-installed is restored and before the VM boots; when the test ends it is
// deleted after base-installed is restored again, which detaches it. base-installed itself never changes.
func (v *VM) FreshWithDisk() { v.fresh(true) }

func (v *VM) fresh(disk bool) {
	v.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	var medium string
	if disk {
		dir, err := os.MkdirTemp("", "paddock-systest-disk-")
		if err != nil {
			v.t.Fatal(err)
		}
		medium = filepath.Join(dir, v.Name+"-revoke-target.vdi")
		// Registered before the restore below, so it runs after it (cleanups run last first).
		v.t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if s := v.state(ctx); s != "poweroff" && s != "aborted" && s != "saved" {
				v.t.Logf("%s is %s; leaving the test disk %s", v.Name, s, medium)
				return
			}
			if out, err := run(ctx, "VBoxManage", "closemedium", "disk", medium, "--delete"); err != nil {
				v.t.Errorf("delete the test disk of %s: %v: %s", v.Name, err, out)
			}
			_ = os.RemoveAll(dir)
		})
	}
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
	if disk {
		for _, args := range [][]string{
			{"createmedium", "disk", "--filename", medium, "--size", "64", "--format", "VDI"},
			{"storagectl", v.Name, "--name", "SATA", "--portcount", "3"},
			{"storageattach", v.Name, "--storagectl", "SATA", "--port", "2", "--device", "0", "--type", "hdd", "--medium", medium},
		} {
			if out, err := run(ctx, "VBoxManage", args...); err != nil {
				v.t.Fatalf("VBoxManage %s: %v: %s", strings.Join(args, " "), err, out)
			}
		}
	}
	if err := v.Start(ctx); err != nil {
		v.t.Fatal(err)
	}
	v.Must("sudo systemctl mask --now " + aptUnits)
	// Masking a timer does not stop the run it already started: base-installed is days old, so the persistent timers
	// catch up at boot, and that run (unattended-upgrade, python) holds the dpkg lock for up to a minute (PDK-080). It
	// is waited for, not stopped: apt-daily-upgrade.service may be inside dpkg.
	v.Must("timeout 240 sh -c 'while systemctl is-active " + aptServices + " | grep -qx \"active\\|activating\"; do sleep 2; done'")
}

// aptServices are the services aptUnits' timers start.
const aptServices = "apt-daily.service apt-daily-upgrade.service"

func (v *VM) sshArgs() []string {
	return []string{
		"-i", filepath.Join(v.dir, ".secrets", "id_ed25519"), "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=30", "-o", "BatchMode=yes",
	}
}

// SSH runs a shell command in the guest as user paddock (passwordless sudo) with optional stdin and returns its
// standard output followed by its standard error. It repeats the command once when ssh failed before the command
// started; a command that cuts its own connection (reboot, poweroff, an sshd restart) must use SSHNoRetry, because a
// drop that leaves no text is indistinguishable from a handshake failure and the repeat would run the command twice
// (PDK-720). A caller that parses the output uses Must, which returns the standard output alone.
func (v *VM) SSH(ctx context.Context, stdin []byte, command string) (string, error) {
	stdout, stderr, err := v.sshRetrying(ctx, stdin, command, false)
	return stdout + stderr, err
}

// SSHNoRetry runs the command exactly once. State-changing commands that end the session use it.
func (v *VM) SSHNoRetry(ctx context.Context, stdin []byte, command string) (string, error) {
	stdout, stderr, err := v.sshRetrying(ctx, stdin, command, true)
	return stdout + stderr, err
}

func (v *VM) sshRetrying(ctx context.Context, stdin []byte, command string, noRetry bool) (stdout, stderr string, err error) {
	stdout, stderr, err = v.ssh(ctx, stdin, command)
	// Transport resilience, not a test retry: package upgrades in a gate restart sshd and drop a connection that was
	// being opened.
	if shouldRetrySSH(noRetry, sshExitCode(err), stdout+stderr) && ctx.Err() == nil {
		if v.t != nil {
			v.t.Logf("%s: ssh exited 255 (%s); retrying once: %s", v.Name, strings.TrimSpace(stdout+stderr), command)
		}
		stdout, stderr, err = v.ssh(ctx, stdin, command)
	}
	return stdout, stderr, err
}

// shouldRetrySSH decides whether a command is run again: never when the caller opted out, otherwise only for an ssh
// exit 255 whose output shows a failure before the command started.
func shouldRetrySSH(noRetry bool, exitCode int, out string) bool {
	return !noRetry && exitCode == 255 && sshHandshakeFailed(out)
}

// sshHandshakeFailed reports whether out, the combined output of an ssh that exited 255, shows only a failure to
// establish the session, so the remote command never ran. Any other line, such as the command's own output or
// "Connection to ... closed by remote host." or "client_loop: send disconnect", means it may have started.
// Empty output is a handshake failure too: sshArgs sets LogLevel=ERROR, which suppresses ssh's INFO-level
// "Connection closed/reset by <host> port N", so a peer that drops after the TCP connect leaves nothing. A drop after
// the command started prints "Connection to ... closed by remote host." and stays false.
func sshHandshakeFailed(out string) bool {
	prefixes := []string{
		"kex_exchange_identification", "ssh_exchange_identification", "ssh: connect to host ",
		"Connection reset by ", "Connection closed by ", "Connection timed out during banner exchange",
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(line, p) }) {
			return false
		}
	}
	return true
}

// ssh keeps the guest command's standard output apart from its standard error (and ssh's own messages): an NSS
// module that logs while the guest resolves a user, e.g. in sudo, must never become command output (PDK-892).
func (v *VM) ssh(ctx context.Context, stdin []byte, command string) (string, string, error) {
	args := append(v.sshArgs(), "-p", v.port, "paddock@127.0.0.1", command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// Bind makes the VM's helpers (Must, Copy, …) report to the subtest t until t ends; then they report to the test they
// reported to before. Every subtest that uses them binds itself first: FailNow on the per-VM parent test from inside
// a subtest panics and aborts the remaining gates of that VM.
func (v *VM) Bind(t *testing.T) {
	prev := v.t
	v.t = t
	t.Cleanup(func() { v.t = prev })
}

// Must runs a command and fails the test on error. It returns the command's standard output alone, trimmed; a
// command whose result is on standard error redirects it (2>&1).
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
		stdout, stderr, err := v.sshRetrying(ctx, stdin, command, false)
		if err == nil {
			return strings.TrimSpace(stdout)
		}
		var exit *exec.ExitError
		connection := errors.As(err, &exit) && exit.ExitCode() == 255 && strings.Contains(stderr, "Connection")
		if !connection || time.Now().After(deadline) {
			v.t.Fatalf("%s: %s: %v\n%s%s", v.Name, command, err, stdout, stderr)
		}
		v.t.Logf("%s: SSH connection failed (%s), retrying", v.Name, strings.TrimSpace(stderr))
		time.Sleep(5 * time.Second)
	}
}

// MustRoot runs a command as root and returns its standard output alone, trimmed. Use it for every lookup whose output
// is parsed. sudo itself resolves users through NSS while it starts, and a module that logs there (himmelblaud while
// it is down) writes to sudo's standard output, which would be mixed into the result (PDK-926). The guest has no root
// login, so the command writes into a file of the paddock user and sudo's own standard output is discarded; the file
// holds the bytes of the target command and nothing else. The command is a plain shell command, without sudo.
func (v *VM) MustRoot(command string) string {
	v.t.Helper()
	return v.MustRootIn(nil, command)
}

// MustRootIn is MustRoot with stdin for the command.
func (v *VM) MustRootIn(stdin []byte, command string) string {
	v.t.Helper()
	return v.MustIn(stdin, rootCapture(command))
}

// rootCapture wraps command so that only its own standard output reaches the caller. The file lives in the home
// directory, not in /tmp: root may not open another user's file in a sticky directory (fs.protected_regular).
func rootCapture(command string) string {
	return `f=$(mktemp -p "$HOME") || exit 1; sudo -n sh -c ` + shellQuote(`exec >"$0"; `+command) +
		` "$f" >/dev/null; rc=$?; cat "$f"; rm -f "$f"; exit $rc`
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

// Gate marks t as gate of this VM for the rendezvous of the VMs running in parallel (vmGroup.Gate).
func (v *VM) Gate(t *testing.T, gate string) { v.group.Gate(t, v.Name, gate) }

// Share records this VM's value under key for a step that Together runs once for all VMs (vmGroup.Share).
func (v *VM) Share(key, value string) { v.group.Share(v.Name, key, value) }

// Shared returns the values the VMs shared under key, by VM (vmGroup.Shared).
func (v *VM) Shared(key string) map[string]string { return v.group.Shared(key) }

// AfterAll runs fn once the subtests of every VM running in parallel ended (vmGroup.AfterAll).
func (v *VM) AfterAll(t *testing.T, fn func(t *testing.T)) { v.group.AfterAll(t, fn) }

// Together runs fn once for all VMs running in parallel when each of them arrived at step of gate (vmGroup.Together).
func (v *VM) Together(t *testing.T, gate, step string, fn func() string) string {
	t.Helper()
	return v.group.Together(t, v.Name, gate, step, fn)
}

// autologinScript makes GDM log the account $1 in automatically and restarts GDM: the AutomaticLogin keys go into the
// [daemon] section of /etc/gdm3/custom.conf (added when the file or the section is missing), replacing earlier ones.
// It ends with autologinRestart.
const autologinScript = `set -eu
conf=/etc/gdm3/custom.conf
[ -f "$conf" ] || : >"$conf"
grep -q '^\[daemon\]' "$conf" || printf '\n[daemon]\n' >>"$conf"
awk -v n="$1" '/^AutomaticLogin/ {next} {print} /^\[daemon\]$/ {print "AutomaticLoginEnable=true"; print "AutomaticLogin=" n}' "$conf" >"$conf.new"
mv "$conf.new" "$conf"
` + autologinRestart

// autologinRestart restarts GDM so that it applies the automatic login. GDM logs in automatically only on its first
// start per boot; its ran-once marker in /run would skip the autologin after the restart (as in DS1's ensureUserSession).
const autologinRestart = `rm -f /run/gdm3/ran-once-marker /run/gdm/ran-once-marker
systemctl restart display-manager.service
`

// Autologin gives the account name a graphical session through GDM's automatic login and waits until logind lists it
// as an active Wayland or X11 session of class user, which it returns. Nobody may be logged in at the console: the
// restart of GDM ends every graphical session. The session lasts until the VM returns to its snapshot.
func (v *VM) Autologin(t *testing.T, name string) Session {
	t.Helper()
	v.MustRootIn([]byte(autologinScript), "bash -s -- "+shellQuote(name))
	var found Session
	Until(t, v.Name+": graphical session of "+name, 3*time.Minute, 5*time.Second, nil, func() bool {
		for _, s := range v.UserSessions(name) {
			if (s.Type == "wayland" || s.Type == "x11") && s.State == "active" {
				found = s
				return true
			}
		}
		return false
	})
	return found
}
