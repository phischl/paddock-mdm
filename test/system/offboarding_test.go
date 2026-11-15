package system

import (
	"context"
	"strings"
	"testing"
	"time"
)

// guestPhaseNow reads the phase of the guest; ok is false while the guest does not answer (sshd restarts during the
// package removal).
func guestPhaseNow(t *testing.T, vm *VM) (phase guestPhase, triggered, ok bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := vm.SSH(ctx, nil, guestPhaseScript)
	if err != nil {
		return "", false, false
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	phase, triggered, err = parseGuestPhase(lines[len(lines)-1])
	if err != nil {
		t.Logf("%s: %v", vm.Name, err)
		return "", false, false
	}
	return phase, triggered, true
}

// waitRemoved waits until Paddock is gone from the guest and returns the phases seen on the way. The device removes
// Paddock at a check-in it makes itself; the gate only nudges the agent, as WaitEvent does, because the organization
// no longer reports anything to wait for. A dead man's switch that triggers fails the gate at once.
func waitRemoved(t *testing.T, vm *VM, timeout time.Duration) phaseTrace {
	t.Helper()
	var seen phaseTrace
	var last time.Time
	Until(t, vm.Name+": Paddock removed", timeout, 2*time.Second, func() {
		if time.Since(last) < 65*time.Second {
			return
		}
		last = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = vm.SSH(ctx, nil, "sudo pkill -HUP -f '^/opt/paddock/agent/current/paddockd run' || true")
	}, func() bool {
		p, triggered, ok := guestPhaseNow(t, vm)
		if !ok {
			return false
		}
		if triggered {
			t.Fatalf("%s: the dead man's switch triggered while the device was offboarded", vm.Name)
		}
		seen.add(p)
		return p == phaseRemoved
	})
	if err := seen.check(); err != nil {
		t.Fatalf("%s: %v", vm.Name, err)
	}
	return seen
}

// TestOffboarding is gate OS1 of plan M17 (§8.8; PDK-1022): both VMs are enrolled into an organization of their own,
// with the dead man's switch on, and one of them is switched off before the organization's deletion is requested
// (grace 0, development builds). The other removes Paddock at once; the switched-off one stays off until the
// organization is `deleted`, is started, and removes Paddock at its next contact. On both, Paddock and the sudoers
// files are gone, the dead man's switch token (self-lock.dsse) with them, the local administrator still signs in with
// the password revealed before the deletion, the home directories and the LUKS keyslots are unchanged, nothing locked
// the device, and the disk unlocks at the next boot. The VMs run in parallel; the organization is created once and
// ends deleted.
//
// A watcher on the guest timestamps the token's disappearance and the removal, so the order (disarm first) is asserted
// from its log, not from polls. Not covered: the variant in which the uninstall is refused (a revocation handed to
// paddock-revoke within 24 h); it needs a device that stays in a deleted organization, and the gate has two VMs
// (follow-up ticket); the agent's unit test TestOffboardedDeviceDisarmsBeforeRefusedUninstall and acceptance gate OF6
// cover the disarm that comes first.
func TestOffboarding(t *testing.T) {
	var gate *offboardingGate
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		names := vms(t)
		off := vm.Name == offboardingOffVM(names)
		vm.Gate(t, "OS1")
		vm.Together(t, "OS1", "organization", func() string {
			gate = newOffboardingGate(t, vm, names)
			return gate.slug
		})
		s.gate = gate.admins[vm.Name]
		s.Login(t)
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		w := &uninstallWorld{laWorld: newLAWorld(t, d)}
		password := active(t, w.reveal(t)).Password
		homes := vm.Must("ls -1 /home | sort")
		keyslots := vm.Keyslots(t)
		boot := vm.bootID(t)

		// A run cut short before its cleanup leaves the switch on for the organization only, which is deleted.
		vm.Together(t, "OS1", "switch on", func() string { setDMS(t, s, true); return "" })
		Until(t, vm.Name+": self-lock token stored", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
			at, _ := dmsState(t, d)
			return !at.IsZero() && vm.Must("sudo test -s /var/lib/paddock/revoke/self-lock.dsse && echo stored || true") == "stored"
		})
		if p, _, _ := guestPhaseNow(t, vm); p != phaseArmed {
			t.Fatalf("%s is %q before the deletion, want armed", vm.Name, p)
		}

		installWatcher(vm)

		var lastCheckin time.Time
		if off {
			// The last contact with the stack is the last ticket of the dead man's switch; the device never sees
			// the deletion.
			d.Checkin()
			time.Sleep(10 * time.Second)
			lastCheckin = time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			err := vm.PowerOff(ctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
		}
		vm.Together(t, "OS1", "request deletion", func() string { gate.requestDeletion(t); return "" })
		s.orgGone.Store(true)

		var started time.Time
		if off {
			gate.waitDeleted(t, 15*time.Minute)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			err := vm.Start(ctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			started = time.Now()
			// A restart is not a lock: the boot before the shutdown is gone, so its ID cannot be compared.
			boot = vm.bootID(t)
		}
		seen := waitRemoved(t, vm, 20*time.Minute)
		t.Logf("%s: phases %v (off during the deletion: %v)", vm.Name, seen, off)
		if err := checkWatchLog(vm.Must("sudo cat " + watchLog)); err != nil {
			t.Fatalf("%s: %v", vm.Name, err)
		}

		w.packagesGone(t)
		w.absent(t, "/etc/paddock", "/var/lib/paddock", "/opt/paddock", "/var/lib/paddock/revoke/self-lock.dsse")
		if out := vm.Must("sudo find /etc/sudoers.d -name 'paddock-*'"); out != "" {
			t.Fatalf("sudoers files left: %s", out)
		}
		w.Must("sudo visudo -c")
		vm.Must("getent passwd " + localAdmin)
		if out := w.sshLogin(t, password); !strings.Contains(out, localAdmin) {
			t.Fatalf("SSH login as %s: %s", localAdmin, out)
		}
		if got := vm.Must("ls -1 /home | sort"); got != homes {
			t.Fatalf("home directories %q, before %q", got, homes)
		}

		if off {
			// The dead man's switch counts uptime from the ticket: one period after the device came back is more
			// than the single period it could have run since its last check-in.
			t.Logf("%s: last check-in %s, started %s; waiting one switch period of %d min", vm.Name, lastCheckin.Format(time.TimeOnly),
				started.Format(time.TimeOnly), dmsPeriod)
			time.Sleep(time.Until(started.Add((dmsPeriod + 2) * time.Minute)))
		}
		if got := vm.Must("test -e /run/paddock/revoke-would-reboot && echo yes || echo no"); got != "no" {
			t.Fatalf("%s: the device self-locked (would-reboot marker)", vm.Name)
		}
		if after := vm.bootID(t); after != boot {
			t.Fatalf("%s: the guest rebooted by itself: boot ID %s, before %s", vm.Name, after, boot)
		}
		if got := vm.Keyslots(t); strings.Join(got, ",") != strings.Join(keyslots, ",") {
			t.Fatalf("%s: keyslots %v, before %v", vm.Name, got, keyslots)
		}

		vm.RebootWithPassphrase(t)
		if !vm.Opens(t, credential(t, vm, "PADDOCK_LUKS_PASSPHRASE")) {
			t.Fatal("the LUKS passphrase no longer opens the disk")
		}
	})
}
