package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// revokeTarget is the LUKS test target of paddock-revoke on a VM: a loop device or the secondary disk (gate R1).
type revokeTarget struct {
	*Device
	device string
}

// loopTarget formats a 64 MiB file on a loop device as LUKS2 with two keyslots and names it in the test target
// override of paddock-revoke test builds (plan M4c decision 13).
func loopTarget(t *testing.T, d *Device) *revokeTarget {
	t.Helper()
	dev := d.Must(`sudo sh -c 'truncate -s 64M /root/revoke-target.img && losetup -f --show /root/revoke-target.img'`)
	if !strings.HasPrefix(dev, "/dev/loop") {
		t.Fatalf("loop device %q", dev)
	}
	r := &revokeTarget{Device: d, device: dev}
	r.format(t)
	d.Must("echo " + dev + " | sudo tee /etc/paddock/revoke-test-target >/dev/null")
	return r
}

// format writes a new LUKS2 header with two passphrase keyslots (fast PBKDF2; the target holds no data).
func (r *revokeTarget) format(t *testing.T) {
	t.Helper()
	r.Must(`sudo sh -c 'printf one | cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 ` +
		r.device + ` - && printf two > /root/revoke-two && printf one | cryptsetup luksAddKey --batch-mode --pbkdf pbkdf2 ` +
		`--pbkdf-force-iterations 1000 --key-file - ` + r.device + ` /root/revoke-two && rm /root/revoke-two'`)
	if n := r.slots(t); n != 2 {
		t.Fatalf("test target with %d keyslots", n)
	}
}

// slots counts the keyslots of the target.
func (r *revokeTarget) slots(t *testing.T) int {
	t.Helper()
	return keyslotCount(t, r.VM, r.device)
}

func keyslotCount(t *testing.T, vm *VM, device string) int {
	t.Helper()
	var md struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
	}
	if err := json.Unmarshal([]byte(vm.Must("sudo cryptsetup luksDump --dump-json-metadata "+device)), &md); err != nil {
		t.Fatal(err)
	}
	return len(md.Keyslots)
}

// tokenSigner signs revocation tokens for a device with a key the device was made to trust.
type tokenSigner struct {
	key    ed25519.PrivateKey
	device string
	org    string
}

// pinTestKey replaces the device's revocation trust anchor with a key of the test: gate R4 checks paddock-revoke's
// own checks with tokens the server would never sign (expired, other device); R1 runs with the server's tokens.
func pinTestKey(t *testing.T, d *Device) *tokenSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, _ := json.Marshal(revocation.TrustFile{RevocationKeys: []revocation.Key{{KeyID: "revocation-signing:v1",
		PublicKey: base64.StdEncoding.EncodeToString(pub)}}})
	d.MustIn(trust, "sudo tee /etc/paddock/revoke-trust.json >/dev/null")
	// paddock-revoke binds a token to the device only; the organization is not on the device's side of the check.
	return &tokenSigner{key: priv, device: d.ID, org: uuid.NewString()}
}

func (s *tokenSigner) sign(t *testing.T, key ed25519.PrivateKey, change func(*revocation.Token)) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	id := uuid.NewString()
	tok := revocation.Token{CommandID: id, DeviceID: s.device, OrganizationID: s.org, Action: revocation.ActionLock,
		IssuedAt: now, ExpiresAt: now.Add(revocation.Lifetime), RequestID: id}
	if change != nil {
		change(&tok)
	}
	payload, err := revocation.Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.New(revocation.PayloadType, payload, dsse.SignEd25519(key, "revocation-signing:v1", revocation.PayloadType, payload)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// executeRevoke runs `<bin> execute` with the token on stdin and returns the exit code and stdout. It runs as a
// transient system service, as paddockd runs it: paddock-revoke terminates the sessions of every non-system user,
// including the SSH session of the test, which reconnects and waits for the result.
func executeRevoke(t *testing.T, vm *VM, bin string, env []byte) (int, string) {
	t.Helper()
	vm.MustIn(env, "umask 077 && cat > /tmp/revoke-token && sudo rm -f /tmp/revoke.out /tmp/revoke.exit")
	vm.Must(`sudo systemd-run --quiet --collect --unit paddock-revoke-gate-` + uuid.NewString()[:8] + ` sh -c '` + bin +
		` execute </tmp/revoke-token >/tmp/revoke.out 2>/dev/null; echo $? >/tmp/revoke.exit'`)
	var exit string
	Until(t, vm.Name+": paddock-revoke result", 2*time.Minute, 2*time.Second, func() {}, func() bool {
		exit = vm.Must("sudo cat /tmp/revoke.exit 2>/dev/null || true")
		return exit != ""
	})
	code, err := strconv.Atoi(exit)
	if err != nil {
		t.Fatalf("paddock-revoke exit %q", exit)
	}
	return code, vm.Must("sudo cat /tmp/revoke.out")
}

func expectRefused(t *testing.T, vm *VM, bin string, env []byte, reason string) {
	t.Helper()
	code, out := executeRevoke(t, vm, bin, env)
	if code != 2 || out != `{"refused":"`+reason+`"}` {
		t.Fatalf("exit %d %s, want refused %s", code, out, reason)
	}
}

const revokeBinary = "/opt/paddock/revoke/paddock-revoke"

// TestRevocationRefusalGates is gate R4 of plan M4c (decision 11): on each VM, paddock-revoke refuses an expired
// token, another device's token, an untrusted key, a second revocation within 24 h and any token without the
// revoke-enabled marker, without touching a keyslot; a release build refuses every token while the test target
// override exists; a token paddockd hands over and paddock-revoke refuses is reported as
// device.revocation_refused. The VMs run in parallel.
func TestRevocationRefusalGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		Until(t, vm.Name+": revoke-enabled marker", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
			return d.Must("test -e /etc/paddock/revoke-enabled && echo yes || echo no") == "yes"
		})
		if out := d.Must("sudo test -s /etc/paddock/revoke-trust.json && echo pinned"); out != "pinned" {
			t.Fatal("no revocation trust anchor after enrollment")
		}
		rootDev := vm.LUKSDevice() // before the loop target, which blkid lists as well
		rootSlots := keyslotCount(t, vm, rootDev)
		target := loopTarget(t, d)
		signer := pinTestKey(t, d)
		// The agent keeps the marker from the bundle; it is stopped while the gate changes the marker itself.
		d.Must("sudo systemctl stop paddock-supervisor")
		_, other, _ := ed25519.GenerateKey(rand.Reader)

		t.Run("refusals", func(t *testing.T) {
			for name, c := range map[string]struct {
				env    []byte
				reason string
			}{
				"expired": {signer.sign(t, signer.key, func(k *revocation.Token) {
					k.IssuedAt, k.ExpiresAt = k.IssuedAt.Add(-31*24*time.Hour), k.IssuedAt.Add(-time.Hour)
				}), "expired"},
				"other device":  {signer.sign(t, signer.key, func(k *revocation.Token) { k.DeviceID = uuid.NewString() }), "wrong_device"},
				"untrusted key": {signer.sign(t, other, nil), "signature"},
			} {
				expectRefused(t, vm, revokeBinary, c.env, c.reason)
				if n := target.slots(t); n != 2 {
					t.Fatalf("%s: %d keyslots left on the test target", name, n)
				}
			}
			d.Must("sudo rm /etc/paddock/revoke-enabled")
			expectRefused(t, vm, revokeBinary, signer.sign(t, signer.key, nil), "disabled")
			d.Must("sudo touch /etc/paddock/revoke-enabled")
			if n := target.slots(t); n != 2 {
				t.Fatalf("without the marker: %d keyslots left", n)
			}
		})

		t.Run("one revocation per 24 h", func(t *testing.T) {
			code, out := executeRevoke(t, vm, revokeBinary, signer.sign(t, signer.key, nil))
			if code != 0 || out != `{"erased":true,"slots_before":2,"slots_after":0}` || target.slots(t) != 0 {
				t.Fatalf("valid token: exit %d %s", code, out)
			}
			if d.Must("test -s /run/paddock/revoke-would-reboot && echo marker") != "marker" {
				t.Fatal("no would-reboot marker")
			}
			target.format(t)
			expectRefused(t, vm, revokeBinary, signer.sign(t, signer.key, nil), "rate_limited")
			if n := target.slots(t); n != 2 {
				t.Fatalf("second revocation: %d keyslots left", n)
			}
		})

		t.Run("release build ignores the test target", func(t *testing.T) {
			vm.Copy(filepath.Join(s.root, "bin", "revoke-release", "paddock-revoke"), "/tmp/paddock-revoke-release")
			d.Must("chmod 0755 /tmp/paddock-revoke-release && sudo rm -f /var/lib/paddock/revoke/state.json")
			expectRefused(t, vm, "/tmp/paddock-revoke-release", signer.sign(t, signer.key, nil), "test_target_present")
			if n, root := target.slots(t), keyslotCount(t, vm, rootDev); n != 2 || root != rootSlots {
				t.Fatalf("release build: test target %d keyslots, root %d (before %d)", n, root, rootSlots)
			}
		})

		t.Run("refusal reported", func(t *testing.T) {
			d.Must("sudo systemctl start paddock-supervisor")
			// An expired token in cmd:<device_id>, as a compromised Valkey could put it there.
			env := signer.sign(t, signer.key, func(k *revocation.Token) {
				k.IssuedAt, k.ExpiresAt = k.IssuedAt.Add(-31*24*time.Hour), k.IssuedAt.Add(-time.Hour)
			})
			field, _ := json.Marshal(map[string]any{"expires_at": time.Now().Add(time.Hour).UTC(), "envelope": json.RawMessage(env)})
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			script := fmt.Sprintf(`REDISCLI_AUTH="$(cat /run/secrets/valkey_password)" valkey-cli --no-auth-warning HSET cmd:%s %s '%s'`,
				d.ID, uuid.NewString(), string(field))
			if out, err := portal.Compose(ctx, "exec", "-T", "valkey", "sh", "-c", script); err != nil {
				t.Fatalf("valkey: %v %s", err, out)
			}
			d.WaitEvent(t, "device.revocation_refused", 3*time.Minute, func(p map[string]any) bool { return p["reason"] == "expired" })
			if n := target.slots(t); n != 2 {
				t.Fatalf("handed refusal: %d keyslots left", n)
			}
		})
	})
}

// revocationAdmin is a temporary acme administrator with a TOTP authenticator: the gate's Locks count against its
// own revocation limits (ADR 0014), never against alice's.
type revocationAdmin struct {
	session            *portal.Session
	username, password string
	totp               *portal.TOTP
}

func newRevocationAdmin(t *testing.T) *revocationAdmin {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ak, err := portal.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	a := &revocationAdmin{username: "systest-revoke-" + unique() + "@acme.test", password: "pw-" + uuid.NewString()}
	pk, err := ak.CreateUser(ctx, a.username, a.password, portal.RoleGroup("acme", "admins"))
	t.Cleanup(func() {
		if pk != 0 {
			_ = ak.DeleteUser(context.Background(), pk)
		}
	})
	if err != nil {
		t.Fatalf("create %s: %v", a.username, err)
	}
	if a.totp, err = portal.AddTOTP(ctx, a.username); err != nil {
		t.Fatal(err)
	}
	if a.session, err = portal.LoginAs(ctx, a.username, a.password); err != nil {
		t.Fatalf("login %s: %v", a.username, err)
	}
	return a
}

// stepUp runs a step-up, repeated once after the maximum auth age (see Stack.StepUp).
func (a *revocationAdmin) stepUp(t *testing.T) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		final, err := portal.StepUpAs(ctx, a.session, a.username, a.password, a.totp)
		cancel()
		if err == nil && !strings.Contains(final, "stepup=failed") {
			return
		}
		if attempt == 2 {
			t.Fatalf("step-up of %s: %v (returned to %s)", a.username, err, final)
		}
		time.Sleep(stepUpRetryAfter)
	}
}

func (a *revocationAdmin) call(t *testing.T, method, path string, body any, status int) portal.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := a.session.Do(ctx, method, path, body)
	if err != nil || res.Status != status {
		t.Fatalf("%s %s: %v HTTP %d %s, want %d", method, path, err, res.Status, res.Body, status)
	}
	return res
}

// secondDiskTarget makes the empty 64 MiB disk of FreshWithDisk a copy of the root volume's LUKS header with a UUID
// of its own, and names it in the test target override: the root volume's escrowed header and recovery key open it,
// so the restore of a Lock can be shown on it without touching the root volume.
func secondDiskTarget(t *testing.T, d *Device, rootDev string) *revokeTarget {
	t.Helper()
	dev := d.Must(`lsblk -dnbpo NAME,SIZE | awk '$2 == 67108864 { print $1 }'`)
	if !strings.HasPrefix(dev, "/dev/sd") {
		t.Fatalf("second disk %q", dev)
	}
	d.Must(`sudo sh -c 'set -e
umask 077
cryptsetup luksHeaderBackup ` + rootDev + ` --header-backup-file /run/paddock-gate-root-header.img
trap "rm -f /run/paddock-gate-root-header.img" EXIT
cryptsetup luksHeaderRestore -q ` + dev + ` --header-backup-file /run/paddock-gate-root-header.img
cryptsetup luksUUID -q ` + dev + ` --uuid ` + uuid.NewString() + `
echo ` + dev + ` > /etc/paddock/revoke-test-target'`)
	return &revokeTarget{Device: d, device: dev}
}

// TestRevocationLockGate is gate R1 of plan M4c (AC1): on each VM with a second disk as test target of the
// paddock_revoke_testtarget build, a Lock terminates the user sessions, erases every keyslot of the target, stores the
// confirmation before the would-reboot marker appears, and the request is confirmed; the root volume is not touched.
// Then the escrowed header and recovery key restore the target. The VMs run in parallel.
func TestRevocationLockGate(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.FreshWithDisk()
		d := Install(t, s, vm, debDir(s))
		w := &diskWorld{Device: d, pin: randomDigits(t, 8)}
		if !t.Run("root volume escrowed", func(t *testing.T) { gateDiskFlow(t, w) }) {
			t.FailNow()
		}
		rootDev := vm.LUKSDevice() // before the target, which carries a copy of its header
		rootSlots := keyslotCount(t, vm, rootDev)
		target := secondDiskTarget(t, d, rootDev)
		before := target.slots(t)
		if before != rootSlots {
			t.Fatalf("target %d keyslots, root %d", before, rootSlots)
		}
		admin := newRevocationAdmin(t)
		hostname := d.Must("hostname")

		// A session of the user paddock (UID 1000) that the Lock must end.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		session := exec.CommandContext(ctx, "ssh", append(vm.sshArgs(), "-p", vm.port, "paddock@127.0.0.1", "sleep 900")...)
		if err := session.Start(); err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- session.Wait() }()
		Until(t, vm.Name+": user session", time.Minute, 2*time.Second, nil, func() bool {
			return strings.Contains(vm.Must("loginctl list-sessions --no-legend"), "paddock")
		})

		admin.stepUp(t)
		res := admin.call(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/lock", map[string]any{"confirm_hostname": hostname, "reason": "gate R1"},
			http.StatusCreated)
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(res.Body, &req); err != nil {
			t.Fatal(err)
		}
		var confirmed struct {
			Status      string          `json:"status"`
			ConfirmedAt *time.Time      `json:"confirmed_at"`
			Result      json.RawMessage `json:"result"`
		}
		Until(t, vm.Name+": Lock confirmed", 5*time.Minute, 5*time.Second, d.Checkin, func() bool {
			var page struct {
				Items []json.RawMessage `json:"items"`
			}
			_ = json.Unmarshal(admin.call(t, http.MethodGet, "/api/v1/revocation-requests?device_id="+d.ID, nil, http.StatusOK).Body, &page)
			for _, it := range page.Items {
				var r struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(it, &r) == nil && r.ID == req.ID {
					_ = json.Unmarshal(it, &confirmed)
				}
			}
			return confirmed.Status == "confirmed"
		})
		select {
		case <-ended:
		case <-time.After(time.Minute):
			t.Fatal("the user session survived the Lock")
		}
		if n := target.slots(t); n != 0 {
			t.Fatalf("%d keyslots left on the target", n)
		}
		if n := keyslotCount(t, vm, rootDev); n != rootSlots {
			t.Fatalf("root volume: %d keyslots, %d before", n, rootSlots)
		}
		want := fmt.Sprintf(`{"erased":true,"slots_after":0,"slots_before":%d}`, before)
		var result map[string]any
		_ = json.Unmarshal(confirmed.Result, &result)
		if got, _ := json.Marshal(result); string(got) != want {
			t.Fatalf("confirmation %s, want %s", got, want)
		}
		marker, err := time.Parse(time.RFC3339Nano, vm.Must("cat /run/paddock/revoke-would-reboot"))
		if err != nil || confirmed.ConfirmedAt == nil {
			t.Fatalf("would-reboot marker %v, confirmed at %v", err, confirmed.ConfirmedAt)
		}
		// The server stored the confirmation before paddock-revoke went on to reboot (clocks synchronized by NTP).
		if confirmed.ConfirmedAt.After(marker.Add(time.Second)) {
			t.Fatalf("confirmation stored at %s, after the would-reboot marker %s", confirmed.ConfirmedAt, marker)
		}
		t.Logf("%s: confirmation stored %s, would-reboot %s", vm.Name, confirmed.ConfirmedAt.Format(time.RFC3339Nano), marker.Format(time.RFC3339Nano))

		t.Run("restore from the escrow", func(t *testing.T) {
			admin.stepUp(t)
			body := map[string]any{"confirm_hostname": hostname}
			var revealed struct {
				RecoveryKey string `json:"recovery_key"`
			}
			if err := json.Unmarshal(admin.call(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/disk/recovery-key", body, http.StatusOK).Body, &revealed); err != nil {
				t.Fatal(err)
			}
			header := admin.call(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/disk/header", body, http.StatusOK).Body
			if _, err := vm.SSH(context.Background(), []byte(revealed.RecoveryKey), "sudo cryptsetup open --test-passphrase --key-file=- "+target.device); err == nil {
				t.Fatal("the erased target opens before the restore")
			}
			vm.MustIn(header, "sudo sh -c 'umask 077 && cat > /run/paddock-gate-header.img'")
			vm.MustIn([]byte(revealed.RecoveryKey), `sudo sh -c 'set -e
trap "rm -f /run/paddock-gate-header.img" EXIT
cryptsetup luksHeaderRestore -q `+target.device+` --header-backup-file /run/paddock-gate-header.img
cryptsetup open --test-passphrase --key-file=- `+target.device+`'`)
		})
		vm.Must("sudo wipefs -aq " + target.device)
	})
}

// dmsPeriod is the dead man's switch period of gate R6 in days of the development builds, which are minutes: longer
// than the longest check-in interval (6 min), so the switch never fires while the stack answers.
const dmsPeriod = 8

// setDMS turns the acme dead man's switch on (period dmsPeriod, warnings 3 and 1 before) or off, as alice, signed in
// again: the gate outlasts a portal session.
func setDMS(s *Stack, enabled bool) {
	s.Login()
	s.StepUp()
	s.Call(http.MethodPut, "/api/v1/settings/dms", map[string]any{"enabled": enabled, "period_days": dmsPeriod, "warn_days": []int{3, 1}},
		http.StatusOK)
}

// blockStack makes the stack unreachable for the guest — the stack seen from the device is down — while SSH, which
// comes in through the NAT port forward, keeps working.
func blockStack(d *Device, on bool) {
	rule := "OUTPUT -d 10.0.2.2 -p tcp --dport 8443 -j REJECT"
	if on {
		d.Must("sudo iptables -I " + rule)
		return
	}
	d.Must("while sudo iptables -D " + rule + " 2>/dev/null; do :; done")
}

// dmsState is the agent's /var/lib/paddock/state/dms.json.
func dmsState(t *testing.T, d *Device) (ticketAt time.Time, triggered bool) {
	t.Helper()
	var st struct {
		TicketAt  time.Time `json:"ticket_at"`
		Triggered bool      `json:"triggered"`
	}
	if out := d.Must("sudo cat /var/lib/paddock/state/dms.json 2>/dev/null || echo '{}'"); json.Unmarshal([]byte(out), &st) != nil {
		t.Fatalf("dms.json %q", out)
	}
	return st.TicketAt, st.Triggered
}

func issue(d *Device) string {
	return d.Must("cat /etc/issue.d/80-paddock-dms.issue 2>/dev/null || true")
}

// TestDeadMansSwitchGate is gate R6 of plan M4c (AC4) with the development builds, whose days are minutes: on each VM
// with the stack unreachable, the device warns 3 and 1 periods' days before the end, locks itself only after the
// period of uptime — wall-clock jumps neither defer nor trigger it — and with the switch off nothing happens for
// three periods. The VMs run in parallel; the acme switch is turned on and off for both at once.
func TestDeadMansSwitchGate(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		vm.Gate(t, "R6")
		d := Install(t, s, vm, debDir(s))
		target := loopTarget(t, d)
		t.Cleanup(func() { vm.Together(t, "R6", "switch off at the end", func() string { setDMS(s, false); return "" }) })
		vm.Together(t, "R6", "switch on", func() string { setDMS(s, true); return "" })
		Until(t, vm.Name+": self-lock token stored", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
			at, _ := dmsState(t, d)
			return !at.IsZero() && d.Must("sudo test -s /var/lib/paddock/revoke/self-lock.dsse && echo stored || true") == "stored"
		})

		t.Run("warnings, then the self-lock", func(t *testing.T) {
			// The last ticket the device accepts before the stack goes away starts the count.
			before, _ := dmsState(t, d)
			Until(t, vm.Name+": fresh ticket", 2*time.Minute, 5*time.Second, d.Checkin, func() bool {
				at, _ := dmsState(t, d)
				return at.After(before)
			})
			blockStack(d, true)
			start := time.Now()
			t.Cleanup(func() {
				// The guest clock goes back to the host's time, also after a failure: later steps verify lifetimes.
				d.Must(fmt.Sprintf("sudo date -s @%d >/dev/null && sudo timedatectl set-ntp true", time.Now().Unix()))
				blockStack(d, false)
			})
			at := func(m float64) { time.Sleep(time.Until(start.Add(time.Duration(m * float64(time.Minute))))) }
			since := func() float64 { return time.Since(start).Minutes() }
			// The device counts in ticks of a minute from the ticket, accepted a few seconds before start: each step
			// may come up to one tick after its time, never before.
			const early = 0.25
			wouldReboot := func() bool { return d.Must("test -e /run/paddock/revoke-would-reboot && echo yes || echo no") == "yes" }
			waitFor := func(what string, until float64, ok func() bool) float64 {
				t.Helper()
				for !ok() {
					if since() > until {
						t.Fatalf("%s: not seen %.2f min after the stack went away", what, since())
					}
					time.Sleep(10 * time.Second)
				}
				return since()
			}

			at(1)
			d.Must("sudo timedatectl set-ntp false && sudo date -s '+3 days' >/dev/null") // must not trigger
			at(dmsPeriod - 3 - 1)
			if w := issue(d); w != "" || wouldReboot() {
				t.Fatalf("warning or self-lock after the jump forward: %q", w)
			}
			d.Must("sudo date -s '-6 days' >/dev/null") // must not defer
			first := waitFor("first warning", dmsPeriod-3+1.5, func() bool { return strings.Contains(issue(d), "locks itself in 3 minutes") })
			second := waitFor("second warning", dmsPeriod-1+1.5, func() bool { return strings.Contains(issue(d), "locks itself in 1 minutes") })
			if first < dmsPeriod-3-early || second < dmsPeriod-1-early || wouldReboot() || target.slots(t) != 2 {
				t.Fatalf("warnings at %.2f and %.2f min, self-lock %v, %d keyslots", first, second, wouldReboot(), target.slots(t))
			}
			locked := waitFor("self-lock", dmsPeriod+2, wouldReboot)
			if locked < dmsPeriod-early {
				t.Fatalf("self-locked after %.2f min, before the period", locked)
			}
			if n := target.slots(t); n != 0 {
				t.Fatalf("%d keyslots left after the self-lock", n)
			}
			t.Logf("%s: warnings after %.2f and %.2f min, self-lock after %.2f min (period %d)", vm.Name, first, second, locked, dmsPeriod)
		})

		t.Run("switch off: nothing happens", func(t *testing.T) {
			vm.Together(t, "R6", "switch off", func() string { setDMS(s, false); return "" })
			Until(t, vm.Name+": self-lock token deleted", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
				return d.Must("sudo test -e /var/lib/paddock/revoke/self-lock.dsse && echo stored || echo gone") == "gone"
			})
			d.Must("sudo rm -f /run/paddock/revoke-would-reboot /var/lib/paddock/revoke/state.json")
			target.format(t)
			blockStack(d, true)
			time.Sleep(3 * dmsPeriod * time.Minute)
			_, triggered := dmsState(t, d)
			if w := issue(d); w != "" || triggered || d.Must("test -e /run/paddock/revoke-would-reboot && echo yes || echo no") != "no" ||
				target.slots(t) != 2 {
				t.Fatalf("switch off: warning %q, triggered %v, %d keyslots", w, triggered, target.slots(t))
			}
			blockStack(d, false)
		})
	})
}
