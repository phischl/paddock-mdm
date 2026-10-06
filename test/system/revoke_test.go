package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
