package system

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/portal"
)

// localAdmin is the managed local administrator account of the dev organization acme (its default name).
const localAdmin = "paddock-admin"

// laWorld is an enrolled device of acme whose local administrator has a first escrowed password.
type laWorld struct {
	*Device
	reveals int // reveals of this device so far: each must be exactly one audit event
}

// localAdminState is GET /api/v1/devices/{id}/local-admin.
type localAdminState struct {
	Username string `json:"username"`
	Active   *int   `json:"active_generation"`
	Pending  *int   `json:"pending_generation"`
	Error    *struct {
		Reason     string `json:"reason"`
		Generation int    `json:"generation"`
	} `json:"last_rotation_error"`
}

func (w *laWorld) state() localAdminState {
	w.t.Helper()
	var s localAdminState
	if err := json.Unmarshal(w.s.Call(http.MethodGet, "/api/v1/devices/"+w.ID+"/local-admin", nil, http.StatusOK).Body, &s); err != nil {
		w.t.Fatal(err)
	}
	return s
}

// waitActive waits until generation is the active one, checking in every 65 s.
func (w *laWorld) waitActive(t *testing.T, generation int, timeout time.Duration) {
	t.Helper()
	last := time.Time{}
	Until(t, "local administrator generation active", timeout, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			w.Checkin()
			last = time.Now()
		}
	}, func() bool {
		s := w.state()
		return s.Active != nil && *s.Active == generation
	})
}

// revealed is one password of a reveal.
type revealed struct {
	Generation int    `json:"generation"`
	State      string `json:"state"`
	Password   string `json:"password"`
}

// reveal reveals the passwords after a step-up of alice and checks that the reveal is exactly one audit event.
func (w *laWorld) reveal(t *testing.T) []revealed {
	t.Helper()
	w.s.StepUp()
	hostname := w.Must("hostname")
	res := w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/local-admin/reveal", map[string]any{"confirm_hostname": hostname}, http.StatusOK)
	var out struct {
		Passwords []revealed `json:"passwords"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil || len(out.Passwords) == 0 {
		t.Fatalf("reveal: %v", err)
	}
	w.reveals++
	Until(t, "one audit event per reveal", time.Minute, 2*time.Second, nil, func() bool {
		return len(w.s.Events("local_admin.revealed", w.ID)) == w.reveals
	})
	return out.Passwords
}

// active is the active password of a reveal.
func active(t *testing.T, ps []revealed) revealed {
	t.Helper()
	for _, p := range ps {
		if p.State == "active" {
			return p
		}
	}
	t.Fatalf("no active password among generations %v", generations(ps))
	return revealed{}
}

func generations(ps []revealed) []int {
	var out []int
	for _, p := range ps {
		out = append(out, p.Generation)
	}
	return out
}

// login checks a password at the console PAM stack (login: authenticate and open a session).
func (w *laWorld) login(t *testing.T, password string) bool {
	t.Helper()
	exit, transcript := w.PAM(t, "login", localAdmin, []string{"authenticate", "open_session", "close_session"}, pamOpts{password: password, timeout: time.Minute})
	if exit != 0 {
		t.Logf("pamtester login %s: exit %d\n%s", localAdmin, exit, transcript)
	}
	return exit == 0
}

// sshLogin logs in over SSH with a password (from the guest to itself) and returns the remote user name.
func (w *laWorld) sshLogin(t *testing.T, password string) string {
	t.Helper()
	exit, transcript := w.Converse(t, "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no "+
		"-o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1 "+localAdmin+"@localhost 'id -un'",
		pamOpts{password: password, timeout: time.Minute})
	if exit != 0 {
		t.Fatalf("SSH login as %s: exit %d\n%s", localAdmin, exit, transcript)
	}
	return transcript
}

// newLAWorld waits for the local administrator: the account with the first escrowed password.
func newLAWorld(t *testing.T, d *Device) *laWorld {
	t.Helper()
	w := &laWorld{Device: d}
	// pamtester drives the PAM stacks of the checks (PoC M1); it is not part of the desktop installation.
	d.Must("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=600 pamtester >/dev/null")
	w.waitActive(t, 1, 15*time.Minute)
	return w
}

// TestLocalAdminGates runs gates LA1 and LA2 of plan M4a on each VM, each from a fresh base-installed.
func TestLocalAdminGates(t *testing.T) {
	for _, name := range vms(t) {
		t.Run(name, func(t *testing.T) {
			s := newStack(t)
			vm := newVM(t, s.root, name)
			vm.Fresh()
			w := newLAWorld(t, Install(t, s, vm, debDir(s)))
			if !t.Run("LA1 local administrator", func(t *testing.T) { gateLA1(t, w) }) {
				t.FailNow()
			}
			t.Run("LA2 tamper", func(t *testing.T) { gateLA2(t, w) })
		})
	}
}

// gateLA1: the account exists after enrollment with a rotated, escrowed password; the revealed password works at
// the console and over SSH (local_admin.login); Rotate now gives a new generation and the old password stops
// working; while the worker is stopped a rotation is never applied and the old password stays valid and revealable
// (rotation_failed after 15 minutes); once the worker is back the next rotation succeeds. Every reveal is exactly
// one audit event.
func gateLA1(t *testing.T, w *laWorld) {
	if out := w.Must("getent passwd " + localAdmin + " | cut -d: -f7; sudo stat -c %a /home/" + localAdmin + "; id -nG " + localAdmin); !strings.HasPrefix(out, "/bin/bash\n700\n") ||
		!slices.Contains(strings.Fields(out), "sudo") {
		t.Fatalf("account: %q", out)
	}
	pw1 := active(t, w.reveal(t))
	if pw1.Generation != 1 || len(pw1.Password) != 24 {
		t.Fatalf("first password: generation %d, %d characters", pw1.Generation, len(pw1.Password))
	}
	if !w.login(t, pw1.Password) {
		t.Fatal("console login with the revealed password failed")
	}
	if out := w.sshLogin(t, pw1.Password); !strings.Contains(out, " vm: "+localAdmin+"\n") {
		t.Fatalf("SSH login did not run as %s:\n%s", localAdmin, out)
	}
	for _, service := range []string{"login", "sshd"} {
		w.WaitEvent(t, "local_admin.login", 5*time.Minute, func(p map[string]any) bool { return p["service"] == service })
	}

	// Rotate now.
	w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/local-admin/rotate", nil, http.StatusAccepted)
	w.waitActive(t, 2, 5*time.Minute)
	pw2 := active(t, w.reveal(t))
	if pw2.Generation != 2 || pw2.Password == pw1.Password || !w.login(t, pw2.Password) || w.login(t, pw1.Password) {
		t.Fatalf("after Rotate now: generation %d, old password still works or new one does not", pw2.Generation)
	}

	// Confirmation failure: the worker is stopped after it signed the command, before the device uploads.
	since := w.Must("date -u +'%Y-%m-%d %H:%M:%S'")
	w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/local-admin/rotate", nil, http.StatusAccepted)
	time.Sleep(5 * time.Second)
	if out, err := compose(t, "stop", "paddock-worker"); err != nil {
		t.Fatalf("stop worker: %v: %s", err, out)
	}
	workerStopped := true
	defer func() {
		if workerStopped {
			_, _ = portal.Compose(context.Background(), "start", "paddock-worker")
		}
	}()
	agentLog := func() string {
		return w.Must("sudo journalctl -u paddock-supervisor --since '" + since + "' --no-pager -o cat | grep 'local administrator' || true")
	}
	Until(t, "rotation started on the device", 3*time.Minute, 5*time.Second, w.Checkin, func() bool {
		return strings.Contains(agentLog(), "local administrator rotation started")
	})
	if !w.login(t, pw2.Password) {
		t.Fatal("the old password stopped working while the rotation waits")
	}
	if ps := w.reveal(t); len(ps) != 1 || ps[0].Generation != 2 || ps[0].Password != pw2.Password {
		t.Fatalf("reveal while the worker is stopped: generations %v", generations(ps))
	}
	Until(t, "rotation failed on the device", 20*time.Minute, 30*time.Second, nil, func() bool {
		return strings.Contains(agentLog(), "local administrator rotation failed")
	})
	if !w.login(t, pw2.Password) {
		t.Fatal("the old password stopped working after the failed rotation")
	}
	if out, err := compose(t, "start", "paddock-worker"); err != nil {
		t.Fatalf("start worker: %v: %s", err, out)
	}
	workerStopped = false
	w.s.Login() // the worker restart does not end the session, but the step-up is older than 5 minutes anyway
	w.WaitEvent(t, "local_admin.rotation_failed", 5*time.Minute, func(p map[string]any) bool { return p["reason"] == "escrow_timeout" })
	if p := active(t, w.reveal(t)); p.Generation != 2 || p.Password != pw2.Password {
		t.Fatalf("after the failure the active generation is %d", p.Generation)
	}

	// The next rotation succeeds with a new generation; the never applied one is superseded.
	w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/local-admin/rotate", nil, http.StatusAccepted)
	w.waitActive(t, 4, 5*time.Minute)
	ps := w.reveal(t)
	pw4 := active(t, ps)
	if len(ps) != 1 || !w.login(t, pw4.Password) || w.login(t, pw2.Password) {
		t.Fatalf("after the worker is back: generations %v", generations(ps))
	}
}

// compose runs a docker compose command of the dev stack with a timeout of its own.
func compose(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return portal.Compose(ctx, args...)
}

// gateLA2: a password set locally and a removed sudo membership are reported (tamper.local_admin_changed) and
// restored: the next rotation sets a password Paddock knows, the membership comes back.
func gateLA2(t *testing.T, w *laWorld) {
	before := *w.state().Active
	w.MustIn([]byte(localAdmin+":Local-Change-1\n"), "sudo chpasswd --crypt-method SHA512") // like passwd, without Himmelblau's PAM module
	w.WaitEvent(t, "device.tamper_local_admin_changed", 5*time.Minute, func(p map[string]any) bool { return p["field"] == "password" })
	w.waitActive(t, before+1, 5*time.Minute)
	pw := active(t, w.reveal(t))
	if !w.login(t, pw.Password) || w.login(t, "Local-Change-1") {
		t.Fatal("the repair rotation did not restore a known password")
	}

	w.Must("sudo gpasswd -d " + localAdmin + " sudo")
	w.WaitEvent(t, "device.tamper_local_admin_changed", 5*time.Minute, func(p map[string]any) bool { return p["field"] == "group" })
	Until(t, "sudo membership restored", 2*time.Minute, 5*time.Second, nil, func() bool {
		return slices.Contains(strings.Fields(w.Must("id -nG "+localAdmin)), "sudo")
	})
}
