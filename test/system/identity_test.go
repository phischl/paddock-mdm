package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/dsse"
	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/pkg/sudoers"
	"github.com/paddock-mdm/paddock/test/acceptance/portal"
)

// directoryUser is an Authentik user of the identity gates with password and TOTP (enrolled at the first approval).
type directoryUser struct {
	name, password, pin string
	totp                *portal.TOTP
	id                  string // Paddock user ID (synced users of acme)
}

func (u *directoryUser) short() string { name, _, _ := strings.Cut(u.name, "@"); return name }

// identityWorld is one VM's device with the users, the login assignment and the permission profiles of the gates.
type identityWorld struct {
	*Device
	ak                       *portal.Authentik
	dave, fred, nina, erin   *directoryUser // acme: assigned (restricted, full, none), not assigned
	gus                      *directoryUser // globex
	restrictedID, fullID     string         // permission profiles
	restrictedCommands       []string
	adminPassword, deviceRun string
}

// TestIdentityGates runs gates L1–L5, P3 and P4 of plan M3b §6 on each VM, each from a fresh base-installed, with
// real GDM and GNOME. Screenshots are kept in bin/system-evidence/<vm>/.
func TestIdentityGates(t *testing.T) {
	for _, name := range vms(t) {
		t.Run(name, func(t *testing.T) {
			s := newStack(t)
			requireBreakGlass(t, s)
			vm := newVM(t, s.root, name)
			vm.Fresh()
			w := newIdentityWorld(t, s, Install(t, s, vm, debDir(s)))
			if !t.Run("L1 login", func(t *testing.T) { gateL1(t, w) }) {
				t.FailNow()
			}
			t.Run("P3 effective profile", func(t *testing.T) { gateP3(t, w) })
			t.Run("L2 identity gate", func(t *testing.T) { gateL2(t, w) })
			t.Run("L3 login suspension", func(t *testing.T) { gateL3(t, w) })
			t.Run("L4 fail safe", func(t *testing.T) { gateL4(t, w) })
			t.Run("L5 PAM order", func(t *testing.T) { gateL5(t, w) })
			t.Run("P4 sudoers hygiene", func(t *testing.T) { gateP4(t, w) })
		})
	}
}

// requireBreakGlass checks the login settings of acme that keep the test VMs administrable: the local admin paddock
// is a break-glass account and its sudoers file 90-paddock is allowed (make dev-seed). Without them the agent would
// take sudo away from the account the tests use.
func requireBreakGlass(t *testing.T, s *Stack) {
	t.Helper()
	var set struct {
		BreakGlass []string `json:"break_glass_accounts"`
		Allowlist  []string `json:"sudoers_d_allowlist"`
		Action     string   `json:"user_lock_session_action"`
		Hello      bool     `json:"hello_enabled"`
	}
	if err := json.Unmarshal(s.Call(http.MethodGet, "/api/v1/settings/login", nil, http.StatusOK).Body, &set); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(set.BreakGlass, "paddock") || !slices.Contains(set.Allowlist, "90-paddock") || !slices.Contains(set.Allowlist, "README") ||
		set.Action != "lock_screen" || !set.Hello {
		t.Fatalf("acme login settings %+v: want break-glass paddock, allow list README and 90-paddock, lock_screen and Hello (run make dev-seed)", set)
	}
}

func randomDigits(t *testing.T, n int) string {
	t.Helper()
	var b strings.Builder
	for range n {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(d.String())
	}
	return b.String()
}

// newDirectoryUser creates an Authentik user in the organization's root group (as an upstream source would) and
// deletes it when the test ends.
func (w *identityWorld) newDirectoryUser(t *testing.T, prefix, slug string) *directoryUser {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	u := &directoryUser{name: prefix + "-" + w.deviceRun + "@" + slug + ".test", password: hex.EncodeToString(pw), pin: randomDigits(t, 8), totp: &portal.TOTP{}}
	pk, err := w.ak.CreateUser(ctx, u.name, u.password, portal.RootGroup(slug))
	if pk != 0 {
		w.s.t.Cleanup(func() { _ = w.ak.DeleteUser(context.Background(), pk) })
	}
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// syncedID waits until the identity sync lists u as a synced user of acme and returns its ID.
func (w *identityWorld) syncedID(t *testing.T, u *directoryUser) string {
	t.Helper()
	Until(t, "user "+u.name+" synced", 4*time.Minute, 5*time.Second, nil, func() bool {
		res := w.s.Call(http.MethodGet, "/api/v1/users?"+url.Values{"q": {u.name}, "source": {"synced"}}.Encode(), nil, http.StatusOK)
		var page struct {
			Items []struct {
				ID       string `json:"id"`
				Username string `json:"username"`
			} `json:"items"`
		}
		_ = json.Unmarshal(res.Body, &page)
		for _, it := range page.Items {
			if it.Username == u.name {
				u.id = it.ID
				return true
			}
		}
		return false
	})
	return u.id
}

func newIdentityWorld(t *testing.T, s *Stack, d *Device) *identityWorld {
	t.Helper()
	ak, err := portal.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	w := &identityWorld{Device: d, ak: ak, deviceRun: d.run}
	w.adminPassword = adminPassword(t, d.VM)
	w.dave, w.fred, w.nina, w.erin = w.newDirectoryUser(t, "dave", "acme"), w.newDirectoryUser(t, "fred", "acme"),
		w.newDirectoryUser(t, "nina", "acme"), w.newDirectoryUser(t, "erin", "acme")
	w.gus = w.newDirectoryUser(t, "gus", "globex")
	for _, u := range []*directoryUser{w.dave, w.fred, w.nina, w.erin} {
		w.syncedID(t, u)
	}
	w.assignLogins(t, w.dave, w.fred, w.nina)

	// Profiles scoped to this run's device group, so no other device and no other test sees them.
	w.restrictedCommands = []string{"/usr/bin/journalctl -u systest.service", "/usr/bin/systemctl restart systest.service"}
	w.restrictedID = s.ID(s.Call(http.MethodPost, "/api/v1/permission-profiles", map[string]any{
		"name": "systest restricted " + d.run, "class": "restricted", "commands": w.restrictedCommands,
	}, http.StatusCreated))
	s.DeleteOnCleanup("/api/v1/permission-profiles/" + w.restrictedID)
	w.fullID = s.ID(s.Call(http.MethodPost, "/api/v1/permission-profiles", map[string]any{
		"name": "systest full " + d.run, "class": "full",
	}, http.StatusCreated))
	s.DeleteOnCleanup("/api/v1/permission-profiles/" + w.fullID)
	for _, a := range []struct{ profile, user string }{{w.restrictedID, w.dave.id}, {w.fullID, w.fred.id}} {
		id := s.ID(s.Call(http.MethodPost, "/api/v1/profile-assignments", map[string]any{
			"profile_id": a.profile, "subject_type": "user", "subject_id": a.user, "device_group_id": d.Group,
		}, http.StatusCreated))
		s.DeleteOnCleanup("/api/v1/profile-assignments/" + id)
	}

	// The agent installs Himmelblau from its bundle and configures the device's allow list.
	allow := "paddock.acme.d." + d.ID
	Until(t, "Himmelblau installed and configured", 15*time.Minute, 10*time.Second, d.Checkin, func() bool {
		out, _ := d.SSH(context.Background(), nil, "dpkg-query -W -f='${Version}' himmelblau 2>/dev/null; echo; grep -h '^pam_allow_groups' /etc/himmelblau/himmelblau.conf 2>/dev/null; systemctl is-active himmelblaud")
		lines := strings.Split(strings.TrimSpace(out), "\n")
		return len(lines) == 3 && strings.HasPrefix(lines[0], "4.0.4-") && lines[1] == "pam_allow_groups = "+allow && lines[2] == "active"
	})
	d.WaitEvent(t, "device.login_applied", 5*time.Minute, func(p map[string]any) bool {
		changed, _ := p["changed"].([]any)
		return slices.Contains(changed, any("package"))
	})
	t.Logf("%s: Himmelblau %s, allow list %s", d.Name, d.Must("dpkg-query -W -f='${Version}' himmelblau"), allow)
	// pamtester drives the PAM stacks of the checks (PoC M1); it is not part of the desktop installation.
	d.Must("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=600 pamtester >/dev/null")
	w.neverIdle(t)
	return w
}

// idleSettings keep the greeter from blanking (a key press to wake it moves GDM's focus) and sessions from locking
// on their own, so only Paddock locks them. The lock settings themselves stay as installed.
const idleSettings = "[org/gnome/desktop/session]\nidle-delay=uint32 0\n\n[org/gnome/settings-daemon/plugins/power]\n" +
	"sleep-inactive-ac-type='nothing'\nsleep-inactive-battery-type='nothing'\n"

// neverIdle writes idleSettings into the dconf databases of the greeter (gdm) and of the user sessions (local) and
// restarts GDM before anyone logged in at the console.
func (w *identityWorld) neverIdle(t *testing.T) {
	t.Helper()
	w.MustIn([]byte(idleSettings), "sudo tee /etc/dconf/db/gdm.d/90-systest /etc/dconf/db/local.d/90-systest >/dev/null && sudo dconf update")
	w.Must("sudo systemctl restart gdm")
	Until(t, "GDM greeter", 2*time.Minute, 3*time.Second, nil, func() bool {
		for _, s := range w.Sessions() {
			if s.Class == "greeter" && s.Seat == "seat0" && s.State != "closing" {
				return true
			}
		}
		return false
	})
	time.Sleep(15 * time.Second) // the greeter needs a moment after its session appears
}

// adminPassword is the password of the local admin paddock (test/vms/virtualbox/.secrets/credentials.env).
func adminPassword(t *testing.T, vm *VM) string {
	t.Helper()
	data, err := os.ReadFile(vm.dir + "/.secrets/credentials.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "PADDOCK_PASSWORD="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	t.Fatal("PADDOCK_PASSWORD missing in credentials.env")
	return ""
}

// approver approves device codes as u (password + TOTP through the Authentik flow executor).
func approver(t *testing.T, u *directoryUser) func(code string) error {
	return func(code string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		stages, err := portal.ApproveDeviceCode(ctx, code, u.name, u.password, u.totp)
		t.Logf("approval of %s as %s: %v %v", code, u.name, stages, err)
		return err
	}
}

// pamLogin runs the gdm-password PAM stack for u (authenticate and account management) and returns pamtester's exit
// code; the transcript is logged.
func (w *identityWorld) pamLogin(t *testing.T, u *directoryUser, approve bool, timeout time.Duration) int {
	t.Helper()
	o := pamOpts{pin: u.pin, timeout: timeout}
	if approve {
		o.approve = approver(t, u)
	}
	exit, transcript := w.PAM(t, "gdm-password", u.name, []string{"authenticate", "acct_mgmt"}, o)
	t.Logf("pamtester %s exit %d:\n%s", u.name, exit, transcript)
	return exit
}

// localLogin runs the gdm-password PAM stack (with session) for the break-glass account with its password.
func (w *identityWorld) localLogin(t *testing.T) int {
	t.Helper()
	exit, transcript := w.PAM(t, "gdm-password", "paddock", []string{"authenticate", "acct_mgmt", "open_session", "close_session"},
		pamOpts{password: w.adminPassword, timeout: time.Minute})
	if exit != 0 {
		t.Logf("pamtester paddock exit %d:\n%s", exit, transcript)
	}
	return exit
}

// waitHimmelblau waits until the restarted himmelblaud accepts PAM requests again (its socket exists).
func (w *identityWorld) waitHimmelblau(t *testing.T) {
	t.Helper()
	Until(t, "himmelblaud ready", time.Minute, 2*time.Second, nil, func() bool {
		out, _ := w.SSH(context.Background(), nil, "systemctl is-active himmelblaud && test -S /run/himmelblaud/socket && echo ready")
		return strings.HasSuffix(strings.TrimSpace(out), "ready")
	})
	time.Sleep(3 * time.Second)
}

// toggleLink cuts the network for a moment: the agent checks in when the link comes back (plan M2b decision 8).
func (w *identityWorld) toggleLink(t *testing.T) {
	t.Helper()
	w.SetLink(false)
	time.Sleep(5 * time.Second)
	w.SetLink(true)
	Until(t, "SSH after the link toggle", 2*time.Minute, 2*time.Second, nil, func() bool {
		_, err := w.SSH(context.Background(), nil, "true")
		return err == nil
	})
}

// gdmLogin logs u in at the GDM greeter: "Not listed?" (after listed users), the user name, the device code approved
// on a second device, and the Hello PIN (enrolled with newPIN on the first login). It waits for the user's session on
// seat0.
func (w *identityWorld) gdmLogin(t *testing.T, u *directoryUser, listed int, newPIN bool) Session {
	t.Helper()
	after := lastDeviceTokenID(t)
	w.Shot(t, "01-greeter")
	for range listed {
		w.Key(keyTab...)
		time.Sleep(time.Second)
	}
	w.Key(keyEnter...)
	time.Sleep(2 * time.Second)
	w.Type(u.name)
	code, _ := pendingUserCode(t, "acme", after)
	time.Sleep(3 * time.Second)
	w.Shot(t, "02-device-code")
	if err := approver(t, u)(code); err != nil {
		t.Fatalf("approval at the greeter: %v", err)
	}
	time.Sleep(10 * time.Second) // Himmelblau polls every 5 s
	w.Shot(t, "03-after-approval")
	if newPIN {
		w.Type(u.pin)
		time.Sleep(6 * time.Second) // the confirmation field appears with a delay (PoC M1)
		w.Shot(t, "04-confirm-pin")
		w.Type(u.pin)
	}
	var session Session
	Until(t, u.name+" session on seat0", 3*time.Minute, 3*time.Second, nil, func() bool {
		for _, s := range w.UserSessions(u.name) {
			if s.Seat == "seat0" {
				session = s
				return true
			}
		}
		return false
	})
	time.Sleep(10 * time.Second)
	w.Shot(t, "05-session")
	return session
}

// gateL1: the agent installed Himmelblau from the bundle; the assigned user logs in at GDM with the device code
// (password + TOTP at Authentik) and enrolls a Hello PIN; a globex user and an unassigned user are refused; the
// login reaches device_user_seen.
func gateL1(t *testing.T, w *identityWorld) {
	session := w.gdmLogin(t, w.dave, 1, true)
	t.Logf("%s logged in at GDM: session %+v", w.dave.name, session)
	// The fixed idmap_range keeps directory UIDs within the 9 digits sudo-rs handles.
	if uid, err := strconv.Atoi(w.Must("id -u " + w.dave.name)); err != nil || uid < 200000 || uid > 999999999 {
		t.Errorf("UID of %s: %d %v, want 200000–999999999", w.dave.name, uid, err)
	}
	if session.Type != "wayland" && session.Type != "x11" {
		t.Errorf("session type %s, want a graphical session", session.Type)
	}
	// The Hello PIN works (the second login is a PIN login).
	if exit := w.pamLogin(t, w.dave, false, time.Minute); exit != 0 {
		t.Errorf("PIN login of %s: exit %d", w.dave.name, exit)
	}
	// erin is in acme but not in the login assignment: Authentik approves, the device's allow list refuses.
	if exit := w.pamLogin(t, w.erin, true, 3*time.Minute); exit == 0 {
		t.Errorf("%s (not assigned) was admitted", w.erin.name)
	}
	// gus is a globex user: Authentik refuses the approval, the device code expires.
	if exit := w.pamLogin(t, w.gus, true, 3*time.Minute); exit == 0 {
		t.Errorf("%s (globex) was admitted", w.gus.name)
	}
	query := fmt.Sprintf("SELECT count(*) FROM device_user_seen WHERE device_id = '%s' AND username = '%s'", w.ID, w.dave.name)
	Until(t, "session.login in device_user_seen", 3*time.Minute, 5*time.Second, w.Checkin, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := paddockSQL(ctx, query)
		return err == nil && out == "1"
	})
	if n, _ := paddockSQL(context.Background(), fmt.Sprintf("SELECT count(*) FROM device_user_seen WHERE device_id = '%s' AND username IN ('%s', '%s')",
		w.ID, w.erin.name, w.gus.name)); n != "0" {
		t.Errorf("refused users recorded as seen: %s", n)
	}
}

// sudoList returns the commands `sudo -l -U user` lists for the user ("" for "not allowed").
func (w *identityWorld) sudoList(user string) []string {
	out, _ := w.SSH(context.Background(), nil, "sudo -l -U "+user)
	if strings.Contains(out, "is not allowed to run sudo") {
		return nil
	}
	_, rules, ok := strings.Cut(out, "may run the following commands")
	if !ok {
		w.t.Fatalf("sudo -l -U %s:\n%s", user, out)
	}
	var cmds []string
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "(root) "); ok {
			after = strings.TrimPrefix(after, "NOPASSWD: ")
			for _, c := range strings.Split(after, ", ") {
				cmds = append(cmds, strings.TrimSpace(c))
			}
		}
	}
	slices.Sort(cmds)
	return cmds
}

// gateP3: sudo -l on the device shows exactly the effective profile: restricted commands, full root, nothing for a
// user without profile or a local account with the same short name; a profile change arrives with one check-in.
func gateP3(t *testing.T, w *identityWorld) {
	Until(t, "sudoers of the assigned users", 5*time.Minute, 10*time.Second, w.Checkin, func() bool {
		return len(w.sudoList(w.dave.name)) > 0 && len(w.sudoList(w.fred.name)) > 0
	})
	if got := w.sudoList(w.dave.name); !slices.Equal(got, w.restrictedCommands) {
		t.Errorf("restricted %s: sudo -l lists %q, want exactly %q", w.dave.name, got, w.restrictedCommands)
	}
	if got := w.sudoList(w.fred.name); !slices.Equal(got, []string{"ALL"}) {
		t.Errorf("full %s: sudo -l lists %q, want (root) ALL", w.fred.name, got)
	}
	if got := w.sudoList(w.nina.name); got != nil {
		t.Errorf("%s without profile: sudo -l lists %q", w.nina.name, got)
	}
	// A local account with dave's short name gets nothing: the sudoers files name UIDs. useradd refuses the name
	// (Himmelblau resolves it), so the account is written to /etc/passwd, which NSS reads first, and removed again at
	// once: it would shadow the short name Himmelblau gives dave.
	w.Must("echo '" + w.dave.short() + ":x:59999:59999::/nonexistent:/usr/sbin/nologin' | sudo tee -a /etc/passwd >/dev/null")
	got := w.sudoList(w.dave.short())
	uid := w.Must("id -u " + w.dave.short())
	w.Must("sudo sed -i '/^" + w.dave.short() + ":/d' /etc/passwd")
	if uid != "59999" {
		t.Errorf("the local account was not in effect: id -u %s = %s", w.dave.short(), uid)
	}
	if got != nil {
		t.Errorf("local account %s: sudo -l lists %q", w.dave.short(), got)
	}
	t.Log(w.Must("sudo -l -U " + w.dave.name))

	changed := append(slices.Clone(w.restrictedCommands), "/usr/bin/uptime")
	w.s.Call(http.MethodPatch, "/api/v1/permission-profiles/"+w.restrictedID, map[string]any{"commands": changed}, http.StatusOK)
	start := time.Now()
	Until(t, "profile change on the device", 3*time.Minute, 5*time.Second, nil, func() bool {
		return slices.Equal(w.sudoList(w.dave.name), changed)
	})
	t.Logf("profile change on the device after %s (one check-in)", time.Since(start).Round(time.Second))
	w.restrictedCommands = changed
}

// gateL2 is the identity gate: a lock in Paddock refuses the next online login; within one check-in (link toggle) the
// user's GNOME session shows the lock screen and the real unlock with the PIN is refused; offline login with the cached
// PIN is refused; the unlock in Paddock restores the login (device code and a new PIN); user.lock_applied is audited.
func gateL2(t *testing.T, w *identityWorld) {
	sessions := w.UserSessions(w.dave.name)
	if len(sessions) == 0 {
		t.Fatalf("%s has no session (L1)", w.dave.name)
	}
	for _, s := range sessions {
		if s.LockedHint {
			t.Fatalf("session %s of %s is locked before the lock in Paddock", s.ID, w.dave.name)
		}
	}
	w.s.Call(http.MethodPost, "/api/v1/users/"+w.dave.id+"/lock", nil, http.StatusOK)
	lockedAt := time.Now()
	if exit := w.pamLogin(t, w.dave, true, 3*time.Minute); exit == 0 {
		t.Errorf("online login of the locked user %s succeeded", w.dave.name)
	}
	w.toggleLink(t)
	w.WaitEvent(t, "device.user_lock_applied", 3*time.Minute, func(p map[string]any) bool {
		locked, _ := p["sessions_locked"].(float64)
		return p["username"] == w.dave.name && locked >= 1
	})
	t.Logf("lock applied on the device %s after the lock", time.Since(lockedAt).Round(time.Second))
	var seat Session
	Until(t, "lock screen", time.Minute, 2*time.Second, nil, func() bool {
		for _, s := range w.UserSessions(w.dave.name) {
			if s.Seat == "seat0" && s.LockedHint {
				seat = s
				return true
			}
		}
		return false
	})
	w.Shot(t, "10-locked")
	if !strings.Contains(w.Must("cat /etc/paddock/login-deny"), w.dave.name) {
		t.Errorf("deny list lacks %s", w.dave.name)
	}

	// The real lock screen: Space raises the prompt, the PIN is typed (PoC M1 C5b/C5c).
	w.Key(keySpace...)
	time.Sleep(3 * time.Second)
	w.Shot(t, "11-unlock-prompt")
	w.Type(w.dave.pin)
	time.Sleep(8 * time.Second)
	w.Shot(t, "12-after-unlock-attempt")
	if hint := w.Must("loginctl show-session " + seat.ID + " -p LockedHint --value"); hint != "yes" {
		t.Errorf("the locked user unlocked the screen with the PIN: LockedHint=%s", hint)
	}

	// Offline login with the cached PIN: the network is cut, so the check runs inside the guest (PoC M1 C5a).
	script := fmt.Sprintf(`#!/bin/bash
iface=$(ip -o route get 10.0.2.2 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
for _ in $(seq 1 60); do [ "$(cat /sys/class/net/$iface/carrier)" = 0 ] && break; sleep 1; done
timeout 5 bash -c '</dev/tcp/10.0.2.2/8443' && echo "authentik reachable" || echo "authentik unreachable"
cat /root/systest-secret | timeout 60 pamtester gdm-password %s authenticate acct_mgmt
echo "rc=$?"
`, w.dave.name)
	w.guestScript(script, w.dave.pin+"\n", "/root/systest-offline.log", 5*time.Second)
	w.SetLink(false)
	time.Sleep(90 * time.Second)
	w.SetLink(true)
	var offline string
	Until(t, "offline log", 2*time.Minute, 3*time.Second, nil, func() bool {
		out, err := w.SSH(context.Background(), nil, "sudo cat /root/systest-offline.log")
		offline = out
		return err == nil && strings.Contains(out, "rc=")
	})
	t.Logf("offline login:\n%s", offline)
	if !strings.Contains(offline, "authentik unreachable") || strings.Contains(offline, "rc=0") {
		t.Errorf("offline login of the locked user not refused (or not offline):\n%s", offline)
	}

	// Unlock in Paddock: the device drops the deny entry, and the user signs in with the device code and a new PIN.
	w.s.Call(http.MethodPost, "/api/v1/users/"+w.dave.id+"/unlock", nil, http.StatusOK)
	w.toggleLink(t)
	Until(t, "deny list without "+w.dave.name, 3*time.Minute, 5*time.Second, nil, func() bool {
		out, _ := w.SSH(context.Background(), nil, "cat /etc/paddock/login-deny 2>/dev/null || true")
		return !strings.Contains(out, w.dave.name)
	})
	w.dave.pin = randomDigits(t, 8)
	if exit := w.pamLogin(t, w.dave, true, 4*time.Minute); exit != 0 {
		t.Errorf("login of %s after the unlock: exit %d", w.dave.name, exit)
	}

	// The lock also reaches a device the user is no longer assigned to, through the logins the device reported
	// (device_user_seen, M3a decision 10).
	w.assignLogins(t, w.fred, w.nina)
	relocked := time.Now().Add(-10 * time.Second)
	w.s.Call(http.MethodPost, "/api/v1/users/"+w.dave.id+"/lock", nil, http.StatusOK)
	w.toggleLink(t)
	w.WaitEvent(t, "device.user_lock_applied", 3*time.Minute, func(p map[string]any) bool {
		at, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(p["occurred_at"]))
		return p["username"] == w.dave.name && at.After(relocked)
	})
	if !strings.Contains(w.Must("cat /etc/paddock/login-deny"), w.dave.name) {
		t.Errorf("deny list lacks %s, who is seen on the device but no longer assigned", w.dave.name)
	}
	w.s.Call(http.MethodPost, "/api/v1/users/"+w.dave.id+"/unlock", nil, http.StatusOK)
	w.assignLogins(t, w.dave, w.fred, w.nina)
	w.toggleLink(t)
	Until(t, "deny list without "+w.dave.name+" again", 3*time.Minute, 5*time.Second, nil, func() bool {
		out, _ := w.SSH(context.Background(), nil, "cat /etc/paddock/login-deny 2>/dev/null || true")
		return !strings.Contains(out, w.dave.name)
	})
}

// assignLogins sets the device's login assignment to users.
func (w *identityWorld) assignLogins(t *testing.T, users ...*directoryUser) {
	t.Helper()
	ids := []string{}
	for _, u := range users {
		ids = append(ids, u.id)
	}
	w.s.Call(http.MethodPut, "/api/v1/devices/"+w.ID+"/login-assignment", map[string]any{"users": ids, "groups": []string{}}, http.StatusOK)
}

// gateL3: suspending logins ends the directory sessions within one check-in and refuses directory logins; the
// break-glass account logs in at the console and over SSH; resuming restores the logins.
func gateL3(t *testing.T, w *identityWorld) {
	if len(w.UserSessions(w.dave.name)) == 0 {
		t.Fatalf("%s has no session to end", w.dave.name)
	}
	w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/suspend-logins", nil, http.StatusOK)
	w.toggleLink(t)
	ended := w.WaitEvent(t, "device.logins_suspension_applied", 3*time.Minute, nil)
	t.Logf("logins.suspension_applied %v", ended)
	Until(t, "directory sessions ended", time.Minute, 2*time.Second, nil, func() bool { return len(w.UserSessions(w.dave.name)) == 0 })
	if conf := w.Must("grep '^pam_allow_groups' /etc/himmelblau/himmelblau.conf"); conf != "pam_allow_groups =" {
		t.Errorf("allow list while suspended: %q", conf)
	}
	if exit := w.pamLogin(t, w.dave, false, 2*time.Minute); exit == 0 {
		t.Errorf("%s logged in while logins are suspended", w.dave.name)
	}
	// Break-glass at the console: GDM lists paddock and dave; "Not listed?" and the password.
	time.Sleep(5 * time.Second)
	w.Shot(t, "20-greeter-suspended")
	for range 2 {
		w.Key(keyTab...)
		time.Sleep(time.Second)
	}
	w.Key(keyEnter...)
	time.Sleep(2 * time.Second)
	w.Type("paddock")
	time.Sleep(3 * time.Second)
	w.Type(w.adminPassword)
	var console Session
	Until(t, "paddock session on seat0", 2*time.Minute, 3*time.Second, nil, func() bool {
		for _, s := range w.UserSessions("paddock") {
			if s.Seat == "seat0" {
				console = s
				return true
			}
		}
		return false
	})
	time.Sleep(5 * time.Second)
	w.Shot(t, "21-break-glass-console")
	w.Must("sudo loginctl terminate-session " + console.ID)
	if out := w.Must("id -un && sudo -n true && echo sudo-ok"); out != "paddock\nsudo-ok" {
		t.Errorf("break-glass SSH: %q", out)
	}

	w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/resume-logins", nil, http.StatusOK)
	w.toggleLink(t)
	Until(t, "allow list restored", 3*time.Minute, 5*time.Second, nil, func() bool {
		out, _ := w.SSH(context.Background(), nil, "grep '^pam_allow_groups' /etc/himmelblau/himmelblau.conf")
		return strings.TrimSpace(out) == "pam_allow_groups = paddock.acme.d."+w.ID
	})
	w.waitHimmelblau(t)
	if exit := w.pamLogin(t, w.dave, true, 3*time.Minute); exit != 0 {
		t.Errorf("login of %s after the resume: exit %d", w.dave.name, exit)
	}
}

// gateL4: without the deny file (deleted locally) logins work until the agent restores it at the next drift pass; with
// the Himmelblau daemons stopped the local accounts still log in.
func gateL4(t *testing.T, w *identityWorld) {
	w.s.Call(http.MethodPost, "/api/v1/users/"+w.nina.id+"/lock", nil, http.StatusOK)
	t.Cleanup(func() { w.s.cleanupCall(http.MethodPost, "/api/v1/users/"+w.nina.id+"/unlock", http.StatusOK) })
	w.toggleLink(t)
	Until(t, "deny list with "+w.nina.name, 3*time.Minute, 5*time.Second, nil, func() bool {
		out, _ := w.SSH(context.Background(), nil, "cat /etc/paddock/login-deny 2>/dev/null || true")
		return strings.Contains(out, w.nina.name)
	})
	want := w.Must("sha256sum /etc/paddock/login-deny")
	w.Must("sudo rm /etc/paddock/login-deny")
	removed := time.Now()
	if exit := w.localLogin(t); exit != 0 {
		t.Errorf("break-glass login without the deny file: exit %d", exit)
	}
	if exit := w.pamLogin(t, w.dave, false, time.Minute); exit != 0 {
		t.Errorf("login of %s without the deny file: exit %d", w.dave.name, exit)
	}
	Until(t, "deny file restored by the drift pass", 2*time.Minute, 3*time.Second, nil, func() bool {
		out, _ := w.SSH(context.Background(), nil, "sha256sum /etc/paddock/login-deny 2>/dev/null")
		return strings.TrimSpace(out) == want
	})
	t.Logf("deny file restored %s after the deletion", time.Since(removed).Round(time.Second))
	w.WaitEvent(t, "device.config_drift_corrected", 3*time.Minute, func(p map[string]any) bool {
		ids, _ := p["resource_ids"].([]any)
		return slices.Contains(ids, any("login"))
	})

	w.Must("sudo systemctl stop himmelblaud-tasks himmelblaud")
	if exit := w.localLogin(t); exit != 0 {
		t.Errorf("break-glass login with Himmelblau stopped: exit %d", exit)
	}
	if out := w.Must("id -un"); out != "paddock" {
		t.Errorf("SSH with Himmelblau stopped: %q", out)
	}
	w.Must("sudo systemctl start himmelblaud himmelblaud-tasks")
	w.waitHimmelblau(t)
}

// gateL5: common-auth runs the deny list before pam_himmelblau; removing the profile is reported, and the package
// reconfiguration restores it (the agent never edits PAM files).
func gateL5(t *testing.T, w *identityWorld) {
	auth := w.Must("grep -n -E 'pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed|pam_himmelblau' /etc/pam.d/common-auth")
	lines := strings.Split(auth, "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "requisite") || !strings.Contains(lines[0], "pam_listfile") || !strings.Contains(lines[1], "pam_himmelblau") {
		t.Fatalf("common-auth order:\n%s", auth)
	}
	t.Logf("common-auth:\n%s", w.Must("grep -v '^#' /etc/pam.d/common-auth | grep -v '^$'"))
	w.Must("sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --remove paddock-deny 2>/dev/null; ! grep -q pam_listfile /etc/pam.d/common-auth")
	w.WaitEvent(t, "device.tamper_protected_file_changed", 4*time.Minute, func(p map[string]any) bool { return p["file"] == "/etc/pam.d/common-auth" })
	w.WaitEvent(t, "device.login_apply_failed", 2*time.Minute, func(p map[string]any) bool { return p["stage"] == "pam" })
	w.Must("sudo dpkg-reconfigure paddock-agent >/dev/null 2>&1")
	if out := w.Must("grep -c 'pam_listfile.so item=user sense=deny' /etc/pam.d/common-auth /etc/pam.d/common-account"); out != "/etc/pam.d/common-auth:1\n/etc/pam.d/common-account:1" {
		t.Errorf("after dpkg-reconfigure: %q", out)
	}
}

// gateP4: a foreign sudoers file is quarantined and a directory user added to sudo is removed, both reported; the
// break-glass account keeps sudo and its file; a broken entry (a test-only bundle) never breaks sudo.
func gateP4(t *testing.T, w *identityWorld) {
	before := w.Must("sudo sha256sum /etc/sudoers.d/90-paddock")
	w.Must("echo 'ALL ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/evil >/dev/null && sudo chmod 0440 /etc/sudoers.d/evil")
	w.Must("sudo gpasswd -a " + w.dave.name + " sudo >/dev/null")
	w.WaitEvent(t, "device.tamper_sudoers_d_file", 3*time.Minute, func(p map[string]any) bool { return p["file"] == "evil" })
	w.WaitEvent(t, "device.tamper_sudo_group_member", 3*time.Minute, func(p map[string]any) bool {
		return p["username"] == w.dave.name && p["group"] == "sudo" && p["removed"] == true
	})
	if out := w.Must("test -e /etc/sudoers.d/evil && echo present || echo gone; sudo ls /var/lib/paddock/quarantine/sudoers.d/ | grep -c '^evil\\.'"); out != "gone\n1" {
		t.Errorf("quarantine: %q", out)
	}
	if members := w.Must("getent group sudo | cut -d: -f4"); members != "paddock" {
		t.Errorf("sudo members %q, want only the break-glass account", members)
	}
	if after := w.Must("sudo sha256sum /etc/sudoers.d/90-paddock"); after != before {
		t.Errorf("90-paddock changed: %s → %s", before, after)
	}

	// A broken entry that only a test-only bundle can carry (the compiler checks every entry with visudo before
	// signing): dave's command list gets a command visudo rejects.
	daveFile := "/etc/sudoers.d/" + sudoers.FileName(w.dave.name)
	daveBefore := w.Must("sudo sha256sum " + daveFile)
	restore := w.forgeBundle(t, func(s *bundle.SudoSpec) {
		for i := range s.Entries {
			if s.Entries[i].Username == w.dave.name {
				// A leading ^ starts a sudoers regular expression; without the closing $ visudo refuses it.
				s.Entries[i].Commands = []string{"/usr/bin/systemctl ^"}
			}
		}
	})
	defer restore()
	w.WaitEvent(t, "device.sudo_apply_failed", 4*time.Minute, func(p map[string]any) bool { return p["username"] == w.dave.name })
	if out := w.Must("sudo visudo -c >/dev/null && echo visudo-ok; sudo -n true && echo sudo-ok"); out != "visudo-ok\nsudo-ok" {
		t.Errorf("after the broken entry: %q", out)
	}
	if after := w.Must("sudo sha256sum " + daveFile); after != daveBefore {
		t.Errorf("the broken entry replaced %s", daveFile)
	}
}

// forgeBundle replaces the device's cached bundle by a copy with a changed sudo resource, signed with a test key
// that is added to the device's trust anchor, and restarts the agent, whose drift pass then applies it. The returned
// function restores the original bundle and trust anchor.
func (w *identityWorld) forgeBundle(t *testing.T, change func(*bundle.SudoSpec)) func() {
	t.Helper()
	const cache, trust = "/var/lib/paddock/state/bundle.dsse", "/etc/paddock/trust.json"
	origBundle, origTrust := w.Must("sudo cat "+cache), w.Must("sudo cat "+trust)
	_, payload, err := dsse.Decode([]byte(origBundle))
	if err != nil {
		t.Fatalf("cached bundle: %v", err)
	}
	var b bundle.Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		t.Fatal(err)
	}
	found := false
	for i, r := range b.Resources {
		if r.Type != bundle.TypeSudo {
			continue
		}
		var spec bundle.SudoSpec
		if err := json.Unmarshal(r.Spec, &spec); err != nil {
			t.Fatal(err)
		}
		change(&spec)
		if b.Resources[i], err = bundle.SudoResource(spec); err != nil {
			t.Fatal(err)
		}
		found = true
	}
	if !found {
		t.Fatal("the cached bundle has no sudo resource")
	}
	forged, err := bundle.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := dsse.New(bundle.PayloadType, forged, dsse.SignEd25519(priv, "systest:forged", bundle.PayloadType, forged)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	var tf struct {
		BundleKeys []protocol.BundleKey `json:"bundle_keys"`
	}
	if err := json.Unmarshal([]byte(origTrust), &tf); err != nil {
		t.Fatal(err)
	}
	tf.BundleKeys = append(tf.BundleKeys, protocol.BundleKey{KeyID: "systest:forged", PublicKey: base64.StdEncoding.EncodeToString(pub)})
	trustJSON, _ := json.Marshal(tf)
	w.Must("sudo systemctl stop paddock-supervisor")
	w.MustIn(signed, "sudo install -m 0600 /dev/stdin "+cache)
	w.MustIn(trustJSON, "sudo install -m 0644 /dev/stdin "+trust)
	w.Must("sudo systemctl start paddock-supervisor")
	return func() {
		w.Must("sudo systemctl stop paddock-supervisor")
		w.MustIn([]byte(origBundle), "sudo install -m 0600 /dev/stdin "+cache)
		w.MustIn([]byte(origTrust), "sudo install -m 0644 /dev/stdin "+trust)
		w.Must("sudo systemctl start paddock-supervisor")
	}
}
