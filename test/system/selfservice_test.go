package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// selfServiceGate is the per-VM state the self-service gates share. keep is the VM's test: the server objects live
// as long as it, not as long as the subtest that uses them first.
type selfServiceGate struct {
	keep                *testing.T
	repo                gateRepo
	source, fpSource    string
	slug                string // the gate source's slug (SV12)
	fpSlug              string
	owner, other, local *ssUser
	anchor, offered     string // catalog entries: gateAnchor (required), ssOffered (available to everyone)
	private, slow, hand string // ssPrivate (available to owner), ssSlow (available), gateApp (available, installed by hand)
	fpApp, fpUserApp    string // ssFlatpakApp (system scope), ssFlatpakUserApp (user scope)
	sysUser             string // ssSysUser (required in SV10)
	// tamperSeen are the device's device.tamper_service_stopped events before SV5: none may follow for himmelblaud
	// from the agent's own holds (SV11).
	tamperSeen  []string
	selfService []string
}

// TestSelfServiceGates runs the device gates of plan M13b §9 on the VMs in parallel, each from a fresh
// base-installed with the signed APT repository of the software gates, the self-service packages and a signed Flatpak
// repository built on the VM (no Flathub), two directory users as Himmelblau maps them (owner and other, both owners
// of the device) and the local account paddock. The gates build on each other and run in this order:
//
//   - SV1 the socket: mode 0666, the caller named by its peer credentials;
//   - SV2 every account lists only its own audience, plus the managed applications;
//   - SV4 policy-managed and hand-installed applications cannot be removed (403 required_by_policy);
//   - SV5 the Flatpak remote with its pinned key, a required system-scope application, a planted paddock-rogue remote
//     removed and reported;
//   - SV7 a user-scope application targeted at one user (A10-11) stays pending without a session and is never
//     installed system wide (Q14); with the user's automatic graphical login it lands in that user's installation;
//   - SV3 the owner installs an available APT package: succeeded, the event on the server, the notification in the
//     owner's session; another user cannot read the operation; the owner removes it again;
//   - SV6 the agent killed while an install runs with himmelblaud held: the safety timer starts himmelblaud without
//     the agent, the agent reports the hold as recovered, the operation failed/interrupted, the package consistent;
//   - SV8 a catalog icon reaches the socket; an entry without one has none (the app's glyph);
//   - SV9 forbidding flatpak drops every Flatpak application (A10-9, flatpak_forbidden) and removes flatpak;
//   - SV10 a required plain package whose postinst creates a system account installs under Himmelblau (PDK-983);
//   - SV12 the regular updates run upgrades a package to a version whose new dependency creates a system account,
//     under one hold that the run reports through its report file (PDK-988, plan M5a N6);
//   - SV11 none of the agent's holds was reported as tampering, and a stop of himmelblaud by someone else is.
//
// SV5, SV6, SV10 and SV12 run with himmelblaud active, whose NSS module answers for every unknown name (PDK-983): the agent
// holds it stopped around its package transactions (decisions §45). SV12 runs before SV11 so that SV11's check covers
// the updates run's hold as well.
//
// SV7 runs before SV3 because SV3's notification needs the session that SV7 starts only after its check without one.
// The desktop app (PDK-802) and user names in the status (PDK-805) are not part of these gates.
func TestSelfServiceGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Gate(t, "selfservice")
		vm.Fresh()
		// The accounts exist before enrollment, while no Himmelblau answers their names (PDK-983).
		suffix := unique()
		owner := ssDirectoryUser(t, t, s, vm, suffix, "ss-owner", ssOwnerUID)
		other := ssDirectoryUser(t, t, s, vm, suffix, "ss-other", ssOtherUID)
		d := Install(t, s, vm, debDir(s))
		// SV11 waits for the login reconciler's drift pass.
		d.SetDriftInterval()
		g := &selfServiceGate{keep: t, repo: d.setupGateRepo(), owner: owner, other: other}
		d.MustRootIn([]byte(ssRepoScript), "bash -s")
		g.source, g.slug = d.softwareSource(g.repo)
		g.fpSource, g.fpSlug = d.ssFlatpakSource(t, t, g.repo)
		uid, err := strconv.Atoi(d.MustRoot("id -u paddock"))
		if err != nil {
			t.Fatalf("UID of paddock: %v", err)
		}
		g.local = &ssUser{name: "paddock", uid: uid}
		d.ssSetOwners(t, g.owner, g.other)
		g.anchor = d.catalogEntry(g.source, gateAnchor)
		g.offered = d.catalogEntry(g.source, ssOffered)
		g.private = d.catalogEntry(g.source, ssPrivate)
		g.slow = d.catalogEntry(g.source, ssSlow)
		g.hand = d.catalogEntry(g.source, gateApp)
		g.sysUser = d.catalogEntry(g.source, ssSysUser)
		g.fpApp = d.ssEntry(t, t, "flatpak app", g.fpSource, map[string]any{"flatpak_ref": ssFlatpakApp, "scope": "system"})
		g.fpUserApp = d.ssEntry(t, t, "flatpak user app", g.fpSource, map[string]any{"flatpak_ref": ssFlatpakUserApp, "scope": "user"})
		for _, gate := range []struct {
			name string
			fn   func(*testing.T, *Device, *selfServiceGate)
		}{
			{"SV1 socket", gateSV1}, {"SV2 audience", gateSV2}, {"SV4 managed applications", gateSV4},
			{"SV5 flatpak remote", gateSV5}, {"SV7 user scope", gateSV7}, {"SV3 install", gateSV3},
			{"SV6 interrupted", gateSV6}, {"SV8 icon", gateSV8}, {"SV9 forbid flatpak", gateSV9},
			{"SV10 system account", gateSV10}, {"SV12 updates run", gateSV12}, {"SV11 foreign stop", gateSV11},
		} {
			if !t.Run(gate.name, func(t *testing.T) { d.Bind(t); gate.fn(t, d, g) }) {
				t.FailNow()
			}
		}
	})
}

// gateSV1: the socket is a root-owned socket with mode 0666 in a 0755 directory, it answers once a bundle is applied,
// and each caller is named by its peer credentials: the directory users by their UPN, the local account and root by
// their names, without directory.
func gateSV1(t *testing.T, d *Device, g *selfServiceGate) {
	Until(t, d.Name+": self-service status", 3*time.Minute, 5*time.Second, nil, func() bool {
		r, err := d.ssTry(g.local, http.MethodGet, "/v1/status")
		if err != nil {
			t.Logf("%s: %v", d.Name, err)
		}
		return err == nil && r.Status == http.StatusOK
	})
	if got := d.MustRoot("stat -c '%a %U:%G %F' " + ssSocket); got != "666 root:root socket" {
		t.Errorf("%s: %s, want 666 root:root socket", ssSocket, got)
	}
	if got := d.MustRoot("stat -c '%a %U:%G' /run/paddock"); got != "755 root:root" {
		t.Errorf("/run/paddock: %s, want 755 root:root", got)
	}
	for _, c := range []struct {
		u         *ssUser
		name      string
		directory bool
	}{{g.owner, g.owner.name, true}, {g.other, g.other.name, true}, {g.local, "paddock", false}, {nil, "root", false}} {
		r := d.ssCall(t, c.u, http.MethodGet, "/v1/status")
		var st ssStatus
		if r.Status != http.StatusOK || json.Unmarshal(r.Body, &st) != nil {
			t.Fatalf("GET /v1/status as %s: HTTP %d %s", ssName(c.u), r.Status, r.Body)
		}
		if st.User.Name != c.name || st.User.Directory != c.directory || st.Queue != 0 {
			t.Errorf("GET /v1/status as %s: %+v, want user %s directory %v and an empty queue", ssName(c.u), st, c.name, c.directory)
		}
	}
}

// gateSV2: with gateAnchor required, ssOffered, ssSlow and gateApp available to the device's group and ssPrivate
// available to the owner, the owner sees all five; the other owner, the local account and root see everything but
// ssPrivate, which they can neither read nor install (404, nothing about it is named).
func gateSV2(t *testing.T, d *Device, g *selfServiceGate) {
	k := g.keep
	d.ssAssign(t, k, g.anchor, "required", nil)
	for _, e := range []string{g.offered, g.slow, g.hand} {
		d.ssAssign(t, k, e, "available", nil)
	}
	d.ssAssign(t, k, g.private, "available", g.owner)
	all := []string{g.anchor, g.offered, g.slow, g.hand, g.private}
	apps := d.ssWaitApps(t, g.owner, "the owner's applications", func(apps map[string]ssApp) bool {
		return !slices.ContainsFunc(all, func(e string) bool { _, ok := apps[e]; return !ok })
	})
	if a := apps[g.private]; a.Name != ssPrivate || a.Kind != "apt" || a.Intent != "available" || a.Managed || !a.Installable {
		t.Errorf("the owner's %s: %+v", ssPrivate, a)
	}
	if a := apps[g.anchor]; a.Name != gateAnchor || a.Intent != "required" || !a.Managed || a.Installable || a.Removable {
		t.Errorf("the owner's %s: %+v", gateAnchor, a)
	}
	for _, u := range []*ssUser{g.other, g.local, nil} {
		apps := d.ssAppsOf(t, u)
		for _, e := range []string{g.anchor, g.offered, g.slow, g.hand} {
			if _, ok := apps[e]; !ok {
				t.Errorf("%s does not see entry %s: %+v", ssName(u), e, apps)
			}
		}
		if a, ok := apps[g.private]; ok {
			t.Errorf("%s sees the owner's %s: %+v", ssName(u), ssPrivate, a)
		}
		if len(apps) != 4 {
			t.Errorf("%s sees %d applications, want 4: %+v", ssName(u), len(apps), apps)
		}
		for _, req := range []struct{ method, path string }{
			{http.MethodGet, "/v1/apps/" + g.private}, {http.MethodPost, "/v1/apps/" + g.private + "/install"},
		} {
			if r := d.ssCall(t, u, req.method, req.path); r.Status != http.StatusNotFound || r.code() != "unknown_entry" ||
				bytes.Contains(r.Body, []byte(ssPrivate)) {
				t.Errorf("%s %s as %s: HTTP %d %s, want 404 unknown_entry", req.method, req.path, ssName(u), r.Status, r.Body)
			}
		}
	}
	waitVersion(t, d, gateAnchor, "1.0", 6*time.Minute, true)
}

// gateSV4: the required gateAnchor and gateApp, available but installed by hand, are read-only: removing either is
// 403 required_by_policy, as is installing them again; self-service never made them removable.
func gateSV4(t *testing.T, d *Device, g *selfServiceGate) {
	d.dpkgInstall(t, gateDeb)
	apps := d.ssWaitApps(t, g.owner, gateApp+" installed by hand", func(apps map[string]ssApp) bool {
		return apps[g.hand].State == "installed"
	})
	if a := apps[g.hand]; a.Removable || a.Installable || a.Managed {
		t.Errorf("the owner's %s installed by hand: %+v", gateApp, a)
	}
	for _, e := range []string{g.anchor, g.hand} {
		for _, action := range []string{"remove", "install"} {
			if r := d.ssCall(t, g.owner, http.MethodPost, "/v1/apps/"+e+"/"+action); r.Status != http.StatusForbidden || r.code() != "required_by_policy" {
				t.Errorf("POST %s of %s: HTTP %d %s, want 403 required_by_policy", action, e, r.Status, r.Body)
			}
		}
	}
	if v := d.installedVersion(gateAnchor); v != "1.0" {
		t.Errorf("%s at %q after the refused removal", gateAnchor, v)
	}
	if v := d.installedVersion(gateApp); v != "1.0" {
		t.Errorf("%s at %q after the refused removal", gateApp, v)
	}
}

// flatpakApps are the applications of the device's system installation.
func flatpakApps(d *Device) []string {
	return strings.Fields(d.MustRoot("flatpak list --system --app --columns=application 2>/dev/null || true"))
}

// flatpakRemotes are the system remotes of the device, name → URL.
func flatpakRemotes(d *Device) map[string]string {
	remotes := map[string]string{}
	for _, line := range strings.Split(d.MustRoot("flatpak remotes --system --show-disabled --columns=name,url 2>/dev/null || true"), "\n") {
		if f := strings.Fields(line); len(f) >= 2 {
			remotes[f[0]] = f[1]
		}
	}
	return remotes
}

// gateSV5: a required system-scope Flatpak application makes the agent install the runtime package flatpak (required
// in the health report, Q12) and brings the remote paddock-<slug>, which verifies signatures with exactly the source's
// key, and installs from it; a planted system remote paddock-rogue is removed within the drift interval with
// device.tamper_protected_file_changed.
func gateSV5(t *testing.T, d *Device, g *selfServiceGate) {
	if v := d.installedVersion("flatpak"); v != "" {
		t.Fatalf("flatpak at %q before the agent acted; the setup purges it", v)
	}
	g.tamperSeen = d.eventIDs("device.tamper_service_stopped")
	shields := d.requireSynthesized(t, "_flatpak")
	installed := d.eventIDs("device.software_installed")
	tamper := d.eventIDs("device.tamper_protected_file_changed")
	d.ssAssign(t, g.keep, g.fpApp, "required", nil)
	Until(t, d.Name+": "+ssFlatpakApp+" in the system installation", 10*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return slices.Contains(flatpakApps(d), ssFlatpakApp)
	})
	remote := "paddock-" + g.fpSlug
	if url := flatpakRemotes(d)[remote]; strings.TrimSuffix(url, "/") != strings.TrimSuffix(ssFlatpakURI, "/") {
		t.Errorf("remote %s at %q, want %s", remote, url, ssFlatpakURI)
	}
	if v := d.installedVersion("flatpak"); v == "" {
		t.Error("flatpak is not installed although the agent installed a Flatpak application")
	}
	// Read from the repository's config file: the ostree command line is a separate package that flatpak does not need.
	config := d.MustRoot("cat /var/lib/flatpak/repo/config")
	for _, key := range []string{"gpg-verify", "gpg-verify-summary"} {
		if v := iniValue(config, `remote "`+remote+`"`, key); v != "true" {
			t.Errorf("remote %s: %s = %q, want true", remote, key, v)
		}
	}
	keyring := d.MustRoot("h=$(mktemp -d); GNUPGHOME=$h gpg --show-keys --with-colons /var/lib/flatpak/repo/" + remote +
		".trustedkeys.gpg; s=$?; rm -rf \"$h\"; exit $s")
	if fps := primaryFingerprints(keyring); !slices.Equal(fps, []string{g.repo.Fingerprint}) {
		t.Errorf("trusted keys of remote %s: %v, want exactly %s", remote, fps, g.repo.Fingerprint)
	}
	if out := d.MustRoot("flatpak remote-info --system " + remote + " " + ssFlatpakApp + " 2>&1"); !strings.Contains(out, ssFlatpakApp) {
		t.Errorf("flatpak remote-info %s %s (signature verified with the pinned key):\n%s", remote, ssFlatpakApp, out)
	}
	softwareState(t, d, "flatpak:"+ssFlatpakApp, "installed", "", 5*time.Minute, nil)
	if it, ok, err := healthSoftwareItem(d.Health(), "flatpak"); err != nil || !ok || it.Intent != "required" || it.State != "installed" {
		t.Errorf("health item of the flatpak runtime package: %+v %v %v", it, ok, err)
	}
	d.requireSystemAccount(t, "_flatpak", shields)
	d.waitNewEvent(t, "device.software_installed", installed, 5*time.Minute, func(p map[string]any) bool {
		return p["package"] == "flatpak:"+ssFlatpakApp && p["catalog_entry_id"] == g.fpApp
	})
	if a := d.ssAppsOf(t, g.owner)[g.fpApp]; a.Kind != "flatpak" || a.Scope != "system" || !a.Managed || a.Removable {
		t.Errorf("the owner's %s: %+v", ssFlatpakApp, a)
	}

	d.Must("sudo flatpak remote-add --system --no-gpg-verify paddock-rogue " + ssFlatpakURI)
	Until(t, d.Name+": paddock-rogue removed", 4*time.Minute, 10*time.Second, nil, func() bool {
		_, rogue := flatpakRemotes(d)["paddock-rogue"]
		return !rogue
	})
	d.waitNewEvent(t, "device.tamper_protected_file_changed", tamper, 5*time.Minute, func(p map[string]any) bool {
		return p["file"] == "flatpak:remote/paddock-rogue"
	})
	if !slices.Contains(flatpakApps(d), ssFlatpakApp) {
		t.Errorf("%s gone after the rogue remote's removal", ssFlatpakApp)
	}
}

// userFlatpakApp reports whether the user's own installation holds app.
func userFlatpakApp(d *Device, u *ssUser, app string) bool {
	return d.MustRoot(`h=$(getent passwd `+strconv.Itoa(u.uid)+` | cut -d: -f6); test -d "$h/.local/share/flatpak/app/`+app+`" && echo yes || echo no`) == "yes"
}

// gateSV7: a user-scope application required for the owner alone (a user assignment, so the bundle lists the owner,
// A10-11) is pending/not_yet_applied while the owner has no session and is never put into the system installation
// instead (Q14), also not after two drift intervals; the other owner never sees it. Once the owner logs in
// graphically (GDM automatic login), it lands in the owner's own installation and nowhere else.
func gateSV7(t *testing.T, d *Device, g *selfServiceGate) {
	d.ssAssign(t, g.keep, g.fpUserApp, "required", g.owner)
	softwareState(t, d, "flatpak:"+ssFlatpakUserApp, "pending", "not_yet_applied", 8*time.Minute, d.Checkin)
	a := d.ssWaitApps(t, g.owner, "the owner's "+ssFlatpakUserApp, func(apps map[string]ssApp) bool {
		_, ok := apps[g.fpUserApp]
		return ok
	})[g.fpUserApp]
	if a.Scope != "user" || !a.Managed || a.Kind != "flatpak" {
		t.Errorf("the owner's %s: %+v", ssFlatpakUserApp, a)
	}
	if other, ok := d.ssAppsOf(t, g.other)[g.fpUserApp]; ok {
		t.Errorf("the other owner sees the owner's user-scope application: %+v", other)
	}
	time.Sleep(2 * driftInterval)
	softwareState(t, d, "flatpak:"+ssFlatpakUserApp, "pending", "not_yet_applied", time.Minute, nil)
	if slices.Contains(flatpakApps(d), ssFlatpakUserApp) || userFlatpakApp(d, g.owner, ssFlatpakUserApp) {
		t.Fatalf("%s installed without a session of %s", ssFlatpakUserApp, g.owner.name)
	}

	session := d.Autologin(t, g.owner.name)
	t.Logf("%s: graphical session of %s: %+v", d.Name, g.owner.name, session)
	Until(t, d.Name+": "+ssFlatpakUserApp+" in the owner's installation", 10*time.Minute, 10*time.Second, nil, func() bool {
		return userFlatpakApp(d, g.owner, ssFlatpakUserApp)
	})
	softwareState(t, d, "flatpak:"+ssFlatpakUserApp, "installed", "", 5*time.Minute, nil)
	if slices.Contains(flatpakApps(d), ssFlatpakUserApp) {
		t.Errorf("%s in the system installation", ssFlatpakUserApp)
	}
	if userFlatpakApp(d, g.other, ssFlatpakUserApp) {
		t.Errorf("%s in the other owner's installation", ssFlatpakUserApp)
	}
	d.Shot(t, "sv7-session")
}

// ssNotifyMonitor records the Notify calls on the session bus of u's graphical session into ssNotifyLog in u's home.
func ssNotifyMonitor(d *Device, u *ssUser) {
	monitor := `exec stdbuf -oL dbus-monitor --session "type='method_call',interface='org.freedesktop.Notifications',member='Notify'" >"$HOME/` +
		ssNotifyLog + `" 2>&1`
	d.Must(fmt.Sprintf("sudo systemd-run --machine=%d@.host --user --quiet --collect --unit=paddock-gate-notify sh -c %s", u.uid, shellQuote(monitor)))
}

// gateSV3: the owner installs the available ssOffered through the socket: the operation succeeds, the package is at
// 1.0, the owner's view shows it installed and removable, device.software_self_service records it with the owner's
// UPN, and the notification reaches the owner's session (D-Bus Notify, screenshot as evidence). The other owner cannot
// read the operation (404). The owner's removal succeeds too.
func gateSV3(t *testing.T, d *Device, g *selfServiceGate) {
	ssNotifyMonitor(d, g.owner)
	log := `h=$(getent passwd ` + strconv.Itoa(g.owner.uid) + ` | cut -d: -f6); cat "$h/` + ssNotifyLog + `" 2>/dev/null || true`
	// dbus-monitor writes its first line (NameAcquired) once it is connected to the session bus.
	Until(t, d.Name+": D-Bus monitor in the owner's session", time.Minute, 2*time.Second, nil, func() bool {
		return d.MustRoot(log) != ""
	})
	g.selfService = d.eventIDs("device.software_self_service")
	id := d.ssRequest(t, g.owner, g.offered, "install")
	if op := d.ssWaitOperation(t, g.owner, id, 10*time.Minute); op.State != "succeeded" || op.Action != "install" || op.EntryID != g.offered {
		t.Fatalf("install of %s: %+v", ssOffered, op)
	}
	if v := d.installedVersion(ssOffered); v != "1.0" {
		t.Errorf("%s at %q after the install", ssOffered, v)
	}
	if a := d.ssAppsOf(t, g.owner)[g.offered]; a.State != "installed" || !a.Removable || a.Installable {
		t.Errorf("the owner's %s after the install: %+v", ssOffered, a)
	}
	ev := d.waitNewEvent(t, "device.software_self_service", g.selfService, 5*time.Minute, func(p map[string]any) bool {
		return p["package"] == ssOffered && p["action"] == "install"
	})
	if ev["outcome"] != "succeeded" || ev["user"] != g.owner.name || ev["entry_id"] != g.offered || ev["scope"] != "system" || ev["version"] != "1.0" {
		t.Errorf("device.software_self_service %v", ev)
	}
	// The body's verb follows the system locale (Installed:/Installiert:); the summary and the package name do not.
	Until(t, d.Name+": notification in the owner's session", 2*time.Minute, 5*time.Second, nil, func() bool {
		out := d.MustRoot(log)
		return strings.Contains(out, `"Paddock Self-Service"`) && strings.Contains(out, ": "+ssOffered+`"`)
	})
	d.Shot(t, "sv3-notification")
	if r := d.ssCall(t, g.other, http.MethodGet, "/v1/operations/"+id); r.Status != http.StatusNotFound {
		t.Errorf("the other owner reads the owner's operation: HTTP %d %s", r.Status, r.Body)
	}

	g.selfService = d.eventIDs("device.software_self_service")
	id = d.ssRequest(t, g.owner, g.offered, "remove")
	if op := d.ssWaitOperation(t, g.owner, id, 10*time.Minute); op.State != "succeeded" {
		t.Fatalf("removal of %s: %+v", ssOffered, op)
	}
	if v := d.installedVersion(ssOffered); v != "" {
		t.Errorf("%s at %q after the removal", ssOffered, v)
	}
	d.waitNewEvent(t, "device.software_self_service", g.selfService, 5*time.Minute, func(p map[string]any) bool {
		return p["package"] == ssOffered && p["action"] == "remove" && p["outcome"] == "succeeded" && p["user"] == g.owner.name
	})
}

// gateSV6 (F4, PDK-983): the agent is killed while ssSlow's postinst runs with himmelblaud held, and stays down until
// the safety timer started himmelblaud again; started, it reports the hold as recovered. The operation ends failed/interrupted with the event;
// asked again, the install finishes the interrupted one (dpkg --configure -a), and the package ends installed at 1.0
// with nothing left for dpkg --audit.
func gateSV6(t *testing.T, d *Device, g *selfServiceGate) {
	seen := d.eventIDs("device.software_self_service")
	id := d.ssRequest(t, g.owner, g.slow, "install")
	Until(t, d.Name+": "+ssSlow+"'s postinst runs", 6*time.Minute, 3*time.Second, nil, func() bool {
		return d.MustRoot("test -e "+ssSlowStarted+" && echo yes || echo no") == "yes"
	})
	if d.himmelblaudActive() {
		t.Fatal("himmelblaud runs while the agent's transaction runs; the agent holds it stopped (PDK-983)")
	}
	if timer := d.MustRoot("systemctl is-active paddock-nss-shield-restore.timer || true"); timer != "active" {
		t.Fatalf("safety timer %q during the hold, want active", timer)
	}
	shields := d.eventIDs("device.login_nss_shield")
	// Killed, and kept down within its RestartSec: only the safety timer can start himmelblaud again.
	d.Must("sudo systemctl kill -s SIGKILL paddock-supervisor && sudo systemctl stop paddock-supervisor")
	Until(t, d.Name+": himmelblaud started by the safety timer", shieldTimerWait, 5*time.Second, nil, d.himmelblaudActive)
	if st := d.MustRoot("systemctl is-active paddock-supervisor || true"); st == "active" {
		t.Errorf("paddock-supervisor %s while the safety timer restored himmelblaud", st)
	}
	d.Must("sudo systemctl start paddock-supervisor")
	if ev := d.waitNewEvent(t, "device.login_nss_shield", shields, 5*time.Minute, nil); ev["outcome"] != "recovered" ||
		ev["action"] != "apt-get install" {
		t.Errorf("device.login_nss_shield %v, want the hold reported as recovered", ev)
	}
	var op ssOperation
	Until(t, d.Name+": interrupted operation after the restart", 3*time.Minute, 5*time.Second, nil, func() bool {
		r, err := d.ssTry(g.owner, http.MethodGet, "/v1/operations/"+id)
		if err != nil || r.Status != http.StatusOK {
			t.Logf("%s: operation %s: %v %d %s", d.Name, id, err, r.Status, r.Body)
			return false
		}
		return json.Unmarshal(r.Body, &op) == nil && op.State != "queued" && op.State != "running"
	})
	if op.State != "failed" || op.Reason != "interrupted" {
		t.Fatalf("operation after the restart: %+v, want failed/interrupted", op)
	}
	ev := d.waitNewEvent(t, "device.software_self_service", seen, 5*time.Minute, func(p map[string]any) bool {
		return p["package"] == ssSlow && p["action"] == "install"
	})
	if ev["outcome"] != "failed" || ev["reason"] != "interrupted" || ev["user"] != g.owner.name {
		t.Errorf("device.software_self_service %v, want failed/interrupted", ev)
	}

	if st := d.MustRoot("dpkg-query -W -f '${db:Status-Status}' " + ssSlow); st != "half-configured" {
		t.Fatalf("%s is %q after the restart, want half-configured (killed in its postinst)", ssSlow, st)
	}
	d.Must("sudo touch " + ssSlowRelease)
	if op = d.ssWaitOperation(t, g.owner, d.ssRequest(t, g.owner, g.slow, "install"), 10*time.Minute); op.State != "succeeded" {
		t.Errorf("install after the interruption: %+v, want succeeded", op)
	}
	Until(t, d.Name+": "+ssSlow+" consistent", 3*time.Minute, 10*time.Second, nil, func() bool {
		return d.installedVersion(ssSlow) == "1.0" && d.MustRoot("dpkg --audit 2>&1 || true") == ""
	})
}

// gateSV8 (A10-14): the icon of ssOffered reaches the device through the presigned bundles URL: the owner's view has
// icon true and GET /v1/apps/{id}/icon answers exactly the uploaded PNG; ssPrivate has no icon (the app shows the
// category glyph), and its icon is not found for a user outside its audience either.
func gateSV8(t *testing.T, d *Device, g *selfServiceGate) {
	icon := ssIcon(d.Name + d.run)
	d.s.putIcon(t, g.offered, icon)
	apps := d.ssWaitApps(t, g.owner, "the icon of "+ssOffered, func(apps map[string]ssApp) bool { return apps[g.offered].Icon })
	r := d.ssCall(t, g.owner, http.MethodGet, "/v1/apps/"+g.offered+"/icon")
	if r.Status != http.StatusOK || r.ContentType != "image/png" || !bytes.Equal(r.Body, icon) {
		t.Errorf("icon of %s: HTTP %d %s, %d bytes (want the %d uploaded)", ssOffered, r.Status, r.ContentType, len(r.Body), len(icon))
	}
	if apps[g.private].Icon {
		t.Errorf("the owner's %s has an icon: %+v", ssPrivate, apps[g.private])
	}
	for _, u := range []*ssUser{g.owner, g.other} {
		if r := d.ssCall(t, u, http.MethodGet, "/v1/apps/"+g.private+"/icon"); r.Status != http.StatusNotFound {
			t.Errorf("icon of %s as %s: HTTP %d, want 404", ssPrivate, u.name, r.Status)
		}
	}
}

// compileWarning is an item of GET /api/v1/compile-warnings.
type compileWarning struct {
	AssignmentID   string         `json:"assignment_id"`
	CatalogEntryID string         `json:"catalog_entry_id"`
	Code           string         `json:"code"`
	Params         map[string]any `json:"params"`
}

// gateSV9 (A10-9): forbidding the package flatpak leaves every Flatpak application out of the device's bundle (no
// flatpak: health item, none in the users' lists) with flatpak_forbidden for both Flatpak entries, and the agent
// removes flatpak; the APT part of the section stays.
func gateSV9(t *testing.T, d *Device, g *selfServiceGate) {
	entry := d.ssEntry(t, g.keep, "flatpak", "", map[string]any{"package": "flatpak"})
	d.ssAssign(t, g.keep, entry, "forbid", nil)
	last := time.Time{}
	Until(t, d.Name+": no Flatpak application in the health report", 8*time.Minute, 10*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		pkgs, err := healthPackages(d.Health())
		if err != nil {
			t.Fatal(err)
		}
		return !slices.ContainsFunc(pkgs, func(p string) bool { return strings.HasPrefix(p, "flatpak:") })
	})
	apps := d.ssAppsOf(t, g.owner)
	for _, e := range []string{g.fpApp, g.fpUserApp} {
		if a, ok := apps[e]; ok {
			t.Errorf("the owner still sees %+v", a)
		}
	}
	for _, e := range []string{g.anchor, g.offered, g.private} {
		if _, ok := apps[e]; !ok {
			t.Errorf("the owner lost APT entry %s", e)
		}
	}
	q := url.Values{"device_id": {d.ID}, "code": {"flatpak_forbidden"}, "page_size": {"100"}}
	var page struct {
		Items []compileWarning `json:"items"`
	}
	if err := json.Unmarshal(d.s.Call(t, http.MethodGet, "/api/v1/compile-warnings?"+q.Encode(), nil, http.StatusOK).Body, &page); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ entry, ref string }{{g.fpApp, ssFlatpakApp}, {g.fpUserApp, ssFlatpakUserApp}} {
		if !slices.ContainsFunc(page.Items, func(w compileWarning) bool {
			return w.CatalogEntryID == want.entry && w.Params["flatpak_ref"] == want.ref
		}) {
			t.Errorf("no flatpak_forbidden for %s: %+v", want.ref, page.Items)
		}
	}
	waitVersion(t, d, "flatpak", "", 8*time.Minute, true)
	if v := d.installedVersion(gateAnchor); v != "1.0" {
		t.Errorf("%s at %q after flatpak was forbidden", gateAnchor, v)
	}
}

// shieldTimerWait bounds the wait for the safety timer of a development build (agent.DevNSSShieldMaxHold plus
// agent.DevNSSShieldTimerGrace, 5 minutes) with a margin.
const shieldTimerWait = 7 * time.Minute

// himmelblaudActive reports whether himmelblaud runs.
func (d *Device) himmelblaudActive() bool {
	return d.MustRoot("systemctl is-active himmelblaud.service || true") == "active"
}

// requireSynthesized waits until himmelblaud runs and checks that Himmelblau's NSS module answers for account, which
// /etc/passwd does not have, with a synthetic directory user: the condition under which adduser --system refuses
// (PDK-983). It returns the device's login.nss_shield events so far.
func (d *Device) requireSynthesized(t *testing.T, account string) []string {
	t.Helper()
	Until(t, d.Name+": himmelblaud active", 15*time.Minute, 10*time.Second, d.Checkin, d.himmelblaudActive)
	if d.MustRoot("grep -c '^"+account+":' /etc/passwd || true") != "0" {
		t.Fatalf("%s is a local account before the agent acted", account)
	}
	uid, err := strconv.Atoi(d.MustRoot("getent passwd " + account + " | cut -d: -f3"))
	if err != nil || uid < 200000 {
		t.Fatalf("getent passwd %s: UID %d %v, want Himmelblau's synthetic entry", account, uid, err)
	}
	return d.eventIDs("device.login_nss_shield")
}

// requireSystemAccount checks that the agent's installation created account as a local system account and held
// himmelblaud around it: a login.nss_shield restored after an apt-get install, and himmelblaud running again.
func (d *Device) requireSystemAccount(t *testing.T, account string, shields []string) {
	t.Helper()
	uid, err := strconv.Atoi(d.MustRoot("awk -F: '$1 == \"" + account + "\" {print $3}' /etc/passwd"))
	if err != nil || uid < 100 || uid > 999 {
		t.Errorf("%s in /etc/passwd: UID %d %v, want a system account (100–999)", account, uid, err)
	}
	ev := d.waitNewEvent(t, "device.login_nss_shield", shields, 5*time.Minute, func(p map[string]any) bool {
		return p["action"] == "apt-get install"
	})
	if ev["outcome"] != "restored" {
		t.Errorf("device.login_nss_shield %v, want restored", ev)
	}
	if !d.himmelblaudActive() {
		t.Error("himmelblaud not running after the agent's installation")
	}
}

// gateSV10 (PDK-983, decisions §45): a required plain package whose postinst runs adduser --system installs on a
// device where Himmelblau answers for every unknown name, and its account is a local system account.
func gateSV10(t *testing.T, d *Device, g *selfServiceGate) {
	shields := d.requireSynthesized(t, ssSysAccount)
	d.assign(g.keep, g.sysUser, "required", "")
	softwareState(t, d, ssSysUser, "installed", "", 10*time.Minute, d.Checkin)
	d.requireSystemAccount(t, ssSysAccount, shields)
}

// gateSV12 (PDK-988, plan M5a N6 and N8): the regular updates run, paddock-updates.service started directly, upgrades
// ssUpgrade from 1.0, installed by hand, to 1.1, whose new dependency creates a system account with adduser --system
// while Himmelblau answers for every unknown name. The run reports ok, the account is a local system account, the
// run's hold reaches the server exactly once as device.login_nss_shield through the report file, himmelblaud runs
// again, and no device.tamper_service_stopped names it.
func gateSV12(t *testing.T, d *Device, g *selfServiceGate) {
	Until(t, d.Name+": paddock-updates.service installed", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return d.MustRoot("test -e /etc/systemd/system/paddock-updates.service && echo yes || echo no") == "yes"
	})
	d.MustRootIn([]byte(ssUpgradeScript), "bash -s base")
	d.dpkgInstall(t, ssUpgradeBase)
	if v := d.installedVersion(ssUpgrade); v != "1.0" {
		t.Fatalf("%s at %q before the run, want 1.0", ssUpgrade, v)
	}
	shields := d.requireSynthesized(t, ssUpgradeAccount)
	tamper := d.eventIDs("device.tamper_service_stopped")
	runs := d.eventIDs("device.updates_run")
	d.MustRootIn([]byte(ssUpgradeScript), "bash -s publish")
	// The distribution's and Himmelblau's updates stay out of the run: an upgrade of himmelblau restarts the daemon
	// within the hold, and a long distribution upgrade can outlast the development build's maximum hold of 4 minutes,
	// which starts himmelblaud before the account is created. List-Cleanup keeps the other sources' lists for later.
	d.MustRoot("printf '%s\\n' 'Dir::Etc::sourcelist \"sources.list.d/paddock-" + g.slug + ".sources\";' " +
		"'Dir::Etc::sourceparts \"-\";' 'APT::Get::List-Cleanup \"0\";' >" + ssUpgradeAptConf)
	defer d.MustRoot("rm -f " + ssUpgradeAptConf)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	out, err := d.SSH(ctx, nil, "sudo systemctl start paddock-updates.service")
	cancel()
	if err != nil {
		journal := d.MustRoot("journalctl -u paddock-updates.service --since -30min --no-pager -o cat | tail -n 80")
		t.Fatalf("%s: paddock-updates.service: %v %s\n%s", d.Name, err, out, journal)
	}
	t.Logf("%s: %s after the run: %s", d.Name, nssShieldReport, d.MustRoot("cat "+nssShieldReport+" 2>/dev/null || echo absent"))
	run := d.waitNewEvent(t, "device.updates_run", runs, 5*time.Minute, func(p map[string]any) bool { return p["kind"] == "regular" })
	if run["result"] != "ok" {
		t.Errorf("updates.run %v", run)
	}
	if v := d.installedVersion(ssUpgrade); v != "1.1" {
		t.Errorf("%s at %q after the regular run, want 1.1", ssUpgrade, v)
	}
	if v := d.installedVersion(ssUpgradeDep); v != "1.0" {
		t.Errorf("%s at %q after the regular run, want 1.0", ssUpgradeDep, v)
	}
	uid, err := strconv.Atoi(d.MustRoot("awk -F: '$1 == \"" + ssUpgradeAccount + "\" {print $3}' /etc/passwd"))
	if err != nil || uid < 100 || uid > 999 {
		t.Errorf("%s in /etc/passwd: UID %d %v, want a system account (100–999)", ssUpgradeAccount, uid, err)
	}

	fromRun := func(p map[string]any) bool { return p["action"] == "apt-get dist-upgrade" }
	if ev := d.waitNewEvent(t, "device.login_nss_shield", shields, 5*time.Minute, fromRun); ev["outcome"] != "restored" {
		t.Errorf("device.login_nss_shield %v, want restored", ev)
	}
	// The agent emits every record of the file in one pass and removes it then; a second record of the run would
	// arrive with the next check-in.
	Until(t, d.Name+": report file emitted", 3*time.Minute, 5*time.Second, nil, func() bool {
		return d.MustRoot("test -e "+nssShieldReport+" && echo present || echo absent") == "absent"
	})
	time.Sleep(65 * time.Second)
	d.Checkin()
	time.Sleep(30 * time.Second)
	if evs := d.newEvents("device.login_nss_shield", shields, fromRun); len(evs) != 1 {
		t.Errorf("%d device.login_nss_shield of the updates run, want exactly one: %v", len(evs), evs)
	}
	if !d.himmelblaudActive() {
		t.Error("himmelblaud not running after the regular updates run")
	}
	himmelblaud := func(p map[string]any) bool { return p["unit"] == "himmelblaud.service" }
	if own := d.newEvents("device.tamper_service_stopped", tamper, himmelblaud); len(own) != 0 {
		t.Errorf("the updates run's hold was reported as tampering: %v", own)
	}
}

// gateSV11 (decisions §45, protected area 4): none of the agent's own holds since SV5 was reported as tampering, and
// a stop of himmelblaud by someone else is reported once as device.tamper_service_stopped; the agent does not start
// it again.
func gateSV11(t *testing.T, d *Device, g *selfServiceGate) {
	himmelblaud := func(p map[string]any) bool { return p["unit"] == "himmelblaud.service" }
	if own := d.newEvents("device.tamper_service_stopped", g.tamperSeen, himmelblaud); len(own) != 0 {
		t.Errorf("the agent's own holds were reported as tampering: %v", own)
	}
	seen := d.eventIDs("device.tamper_service_stopped")
	d.Must("sudo systemctl stop himmelblaud.service")
	defer d.Must("sudo systemctl start himmelblaud.service himmelblaud-tasks.service")
	if ev := d.waitNewEvent(t, "device.tamper_service_stopped", seen, 5*time.Minute, himmelblaud); ev["state"] != "inactive" {
		t.Errorf("device.tamper_service_stopped %v, want state inactive", ev)
	}
	if d.himmelblaudActive() {
		t.Error("the agent started himmelblaud after a foreign stop; it only reports it")
	}
}
