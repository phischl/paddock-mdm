package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

const (
	// ssSocket is the agent's self-service socket (plan M13b §6.2).
	ssSocket = "/run/paddock/selfservice.sock"
	// ssOffered is offered to every user of the device (available, device group); ssPrivate only to the owner it
	// targets (available, user); ssSlow is offered to everyone and its postinst waits for ssSlowRelease (gate SV6).
	ssOffered = "paddock-gate-offered"
	ssPrivate = "paddock-gate-private"
	ssSlow    = "paddock-gate-slow"
	// ssSlowStarted is written by ssSlow's postinst when it starts; ssSlowRelease lets it finish.
	ssSlowStarted = "/run/paddock-gate-slow.started"
	ssSlowRelease = "/run/paddock-gate-slow.release"
	// ssSysUser is a plain package whose postinst creates the system account ssSysAccount with adduser --system, as
	// many daemon packages do (gate SV10, PDK-983).
	ssSysUser    = "paddock-gate-sysuser"
	ssSysAccount = "_paddock-gate"
	// ssFlatpakURI is the gate's Flatpak repository, served by paddock-gate-repo next to the APT repository.
	ssFlatpakURI = gateRepoURI + "flatpak/"
	// ssFlatpakApp is the system-scope application of gate SV5, ssFlatpakUserApp the user-scope one of SV7.
	ssFlatpakApp     = "org.paddock.GateApp"
	ssFlatpakUserApp = "org.paddock.GateUserApp"
	// ssFlatpakRuntime is the runtime both applications need, from the same repository.
	ssFlatpakRuntime = "org.paddock.GateRuntime"
	// ssOwnerUID and ssOtherUID are the UIDs of the gate's two directory users, in Himmelblau's idmap range.
	ssOwnerUID = 208071
	ssOtherUID = 208072
	// ssDomain is the domain of acme's users.
	ssDomain = "acme.test"
	// ssNotifyLog is where the D-Bus monitor of gate SV3 writes in the session user's home.
	ssNotifyLog = "paddock-gate-notify.log"
)

// ssRepoScript adds the self-service packages to the gate's APT repository (gateRepoScript ran before) and builds the
// gate's Flatpak repository below it, both signed with the gate's key: a runtime and two applications that need it,
// exported with flatpak build-export (no flatpak-builder, no SDK, nothing from Flathub). flatpak is installed from the
// distribution to build the repository and purged afterwards with its system account, so that SV5 sees the agent
// install it and create _flatpak under Himmelblau (Q12, PDK-983).
//
// apt-get runs with stdin from /dev/null because the script itself arrives on stdin (bash -s): a maintainer script
// or a conffile prompt would read the rest of it. With stdout not a terminal, apt 3 sends dpkg's error messages to
// stdout alone, so the output goes to a log that a failure prints with dpkg --audit and the end of term.log.
const ssRepoScript = `set -eu
dir=` + gateRepoDir + `
export GNUPGHOME="$dir/gnupg"
apt_get() {
	log=$(mktemp)
	rc=0
	DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=300 \
		-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" </dev/null >"$log" 2>&1 || rc=$?
	if [ "$rc" -ne 0 ]; then
		{
			echo "apt-get $* failed with exit status $rc:"
			cat "$log"
			echo "dpkg --audit:"
			dpkg --audit || true
			echo "end of /var/log/apt/term.log:"
			tail -n 80 /var/log/apt/term.log || true
		} >&2
		exit "$rc"
	fi
	rm -f "$log"
}
build() {
	root="$dir/build/$1-1.0"
	mkdir -p "$root/DEBIAN"
	printf 'Package: %s\nVersion: 1.0\nArchitecture: all\nMaintainer: Paddock system tests <systest@paddock.invalid>\nDescription: Paddock self-service gate package\n' "$1" >"$root/DEBIAN/control"
	printf '#!/bin/sh\nset -e\n%s\nmkdir -p /var/lib/%s\necho 1.0 >/var/lib/%s/version\n' "$2" "$1" "$1" >"$root/DEBIAN/postinst"
	chmod 0755 "$root/DEBIAN/postinst"
	dpkg-deb --root-owner-group --build "$root" "$dir/repo/$1_1.0_all.deb" >/dev/null
}
build ` + ssOffered + ` ':'
build ` + ssPrivate + ` ':'
build ` + ssSysUser + ` 'adduser --system --group --no-create-home --quiet ` + ssSysAccount + `'
build ` + ssSlow + ` 'touch ` + ssSlowStarted + `; i=0; while [ ! -e ` + ssSlowRelease + ` ] && [ $i -lt 900 ]; do sleep 1; i=$((i + 1)); done'
cd "$dir/repo"
apt-ftparchive packages . >Packages
apt-ftparchive release . >"$dir/Release"
mv "$dir/Release" Release
gpg --batch --yes --clearsign -o InRelease Release

# With himmelblaud running, flatpak's postinst cannot create its system account _flatpak (PDK-983). The install runs
# as a hold of Paddock's own, under the agent's shield lock, so that the agent never reports the stop as tampering
# (gate SV11). flock -o keeps the lock out of the installation's processes: a daemon it starts must not hold it.
held_install() {
	if systemctl is-active -q himmelblaud.service; then
		# apt_get exits on a failure: the trap of the locked shell starts the daemon on every path.
		trap 'systemctl start himmelblaud.service himmelblaud-tasks.service' EXIT
		systemctl stop himmelblaud.service
	fi
	apt_get install "$@"
}
export -f apt_get held_install
if ! command -v flatpak >/dev/null; then
	flock -o ` + nssShieldLock + ` bash -c 'set -eu; held_install flatpak'
fi
key=$(gpg --with-colons --list-secret-keys | awk -F: '$1 == "fpr" {print $10; exit}')
arch=$(flatpak --default-arch)
fb="$dir/flatpak-build"
repo="$dir/repo/flatpak"
rm -rf "$fb" "$repo"
# A runtime is exported from usr/ (an application from files/), and build-export wants files/ to exist all the same
# as the mark of an initialised build directory.
mkdir -p "$fb/runtime/files" "$fb/runtime/usr/share/paddock-gate"
echo runtime >"$fb/runtime/usr/share/paddock-gate/runtime"
printf '[Runtime]\nname=%s\nruntime=%s/%s/1\nsdk=%s/%s/1\n' ` + ssFlatpakRuntime + ` ` + ssFlatpakRuntime + ` "$arch" ` + ssFlatpakRuntime + ` "$arch" >"$fb/runtime/metadata"
flatpak build-export --runtime --gpg-sign="$key" --gpg-homedir="$GNUPGHOME" "$repo" "$fb/runtime" 1 >/dev/null
for app in ` + ssFlatpakApp + ` ` + ssFlatpakUserApp + `; do
	mkdir -p "$fb/$app/files/bin" "$fb/$app/export"
	printf '#!/bin/sh\necho %s\n' "$app" >"$fb/$app/files/bin/gate"
	chmod 0755 "$fb/$app/files/bin/gate"
	printf '[Application]\nname=%s\nruntime=%s/%s/1\nsdk=%s/%s/1\ncommand=gate\n' "$app" ` + ssFlatpakRuntime + ` "$arch" ` + ssFlatpakRuntime + ` "$arch" >"$fb/$app/metadata"
	flatpak build-export --gpg-sign="$key" --gpg-homedir="$GNUPGHOME" "$repo" "$fb/$app" master >/dev/null
done
flatpak build-update-repo --gpg-sign="$key" --gpg-homedir="$GNUPGHOME" "$repo" >/dev/null
python3 -c "import urllib.request; urllib.request.urlopen(\"` + ssFlatpakURI + `summary\", timeout=10)"
apt_get purge flatpak
# SV5 sees a device where flatpak never was: the agent's installation creates _flatpak itself.
if grep -q '^_flatpak:' /etc/passwd; then deluser --system --quiet _flatpak; fi
if grep -q '^_flatpak:' /etc/group; then delgroup --system --quiet _flatpak; fi
`

// nssShieldLock is the agent's shield lock (reconcile.NSSShieldLock).
const nssShieldLock = "/var/lib/paddock/state/nss-shield.lock"

// ssAs is the setpriv prefix that runs a command as u. It names the account and its group, never their numbers:
// setpriv, id, chown and install read an argument as a name first, and Himmelblau's NSS module answers a number such
// as 208071 as an unknown name with a synthetic directory user of another UID (PDK-983). The account's name is in
// /etc/passwd, which NSS reads first.
func ssAs(u *ssUser) string {
	return "setpriv --reuid=" + shellQuote(u.name) + " --regid=\"$(id -gn " + shellQuote(u.name) + ")\" --clear-groups"
}

// ssUserScript creates the account $1 with UID $2 as Himmelblau would map a directory user (a UPN as its name, a UID
// in the idmap range), with a home and GNOME's first-start setup marked done so that an automatic login opens the
// desktop; after useradd it names the account and its group, never the UID (see ssAs). useradd refuses an "@" without --badname (--badnames before shadow 4.14); only an unknown option falls
// back, any other refusal of the first useradd is printed, since it names the real cause.
const ssUserScript = `set -eu
rc=0
err=$(useradd --badname -m -u "$2" -s /bin/bash "$1" 2>&1) || rc=$?
if [ "$rc" -ne 0 ]; then
	case $err in
	*"unrecognized option"*) useradd --badnames -m -u "$2" -s /bin/bash "$1" ;;
	*)
		echo "useradd --badname $1 (UID $2) failed with exit status $rc: $err" >&2
		exit "$rc"
		;;
	esac
fi
home=$(getent passwd "$2" | cut -d: -f6)
group=$(id -gn "$1")
install -d -o "$1" -g "$group" "$home/.config"
echo yes >"$home/.config/gnome-initial-setup-done"
chown "$1:$group" "$home/.config/gnome-initial-setup-done"
`

// ssClientScript sends one request to the self-service socket as the account it runs as and prints the status, the
// content type and the body (base64) as JSON; argv: method, path. curl is not part of every Ubuntu desktop.
const ssClientScript = `import base64, http.client, json, socket, sys


class Conn(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(30)
        self.sock.connect("` + ssSocket + `")


c = Conn("localhost")
c.request(sys.argv[1], sys.argv[2], body=b"" if sys.argv[1] == "POST" else None)
r = c.getresponse()
print(json.dumps({"status": r.status, "content_type": r.getheader("Content-Type", ""), "body": base64.b64encode(r.read()).decode()}))
`

// ssUser is an account on the device: a gate's directory user (with its Paddock user ID) or a local account (no ID).
type ssUser struct {
	name string
	uid  int
	id   string
}

// ssReply is one answer of the self-service socket.
type ssReply struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// code is the problem code of a refusal ("" when the body is none).
func (r ssReply) code() string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.Body, &p)
	return p.Code
}

// ssApp is an application of GET /v1/apps (plan M13b §6.2).
type ssApp struct {
	EntryID     string `json:"entry_id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Scope       string `json:"scope"`
	Intent      string `json:"intent"`
	Managed     bool   `json:"managed"`
	Installable bool   `json:"installable"`
	Removable   bool   `json:"removable"`
	State       string `json:"state"`
	Version     string `json:"version"`
	Reason      string `json:"reason"`
	Icon        bool   `json:"icon"`
}

// ssOperation is GET /v1/operations/{id}.
type ssOperation struct {
	ID       string `json:"id"`
	EntryID  string `json:"entry_id"`
	Action   string `json:"action"`
	State    string `json:"state"`
	Position int    `json:"position"`
	Reason   string `json:"reason"`
}

// ssStatus is GET /v1/status.
type ssStatus struct {
	User struct {
		Name      string `json:"name"`
		Directory bool   `json:"directory"`
	} `json:"user"`
	Queue int `json:"queue"`
}

// parseSSReply decodes the output of ssClientScript.
func parseSSReply(out string) (ssReply, error) {
	var r ssReply
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return r, fmt.Errorf("self-service reply %q: %w", out, err)
	}
	return r, nil
}

// ssApps decodes the body of GET /v1/apps by entry ID.
func ssApps(body []byte) (map[string]ssApp, error) {
	var page struct {
		Apps []ssApp `json:"apps"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("apps %q: %w", body, err)
	}
	apps := map[string]ssApp{}
	for _, a := range page.Apps {
		apps[a.EntryID] = a
	}
	return apps, nil
}

// ssCall sends one request to the self-service socket as u (root when u is nil). The peer credentials the agent
// reads are u's: setpriv switches the real and effective IDs before python connects. The output goes through
// MustRoot's file, never through sudo's standard output (PDK-926).
func (d *Device) ssCall(t *testing.T, u *ssUser, method, path string) ssReply {
	t.Helper()
	cmd := "python3 - " + method + " " + shellQuote(path)
	if u != nil {
		cmd = ssAs(u) + " " + cmd
	}
	r, err := parseSSReply(d.MustRootIn([]byte(ssClientScript), cmd))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ssTry is ssCall for a socket that may not be there (the agent restarts): an error instead of a failed test.
func (d *Device) ssTry(u *ssUser, method, path string) (ssReply, error) {
	cmd := ssAs(u) + " python3 - " + method + " " + shellQuote(path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := d.SSH(ctx, []byte(ssClientScript), rootCapture(cmd))
	if err != nil {
		return ssReply{}, fmt.Errorf("%s %s as %s: %w: %s", method, path, u.name, err, out)
	}
	return parseSSReply(strings.TrimSpace(out))
}

// healthPackages are the packages of the agent's software health items.
func healthPackages(report string) ([]string, error) {
	var h struct {
		Software *struct {
			Items []softwareItem `json:"items"`
		} `json:"software"`
	}
	if err := json.Unmarshal([]byte(report), &h); err != nil {
		return nil, err
	}
	var pkgs []string
	if h.Software != nil {
		for _, it := range h.Software.Items {
			pkgs = append(pkgs, it.Package)
		}
	}
	return pkgs, nil
}

// ssAppsOf lists the applications u sees.
func (d *Device) ssAppsOf(t *testing.T, u *ssUser) map[string]ssApp {
	t.Helper()
	r := d.ssCall(t, u, http.MethodGet, "/v1/apps")
	if r.Status != http.StatusOK {
		t.Fatalf("GET /v1/apps as %s: HTTP %d %s", ssName(u), r.Status, r.Body)
	}
	apps, err := ssApps(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return apps
}

// ssWaitApps waits, checking in at most every 65 s, until u's list satisfies cond, and returns it.
func (d *Device) ssWaitApps(t *testing.T, u *ssUser, what string, cond func(map[string]ssApp) bool) map[string]ssApp {
	t.Helper()
	var apps map[string]ssApp
	last := time.Time{}
	Until(t, d.Name+": "+what, 8*time.Minute, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		apps = d.ssAppsOf(t, u)
		return cond(apps)
	})
	return apps
}

// ssRequest asks for action on entry as u and returns the operation's ID; the request must be accepted (202).
func (d *Device) ssRequest(t *testing.T, u *ssUser, entry, action string) string {
	t.Helper()
	r := d.ssCall(t, u, http.MethodPost, "/v1/apps/"+entry+"/"+action)
	var out struct {
		OperationID string `json:"operation_id"`
	}
	if r.Status != http.StatusAccepted || json.Unmarshal(r.Body, &out) != nil || out.OperationID == "" {
		t.Fatalf("POST %s of %s as %s: HTTP %d %s", action, entry, ssName(u), r.Status, r.Body)
	}
	return out.OperationID
}

// ssWaitOperation waits until u's operation is finished (neither queued nor running) and returns it.
func (d *Device) ssWaitOperation(t *testing.T, u *ssUser, id string, timeout time.Duration) ssOperation {
	t.Helper()
	var op ssOperation
	Until(t, d.Name+": self-service operation "+id, timeout, 5*time.Second, nil, func() bool {
		r := d.ssCall(t, u, http.MethodGet, "/v1/operations/"+id)
		if r.Status != http.StatusOK || json.Unmarshal(r.Body, &op) != nil {
			t.Fatalf("GET /v1/operations/%s as %s: HTTP %d %s", id, ssName(u), r.Status, r.Body)
		}
		return op.State != "queued" && op.State != "running"
	})
	t.Logf("%s: operation %+v", d.Name, op)
	return op
}

func ssName(u *ssUser) string {
	if u == nil {
		return "root"
	}
	return u.name
}

// ssDirectoryUser creates a local Paddock user of acme with suffix (deleted when keep ends) and the same account on
// the VM with uid, as Himmelblau would map it. It runs before the device is enrolled: once himmelblaud is online,
// Himmelblau answers the new UPN with a synthetic user and useradd refuses it as existing (PDK-983).
func ssDirectoryUser(t, keep *testing.T, s *Stack, vm *VM, suffix, prefix string, uid int) *ssUser {
	t.Helper()
	s.StepUp(t) // a user who would receive root through grants to everyone needs a step-up
	name := prefix + "-" + suffix + "@" + ssDomain
	res := s.Call(t, http.MethodPost, "/api/v1/users", map[string]string{"username": name, "display_name": "systest " + prefix}, http.StatusCreated)
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil || out.User.ID == "" {
		t.Fatalf("created user %s: %v", res.Body, err)
	}
	keep.Cleanup(func() {
		s.cleanupCall(keep, http.MethodDelete, "/api/v1/users/"+out.User.ID, http.StatusNoContent, http.StatusNotFound)
	})
	vm.MustRootIn([]byte(ssUserScript), "bash -s -- "+shellQuote(name)+" "+strconv.Itoa(uid))
	return &ssUser{name: name, uid: uid, id: out.User.ID}
}

// ssSetOwners makes users the owners of the device.
func (d *Device) ssSetOwners(t *testing.T, users ...*ssUser) {
	t.Helper()
	ids := []string{}
	for _, u := range users {
		ids = append(ids, u.id)
	}
	d.s.Call(t, http.MethodPut, "/api/v1/devices/"+d.ID+"/owners", map[string]any{"user_ids": ids}, http.StatusOK)
}

// ssFlatpakSource creates the gate's Flatpak source with the run's suffix, after a step-up (a Flatpak source change
// needs one, plan M13b SS4), and deletes it with a step-up when keep ends; it returns the source's ID and slug.
func (d *Device) ssFlatpakSource(t, keep *testing.T, repo gateRepo) (id, slug string) {
	t.Helper()
	slug = "gatefp-" + d.run
	d.s.StepUp(t)
	id = d.s.ID(t, d.s.Call(t, http.MethodPost, "/api/v1/software-sources", map[string]any{
		"kind": "flatpak", "slug": slug, "name": "systest flatpak " + d.Name + " " + d.run, "uris": []string{ssFlatpakURI},
		"signing_key": repo.Key, "fingerprint": repo.Fingerprint,
	}, http.StatusCreated))
	s := d.s
	keep.Cleanup(func() {
		s.StepUp(keep)
		s.cleanupCall(keep, http.MethodDelete, "/api/v1/software-sources/"+id, http.StatusNoContent, http.StatusNotFound)
	})
	return id, slug
}

// ssEntry creates a catalog entry of one package reference for every release and architecture of the VM's
// distribution (source "" for the distribution's own repositories) and deletes it when keep ends.
func (d *Device) ssEntry(t, keep *testing.T, label, source string, ref map[string]any) string {
	t.Helper()
	ref["distribution"] = d.Must(". /etc/os-release && echo \"$ID\"")
	ref["release"], ref["architecture"] = "*", "*"
	body := map[string]any{"name": "systest " + label + " " + d.Name + " " + d.run, "packages": []map[string]any{ref}}
	if source != "" {
		body["source_id"] = source
	}
	id := d.s.ID(t, d.s.Call(t, http.MethodPost, "/api/v1/software-catalog", body, http.StatusCreated))
	d.s.DeleteOnCleanup(keep, "/api/v1/software-catalog/"+id)
	return id
}

// ssAssign assigns entry with intent to the device's group (user nil) or to user, and deletes the assignment when
// keep ends, before its entry and its user (cleanups run last in, first out).
func (d *Device) ssAssign(t, keep *testing.T, entry, intent string, user *ssUser) string {
	t.Helper()
	body := map[string]any{"catalog_entry_id": entry, "intent": intent, "reason": "system test " + d.run}
	if user != nil {
		body["user_id"] = user.id
	} else {
		body["device_group_id"] = d.Group
	}
	id := d.s.ID(t, d.s.Call(t, http.MethodPost, "/api/v1/software-assignments", body, http.StatusCreated))
	d.s.DeleteOnCleanup(keep, "/api/v1/software-assignments/"+id)
	return id
}

// ssIcon is a 16×16 PNG in a colour of seed, so that every run uploads its own icon (and digest).
func ssIcon(seed string) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	c := color.RGBA{A: 255}
	for i, b := range []byte(seed) {
		switch i % 3 {
		case 0:
			c.R ^= b
		case 1:
			c.G ^= b
		default:
			c.B ^= b
		}
	}
	for y := range 16 {
		for x := range 16 {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// putIcon sets the icon of a catalog entry (PUT with Content-Type image/png, which Stack.Call does not send).
func (s *Stack) putIcon(t *testing.T, entry string, icon []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, portal.AdminURL()+"/api/v1/software-catalog/"+entry+"/icon", bytes.NewReader(icon))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "image/png")
	req.Header.Set("X-Paddock-CSRF", "1")
	resp, err := s.session().Client.Do(req)
	if err != nil {
		t.Fatalf("PUT icon of %s: %v", entry, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT icon of %s: HTTP %d", entry, resp.StatusCode)
	}
}

// iniValue returns the value of key in section of a GKeyFile such as an OSTree repository's config ("" when missing).
func iniValue(text, section, key string) string {
	in := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			in = line == "["+section+"]"
			continue
		}
		if k, v, ok := strings.Cut(line, "="); in && ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// primaryFingerprints returns the fingerprints of the primary keys in gpg's --with-colons output, without subkeys.
func primaryFingerprints(colons string) []string {
	var fps []string
	primary := false
	for _, line := range strings.Split(colons, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		switch {
		case f[0] == "pub":
			primary = true
		case f[0] == "sub":
			primary = false
		case f[0] == "fpr" && primary && len(f) > 9:
			fps = append(fps, f[9])
			primary = false
		}
	}
	return fps
}
