package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

const (
	// gateApp is the package of the software gate: versions 1.0 and 1.1 in the VM's local repository.
	gateApp = "paddock-gate-app"
	// gateAnchor is a second package of the same repository, required from SW3 on. A bundle carries a source only for
	// required packages (plan M13a decision 14), so it keeps the source while gateApp is forbidden (SW3: apt-get install
	// fails at the -1 pin, not at a missing source) or held (SW4: otherwise the regular run's apt-get update drops the
	// repository and no newer version exists to hold back).
	gateAnchor = "paddock-gate-anchor"
	// gateRepoDir holds the repository, its keys, its TLS files and the scripts of the gate on the VM.
	gateRepoDir = "/srv/paddock-gate"
	// gateRepoURI is where the transient unit paddock-gate-repo serves the repository.
	gateRepoURI = "https://127.0.0.1:8443/"
	// gateDeb is version 1.0 of gateApp for dpkg -i.
	gateDeb = gateRepoDir + "/repo/" + gateApp + "_1.0_all.deb"
	// gateForbidFile is the agent's forbid pin file (plan M13a decision 20).
	gateForbidFile = "/etc/apt/preferences.d/51paddock-software"
	// managedHeader is the first line of every file the agent manages.
	managedHeader = "# Managed by Paddock. Do not edit: local changes are reverted.\n"
)

// gateRepoScript builds the signed flat APT repository of the software gate on the VM (plan M13a §9): a throwaway
// Ed25519 signing key in its own GNUPGHOME (the private key never leaves the VM), gateApp 1.0 and 1.1 and gateAnchor
// 1.0 (dpkg-deb), Packages, Release and the clearsigned InRelease, a throwaway CA in the system store with a server
// certificate for 127.0.0.1, and the TLS server as the transient unit paddock-gate-repo. A missing gpg, openssl,
// python3 or dpkg-deb fails the gate; apt-ftparchive is installed with apt-utils when it is missing. It prints the
// key's fingerprint lines (gpg --with-colons).
const gateRepoScript = `set -eu
dir=` + gateRepoDir + `
for tool in gpg openssl python3 dpkg-deb; do
	command -v "$tool" >/dev/null || { echo "the software gate needs $tool" >&2; exit 1; }
done
command -v apt-ftparchive >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=300 apt-utils >/dev/null
rm -rf "$dir"
mkdir -p "$dir/repo" "$dir/tls" "$dir/build"
install -d -m 0700 "$dir/gnupg"
export GNUPGHOME="$dir/gnupg"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'Paddock gate repository <gate@paddock.invalid>' ed25519 sign 1d
build() {
	root="$dir/build/$1-$2"
	mkdir -p "$root/DEBIAN"
	printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: Paddock system tests <systest@paddock.invalid>\nDescription: Paddock system gate package\n' "$1" "$2" >"$root/DEBIAN/control"
	printf '#!/bin/sh\nset -e\nmkdir -p /var/lib/%s\necho %s >/var/lib/%s/version\n' "$1" "$2" "$1" >"$root/DEBIAN/postinst"
	chmod 0755 "$root/DEBIAN/postinst"
	dpkg-deb --root-owner-group --build "$root" "$dir/repo/$1_$2_all.deb" >/dev/null
}
build ` + gateApp + ` 1.0
build ` + gateApp + ` 1.1
build ` + gateAnchor + ` 1.0
cd "$dir/repo"
apt-ftparchive packages . >Packages
apt-ftparchive release . >"$dir/Release"
mv "$dir/Release" Release
gpg --batch --yes --clearsign -o InRelease Release
cd "$dir/tls"
# Strict X.509 verification (Python 3.13 and later, apt's GnuTLS) wants the key usages and key identifiers set.
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' >ca.ext
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=Paddock gate CA' -keyout ca.key -out ca.csr 2>/dev/null
openssl x509 -req -in ca.csr -signkey ca.key -days 2 -extfile ca.ext -out ca.crt 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' >server.ext
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' -keyout server.key -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.crt 2>/dev/null
install -m 0644 ca.crt /usr/local/share/ca-certificates/paddock-gate.crt
update-ca-certificates >/dev/null
cat >"$dir/serve.py" <<'EOF'
import functools, http.server, ssl, sys
d = sys.argv[1]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=d + "/repo")
server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(d + "/tls/server.crt", d + "/tls/server.key")
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
EOF
cat >"$dir/lock.py" <<'EOF'
# apt and dpkg lock with fcntl (POSIX record locks); flock(1) takes a BSD lock, which they never see.
import fcntl, time
with open("/var/lib/dpkg/lock-frontend", "a") as f:
    fcntl.lockf(f, fcntl.LOCK_EX)
    time.sleep(600)
EOF
systemd-run --quiet --unit paddock-gate-repo python3 "$dir/serve.py" "$dir"
tries=0
until err=$(python3 -c "import urllib.request; urllib.request.urlopen(\"` + gateRepoURI + `InRelease\", timeout=5)" 2>&1); do
	tries=$((tries + 1))
	if [ "$tries" -ge 30 ]; then
		echo "the gate repository is not reachable at ` + gateRepoURI + `: $err" >&2
		systemctl status paddock-gate-repo --no-pager >&2 || true
		exit 1
	fi
	sleep 1
done
gpg --with-colons --fingerprint
`

// gateRotateScript gives the repository a new throwaway signing key and signs InRelease with it alone (gate SW7). It
// prints the new key's fingerprint lines.
const gateRotateScript = `set -eu
dir=` + gateRepoDir + `
rm -rf "$dir/gnupg"
install -d -m 0700 "$dir/gnupg"
export GNUPGHOME="$dir/gnupg"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'Paddock gate repository rotated <gate@paddock.invalid>' ed25519 sign 1d
cd "$dir/repo"
gpg --batch --yes --clearsign -o InRelease Release
gpg --with-colons --fingerprint
`

// gateRepo is the VM's repository as the server knows it.
type gateRepo struct {
	Key, Fingerprint string
}

// colonFingerprint returns the fingerprint of the first key in gpg's --with-colons output ("" when none).
func colonFingerprint(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Split(strings.TrimSpace(line), ":"); len(f) > 9 && f[0] == "fpr" {
			return f[9]
		}
	}
	return ""
}

// gateSourceFile is the agent's rendering of the gate's source (plan M13a §6.2): a flat repository has no
// components and the source names no architectures.
func gateSourceFile(slug string) string {
	return managedHeader + "Types: deb\nURIs: " + gateRepoURI + "\nSuites: ./\nSigned-By: " + gateKeyringPath(slug) + "\n"
}

// gateSourcePath and gateKeyringPath are the files the agent writes for the source slug.
func gateSourcePath(slug string) string {
	return "/etc/apt/sources.list.d/paddock-" + slug + ".sources"
}
func gateKeyringPath(slug string) string { return "/etc/apt/keyrings/paddock-" + slug + ".gpg" }

// gateForbidPin is the stanza of the forbid pin file for pkg.
func gateForbidPin(pkg string) string {
	return "Package: " + pkg + "\nPin: release *\nPin-Priority: -1"
}

// sha256Hex is the hexadecimal SHA-256 of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// softwareItem is one item of the agent's software health (plan M13a §6.2).
type softwareItem struct {
	ID      string `json:"id"`
	Package string `json:"package"`
	Intent  string `json:"intent"`
	State   string `json:"state"`
	Version string `json:"version"`
	Reason  string `json:"reason"`
}

// healthSoftwareItem returns the item of pkg in the agent's health report; ok is false without one.
func healthSoftwareItem(report, pkg string) (item softwareItem, ok bool, err error) {
	var h struct {
		Software *struct {
			Items []softwareItem `json:"items"`
		} `json:"software"`
	}
	if err := json.Unmarshal([]byte(report), &h); err != nil {
		return item, false, err
	}
	if h.Software == nil {
		return item, false, nil
	}
	for _, it := range h.Software.Items {
		if it.Package == pkg {
			return it, true, nil
		}
	}
	return item, false, nil
}

// setupGateRepo builds and serves the gate's repository on the VM and returns its public key and fingerprint. It is
// torn down with the VM snapshot.
func (d *Device) setupGateRepo() gateRepo {
	d.t.Helper()
	return d.gateKey(d.MustIn([]byte(gateRepoScript), "sudo bash -s"))
}

// rotateGateRepo gives the repository a new signing key (gate SW7) and returns it.
func (d *Device) rotateGateRepo() gateRepo {
	d.t.Helper()
	return d.gateKey(d.MustIn([]byte(gateRotateScript), "sudo bash -s"))
}

func (d *Device) gateKey(colons string) gateRepo {
	d.t.Helper()
	fp := colonFingerprint(colons)
	if len(fp) != 40 {
		d.t.Fatalf("%s: no fingerprint of the gate key in %q", d.Name, colons)
	}
	key := d.Must("sudo env GNUPGHOME=" + gateRepoDir + "/gnupg gpg --armor --export " + fp)
	return gateRepo{Key: key + "\n", Fingerprint: fp}
}

// keyringFingerprint is the fingerprint of the keyring file at path on the VM ("" when it holds none).
func (d *Device) keyringFingerprint(path string) string {
	d.t.Helper()
	return colonFingerprint(d.Must("sudo sh -c 'h=$(mktemp -d); GNUPGHOME=$h gpg --show-keys --with-colons " + path +
		" 2>/dev/null; rm -rf \"$h\"; true'"))
}

// scopedUpdate runs apt-get update for the source slug alone, as the agent does, and returns its output and error.
func (d *Device) scopedUpdate(slug string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return d.SSH(ctx, nil, "sudo env LC_ALL=C apt-get update -q -o Dir::Etc::sourcelist=sources.list.d/paddock-"+slug+
		".sources -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 2>&1")
}

// scopedUpdateUnlocked is scopedUpdate that waits for the package lists lock: the agent refreshes the same source on
// its own, and a lock it holds is retried (at most 5 times, 10 s apart, logged), never any other output.
func (d *Device) scopedUpdateUnlocked(t *testing.T, slug string) (string, error) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		out, err := d.scopedUpdate(slug)
		if !listsLocked(out) || attempt == 6 {
			return out, err
		}
		t.Logf("%s: apt lists locked (attempt %d), retrying in 10 s", d.Name, attempt)
		time.Sleep(10 * time.Second)
	}
}

// dpkgInstall installs a package file with dpkg -i as a local administrator would. dpkg has no lock timeout, so a
// frontend lock another package operation holds (the agent's drift pass) is retried, at most 12 times 10 s apart and
// logged; any other failure fails t.
func (d *Device) dpkgInstall(t *testing.T, deb string) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		out, err := d.SSH(ctx, nil, "sudo env LC_ALL=C dpkg -i "+deb+" 2>&1")
		cancel()
		switch {
		case err == nil:
			return
		case dpkgLocked(out) && attempt < 12:
			t.Logf("%s: dpkg locked (attempt %d), retrying in 10 s", d.Name, attempt)
			time.Sleep(10 * time.Second)
		default:
			t.Fatalf("%s: dpkg -i %s: %v\n%s", d.Name, deb, err, out)
		}
	}
}

// dpkgLocked reports whether dpkg stopped because another process holds its frontend or database lock (the wording
// of dpkg 1.19 and later, and the older one).
func dpkgLocked(out string) bool {
	return strings.Contains(out, "lock was locked by another process") ||
		strings.Contains(out, "database is locked by another process")
}

// lockPID matches dpkg's report of the process that holds its lock.
var lockPID = regexp.MustCompile(`locked by another process with pid (\d+)`)

// lockHolder is the PID dpkg names as holding its lock ("" when it names none).
func lockHolder(out string) string {
	if m := lockPID.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// signatureMarkers are what apt prints when a repository's signature does not verify: gpgv's NO_PUBKEY, sqv's
// "Missing key" and "No good signature" (apt 3 on Debian 13 and Ubuntu 26.04 never prints NO_PUBKEY), and the error
// for a repository left unsigned.
var signatureMarkers = []string{"NO_PUBKEY", "Missing key", "No good signature", "is not signed"}

// signatureRefused reports whether apt-get update's output refuses a signature: a marker and a W: or E: line.
func signatureRefused(out string) bool {
	return slices.ContainsFunc(signatureMarkers, func(m string) bool { return strings.Contains(out, m) }) &&
		(aptError(out) || aptLine(out, "W:"))
}

// aptError reports whether apt printed an error line.
func aptError(out string) bool { return aptLine(out, "E:") }

func aptLine(out, prefix string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return true
		}
	}
	return false
}

// listsLocked reports whether apt-get update stopped at the package lists lock another apt run holds.
func listsLocked(out string) bool {
	return strings.Contains(out, "Could not get lock") && strings.Contains(out, "/var/lib/apt/lists/lock")
}

// installedVersion is the installed version of pkg ("" when it is not installed).
func (d *Device) installedVersion(pkg string) string {
	d.t.Helper()
	// db:Status-Status ignores the selection, so a held package ("hold ok installed") counts as installed, as for the agent.
	return d.Must("dpkg-query -W -f '${db:Status-Status} ${Version}\\n' " + pkg + " 2>/dev/null | sed -n 's/^installed //p' | head -n 1")
}

// softwareSource creates the gate's source for repo with the run's suffix, as alice after a step-up, and deletes it
// with a step-up when the test ends; it returns the source's ID and slug.
func (d *Device) softwareSource(repo gateRepo) (id, slug string) {
	d.t.Helper()
	slug = "gate-" + d.run
	d.s.StepUp(d.t)
	id = d.s.ID(d.t, d.s.Call(d.t, http.MethodPost, "/api/v1/software-sources", map[string]any{
		"slug": slug, "name": "systest " + d.Name + " " + d.run, "uris": []string{gateRepoURI}, "suites": []string{"./"},
		"signing_key": repo.Key, "fingerprint": repo.Fingerprint,
	}, http.StatusCreated))
	s, t := d.s, d.t
	t.Cleanup(func() {
		s.StepUp(t)
		s.cleanupCall(t, http.MethodDelete, "/api/v1/software-sources/"+id, http.StatusNoContent, http.StatusNotFound)
	})
	return id, slug
}

// catalogEntry creates a catalog entry of pkg from source for the VM's distribution (every release and
// architecture) with the run's suffix and deletes it, with its assignments, when the test ends.
func (d *Device) catalogEntry(source, pkg string) string {
	d.t.Helper()
	distribution := d.Must(". /etc/os-release && echo \"$ID\"")
	id := d.s.ID(d.t, d.s.Call(d.t, http.MethodPost, "/api/v1/software-catalog", map[string]any{
		"name": "systest " + pkg + " " + d.Name + " " + d.run, "source_id": source,
		"packages": []map[string]any{{"distribution": distribution, "release": "*", "architecture": "*", "package": pkg}},
	}, http.StatusCreated))
	d.s.DeleteOnCleanup(d.t, "/api/v1/software-catalog/"+id)
	return id
}

// assignmentBody is an assignment's intent with its version ("" for none).
func assignmentBody(intent, version string) map[string]any {
	body := map[string]any{"intent": intent}
	if version != "" {
		body["version"] = version
	}
	return body
}

// assign assigns the entry to the device's group with intent and version ("" for none) and returns the
// assignment's ID; it goes with the entry.
func (d *Device) assign(entry, intent, version string) string {
	d.t.Helper()
	body := assignmentBody(intent, version)
	body["catalog_entry_id"], body["device_group_id"], body["reason"] = entry, d.Group, "system test "+d.run
	return d.s.ID(d.t, d.s.Call(d.t, http.MethodPost, "/api/v1/software-assignments", body, http.StatusCreated))
}

// reassign changes the intent and version of an assignment.
func (d *Device) reassign(assignment, intent, version string) {
	d.t.Helper()
	d.s.Call(d.t, http.MethodPatch, "/api/v1/software-assignments/"+assignment, assignmentBody(intent, version), http.StatusOK)
}

// eventIDs are the IDs of the device's audit events of code so far: events a later step waits for are new ones.
func (d *Device) eventIDs(code string) []string {
	d.t.Helper()
	var ids []string
	for _, e := range d.s.Events(d.t, code, d.ID) {
		ids = append(ids, e.EventID)
	}
	return ids
}

// newEvents are the device's events of code that are not in seen and match.
func (d *Device) newEvents(code string, seen []string, match func(map[string]any) bool) []portal.AuditEvent {
	d.t.Helper()
	var out []portal.AuditEvent
	for _, e := range d.s.Events(d.t, code, d.ID) {
		if !slices.Contains(seen, e.EventID) && (match == nil || match(e.Params)) {
			out = append(out, e)
		}
	}
	return out
}

// waitNewEvent waits, checking in at most every 65 s, until the device has an event of code that is not in seen
// and matches, and returns its params.
func (d *Device) waitNewEvent(t *testing.T, code string, seen []string, timeout time.Duration, match func(map[string]any) bool) map[string]any {
	t.Helper()
	var found map[string]any
	last := time.Time{}
	Until(t, d.Name+": new audit event "+code, timeout, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		if events := d.newEvents(code, seen, match); len(events) > 0 {
			found = events[0].Params
			return true
		}
		return false
	})
	return found
}

// requestEvent waits for the audit event of code that the admin API request requestID recorded.
func (s *Stack) requestEvent(t *testing.T, code, requestID string) portal.AuditEvent {
	t.Helper()
	var found portal.AuditEvent
	Until(t, "audit event "+code+" of request "+requestID, 2*time.Minute, 2*time.Second, nil, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		events, err := s.session().AuditEvents(ctx, code)
		if err != nil && strings.Contains(err.Error(), "HTTP 401") {
			t.Logf("audit events %s: HTTP 401, alice's session expired; signing in again once", code)
			s.Login(t)
			events, err = s.session().AuditEvents(ctx, code)
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.CorrelationID == requestID {
				found = e
				return true
			}
		}
		return false
	})
	return found
}
