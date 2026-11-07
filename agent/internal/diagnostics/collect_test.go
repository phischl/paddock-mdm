package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/desktop"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	volume      = "6f1c2c1e-1b7d-4a49-9c55-0d6a1c3b2e10"
	otherVolume = "0b5d7c0e-55a4-4d8e-8f0e-6a3c1a2f9b11"
)

type fixedHealth struct{ r health.Report }

func (f fixedHealth) Report() health.Report { return f.r }

func sources() Sources {
	return Sources{
		Health: fixedHealth{health.Report{Status: "ok", Version: "1.2.3", Disk: &protocol.DiskHealth{Volumes: []protocol.DiskVolume{
			{UUID: volume, Root: true}, {UUID: otherVolume}, {UUID: "../../etc/shadow"}, {UUID: volume, SharedUUID: true},
		}}}},
		Healthz:      func(context.Context) ([]byte, error) { return []byte("HTTP 200\nok\n"), nil },
		DeviceID:     "dev-1",
		AgentVersion: "1.2.3",
		Now:          time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC),
	}
}

// commandLine is the command line Collect runs for an exec or journal entry.
func commandLine(e Entry) string {
	if e.Kind == KindJournal {
		return "journalctl -u " + e.Source + " --since=-7d --no-pager -o short-iso --reverse"
	}
	return e.Source
}

func luksLine(uuid string) string { return "cryptsetup luksDump -- /dev/disk/by-uuid/" + uuid }

// Planted secrets: none of them may appear in any archive file.
const (
	identityKey    = "-----BEGIN PRIVATE KEY-----planted-identity"
	enrollToken    = "pdk_enroll_planted_token_value"
	shadowHash     = "$y$j9T$planted$shadowhash"
	clientSecret   = "planted-client-secret-value"
	proxyPassword  = "planted-proxy@password"
	enrollSecret   = "planted-enroll-aaaa"
	fileContent    = "planted-file-content-aaaa"
	repoPassword   = "planted-repo@aaaa"
	cifsPassword   = "planted-cifs-aaaa"
	userFile       = "planted thesis of alice"
	rootHistory    = "planted root history"
	luksPassphrase = "planted install passphrase"
	stateIdentity  = "planted-identity-in-state"
	aptUser        = "alice (1000)"
	macAddress     = "52:54:00:12:34:56"
)

func device() *fakesys.System {
	sys := fakesys.New()
	file := func(p, data string) { sys.Files[p] = &fakesys.File{Data: []byte(data), Mode: 0o644} }
	file("/var/lib/paddock/identity/sign.key", identityKey)
	file("/etc/paddock/enroll.json", `{"token":"`+enrollToken+`"}`)
	file("/var/lib/paddock/install-passphrase", luksPassphrase)
	file("/etc/shadow", "root:"+shadowHash+":20000::::::\n")
	file("/home/alice/thesis.odt", userFile)
	file("/root/.bash_history", rootHistory)
	file("/var/lib/paddock/state/state.json", `{"device_id":"dev-1","seq":7,"identity_key":"`+stateIdentity+
		`","local_admin":{"username":"padmin","shadow_sha256":"abc"},"luks":{"keyslots":["recovery"]}}`)
	file("/var/lib/paddock/state/managed.json", `{"files":{}}`)
	file("/var/lib/paddock/state/bundle.dsse", string(bundleEnvelope()))
	file("/etc/paddock/trust.json", `{"keys":[]}`)
	file("/etc/paddock/agent.yml", "server_url: https://paddock.example\nproxy: http://svc:"+proxyPassword+"@proxy.example:3128\n")
	file("/etc/sudoers", "Defaults env_reset\n")
	file("/etc/sudoers.d/paddock-u-alice", "alice ALL=(ALL) ALL\n")
	file("/etc/sudoers.d/vagrant", "vagrant ALL=(ALL) NOPASSWD: ALL\n")
	sys.Files["/etc/sudoers.d/link"] = &fakesys.File{Symlink: true, Data: []byte(shadowHash)}
	file("/etc/pam.d/common-auth", "auth required pam_unix.so\n")
	file("/etc/pam.d/sshd", "@include common-auth\n")
	file("/etc/nsswitch.conf", "passwd: files himmelblau\n")
	file("/etc/himmelblau/himmelblau.conf", "[global]\ndomains = acme.test\napp_secret = "+clientSecret+
		"\n# client_password: "+clientSecret+"\nhsm_key "+clientSecret+"\nPassword_Policy="+clientSecret+"\n")
	file("/etc/apt/sources.list.d/paddock-agent.sources", "Types: deb\n")
	file("/etc/apt/sources.list.d/ubuntu.sources", "Types: deb\n")
	file("/etc/apt/preferences.d/50paddock", "Package: *\n")
	file("/etc/crypttab", "dm_crypt-0 UUID="+volume+" none luks\n")
	file("/etc/fstab", "UUID="+volume+" / ext4 defaults 0 1\n//nas/share /mnt/nas cifs username=alice,password="+cifsPassword+",,"+cifsPassword+
		",uid=1000 0 0\n//nas/b /mnt/b cifs pass="+cifsPassword+" 0 0\n")
	file("/usr/lib/os-release", "ID=ubuntu\n")
	file("/var/log/apt/history.log", "Start-Date: 2026-11-01\nCommandline: apt-get install vim\nRequested-By: "+aptUser+
		"\nInstall: vim:amd64 (2:9.1)\n")
	sys.Files["/dev/tpmrm0"] = &fakesys.File{Mode: 0o600}
	sys.Outputs = map[string]fakesys.OutputReply{luksLine(volume): {Data: []byte("LUKS header information\n")}}
	for _, e := range Entries() {
		switch e.Kind {
		case KindExec, KindJournal:
			sys.Outputs[commandLine(e)] = fakesys.OutputReply{Data: []byte(e.Name + " output\n")}
		}
	}
	sys.Outputs["ip -brief link"] = fakesys.OutputReply{Data: []byte("enp1s0 UP " + macAddress + " <BROADCAST,UP>\n")}
	return sys
}

// bundleEnvelope is a signed bundle as the device keeps it: its payload carries the Fleet enroll secret, the content
// of a managed file and a package source with credentials.
func bundleEnvelope() []byte {
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, BundleVersion: 3, DeviceID: "dev-1", OrganizationID: "org-1",
		Resources: []bundle.Resource{{ID: "file:/etc/motd", Type: bundle.TypeFile,
			Spec: json.RawMessage(`{"path":"/etc/motd","mode":"0644","owner":"root","group":"root","content":"` + fileContent +
				`","content_sha256":"00"}`)}},
		Inventory: &bundle.Inventory{FleetURL: "https://fleet.example", EnrollSecret: enrollSecret},
		Software: &bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{{Slug: "acme",
			URIs: []string{"https://acme:" + repoPassword + "@repo.example/ubuntu"}}}}}
	payload, _ := json.Marshal(b)
	env, _ := dsse.New(bundle.PayloadType, payload, dsse.Signature{KeyID: "bundle:v1", Sig: "c2ln"}).Encode()
	return env
}

func untar(t *testing.T, archive []byte) (names []string, files map[string][]byte) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	files = map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names, files
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Mode != 0o600 || h.Typeflag != tar.TypeReg {
			t.Fatalf("%s: mode %o type %c", h.Name, h.Mode, h.Typeflag)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		files[h.Name] = data
	}
}

// TestEntriesClosedList: unique names, a cap on every entry, file sources absolute and never below a home directory
// or the identity directory, commands only from a fixed set of read-only tools.
func TestEntriesClosedList(t *testing.T) {
	tools := []string{"systemctl", "uname", "timedatectl", "df", "uptime", "lsblk", "cryptsetup", "dpkg", "ip", "resolvectl"}
	seen := map[string]bool{}
	for _, e := range Entries() {
		if seen[e.Name] || e.Name == "manifest.json" || e.MaxBytes <= 0 || e.Source == "" {
			t.Fatalf("entry %+v", e)
		}
		seen[e.Name] = true
		switch e.Kind {
		case KindFile, KindGlob, KindTPM:
			for _, src := range strings.Fields(e.Source) {
				if !filepath.IsAbs(src) || filepath.Clean(src) != src {
					t.Fatalf("%s: source %q is not absolute", e.Name, src)
				}
				for _, banned := range []string{"/home", "/root", "/var/lib/paddock/identity", "/etc/shadow", "/etc/paddock/enroll.json",
					"/var/lib/paddock/install-passphrase"} {
					if src == banned || strings.HasPrefix(src, banned+"/") {
						t.Fatalf("%s: source %q lies below %s", e.Name, src, banned)
					}
				}
			}
		case KindExec, KindLUKS:
			if !slices.Contains(tools, strings.Fields(e.Source)[0]) {
				t.Fatalf("%s: tool %q", e.Name, e.Source)
			}
		case KindJournal:
			if e.MaxBytes != MaxJournal || strings.ContainsAny(e.Source, " /") {
				t.Fatalf("%s: journal %+v", e.Name, e)
			}
		case KindHealth, KindHealthz:
		default:
			t.Fatalf("%s: kind %q", e.Name, e.Kind)
		}
	}
}

// TestCollect: the manifest lists exactly Entries() in order, the archive holds manifest.json first and the files of
// the manifest only, missing files and failed commands are entries with an error, and no planted secret, user file
// or address leaves the device.
func TestCollect(t *testing.T) {
	sys := device()
	sys.Outputs["uptime -p"] = fakesys.OutputReply{Exit: 1}
	sys.Outputs[unitStatusCommand()] = fakesys.OutputReply{Data: []byte(unitShow)}
	var archive bytes.Buffer
	m, err := Collect(context.Background(), sys, sources(), &archive)
	if err != nil {
		t.Fatal(err)
	}
	names, files := untar(t, archive.Bytes())
	if names[0] != "manifest.json" {
		t.Fatalf("first file %s", names[0])
	}
	var got Manifest
	if err := json.Unmarshal(files["manifest.json"], &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != Schema || got.DeviceID != "dev-1" || got.AgentVersion != "1.2.3" || !got.CollectedAt.Equal(sources().Now) {
		t.Fatalf("manifest %+v", got)
	}
	var want []string
	for _, e := range Entries() {
		want = append(want, e.Name)
	}
	var listed, members []string
	byName := map[string]ManifestEntry{}
	for _, e := range got.Entries {
		listed = append(listed, e.Name)
		byName[e.Name] = e
		if e.SHA256 != "" {
			members = append(members, e.Name)
			checkFile(t, files, File{Name: e.Name, Bytes: e.Bytes, SHA256: e.SHA256})
		}
		for _, f := range e.Files {
			members = append(members, f.Name)
			checkFile(t, files, f)
		}
	}
	if !slices.Equal(listed, want) {
		t.Fatalf("manifest entries %v, want %v", listed, want)
	}
	if !slices.Equal(names[1:], members) || m.Files() != len(members) {
		t.Fatalf("archive %v, manifest files %v (%d)", names[1:], members, m.Files())
	}
	for _, name := range []string{"paddock/probation.json", "paddock/update-result.json", "system/uptime.txt"} {
		if e := byName[name]; e.Error == "" || e.Bytes != 0 || e.SHA256 != "" {
			t.Fatalf("%s: %+v, want an error and no content", name, e)
		}
	}
	if e := byName["systemd/status.txt"]; e.Error != "" || string(files["systemd/status.txt"]) != unitShow {
		t.Fatalf("unit status: %+v\n%s", e, files["systemd/status.txt"])
	}
	if fs := byName["etc/sudoers.d"].Files; len(fs) != 2 || fs[0].Name != "etc/sudoers.d/paddock-u-alice" || fs[1].Name != "etc/sudoers.d/vagrant" {
		t.Fatalf("sudoers.d %+v", fs)
	}
	if fs := byName["etc/pam.d"].Files; len(fs) != 1 || fs[0].Name != "etc/pam.d/common-auth" {
		t.Fatalf("pam.d %+v", fs)
	}
	if fs := byName["etc/apt/sources.list.d"].Files; len(fs) != 1 {
		t.Fatalf("sources %+v", fs)
	}
	if e := byName["system/luksDump"]; len(e.Files) != 1 || e.Files[0].Name != "system/luksDump-"+volume+".txt" ||
		!strings.Contains(e.Error, otherVolume) {
		t.Fatalf("luksDump %+v", e)
	}
	if string(files["system/tpm.txt"]) != "/dev/tpm0 present=false\n/dev/tpmrm0 present=true\n" {
		t.Fatalf("tpm %q", files["system/tpm.txt"])
	}
	if string(files["system/server-healthz.txt"]) != "HTTP 200\nok\n" {
		t.Fatalf("healthz %q", files["system/server-healthz.txt"])
	}
	var h health.Report
	if json.Unmarshal(files["paddock/health.json"], &h) != nil || h.Version != "1.2.3" {
		t.Fatalf("health %s", files["paddock/health.json"])
	}
	var st map[string]any
	if json.Unmarshal(files["paddock/state.json"], &st) != nil || st["device_id"] != "dev-1" || st["identity_key"] != nil {
		t.Fatalf("state %s", files["paddock/state.json"])
	}
	conf := string(files["etc/himmelblau/himmelblau.conf"])
	secretLine := regexp.MustCompile(`(?i)secret|password|key`)
	for _, line := range strings.Split(strings.TrimSpace(conf), "\n") {
		if secretLine.MatchString(line) && !strings.HasSuffix(line, Redacted) {
			t.Fatalf("himmelblau.conf line %q not redacted", line)
		}
	}
	if !strings.Contains(conf, "domains = acme.test\n") || !strings.Contains(conf, "app_secret = <redacted>\n") {
		t.Fatalf("himmelblau.conf %q", conf)
	}
	var rendered struct {
		Note       string           `json:"note"`
		Signatures []dsse.Signature `json:"signatures"`
		Payload    struct {
			DeviceID  string `json:"device_id"`
			Inventory struct {
				FleetURL     string `json:"fleet_url"`
				EnrollSecret string `json:"enroll_secret"`
			} `json:"inventory"`
			Resources []struct {
				Spec map[string]any `json:"spec"`
			} `json:"resources"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(files["paddock/bundle-redacted.json"], &rendered); err != nil || rendered.Payload.DeviceID != "dev-1" ||
		rendered.Payload.Inventory.EnrollSecret != Redacted || rendered.Payload.Inventory.FleetURL != "https://fleet.example" ||
		len(rendered.Signatures) != 1 || rendered.Signatures[0].KeyID != "bundle:v1" || !strings.Contains(rendered.Note, "not the signed envelope") ||
		len(rendered.Payload.Resources) != 1 || rendered.Payload.Resources[0].Spec["content"] != Redacted ||
		rendered.Payload.Resources[0].Spec["path"] != "/etc/motd" {
		t.Fatalf("bundle %v %s", err, files["paddock/bundle-redacted.json"])
	}
	if _, ok := files["paddock/bundle.dsse"]; ok {
		t.Fatal("the signed envelope is archived")
	}
	if got := string(files["etc/fstab"]); !strings.Contains(got, "username=alice,password=<redacted>,uid=1000") ||
		!strings.Contains(got, " pass=<redacted> 0 0") || !strings.Contains(got, " / ext4 defaults 0 1\n") {
		t.Fatalf("fstab %q", got)
	}
	if got := string(files["paddock/agent.yml"]); !strings.Contains(got, "proxy: http://<redacted>@proxy.example:3128\n") {
		t.Fatalf("agent.yml %q", got)
	}
	if !strings.Contains(string(files["system/apt-history.log"]), "Install: vim:amd64") {
		t.Fatalf("apt history %q", files["system/apt-history.log"])
	}
	for name, data := range files {
		for _, secret := range []string{identityKey, enrollToken, shadowHash, clientSecret, proxyPassword, userFile, rootHistory,
			luksPassphrase, stateIdentity, aptUser, macAddress, "shadow_sha256", "password@proxy", enrollSecret, fileContent,
			repoPassword, "aaaa@repo", cifsPassword} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("%s contains the planted %q", name, secret)
			}
		}
		if strings.HasPrefix(name, "home/") || strings.HasPrefix(name, "root/") || strings.Contains(name, "identity") {
			t.Fatalf("archive file %s", name)
		}
	}
	for _, call := range sys.OutputCalls {
		if strings.Contains(call, "..") {
			t.Fatalf("command with an unchecked volume: %s", call)
		}
	}
}

func checkFile(t *testing.T, files map[string][]byte, f File) {
	t.Helper()
	data, ok := files[f.Name]
	sum := sha256.Sum256(data)
	if !ok || int64(len(data)) != f.Bytes || hex.EncodeToString(sum[:]) != f.SHA256 {
		t.Fatalf("%s: archived %d bytes, manifest %+v", f.Name, len(data), f)
	}
}

// TestCollectCaps: with every entry over its cap, each journal is cut at 8 MiB (newest first: the start is kept), the
// content stops at MaxContent, entries after it are not read and the archive stays under 24 MiB.
func TestCollectCaps(t *testing.T) {
	rnd := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // test data
	random := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rnd.Uint32())
		}
		return b
	}
	sys := device()
	for p, f := range sys.Files {
		if !f.Symlink && f.Data != nil && !strings.HasPrefix(p, "/dev/") {
			f.Data = random(5 << 20)
		}
	}
	journal := random(10 << 20)
	for line := range sys.Outputs {
		sys.Outputs[line] = fakesys.OutputReply{Data: journal}
	}
	var archive bytes.Buffer
	m, err := Collect(context.Background(), sys, sources(), &archive)
	if err != nil {
		t.Fatal(err)
	}
	if archive.Len() >= MaxArchive {
		t.Fatalf("archive %d bytes", archive.Len())
	}
	_, files := untar(t, archive.Bytes())
	var content int64
	for name, data := range files {
		if name != "manifest.json" {
			content += int64(len(data))
		}
	}
	if content != MaxContent {
		t.Fatalf("content %d bytes, want the budget %d", content, MaxContent)
	}
	paddockd := files["journal/paddockd.log"]
	if !bytes.Equal(paddockd, journal[:len(paddockd)]) {
		t.Fatal("the journal does not keep its newest (first) lines")
	}
	truncated := m.Truncated()
	for _, name := range []string{"paddock/managed.json", "system/uname.txt", "journal/paddockd.log", "journal/himmelblaud-tasks.log",
		"etc/sudoers.d/vagrant"} {
		if !slices.Contains(truncated, name) {
			t.Fatalf("%s not truncated: %v", name, truncated)
		}
	}
	if last := "journalctl -u himmelblaud-tasks.service --since=-7d --no-pager -o short-iso --reverse"; slices.Contains(sys.OutputCalls, last) {
		t.Fatal("an entry was read after the budget was spent")
	}
	for _, e := range m.Entries {
		if e.Bytes > MaxJournal {
			t.Fatalf("%s: %d bytes", e.Name, e.Bytes)
		}
	}
}

// TestCollectWriteFails: only a failed write aborts the archive.
func TestCollectWriteFails(t *testing.T) {
	if _, err := Collect(context.Background(), device(), sources(), failingWriter{}); err == nil {
		t.Fatal("no error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestNotice(t *testing.T) {
	summary, body := Notice(desktop.German, "Ticket 42\nAnmeldung")
	if summary != "Paddock: Diagnosedaten erfasst" || !strings.Contains(body, "Grund: Ticket 42 Anmeldung.") ||
		!strings.Contains(body, "keine persönlichen Dateien") {
		t.Fatalf("de: %q %q", summary, body)
	}
	_, body = Notice(desktop.English, "VPN fails")
	if body != "Paddock collected diagnostic data from this device for your administrator. Reason: VPN fails. "+
		"What was collected: Paddock's own logs and configuration, no personal files." {
		t.Fatalf("en: %q", body)
	}
}

// TestNoticeEscapesMarkup: the reason cannot add markup to the notification body.
func TestNoticeEscapesMarkup(t *testing.T) {
	_, body := Notice(desktop.English, `R&D <a href="https://x.example">login</a>`)
	if !strings.Contains(body, `Reason: R&amp;D &lt;a href="https://x.example"&gt;login&lt;/a&gt;.`) {
		t.Fatalf("%q", body)
	}
}

// TestRedactURLCredentials: the user information is removed up to the last "@" of the authority.
func TestRedactURLCredentials(t *testing.T) {
	in := "proxy: http://user:p@ss@proxy:3128\nserver_url: https://paddock.example/x@y\n"
	if got := string(redactURLCredentials([]byte(in))); got != "proxy: http://<redacted>@proxy:3128\nserver_url: https://paddock.example/x@y\n" {
		t.Fatalf("%q", got)
	}
}

// TestRedactBundleUndecodable: an envelope that does not decode, or a payload that is not JSON, is replaced whole.
func TestRedactBundleUndecodable(t *testing.T) {
	notJSON, _ := dsse.New(bundle.PayloadType, []byte("enroll_secret "+enrollSecret), dsse.Signature{KeyID: "k", Sig: "c2ln"}).Encode()
	for _, in := range [][]byte{[]byte(`{"payload":"` + enrollSecret + `"}`), notJSON} {
		if got := string(redactBundle(in)); got != Redacted+"\n" {
			t.Fatalf("%q", got)
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	in := "a = 1\nclient_secret=xyz\nno newline key"
	if got := string(RedactSecrets([]byte(in))); got != "a = 1\nclient_secret= <redacted>\n<redacted>" {
		t.Fatalf("%q", got)
	}
}

// TestCollectJournalCap: a journal over 8 MiB is cut at 8 MiB and reported as truncated.
func TestCollectJournalCap(t *testing.T) {
	sys := device()
	big := bytes.Repeat([]byte("2026-11-05T10:00:00+0000 host paddockd: check-in\n"), 9<<20/48)
	sys.Outputs["journalctl -u himmelblaud.service --since=-7d --no-pager -o short-iso --reverse"] = fakesys.OutputReply{Data: big}
	var archive bytes.Buffer
	m, err := Collect(context.Background(), sys, sources(), &archive)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Truncated(), []string{"journal/himmelblaud.log"}) {
		t.Fatalf("truncated %v", m.Truncated())
	}
	_, files := untar(t, archive.Bytes())
	if got := files["journal/himmelblaud.log"]; len(got) != MaxJournal || !bytes.Equal(got, big[:MaxJournal]) {
		t.Fatalf("journal %d bytes", len(got))
	}
}

// unitStatusCommand is the command line of systemd/status.txt as the fake system receives it.
func unitStatusCommand() string {
	for _, e := range Entries() {
		if e.Name == "systemd/status.txt" {
			return e.Source
		}
	}
	panic("no systemd/status.txt entry")
}

// unitShow is what `systemctl show` answers for two of the units: a running one and one that is not installed.
const unitShow = `Result=success
ExecMainStartTimestamp=Thu 2026-11-05 08:12:01 CET
ExecMainExitTimestamp=
ExecMainStatus=0
ActiveState=active
SubState=running
StateChangeTimestamp=Thu 2026-11-05 08:12:01 CET
ActiveEnterTimestamp=Thu 2026-11-05 08:12:01 CET
ActiveExitTimestamp=
InactiveEnterTimestamp=

Result=success
ExecMainStartTimestamp=
ExecMainExitTimestamp=
ExecMainStatus=0
ActiveState=inactive
SubState=dead
StateChangeTimestamp=
ActiveEnterTimestamp=
ActiveExitTimestamp=
InactiveEnterTimestamp=
`

// unitShowUnlisted is what `systemctl show` answers beyond the requested properties (a unit file's command line
// with its arguments, process ids, the cgroup) plus a key that only resembles a listed one: a redactor that keeps
// any <key>=<value> line leaks them, so the allow list of keepUnitState is what this proves.
const unitShowUnlisted = `ExecStart={ path=/opt/orbit/bin/orbit ; argv[]=/opt/orbit/bin/orbit --enroll_secret_path=/opt/orbit/secret.txt ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
MainPID=1234
ExecMainPID=1234
ControlGroup=/system.slice/orbit.service
ActiveStateX=leak
`

// unitStatusFull is `systemctl status --full` of orbit: the unit's processes with their command lines (the CGroup
// tree) and its newest journal lines.
const unitStatusFull = `● orbit.service - Orbit osquery
     Loaded: loaded (/usr/lib/systemd/system/orbit.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-11-05 08:12:01 CET; 2h ago
   Main PID: 1234 (orbit)
      Tasks: 31 (limit: 9389)
     Memory: 120.4M (peak: 180.2M)
        CPU: 1min 2.345s
     CGroup: /system.slice/orbit.service
             ├─1234 /opt/orbit/bin/orbit/linux/stable/orbit
             └─1301 /opt/orbit/bin/osqueryd/linux/stable/osqueryd --pidfile=/opt/orbit/osquery.pid --enroll_secret_path=/opt/orbit/secret.txt
Nov 05 10:01:02 ws-alice orbit[1234]: 2026-11-05T09:01:02Z INF enroll user=alice@acme.test
Nov 05 10:01:03 ws-alice osqueryd[1301]: I1105 query "SELECT * FROM users" by alice
`

// TestUnitStatusHoldsNoProcessesOrJournal (decision of 2026-11-05 on PDK-791): systemd/status.txt is `systemctl
// show` of the state properties only, and whatever else the command answers — the CGroup tree with the command
// lines of `systemctl status --full`, its journal lines — never reaches the archive.
func TestUnitStatusHoldsNoProcessesOrJournal(t *testing.T) {
	cmd := strings.Fields(unitStatusCommand())
	if cmd[0] != "systemctl" || cmd[1] != "show" || cmd[2] != "--property="+strings.Join(UnitStateProperties, ",") {
		t.Fatalf("systemd/status.txt runs %q, want systemctl show --property=<state properties>", unitStatusCommand())
	}
	for _, arg := range cmd[3:] {
		if strings.HasPrefix(arg, "-") {
			t.Fatalf("systemd/status.txt passes the option %q", arg)
		}
	}
	sys := device()
	sys.Outputs[unitStatusCommand()] = fakesys.OutputReply{Data: []byte(unitShow + unitShowUnlisted + "\n" + unitStatusFull)}
	var archive bytes.Buffer
	if _, err := Collect(context.Background(), sys, sources(), &archive); err != nil {
		t.Fatal(err)
	}
	_, files := untar(t, archive.Bytes())
	if got := string(files["systemd/status.txt"]); got != unitShow+"\n" {
		t.Fatalf("systemd/status.txt holds more than the state properties:\n%s", got)
	}
	for name, data := range files {
		for _, leak := range []string{"CGroup", "osqueryd", "/opt/orbit", "enroll_secret_path", "alice@acme.test", "Main PID", "Nov 05 10:01",
			"ExecStart", "argv[]", "MainPID", "ControlGroup", "ActiveStateX"} {
			if bytes.Contains(data, []byte(leak)) {
				t.Errorf("%s holds %q of systemctl status", name, leak)
			}
		}
	}
}
