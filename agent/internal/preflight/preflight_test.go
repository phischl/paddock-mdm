package preflight_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/preflight"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
)

type luksTools struct {
	lsblk string
	err   error
}

func (l luksTools) Command(_ context.Context, _ []string, name string, _ ...string) (string, string, int, error) {
	if l.err != nil {
		return "", "", -1, l.err
	}
	if name == "findmnt" {
		return "/dev/mapper/dm_crypt-0\n", "", 0, nil
	}
	return l.lsblk, "", 0, nil
}

const encrypted = `{"blockdevices":[{"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"ext4","children":[{"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS"}]}]}`
const plain = `{"blockdevices":[{"name":"/dev/sda2","type":"part","fstype":"ext4"}]}`

func osRelease(version string) []byte {
	return []byte("ID=ubuntu\nVERSION_ID=\"" + version + "\"\nPRETTY_NAME=\"Ubuntu " + version + " LTS\"\n")
}

// healthy is a device on which every check is ok.
func healthy() *fakesys.System {
	s := fakesys.New()
	s.Files["/etc/os-release"] = &fakesys.File{Data: osRelease("24.04")}
	s.Files["/run/systemd/system"] = &fakesys.File{}
	s.NTP = true
	return s
}

func run(t *testing.T, s *fakesys.System, tools luks.Tools, mod func(*preflight.Options)) map[string]preflight.Check {
	t.Helper()
	o := preflight.Options{Sys: s, LUKS: tools, Root: t.TempDir(), EUID: 0}
	if mod != nil {
		mod(&o)
	}
	checks := preflight.Run(context.Background(), o)
	want := []string{"os", "systemd", "root", "sudo", "tpm2", "luks", "sssd", "himmelblau", "sudoers_d", "privileged_groups", "server", "clock"}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d", len(checks), len(want))
	}
	got := map[string]preflight.Check{}
	for i, c := range checks {
		if c.Name != want[i] {
			t.Fatalf("check %d is %s, want %s", i, c.Name, want[i])
		}
		got[c.Name] = c
	}
	return got
}

func status(t *testing.T, got map[string]preflight.Check, name, want string) preflight.Check {
	t.Helper()
	if got[name].Status != want {
		t.Errorf("%s = %s (%s), want %s", name, got[name].Status, got[name].Detail, want)
	}
	return got[name]
}

func TestHealthyDevice(t *testing.T) {
	s := healthy()
	root := t.TempDir()
	tpm := filepath.Join(root, "sys/class/tpm/tpm0")
	if err := os.MkdirAll(tpm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tpm, "tpm_version_major"), []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := run(t, s, luksTools{lsblk: encrypted}, func(o *preflight.Options) { o.Root = root })
	for _, name := range []string{"os", "systemd", "root", "sudo", "tpm2", "luks", "sssd", "sudoers_d", "privileged_groups", "clock"} {
		status(t, got, name, preflight.OK)
	}
	status(t, got, "himmelblau", preflight.Info)
	status(t, got, "server", preflight.Info)
	if !strings.Contains(got["luks"].Detail, "unmanaged") || got["sudo"].Detail != "classic" {
		t.Errorf("details: luks %q sudo %q", got["luks"].Detail, got["sudo"].Detail)
	}
	if calls := s.TakeCalls(); len(calls) != 0 {
		t.Errorf("preflight changed the device: %v", calls)
	}
}

func TestOS(t *testing.T) {
	for version, want := range map[string]string{"22.04": preflight.Fail, "24.04": preflight.OK, "26.04": preflight.OK} {
		s := healthy()
		s.Files["/etc/os-release"].Data = osRelease(version)
		status(t, run(t, s, luksTools{lsblk: plain}, nil), "os", want)
	}
	s := healthy()
	s.Files["/etc/os-release"].Data = []byte("ID=debian\nVERSION_ID=\"24.04\"\n")
	status(t, run(t, s, luksTools{lsblk: plain}, nil), "os", preflight.Fail)
	delete(s.Files, "/etc/os-release")
	status(t, run(t, s, luksTools{lsblk: plain}, nil), "os", preflight.Fail)
}

func TestFailures(t *testing.T) {
	s := healthy()
	delete(s.Files, "/run/systemd/system")
	s.Links = map[string]string{}
	got := run(t, s, luksTools{lsblk: plain}, func(o *preflight.Options) { o.EUID = 1000 })
	status(t, got, "systemd", preflight.Fail)
	status(t, got, "root", preflight.Fail)
	status(t, got, "tpm2", preflight.Warn)
	status(t, got, "luks", preflight.Warn)
}

func TestSudoRSFlavor(t *testing.T) {
	s := healthy()
	s.SudoVersions = map[string]string{}
	s.Links = map[string]string{"/usr/bin/sudo": "/usr/lib/cargo/bin/sudo"}
	s.SudoVersions["/usr/lib/cargo/bin/sudo"] = "sudo-rs 0.2.8\n"
	got := run(t, s, luksTools{lsblk: plain}, nil)
	status(t, got, "sudo", preflight.OK)
	if got["sudo"].Detail != "sudo-rs" {
		t.Errorf("detail %q", got["sudo"].Detail)
	}
}

func TestLUKSCannotBeRead(t *testing.T) {
	got := run(t, healthy(), luksTools{err: errors.New("no lsblk")}, nil)
	status(t, got, "luks", preflight.Warn)
}

func TestSSSDAndHimmelblau(t *testing.T) {
	s := healthy()
	s.Packages["sssd"] = true
	s.Packages["himmelblau"], s.Versions["himmelblau"] = true, "1.2.3"
	got := run(t, s, luksTools{lsblk: plain}, nil)
	status(t, got, "sssd", preflight.Warn)
	if status(t, got, "himmelblau", preflight.Info).Detail != "installed 1.2.3" {
		t.Errorf("detail %q", got["himmelblau"].Detail)
	}
}

func TestSudoersDListsEveryEntryTheReconcilerQuarantines(t *testing.T) {
	s := healthy()
	s.Files["/etc/sudoers.d/paddock-u-alice"] = &fakesys.File{Data: []byte("x")}
	s.Files["/etc/sudoers.d/README"] = &fakesys.File{Data: []byte("x")}
	s.Files["/etc/sudoers.d/90-cloud-init-users"] = &fakesys.File{Data: []byte("x")}
	s.Files["/etc/sudoers.d/ops"] = &fakesys.File{Data: []byte("x")}
	s.Files["/etc/sudoers.d/paddock-other"] = &fakesys.File{Data: []byte("x")}
	s.Files["/etc/sudoers.d/link"] = &fakesys.File{Symlink: true}
	c := status(t, run(t, s, luksTools{lsblk: plain}, nil), "sudoers_d", preflight.Warn)
	if !strings.Contains(c.Detail, "90-cloud-init-users, link, ops, paddock-other") || strings.Contains(c.Detail, "paddock-u-alice") ||
		strings.Contains(c.Detail, "README") {
		t.Errorf("detail %q", c.Detail)
	}
}

func TestPrivilegedGroupsListsEveryMember(t *testing.T) {
	s := healthy()
	s.Members["sudo"] = []string{"alice", "bob"}
	s.Members["admin"] = []string{"carol"}
	c := status(t, run(t, s, luksTools{lsblk: plain}, nil), "privileged_groups", preflight.Warn)
	for _, m := range []string{"alice,bob", "carol"} {
		if !strings.Contains(c.Detail, m) {
			t.Errorf("detail %q lacks %s", c.Detail, m)
		}
	}
}

func TestClockWarnsWithoutNTP(t *testing.T) {
	s := healthy()
	s.NTP = false
	status(t, run(t, s, luksTools{lsblk: plain}, nil), "clock", preflight.Warn)
	if calls := s.TakeCalls(); len(calls) != 0 {
		t.Errorf("preflight changed the device: %v", calls)
	}
}

// gateway models the device gateway: only /v1 routes and a 404 problem catch-all, no /healthz.
func gateway(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"code":"not_found"}`))
}

func TestServer(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		switch {
		case strings.HasPrefix(r.URL.Path, "/portal"):
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>sign in</html>"))
		case strings.HasPrefix(r.URL.Path, "/ok200"):
			w.WriteHeader(http.StatusOK)
		default:
			gateway(w, r)
		}
	}))
	defer srv.Close()
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "enroll.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := func(url string) func(*preflight.Options) {
		return func(o *preflight.Options) {
			o.ConfigPath = write(`{"server_url":"` + url + `"}`)
			o.HTTP = srv.Client()
		}
	}
	status(t, run(t, healthy(), luksTools{lsblk: plain}, cfg(srv.URL)), "server", preflight.OK)
	if strings.HasPrefix(path, "/healthz") {
		t.Errorf("requested %q", path)
	}
	status(t, run(t, healthy(), luksTools{lsblk: plain}, cfg(srv.URL+"/portal")), "server", preflight.Fail)
	status(t, run(t, healthy(), luksTools{lsblk: plain}, cfg(srv.URL+"/ok200")), "server", preflight.Fail)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	status(t, run(t, healthy(), luksTools{lsblk: plain}, cfg(closed.URL)), "server", preflight.Fail)
	status(t, run(t, healthy(), luksTools{lsblk: plain}, func(o *preflight.Options) { o.ConfigPath = write(`{}`) }), "server", preflight.Fail)
	status(t, run(t, healthy(), luksTools{lsblk: plain}, func(o *preflight.Options) { o.ConfigPath = "/nonexistent" }), "server", preflight.Fail)
}

// TestServerProxy: the probe goes through the proxy of the options and never the environment's.
func TestServerProxy(t *testing.T) {
	var via string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		via = r.Host
		gateway(w, r)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	p := filepath.Join(t.TempDir(), "enroll.json")
	if err := os.WriteFile(p, []byte(`{"server_url":"http://device.example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	status(t, run(t, healthy(), luksTools{lsblk: plain}, func(o *preflight.Options) { o.ConfigPath, o.Proxy = p, proxy.URL }), "server", preflight.OK)
	if via != "device.example.test" {
		t.Errorf("proxy saw host %q", via)
	}
	status(t, run(t, healthy(), luksTools{lsblk: plain}, func(o *preflight.Options) { o.ConfigPath, o.Proxy = p, "://bad" }), "server", preflight.Fail)
}

func TestFailedAndOutput(t *testing.T) {
	checks := []preflight.Check{{Name: "a", Status: preflight.Warn, Detail: "d"}, {Name: "b", Status: preflight.OK, Detail: "e"}}
	if preflight.Failed(checks) {
		t.Error("warn is not a failure")
	}
	if !preflight.Failed(append(checks, preflight.Check{Name: "c", Status: preflight.Fail})) {
		t.Error("fail is a failure")
	}
	var table bytes.Buffer
	preflight.WriteTable(&table, checks)
	if lines := strings.Split(strings.TrimSpace(table.String()), "\n"); len(lines) != 2 || !strings.HasPrefix(lines[0], "a ") {
		t.Errorf("table %q", table.String())
	}
	var out bytes.Buffer
	if err := preflight.WriteJSON(&out, checks); err != nil {
		t.Fatal(err)
	}
	var back []preflight.Check
	if err := json.Unmarshal(out.Bytes(), &back); err != nil || len(back) != 2 || back[1].Status != preflight.OK {
		t.Errorf("json %s: %v", out.String(), err)
	}
}
