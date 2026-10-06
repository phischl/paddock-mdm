package autoinstall_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oasdiff/yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/phischl/paddock-mdm/server/internal/autoinstall"
)

// The schema is testdata/autoinstall-schema.json, a copy of autoinstall-schema.json of canonical/subiquity at
// commit 9be1dcefdf8bc6a75475e25fe19e2805db9d2826 (SHA-256 beb72fef…a2ae), vendored as test data (plan M4b
// decision 3).

const enrollmentConfig = `{"server_url":"https://device.paddock.example","organization_id":"0193f7a2-6c1e-7cc1-9d1e-6a4f0f6e8a10",` +
	`"token":"secret-token","bundle_keys":[{"key_id":"bundle-signing:v1","public_key":"AAAA"}]}`

func input(release string) autoinstall.Input {
	return autoinstall.Input{
		Release: release, Hostname: "laptop-0042", Locale: "de_DE.UTF-8", KeyboardLayout: "de", Timezone: "Europe/Berlin",
		EnrollmentConfig: []byte(enrollmentConfig), AgentVersion: "1.4.0", BootPINMinLength: 10,
		Packages: []autoinstall.Package{
			{Name: "paddock-supervisor", URL: "https://bundles.paddock.example/packages/1.4.0/paddock-supervisor_1.4.0_amd64.deb", SHA256: strings.Repeat("a", 64)},
			{Name: "paddock-agent", URL: "https://bundles.paddock.example/packages/1.4.0/paddock-agent_1.4.0_amd64.deb", SHA256: strings.Repeat("b", 64)},
		},
	}
}

// userData is the parsed autoinstall section of a rendering.
type userData struct {
	raw  []byte
	json []byte // the autoinstall section as JSON
	doc  struct {
		Identity struct {
			Hostname, Username, Password string
		}
		Storage struct {
			Layout struct{ Name, Password string }
		}
		Locale, Timezone string
		Keyboard         struct{ Layout string }
		Packages         []string
		LateCommands     []any `json:"late-commands"`
		Shutdown         string
	}
}

func render(t *testing.T, in autoinstall.Input) userData {
	t.Helper()
	raw, err := autoinstall.Render(in, time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("#cloud-config\n")) {
		t.Fatalf("user-data does not start with #cloud-config:\n%s", raw)
	}
	all, err := yaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatalf("user-data is not YAML: %v\n%s", err, raw)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(all, &top); err != nil || len(top) != 1 || top["autoinstall"] == nil {
		t.Fatalf("want exactly the key autoinstall, got %s", all)
	}
	u := userData{raw: raw, json: top["autoinstall"]}
	if err := json.Unmarshal(u.json, &u.doc); err != nil {
		t.Fatal(err)
	}
	return u
}

// commands returns the late-commands as argument lists.
func (u userData) commands(t *testing.T) [][]string {
	t.Helper()
	var out [][]string
	for _, c := range u.doc.LateCommands {
		list, ok := c.([]any)
		if !ok {
			t.Fatalf("late-command %v is not an argument list", c)
		}
		var args []string
		for _, a := range list {
			args = append(args, a.(string))
		}
		out = append(out, args)
	}
	return out
}

// find returns the first command whose arguments contain all of parts.
func find(cmds [][]string, parts ...string) []string {
	for _, c := range cmds {
		if !slices.ContainsFunc(parts, func(p string) bool { return !slices.Contains(c, p) }) {
			return c
		}
	}
	return nil
}

func TestRenderMatchesSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "autoinstall-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("autoinstall-schema.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("autoinstall-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, release := range autoinstall.Releases {
		t.Run(release, func(t *testing.T) {
			u := render(t, input(release))
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(u.json))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(inst); err != nil {
				t.Fatalf("%s user-data violates the autoinstall schema: %v\n%s", release, err, u.raw)
			}
		})
	}
}

func TestRenderContent(t *testing.T) {
	alnum := regexp.MustCompile(`^[A-Za-z0-9]{32,}$`)
	for _, release := range autoinstall.Releases {
		t.Run(release, func(t *testing.T) {
			in := input(release)
			u := render(t, in)
			d := u.doc
			if d.Storage.Layout.Name != "lvm" || !alnum.MatchString(d.Storage.Layout.Password) {
				t.Errorf("storage %+v: want lvm with a random alphanumeric passphrase of at least 32 characters", d.Storage.Layout)
			}
			if d.Identity.Hostname != "laptop-0042" || d.Identity.Username != autoinstall.InstallUser || d.Identity.Password != "!" {
				t.Errorf("identity %+v: want the hostname and the locked installer account", d.Identity)
			}
			if d.Locale != "de_DE.UTF-8" || d.Keyboard.Layout != "de" || d.Timezone != "Europe/Berlin" || d.Shutdown != "poweroff" {
				t.Errorf("locale %q keyboard %q timezone %q shutdown %q", d.Locale, d.Keyboard.Layout, d.Timezone, d.Shutdown)
			}
			if !slices.Contains(d.Packages, "tpm2-tools") || !slices.Contains(d.Packages, "cryptsetup") {
				t.Errorf("packages %v: want tpm2-tools and cryptsetup", d.Packages)
			}
			cmds := u.commands(t)
			for _, p := range in.Packages {
				if find(cmds, "in-target", "python3", p.URL, p.SHA256, "/tmp/"+p.Name+".deb") == nil {
					t.Errorf("no verified download of %s", p.Name)
				}
			}
			if find(cmds, "apt-get", "install", "/tmp/paddock-supervisor.deb", "/tmp/paddock-agent.deb") == nil {
				t.Error("packages are not installed")
			}
			enroll := find(cmds, "sh", "-c", "umask 077 && printf %s \"$1\" | base64 -d > /target/etc/paddock/enroll.json")
			if enroll == nil {
				t.Fatal("no enroll.json")
			}
			if cfg, err := base64.StdEncoding.DecodeString(enroll[len(enroll)-1]); err != nil || string(cfg) != enrollmentConfig {
				t.Errorf("enroll.json %q, %v", cfg, err)
			}
			pass := find(cmds, d.Storage.Layout.Password)
			if pass == nil || !strings.Contains(strings.Join(pass, " "), "umask 077") || !strings.Contains(strings.Join(pass, " "), "/target/var/lib/paddock/install-passphrase") {
				t.Errorf("passphrase file: %q", pass)
			}
			if find(cmds, `{"boot_pin_min_length":10}`) == nil || find(cmds, "touch", "/target/var/lib/paddock/disk-setup-pending") == nil {
				t.Error("disk setup configuration or pending marker missing")
			}
			if find(cmds, "sed", "/etc/crypttab") == nil || find(cmds, "dracut", "-f", "--regenerate-all") == nil {
				t.Error("crypttab or initramfs rebuild missing")
			}
			if find(cmds, "passwd -l") == nil && find(cmds, "! id -- \"$1\" >/dev/null 2>&1 || passwd -l -- \"$1\"") == nil {
				t.Error("the installer account is not locked")
			}
			dracutSwitch := find(cmds, "apt-get", "install", "dracut") != nil
			if dracutSwitch != (release == "24.04") {
				t.Errorf("dracut switch %v on %s", dracutSwitch, release)
			}
			if release == "24.04" {
				conf := find(cmds, `hostonly="yes"`, `add_dracutmodules+=" systemd crypt tpm2-tss lvm "`)
				if conf == nil || !strings.Contains(conf[2], "/target/etc/dracut.conf.d/90-paddock-tpm2.conf") {
					t.Errorf("dracut configuration %q", conf)
				}
			}
		})
	}
}

func TestRenderNewPassphraseEachTime(t *testing.T) {
	a, b := render(t, input("26.04")), render(t, input("26.04"))
	if a.doc.Storage.Layout.Password == b.doc.Storage.Layout.Password {
		t.Fatal("two renderings share the passphrase")
	}
}

func TestValidate(t *testing.T) {
	ok := []string{"24.04", "laptop-0042", "en_US.UTF-8", "us", "Etc/UTC"}
	if err := autoinstall.Validate(ok[0], ok[1], ok[2], ok[3], ok[4]); err != nil {
		t.Fatal(err)
	}
	for _, tz := range []string{"America/Argentina/Buenos_Aires", "UTC", "Europe/Berlin"} {
		if err := autoinstall.Validate("26.04", "a", "de_DE.UTF-8", "de", tz); err != nil {
			t.Errorf("%s: %v", tz, err)
		}
	}
	bad := map[string]struct {
		field int
		value string
		want  error
	}{
		"release":           {0, "22.04", autoinstall.ErrRelease},
		"hostname upper":    {1, "Laptop", autoinstall.ErrHostname},
		"hostname dot":      {1, "laptop.example.com", autoinstall.ErrHostname},
		"hostname quote":    {1, `a"b`, autoinstall.ErrHostname},
		"hostname long":     {1, strings.Repeat("a", 64), autoinstall.ErrHostname},
		"hostname hyphen":   {1, "-a", autoinstall.ErrHostname},
		"locale no charset": {2, "en_US", autoinstall.ErrLocale},
		"locale injection":  {2, "en_US.UTF-8\nx: y", autoinstall.ErrLocale},
		"keyboard":          {3, "us; reboot", autoinstall.ErrKeyboard},
		"timezone dots":     {4, "../../etc/passwd", autoinstall.ErrTimezone},
		"timezone space":    {4, "Europe/ Berlin", autoinstall.ErrTimezone},
	}
	for name, c := range bad {
		args := slices.Clone(ok)
		args[c.field] = c.value
		if err := autoinstall.Validate(args[0], args[1], args[2], args[3], args[4]); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

// TestCrypttabScript runs the late-command's sed expression on crypttab lines: only LUKS entries without a TPM2
// option change, comments stay.
func TestCrypttabScript(t *testing.T) {
	cmds := render(t, input("26.04")).commands(t)
	sed := find(cmds, "sed", "/etc/crypttab")
	file := filepath.Join(t.TempDir(), "crypttab")
	in := "# <target name> <source device> <key file> <options>\n" +
		"dm_crypt-0 UUID=1234 none luks,discard\n" +
		"swap /dev/sdb2 /dev/urandom swap\n" +
		"data UUID=5678 none luks,tpm2-device=/dev/tpmrm0\n"
	if err := os.WriteFile(file, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append(slices.Clone(sed[slices.Index(sed, "sed")+1:len(sed)-1]), file)
	if out, err := exec.Command("sed", args...).CombinedOutput(); err != nil {
		t.Fatalf("sed: %v %s", err, out)
	}
	got, _ := os.ReadFile(file)
	want := "# <target name> <source device> <key file> <options>\n" +
		"dm_crypt-0 UUID=1234 none luks,discard,tpm2-device=auto\n" +
		"swap /dev/sdb2 /dev/urandom swap\n" +
		"data UUID=5678 none luks,tpm2-device=/dev/tpmrm0\n"
	if string(got) != want {
		t.Fatalf("crypttab:\n%s\nwant:\n%s", got, want)
	}
}

// TestFetchScript runs the late-command's download script with python3: a matching SHA-256 writes the package, a
// mismatch fails without writing.
func TestFetchScript(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required to test the download script of the autoinstall")
	}
	body := []byte("debian package")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	sum := sha256.Sum256(body)
	in := input("26.04")
	in.Packages[0].URL = srv.URL + "/p.deb"
	in.Packages[0].SHA256 = hex.EncodeToString(sum[:])
	fetch := find(render(t, in).commands(t), "python3", in.Packages[0].URL)
	script := fetch[slices.Index(fetch, "-c")+1]
	dir := t.TempDir()
	if out, err := exec.Command(python, "-c", script, in.Packages[0].URL, in.Packages[0].SHA256, filepath.Join(dir, "ok.deb")).CombinedOutput(); err != nil {
		t.Fatalf("download: %v %s", err, out)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "ok.deb")); !bytes.Equal(got, body) {
		t.Fatalf("downloaded %q", got)
	}
	out, err := exec.Command(python, "-c", script, in.Packages[0].URL, strings.Repeat("0", 64), filepath.Join(dir, "bad.deb")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "SHA-256 mismatch") {
		t.Fatalf("mismatch accepted: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "bad.deb")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a package with the wrong SHA-256 was written")
	}
}
