package system

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseInitrds: one entry per initrd line of initrdScript; counts other than 0 mean present, and a missing
// crypttab is empty.
func TestParseInitrds(t *testing.T) {
	out := "/boot/initrd.img-6.8.0-50-generic\t3\t1\tdm_crypt-0 UUID=1111 none luks,tpm2-device=auto;\n" +
		"/boot/initrd.img-6.8.0-31-generic\t0\t0\t\n" +
		"lsinitrd: some warning\n"
	got := parseInitrds(out)
	want := map[string]initrdInfo{
		"/boot/initrd.img-6.8.0-50-generic": {Module: true, Key: true, Crypttab: "dm_crypt-0 UUID=1111 none luks,tpm2-device=auto;"},
		"/boot/initrd.img-6.8.0-31-generic": {},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %+v, want %+v", k, got[k], v)
		}
	}
}

// TestIETemplates: both throwaway templates render without a placeholder left, keep the late-commands that
// withTestAccess extends, log the test user in and put the console on the serial port the gates read.
func TestIETemplates(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}
	for template, storage := range map[string]string{"unencrypted-lvm.yaml.tmpl": "name: lvm", "unencrypted-plain.yaml.tmpl": "ptable: gpt"} {
		_, body, found := strings.Cut(string(renderIETemplate(t, root, template, "paddock-ie-test")), "autoinstall:")
		if !found {
			t.Fatalf("%s: no autoinstall section", template)
		}
		for _, want := range []string{"hostname: paddock-ie-test", "username: " + ieUser, "AutomaticLogin=" + ieUser,
			"TTYPath=/dev/ttyS0", "console=ttyS0,115200 console=tty0", "\n  late-commands:\n", storage, "password: '$6$"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: %q missing", template, want)
			}
		}
		if strings.Contains(body, "@@") {
			t.Errorf("%s: a placeholder is left", template)
		}
		// A storage password (storage.layout.password, six spaces deep) would encrypt the install.
		if strings.Contains(body, "\n      password:") {
			t.Errorf("%s: the throwaway VM must not be encrypted", template)
		}
	}
}
