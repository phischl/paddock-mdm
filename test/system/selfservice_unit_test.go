package system

import (
	"bytes"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSelfServiceHelpersUnit pins the parsers of the self-service gates: a parser that silently found nothing would
// make SV2's audience checks and SV9's health check pass against an empty list, and SV5's key checks against nothing.
func TestSelfServiceHelpersUnit(t *testing.T) {
	r, err := parseSSReply(`{"status": 403, "content_type": "application/json", "body": "eyJjb2RlIjoicmVxdWlyZWRfYnlfcG9saWN5In0K"}`)
	if err != nil || r.Status != 403 || r.code() != "required_by_policy" {
		t.Errorf("parseSSReply = %+v (code %q) %v", r, r.code(), err)
	}
	if _, err := parseSSReply("Traceback (most recent call last):"); err == nil {
		t.Error("parseSSReply accepted python's error output")
	}
	if (ssReply{Body: []byte{0x89, 'P', 'N', 'G'}}).code() != "" {
		t.Error("code of a PNG body is not empty")
	}

	apps, err := ssApps([]byte(`{"apps":[{"entry_id":"e1","name":"paddock-gate-offered","kind":"apt","scope":"system",` +
		`"intent":"available","managed":false,"installable":true,"state":"absent","icon":true},` +
		`{"entry_id":"e2","name":"org.paddock.GateUserApp","kind":"flatpak","scope":"user","intent":"required","managed":true,"state":"pending"}]}`))
	if err != nil || len(apps) != 2 || !apps["e1"].Installable || !apps["e1"].Icon || apps["e2"].Scope != "user" || !apps["e2"].Managed {
		t.Errorf("ssApps = %+v %v", apps, err)
	}
	if _, err := ssApps([]byte(`{"code":"no_bundle"`)); err == nil {
		t.Error("ssApps accepted a broken body")
	}

	pkgs, err := healthPackages(`{"software":{"items":[{"package":"flatpak"},{"package":"flatpak:org.paddock.GateApp"}]}}`)
	if err != nil || strings.Join(pkgs, ",") != "flatpak,flatpak:org.paddock.GateApp" {
		t.Errorf("healthPackages = %v %v", pkgs, err)
	}
	if pkgs, err := healthPackages(`{"reconcile":"ok"}`); err != nil || len(pkgs) != 0 {
		t.Errorf("healthPackages without software = %v %v", pkgs, err)
	}

	config := "[core]\nrepo_version=1\n\n[remote \"paddock-gate-x\"]\nurl=https://127.0.0.1:8443/flatpak/\ngpg-verify=true\n" +
		"gpg-verify-summary=false\n\n[remote \"paddock-rogue\"]\ngpg-verify-summary=true\n"
	if v := iniValue(config, `remote "paddock-gate-x"`, "gpg-verify"); v != "true" {
		t.Errorf("iniValue gpg-verify = %q", v)
	}
	if v := iniValue(config, `remote "paddock-gate-x"`, "gpg-verify-summary"); v != "false" {
		t.Errorf("iniValue reads gpg-verify-summary of another section: %q", v)
	}
	if v := iniValue(config, `remote "paddock-gate-y"`, "gpg-verify"); v != "" {
		t.Errorf("iniValue of a missing section = %q", v)
	}
	colons := "pub:-:255:22:AAAA:1:::-:::scESC:::::ed25519:::0:\nfpr:::::::::FP1:\nuid:-::::1::H::gate:::::::::0:\n" +
		"sub:-:255:18:BBBB:1::::::e:::::cv25519::\nfpr:::::::::SUBFP:\npub:-:255:22:CCCC:1:::-:::scESC:::::ed25519:::0:\nfpr:::::::::FP2:\n"
	if fps := primaryFingerprints(colons); strings.Join(fps, ",") != "FP1,FP2" {
		t.Errorf("primaryFingerprints = %v, want FP1,FP2 without the subkey", fps)
	}
	if fps := primaryFingerprints(""); len(fps) != 0 {
		t.Errorf("primaryFingerprints of nothing = %v", fps)
	}

	icon := ssIcon("paddock-u2404abcd1234")
	img, err := png.Decode(bytes.NewReader(icon))
	if err != nil || len(icon) > 65536 || img.Bounds().Dx() != 16 || img.Bounds().Dy() != 16 {
		t.Errorf("ssIcon: %d bytes, %v", len(icon), err)
	}
	if bytes.Equal(icon, ssIcon("paddock-u2604abcd1234")) {
		t.Error("ssIcon gives two runs the same icon")
	}
}

// TestSelfServiceScriptsUnit checks the syntax of the gates' guest scripts on the host (bash -n, python3's compiler),
// which would otherwise fail only on the VMs, and runs the GDM part of the automatic-login script against a copy of
// Ubuntu's custom.conf.
func TestSelfServiceScriptsUnit(t *testing.T) {
	for name, script := range map[string]string{"repo": ssRepoScript, "user": ssUserScript, "autologin": autologinScript} {
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s script: %v\n%s", name, err, out)
		}
	}
	if _, err := exec.LookPath("python3"); err == nil {
		dir := t.TempDir()
		file := filepath.Join(dir, "client.py")
		if err := os.WriteFile(file, []byte(ssClientScript), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("python3", "-m", "py_compile", file).CombinedOutput(); err != nil {
			t.Errorf("client script: %v\n%s", err, out)
		}
	}

	dir := t.TempDir()
	conf := filepath.Join(dir, "custom.conf")
	if err := os.WriteFile(conf, []byte("# GDM configuration storage\n\n[daemon]\nAutomaticLogin=old\n# WaylandEnable=false\n\n[security]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(autologinScript, "\nrm -f /run/gdm3/ran-once-marker /run/gdm/ran-once-marker\n"+
		"systemctl restart display-manager.service\n") {
		t.Errorf("autologin script does not end by removing GDM's ran-once marker and restarting the display manager:\n%s",
			autologinScript)
	}
	gdm := strings.ReplaceAll(strings.TrimSuffix(autologinScript, autologinRestart), "/etc/gdm3/custom.conf", conf)
	cmd := exec.Command("bash", "-s", "--", "ss-owner-1@acme.test")
	cmd.Stdin = strings.NewReader(gdm)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("autologin script: %v\n%s", err, out)
	}
	got, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	want := "# GDM configuration storage\n\n[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=ss-owner-1@acme.test\n# WaylandEnable=false\n\n[security]\n"
	if string(got) != want {
		t.Errorf("custom.conf =\n%s\nwant\n%s", got, want)
	}
}
