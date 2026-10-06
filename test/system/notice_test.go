package system

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestNoticeGate runs gate N1 of plan M4a on each VM, from a fresh base-installed: the organization's login notice
// at the GDM login screen (dconf of the greeter and a screenshot), on text consoles (/etc/issue.d through agetty)
// and before SSH logins; a changed text reaches the device with one check-in, an empty one removes every file.
func TestNoticeGate(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		t.Run("N1 login notice", func(t *testing.T) {
			vm.group.Exclusive(t, "login notice") // the notice is one setting of the organization
			gateN1(t, d)
		})
	})
}

// setNotice changes acme's notice text and returns the previous one.
func setNotice(t *testing.T, s *Stack, text string) string {
	t.Helper()
	var settings map[string]any
	if err := json.Unmarshal(s.Call(http.MethodGet, "/api/v1/settings/login", nil, http.StatusOK).Body, &settings); err != nil {
		t.Fatal(err)
	}
	old, _ := settings["notice_text"].(string)
	delete(settings, "updated_at")
	settings["notice_text"] = text
	s.Call(http.MethodPut, "/api/v1/settings/login", settings, http.StatusOK)
	return old
}

// noticeFiles are the files of the notice on the device.
var noticeFiles = []string{"/etc/dconf/db/gdm.d/90-paddock-notice", "/etc/issue.d/90-paddock.issue", "/etc/paddock/notice",
	"/etc/ssh/sshd_config.d/90-paddock-banner.conf"}

// gdmKey is a key of the login screen as the greeter's dconf profile resolves it. stderr is dropped: on Ubuntu 26.04
// dconf warns that it cannot create a cache directory in gdm's home, which does not affect reading.
func gdmKey(d *Device, key string) string {
	return d.Must("sudo -u gdm env DCONF_PROFILE=gdm dconf read /org/gnome/login-screen/" + key + " 2>/dev/null")
}

// gdmBanner is the banner the greeter shows.
func gdmBanner(d *Device) string { return gdmKey(d, "banner-message-text") }

// sshBanner connects to the guest's SSH server and returns what the client prints before authentication.
func sshBanner(t *testing.T, d *Device) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// ssh takes the first value of an option: LogLevel=INFO (which prints the banner) must precede sshArgs' ERROR.
	args := append(append([]string{"-o", "LogLevel=INFO"}, d.sshArgs()...), "-p", d.port, "paddock@127.0.0.1", "true")
	out, err := run(ctx, "ssh", args...)
	if err != nil {
		t.Fatalf("ssh: %v: %s", err, out)
	}
	return out
}

func gateN1(t *testing.T, d *Device) {
	text := "Paddock system test " + d.run + ": authorized use only.\nActivity is logged."
	old := setNotice(t, d.s, text)
	t.Cleanup(func() { setNotice(t, d.s, old) })
	last := time.Time{}
	tick := func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}
	Until(t, "notice files on the device", 10*time.Minute, 5*time.Second, tick, func() bool {
		out, _ := d.SSH(context.Background(), nil, "cat /etc/paddock/notice 2>/dev/null")
		return strings.TrimSpace(out) == text
	})
	if got := gdmBanner(d); got != "'Paddock system test "+d.run+": authorized use only.\\nActivity is logged.'" {
		t.Errorf("GDM banner %q", got)
	}
	if got := gdmKey(d, "banner-message-enable"); got != "true" {
		t.Errorf("GDM banner enabled: %q", got)
	}
	if out := d.Must("sudo agetty --show-issue tty9 2>&1 || cat /etc/issue.d/90-paddock.issue"); !strings.Contains(out, "authorized use only.") {
		t.Errorf("issue for text consoles:\n%s", out)
	}
	if out := sshBanner(t, d); !strings.Contains(out, "authorized use only.\nActivity is logged.") {
		t.Errorf("SSH banner:\n%s", out)
	}
	// The greeter reads the banner when it starts: restart GDM (no user session on a fresh VM) for the screenshot. It
	// shows the banner above the password prompt: Enter selects the first user.
	d.Must("sudo systemctl restart gdm")
	time.Sleep(20 * time.Second)
	d.Key("1c", "9c")
	time.Sleep(3 * time.Second)
	d.Shot(t, "10-gdm-banner")
	d.Key("01", "81")                         // Escape back to the user list
	d.Key("1d", "38", "3e", "be", "b8", "9d") // Ctrl+Alt+F4: a text console with the issue
	time.Sleep(5 * time.Second)
	d.Shot(t, "11-tty-issue")
	d.Key("1d", "38", "41", "c1", "b8", "9d") // Ctrl+Alt+F7 back (the greeter runs on vt1 or vt7)
	d.Key("1d", "38", "3b", "bb", "b8", "9d") // Ctrl+Alt+F1

	// A changed text arrives with one check-in.
	changed := "Changed notice " + d.run
	setNotice(t, d.s, changed)
	time.Sleep(5 * time.Second) // the compiler publishes the bundle
	d.Checkin()
	Until(t, "changed notice after one check-in", 2*time.Minute, 5*time.Second, nil, func() bool {
		out, _ := d.SSH(context.Background(), nil, "cat /etc/paddock/notice /etc/issue.d/90-paddock.issue 2>/dev/null")
		return strings.Count(out, changed) == 2
	})
	if got := gdmBanner(d); got != "'"+changed+"'" {
		t.Errorf("GDM banner after the change %q", got)
	}

	// An empty text removes every file.
	setNotice(t, d.s, "")
	time.Sleep(5 * time.Second)
	d.Checkin()
	Until(t, "notice removed", 2*time.Minute, 5*time.Second, nil, func() bool {
		out, _ := d.SSH(context.Background(), nil, "ls "+strings.Join(noticeFiles, " ")+" 2>/dev/null | wc -l")
		return strings.TrimSpace(out) == "0"
	})
	if got := gdmBanner(d); strings.Contains(got, changed) {
		t.Errorf("GDM banner after the removal %q", got)
	}
	if out := sshBanner(t, d); strings.Contains(out, changed) {
		t.Errorf("SSH banner after the removal:\n%s", out)
	}
}
