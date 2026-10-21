package encrypt_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/encrypt/encrypttest"
)

// session is a logind session of the notification fake.
type session struct {
	id, class, typ string
	uid            int
}

// desktop is a fake device with logind sessions and the notification tools.
type desktop struct {
	*encrypttest.Host
	sessions []session
	exit     int
	runs     []string
}

func newDesktop(t *testing.T, sessions ...session) *desktop {
	d := &desktop{Host: encrypttest.New(t), sessions: sessions}
	d.Handle = func(line string) (string, int, bool) {
		switch {
		case line == "loginctl list-sessions --no-legend":
			var b strings.Builder
			for _, s := range d.sessions {
				fmt.Fprintf(&b, "%6s %5d user -\n", s.id, s.uid)
			}
			return b.String(), 0, true
		case strings.HasPrefix(line, "loginctl show-session "):
			var blocks []string
			for _, s := range d.sessions {
				blocks = append(blocks, fmt.Sprintf("Id=%s\nUser=%d\nName=u%d\nClass=%s\nType=%s\n", s.id, s.uid, s.uid, s.class, s.typ))
			}
			return strings.Join(blocks, "\n"), 0, true
		case strings.HasPrefix(line, "getent passwd "):
			uid := strings.TrimPrefix(line, "getent passwd ")
			return "u" + uid + ":x:" + uid + ":" + uid + "::/home/u:/bin/bash\n", 0, true
		case strings.HasPrefix(line, "systemd-run "):
			d.runs = append(d.runs, line)
			return "", d.exit, true
		}
		return "", 0, false
	}
	return d
}

func (d *desktop) notify(mode string, notified map[string]time.Time, now time.Time) bool {
	return encrypt.NotifyRestart(context.Background(), d, d.Root, mode, notified, now)
}

// TestNotifyRestart: plan M8e decision 28 — the exact command line once per graphical session, again after 4 hours
// and for a new session; never for a tty session or the greeter.
func TestNotifyRestart(t *testing.T) {
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	d := newDesktop(t, session{"3", "user", "wayland", 1000}, session{"c1", "greeter", "wayland", 60578},
		session{"5", "user", "tty", 1001})
	notified := map[string]time.Time{}
	if !d.notify("tpm_pin", notified, now) {
		t.Fatal("notified unchanged")
	}
	summary, body := encrypt.Texts("en", "tpm_pin")
	want := fmt.Sprintf("systemd-run --quiet --wait --collect --uid=1000 --gid=1000 --setenv=XDG_RUNTIME_DIR=/run/user/1000 "+
		"--unit=paddock-notify-3-%d -- busctl --user call org.freedesktop.Notifications /org/freedesktop/Notifications "+
		"org.freedesktop.Notifications Notify susssasa{sv}i Paddock 0 drive-harddisk %s %s 0 1 urgency y 1 0", now.Unix(), summary, body)
	if len(d.runs) != 1 || d.runs[0] != want {
		t.Fatalf("runs %q\nwant %q", d.runs, want)
	}
	if summary != "Disk encryption is ready — please restart" || !strings.HasSuffix(body,
		"keep the device on mains power during the restart. At the restart you will be asked to choose a boot PIN that you type every time the device starts.") {
		t.Fatalf("texts %q %q", summary, body)
	}
	d.notify("tpm_pin", notified, now.Add(time.Hour))
	if len(d.runs) != 1 {
		t.Fatalf("notified again within 4 hours: %v", d.runs)
	}
	d.notify("tpm_pin", notified, now.Add(4*time.Hour))
	if len(d.runs) != 2 {
		t.Fatalf("no reminder after 4 hours: %v", d.runs)
	}
	d.sessions = append(d.sessions, session{"7", "user", "x11", 1002})
	d.notify("tpm_pin", notified, now.Add(5*time.Hour))
	if len(d.runs) != 3 || !strings.Contains(d.runs[2], "--uid=1002 ") {
		t.Fatalf("new session not notified: %v", d.runs)
	}
	d.sessions = d.sessions[:1]
	d.notify("tpm_pin", notified, now.Add(5*time.Hour))
	if _, ok := notified["7"]; ok || len(notified) != 1 {
		t.Fatalf("ended session not pruned: %v", notified)
	}
}

// TestNotifyRestartLanguage: German under LANG=de_DE.UTF-8; the PIN sentence only under tpm_pin.
func TestNotifyRestartLanguage(t *testing.T) {
	d := newDesktop(t, session{"3", "user", "wayland", 1000})
	d.Write("/etc/default/locale", "LANG=\"de_DE.UTF-8\"\n")
	d.notify("tpm_only", map[string]time.Time{}, time.Now())
	summary, body := encrypt.Texts("de", "tpm_only")
	if summary != "Festplattenverschlüsselung bereit — bitte neu starten" || strings.Contains(body, "Boot-PIN") ||
		len(d.runs) != 1 || !strings.Contains(d.runs[0], summary+" "+body+" 0 1 urgency") {
		t.Fatalf("runs %v", d.runs)
	}
	if _, body := encrypt.Texts("de", "tpm_pin"); !strings.HasSuffix(body, "die Sie bei jedem Start des Geräts eingeben.") {
		t.Fatalf("German PIN sentence missing: %q", body)
	}
}

// TestNotifyRestartNothingToShow: no session, a tty session only, a greeter only — nothing runs.
func TestNotifyRestartNothingToShow(t *testing.T) {
	for _, sessions := range [][]session{nil, {{"5", "user", "tty", 1001}}, {{"c1", "greeter", "x11", 60578}}} {
		d := newDesktop(t, sessions...)
		if d.notify("tpm_pin", map[string]time.Time{}, time.Now()) || len(d.runs) != 0 {
			t.Fatalf("%v: runs %v", sessions, d.runs)
		}
	}
}

// TestNotifyRestartFailure: a failing notification is recorded like a shown one, so that it is retried (and logged)
// once per 4 hours.
func TestNotifyRestartFailure(t *testing.T) {
	d := newDesktop(t, session{"3", "user", "wayland", 1000})
	d.exit = 1
	now := time.Now()
	notified := map[string]time.Time{}
	d.notify("tpm_pin", notified, now)
	d.notify("tpm_pin", notified, now.Add(time.Minute))
	if len(d.runs) != 1 || notified["3"] != now {
		t.Fatalf("runs %v, notified %v", d.runs, notified)
	}
}
