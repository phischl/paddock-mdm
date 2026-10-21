package encrypt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/sessions"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// NotifyEvery is how often a graphical session is reminded to restart while the conversion is prepared (plan M8e
// decision 28).
const NotifyEvery = 4 * time.Hour

// notifyTimeout bounds one notification.
const notifyTimeout = 30 * time.Second

// Texts of plan M8e §6.7 (binding).
const (
	summaryEN = "Disk encryption is ready — please restart"
	bodyEN    = "Your IT department has switched on disk encryption for this device. It starts at the next restart, which " +
		"takes a few minutes longer than usual. Save your work and restart when it suits you; keep the device on mains " +
		"power during the restart."
	pinEN     = "At the restart you will be asked to choose a boot PIN that you type every time the device starts."
	summaryDE = "Festplattenverschlüsselung bereit — bitte neu starten"
	bodyDE    = "Ihre IT-Abteilung hat die Festplattenverschlüsselung für dieses Gerät eingeschaltet. Sie beginnt beim " +
		"nächsten Neustart, der einige Minuten länger dauert als üblich. Speichern Sie Ihre Arbeit und starten Sie neu, " +
		"wenn es Ihnen passt; lassen Sie das Gerät während des Neustarts am Netzteil."
	pinDE = "Beim Neustart werden Sie gebeten, eine Boot-PIN zu wählen, die Sie bei jedem Start des Geräts eingeben."
)

// NotifyRestart asks every graphical user session to restart (plan M8e decision 28): a session of class user whose
// type is wayland or x11 is notified when it is first seen and again every NotifyEvery. notified holds the last
// attempt per session ID and is pruned to the current sessions; it is updated for a failed attempt as well, so that a
// failure is logged once per session and NotifyEvery. It reports whether notified changed. Without a graphical
// session nothing runs; the device is never restarted.
func NotifyRestart(ctx context.Context, sys System, root, unlockMode string, notified map[string]time.Time, now time.Time) bool {
	list, err := sessions.List(ctx, func(ctx context.Context, args ...string) (string, int, error) {
		out, _, exit, err := sys.Command(ctx, "loginctl", args...)
		return out, exit, err
	})
	if err != nil {
		slog.DebugContext(ctx, "listing sessions for the restart notification failed", "error", err)
		return false
	}
	changed := false
	current := map[string]bool{}
	for _, s := range list {
		if s.Class != "user" || (s.Type != "wayland" && s.Type != "x11") {
			continue
		}
		current[s.ID] = true
		if at, ok := notified[s.ID]; ok && now.Sub(at) < NotifyEvery {
			continue
		}
		notified[s.ID], changed = now, true
		if err := notify(ctx, sys, root, unlockMode, s, now); err != nil {
			slog.InfoContext(ctx, "restart notification not shown", "session", s.ID, "uid", s.UID, "error", err)
		}
	}
	for id := range notified {
		if !current[id] {
			delete(notified, id)
			changed = true
		}
	}
	return changed
}

// notify shows the notification in one session through the user's notification daemon (busctl --user, run as the
// user by systemd-run), bounded by notifyTimeout.
func notify(ctx context.Context, sys System, root, unlockMode string, s sessions.Session, now time.Time) error {
	uid := strconv.Itoa(s.UID)
	out, _, exit, err := sys.Command(ctx, "getent", "passwd", uid)
	if err == nil && exit != 0 {
		err = fmt.Errorf("getent passwd %s: exit %d", uid, exit)
	}
	if err != nil {
		return err
	}
	f := strings.Split(strings.TrimSpace(out), ":")
	if len(f) < 4 {
		return fmt.Errorf("getent passwd %s: no primary group", uid)
	}
	summary, body := Texts(Language(sys, root), unlockMode)
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	_, stderr, exit, err := sys.Command(ctx, "systemd-run", "--quiet", "--wait", "--collect", "--uid="+uid, "--gid="+f[3],
		"--setenv=XDG_RUNTIME_DIR=/run/user/"+uid, "--unit=paddock-notify-"+s.ID+"-"+strconv.FormatInt(now.Unix(), 10), "--",
		"busctl", "--user", "call", "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
		"org.freedesktop.Notifications", "Notify", "susssasa{sv}i", "Paddock", "0", "drive-harddisk", summary, body, "0",
		"1", "urgency", "y", "1", "0")
	if err == nil && exit != 0 {
		err = fmt.Errorf("systemd-run: exit %d: %s", exit, firstLine(stderr))
	}
	return err
}

// Language is the device's language for the notification: "de" when LANG in /etc/default/locale starts with de,
// "en" otherwise.
func Language(sys System, root string) string {
	raw, err := sys.ReadFile(filepath.Join(root, "/etc/default/locale"))
	if err != nil {
		return "en"
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "LANG="); ok && strings.HasPrefix(strings.Trim(v, `"'`), "de") {
			return "de"
		}
	}
	return "en"
}

// Texts returns the summary and the body of plan M8e §6.7 in a language; the PIN sentence only under tpm_pin.
func Texts(lang, unlockMode string) (summary, body string) {
	summary, body, pin := summaryEN, bodyEN, pinEN
	if lang == "de" {
		summary, body, pin = summaryDE, bodyDE, pinDE
	}
	if unlockMode == bundle.UnlockModeTPMPIN {
		body += " " + pin
	}
	return summary, body
}
