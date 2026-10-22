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

// NotifyEvery is how often a graphical session is reminded to restart while the conversion is prepared, or completed
// without the enrollment (plan M8e decision 28; amendment 2026-10-22, item 22).
const NotifyEvery = 4 * time.Hour

// Notice is a restart notification of plan M8e §6.7; its value prefixes the session IDs in state.Conversion.Notified.
type Notice string

// The restart notifications: before the conversion boot (decision 28), and after the completed reencryption for the
// enrollment (amendment 2026-10-22, item 22).
const (
	NoticePrepared  Notice = ""
	NoticeCompleted Notice = "completed:"
)

// notifyTimeout bounds one notification.
const notifyTimeout = 30 * time.Second

// Texts of plan M8e §6.7 (binding); the PIN sentence as corrected by amendment 2026-10-22, item 22.
const (
	summaryEN = "Disk encryption is ready — please restart"
	bodyEN    = "Your IT department has switched on disk encryption for this device. It starts at the next restart, which " +
		"takes a few minutes longer than usual. Save your work and restart when it suits you; keep the device on mains " +
		"power during the restart."
	pinEN = "You will be asked to choose a boot PIN at the first restart after the encryption has completed; from then " +
		"on you type it every time the device starts."
	summaryDE = "Festplattenverschlüsselung bereit — bitte neu starten"
	bodyDE    = "Ihre IT-Abteilung hat die Festplattenverschlüsselung für dieses Gerät eingeschaltet. Sie beginnt beim " +
		"nächsten Neustart, der einige Minuten länger dauert als üblich. Speichern Sie Ihre Arbeit und starten Sie neu, " +
		"wenn es Ihnen passt; lassen Sie das Gerät während des Neustarts am Netzteil."
	pinDE = "Beim ersten Neustart nach Abschluss der Verschlüsselung werden Sie gebeten, eine Boot-PIN zu wählen; danach " +
		"geben Sie sie bei jedem Start des Geräts ein."

	completedSummaryEN = "Disk encryption completed — please restart"
	completedBodyEN    = "The background encryption of this device has completed. Restart the device to finish the " +
		"setup; under TPM + PIN you will be asked to choose a boot PIN at that start. Until then the disk is not fully " +
		"protected."
	completedSummaryDE = "Festplattenverschlüsselung abgeschlossen — bitte neu starten"
	completedBodyDE    = "Die Verschlüsselung dieses Geräts im Hintergrund ist abgeschlossen. Starten Sie das Gerät neu, " +
		"um die Einrichtung abzuschließen; unter TPM + PIN werden Sie bei diesem Start gebeten, eine Boot-PIN zu wählen. " +
		"Bis dahin ist die Festplatte nicht vollständig geschützt."
)

// NotifyRestart asks every graphical user session to restart (plan M8e decision 28): a session of class user whose
// type is wayland or x11 is notified when it is first seen and again every NotifyEvery. notified holds the last
// attempt per notice and session ID and is pruned to the current sessions of notice; it is updated for a failed
// attempt as well, so that a failure is logged once per session and NotifyEvery. ready, when not nil, is asked once
// before the first notification of a call; false shows nothing and records nothing. It reports whether notified
// changed. Without a graphical session nothing runs; the device is never restarted.
func NotifyRestart(ctx context.Context, sys System, root, unlockMode string, notice Notice, notified map[string]time.Time,
	now time.Time, ready func(context.Context) bool) bool {
	list, err := sessions.List(ctx, func(ctx context.Context, args ...string) (string, int, error) {
		out, _, exit, err := sys.Command(ctx, "loginctl", args...)
		return out, exit, err
	})
	if err != nil {
		slog.DebugContext(ctx, "listing sessions for the restart notification failed", "error", err)
		return false
	}
	changed, asked, allowed := false, false, ready == nil
	current := map[string]bool{}
	for _, s := range list {
		if s.Class != "user" || (s.Type != "wayland" && s.Type != "x11") {
			continue
		}
		key := string(notice) + s.ID
		current[key] = true
		if at, ok := notified[key]; ok && now.Sub(at) < NotifyEvery {
			continue
		}
		if !allowed {
			if asked {
				continue
			}
			if asked, allowed = true, ready(ctx); !allowed {
				continue
			}
		}
		notified[key], changed = now, true
		if err := notify(ctx, sys, root, unlockMode, notice, s, now); err != nil {
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
func notify(ctx context.Context, sys System, root, unlockMode string, notice Notice, s sessions.Session, now time.Time) error {
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
	summary, body := Texts(Language(sys, root), unlockMode, notice)
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

// Texts returns the summary and the body of plan M8e §6.7 for a notice in a language; the PIN sentence of
// NoticePrepared only under tpm_pin.
func Texts(lang, unlockMode string, notice Notice) (summary, body string) {
	if notice == NoticeCompleted {
		if lang == "de" {
			return completedSummaryDE, completedBodyDE
		}
		return completedSummaryEN, completedBodyEN
	}
	summary, body, pin := summaryEN, bodyEN, pinEN
	if lang == "de" {
		summary, body, pin = summaryDE, bodyDE, pinDE
	}
	if unlockMode == bundle.UnlockModeTPMPIN {
		body += " " + pin
	}
	return summary, body
}
