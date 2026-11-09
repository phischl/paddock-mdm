// Package desktop shows notifications in the graphical sessions of the device's users (ADR 0048 decision 6): one
// notify-send per active wayland or x11 user session, run in the user's own service manager. It is best effort: a
// session that cannot be reached is counted as not notified, never an error of the caller.
package desktop

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/sessions"
)

// NotifyTimeout bounds the notification of one session.
const NotifyTimeout = 5 * time.Second

// LocaleFile is the system locale whose LANG chooses the language of a notification.
const LocaleFile = "/etc/default/locale"

// Languages of a notification.
const (
	German  = "de"
	English = "en"
)

// Result is the outcome of a notification: the active graphical sessions found and how many of them were reached.
type Result struct {
	Sessions int
	Reached  int
}

// Notify shows summary and body in every active wayland or x11 session of class user (plan M12 decision 11): a login
// screen is no user to tell, and on Ubuntu 24.04 the GDM greeter is an active wayland session that cannot show a
// notice (PDK-878). A session it cannot reach is logged at warn
// level with the cause (PDK-878: the signed privacy text promises the notice, so a silent failure is not acceptable)
// and counted as not reached. The error is only that the sessions could not be listed.
func Notify(ctx context.Context, sys reconcile.System, summary, body string) (Result, error) {
	return notify(ctx, sys, -1, summary, body)
}

// NotifyUser is Notify for the sessions of one user only (a self-service operation is told to the user who asked
// for it, plan M13b decision 13).
func NotifyUser(ctx context.Context, sys reconcile.System, uid int, summary, body string) (Result, error) {
	return notify(ctx, sys, uid, summary, body)
}

// notify shows the notification in the active graphical user sessions, of uid only when uid is not negative.
func notify(ctx context.Context, sys reconcile.System, uid int, summary, body string) (Result, error) {
	list, err := sessions.List(ctx, sys.Loginctl)
	if err != nil {
		return Result{}, fmt.Errorf("list the sessions: %w", err)
	}
	var res Result
	for _, s := range list {
		if s.Class != "user" || (s.Type != "wayland" && s.Type != "x11") || s.State != "active" || s.User == "" ||
			s.UID < 0 || (uid >= 0 && s.UID != uid) {
			continue
		}
		res.Sessions++
		nctx, cancel := context.WithTimeout(ctx, NotifyTimeout)
		// The UID, not the name: systemd splits --machine at the first "@", which a directory user's name contains.
		// "--" keeps an administrator's reason that starts with "-" from being read as an option of notify-send.
		_, err := sys.Output(nctx, "systemd-run", "--machine="+strconv.Itoa(s.UID)+"@.host", "--user", "--quiet",
			"--collect", "--wait", "notify-send", "--app-name=Paddock", "--urgency=normal", "--", summary, body)
		cancel()
		if err != nil {
			slog.WarnContext(ctx, "desktop notification not shown", "session", s.ID, "uid", s.UID, "error", err)
			continue
		}
		res.Reached++
	}
	return res, nil
}

// Language returns German when LANG of the system locale starts with "de", English otherwise (also when the file is
// missing): the agent cannot read a session's environment, so the system locale stands for every session.
func Language(sys reconcile.System) string {
	data, _, err := sys.ReadFile(LocaleFile)
	if err != nil || data == nil {
		return English
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "LANG=")
		if !ok {
			continue
		}
		if strings.HasPrefix(strings.Trim(v, `"'`), "de") {
			return German
		}
		return English
	}
	return English
}
