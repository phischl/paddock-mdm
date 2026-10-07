package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/sessions"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// SessionPoll is the interval at which the agent reads the logind sessions for session.login (plan M3b decision
// 11). Polling `loginctl` instead of a D-Bus subscription keeps the agent free of a D-Bus library (plan freedom).
const SessionPoll = 10 * time.Second

// trackSessions reports a directory user's login once per user per 24 h (session.login, username and time only).
// Without a login resource there are no directory users to report.
func (a *Agent) trackSessions(ctx context.Context) {
	domain := a.loginDomain()
	if a.d.Sys == nil || a.st.Status != state.StatusActive || domain == "" {
		return
	}
	list, err := sessions.List(ctx, a.d.Sys.Loginctl)
	if err != nil {
		slog.DebugContext(ctx, "listing sessions failed", "error", err)
		return
	}
	passwd, _, err := a.d.Sys.ReadFile("/etc/passwd")
	if err != nil {
		slog.WarnContext(ctx, "reading /etc/passwd failed", "error", err)
		return
	}
	if a.st.SessionsReported == nil {
		a.st.SessionsReported = map[string]time.Time{}
	}
	now := a.d.Now().UTC()
	before := len(a.st.SessionsReported)
	logins := sessions.NewLogins(list, sessions.LocalUIDs(passwd), a.st.SessionsReported, now)
	for _, s := range logins {
		upn, err := a.upn(ctx, s, domain)
		if err != nil {
			slog.WarnContext(ctx, "session.login not reported: no UPN for the session's user", "error", err)
			continue
		}
		a.event(protocol.EventSessionLogin, protocol.SessionLogin{Username: upn, At: now}) // persists the state
	}
	if len(logins) == 0 && len(a.st.SessionsReported) != before {
		a.saveState() // pruned
	}
}

// upn returns the Paddock username (UPN) of a directory user's session. Himmelblau names the users of its domain by
// their short name (the part before @), and Paddock, device_user_seen and the affected-device rule of locks know the
// UPN: the candidate name@domain counts only if NSS (Himmelblau) resolves it to the session's UID. Himmelblau answers
// for any name, but derives every UID from the name (plan M5a step 0a): only the session user's own name matches.
func (a *Agent) upn(ctx context.Context, s sessions.Session, domain string) (string, error) {
	if strings.Contains(s.User, "@") {
		return s.User, nil
	}
	candidate := s.User + "@" + domain
	out, exit, err := a.d.Sys.Getent(ctx, "passwd", candidate)
	if err != nil {
		return "", fmt.Errorf("getent passwd %s: %w", candidate, err)
	}
	f := strings.Split(strings.TrimSpace(out), ":")
	if exit != 0 || len(f) < 3 || f[2] != strconv.Itoa(s.UID) {
		return "", fmt.Errorf("%s does not resolve to UID %d (getent exit %d)", candidate, s.UID, exit)
	}
	return candidate, nil
}

// loginDomain is the Himmelblau domain of the applied bundle ("" without a login resource).
func (a *Agent) loginDomain() string {
	if a.current == nil {
		return ""
	}
	for _, r := range a.current.Resources {
		var spec bundle.LoginSpec
		if r.Type == bundle.TypeLogin && json.Unmarshal(r.Spec, &spec) == nil {
			return spec.Himmelblau.Domain
		}
	}
	return ""
}
