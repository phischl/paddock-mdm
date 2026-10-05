package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/sessions"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
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
	for _, user := range logins {
		// Himmelblau names the users of its domain by their short name (the part before @); Paddock knows the UPN.
		if !strings.Contains(user, "@") {
			user += "@" + domain
		}
		a.event(protocol.EventSessionLogin, protocol.SessionLogin{Username: user, At: now}) // persists the state
	}
	if len(logins) == 0 && len(a.st.SessionsReported) != before {
		a.saveState() // pruned
	}
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
