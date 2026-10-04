package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/sessions"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// SessionPoll is the interval at which the agent reads the logind sessions for session.login (plan M3b decision
// 11). Polling `loginctl` instead of a D-Bus subscription keeps the agent free of a D-Bus library (plan freedom).
const SessionPoll = 10 * time.Second

// trackSessions reports a directory user's login once per user per 24 h (session.login, username and time only).
func (a *Agent) trackSessions(ctx context.Context) {
	if a.d.Sys == nil || a.st.Status != state.StatusActive {
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
		a.event(protocol.EventSessionLogin, protocol.SessionLogin{Username: user, At: now}) // persists the state
	}
	if len(logins) == 0 && len(a.st.SessionsReported) != before {
		a.saveState() // pruned
	}
}
