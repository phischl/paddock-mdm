package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/sessions"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/timeticket"
)

// The dead man's switch on the device (architecture §12.6, plan M4c decision 16): the agent counts the uptime since
// the last accepted time ticket, warns at the lead times before the period ends and, once it ended, hands the stored
// self-lock token to paddock-revoke with the counted time. Wall-clock changes neither defer nor trigger it: only
// CLOCK_BOOTTIME deltas (/proc/uptime) count, powered-off time does not.

// DMSTick is how often the counter advances and is persisted.
const DMSTick = 60 * time.Second

// dmsDay is a day of the switch's period and lead times: a minute in development builds, so the gate runs in
// minutes (plan M4c gate R6).
func dmsDay() time.Duration {
	if buildinfo.Dev {
		return time.Minute
	}
	return 24 * time.Hour
}

// Files of the dead man's switch.
const (
	dmsIssueFile = "/etc/issue.d/80-paddock-dms.issue"
	selfLockFile = "/var/lib/paddock/revoke/self-lock.dsse" // stored by paddock-revoke
)

// dmsState is /var/lib/paddock/state/dms.json.
type dmsState struct {
	// TicketAt is issued_at of the last accepted time ticket.
	TicketAt time.Time `json:"ticket_at"`
	// Elapsed is the uptime counted since then; BootID and Uptime are the boot and the uptime of the last count.
	Elapsed time.Duration `json:"elapsed_ns"`
	BootID  string        `json:"boot_id"`
	Uptime  time.Duration `json:"uptime_ns"`
	// Warned are the lead times (days) already warned of; Triggered is set once the self-lock was handed over.
	Warned    []int `json:"warned,omitempty"`
	Triggered bool  `json:"triggered,omitempty"`
}

func (a *Agent) dmsPath() string { return a.d.Layout.Join("/var/lib/paddock/state/dms.json") }

func (a *Agent) loadDMS() dmsState {
	var st dmsState
	if data, err := os.ReadFile(a.dmsPath()); err == nil {
		_ = json.Unmarshal(data, &st) // a corrupt file starts the count again
	}
	return st
}

func (a *Agent) saveDMS(st dmsState) {
	data, err := json.Marshal(st)
	if err == nil {
		err = fsutil.WriteFile(a.dmsPath(), data, 0o600, 0o700)
	}
	if err != nil {
		slog.Error("saving the dead man's switch state failed", "error", err)
	}
}

// acceptTicket resets the counter when the check-in carried a valid time ticket newer than the last accepted one,
// and removes the warnings. It reports whether it accepted the ticket.
func (a *Agent) acceptTicket(raw json.RawMessage) bool {
	if len(raw) == 0 || a.current == nil || a.current.Keys == nil || len(a.current.Keys.TimeTicket) == 0 {
		return false
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range a.current.Keys.TimeTicket {
		if pub, err := base64.StdEncoding.DecodeString(k.PublicKey); err == nil && len(pub) == ed25519.PublicKeySize {
			keys[k.KeyID] = pub
		}
	}
	t, err := timeticket.Verify(raw, keys, a.d.Config.OrganizationID)
	if err != nil {
		slog.Warn("time ticket refused", "error", err)
		return false
	}
	st := a.loadDMS()
	if !t.IssuedAt.After(st.TicketAt) {
		return false
	}
	st.TicketAt, st.Elapsed, st.Warned, st.Triggered = t.IssuedAt, 0, nil, false
	// The count starts now, not at the last tick.
	if up, boot, err := a.d.Uptime(); err == nil {
		st.BootID, st.Uptime = boot, up
	}
	a.saveDMS(st)
	a.clearDMSWarning()
	return true
}

// tickDMS advances the counter by the uptime since the last count and acts on the switch of the current bundle.
func (a *Agent) tickDMS(ctx context.Context) {
	up, boot, err := a.d.Uptime()
	if err != nil {
		slog.WarnContext(ctx, "reading the uptime failed", "error", err)
		return
	}
	st := a.loadDMS()
	if boot == st.BootID && up >= st.Uptime {
		st.Elapsed += up - st.Uptime
	} else {
		st.Elapsed += up // a new boot: its uptime so far
	}
	st.BootID, st.Uptime = boot, up
	defer func() { a.saveDMS(st) }()
	if a.current == nil || a.current.DMS == nil || !a.current.DMS.Enabled {
		// Without the switch nothing happens; warnings of a switch turned off go.
		a.dropDMSWarnings(&st)
		return
	}
	period := time.Duration(a.current.DMS.PeriodDays) * dmsDay()
	env, err := os.ReadFile(a.d.Layout.Join(selfLockFile))
	if err != nil {
		// Without a self-lock token (delete_self_lock arrived before the bundle that turns the switch off) there is
		// no lock to warn of (plan M5a step 0b).
		a.dropDMSWarnings(&st)
	} else {
		for _, w := range a.current.DMS.WarnDays {
			if st.Elapsed >= period-time.Duration(w)*dmsDay() && st.Elapsed < period && !slices.Contains(st.Warned, w) {
				st.Warned = append(st.Warned, w)
				a.warnDMS(ctx, period-st.Elapsed)
			}
		}
	}
	if st.Elapsed < period || st.Triggered {
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "the dead man's switch period ended, but there is no self-lock token", "error", err)
		st.Triggered = true
		a.event(protocol.EventRevocationRefused, map[string]any{"reason": "no_self_lock_token"})
		return
	}
	// Recorded first: the self-lock is handed over once per silence.
	st.Triggered = true
	a.saveDMS(st)
	slog.WarnContext(ctx, "the dead man's switch period ended; handing the self-lock to paddock-revoke", "elapsed", st.Elapsed)
	refused, err := a.d.SelfLock(ctx, env, st.Elapsed)
	switch {
	case err != nil:
		a.event(protocol.EventRevocationRefused, map[string]any{"reason": revokeReason(err)})
	case refused != "":
		a.event(protocol.EventRevocationRefused, map[string]any{"reason": refused})
	}
}

// dmsMessage is the warning text; remaining is rounded up to whole days of the period's unit.
func dmsMessage(remaining time.Duration) string {
	days := int((remaining + dmsDay() - 1) / dmsDay())
	unit := "days"
	if buildinfo.Dev {
		unit = "minutes (development build)"
	}
	return fmt.Sprintf("This device has not reached Paddock for a long time. It locks itself in %d %s unless it "+
		"reaches Paddock before. Connect it to the network or contact your administrator.", days, unit)
}

// warnDMS shows the warning on every user session (desktop notification) and on the login screen (/etc/issue.d).
func (a *Agent) warnDMS(ctx context.Context, remaining time.Duration) {
	msg := dmsMessage(remaining)
	slog.WarnContext(ctx, "dead man's switch warning", "remaining", remaining)
	if err := fsutil.WriteFile(a.d.Layout.Join(dmsIssueFile), []byte(msg+"\n"), 0o644, 0o755); err != nil {
		slog.ErrorContext(ctx, "writing the login screen warning failed", "error", err)
	}
	if a.d.Notify != nil {
		a.d.Notify(ctx, msg)
	}
}

// dropDMSWarnings forgets the warnings shown and removes the login screen warning.
func (a *Agent) dropDMSWarnings(st *dmsState) {
	if len(st.Warned) > 0 {
		st.Warned = nil
		a.clearDMSWarning()
	}
}

func (a *Agent) clearDMSWarning() {
	if err := os.Remove(a.d.Layout.Join(dmsIssueFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("removing the login screen warning failed", "error", err)
	}
}

// procUptime returns the time since boot including suspend (/proc/uptime, CLOCK_BOOTTIME) and the boot ID.
func procUptime() (time.Duration, string, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, "", err
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, "", errors.New("empty /proc/uptime")
	}
	secs, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return 0, "", err
	}
	return time.Duration(secs * float64(time.Second)), string(bytes.TrimSpace(boot)), nil
}

// notifySessions sends a desktop notification to the user of every user session (`systemd-run --machine=<user>@
// --user notify-send`); a session without a desktop just fails.
func notifySessions(ctx context.Context, loginctl sessions.Loginctl, run func(ctx context.Context, args ...string) error, msg string) {
	list, err := sessions.List(ctx, loginctl)
	if err != nil {
		return
	}
	done := map[string]bool{}
	for _, s := range list {
		if !strings.HasPrefix(s.Class, "user") || done[s.User] {
			continue
		}
		done[s.User] = true
		if err := run(ctx, "systemd-run", "--machine="+s.User+"@", "--user", "--quiet", "--collect",
			"notify-send", "--urgency=critical", "--app-name=Paddock", "Paddock", msg); err != nil {
			slog.InfoContext(ctx, "desktop notification not shown", "user", s.User, "error", err)
		}
	}
}

// deleteSelfLock is the command delete_self_lock: the organization turned its dead man's switch off, the stored
// self-lock token goes (plan M4c decision 15), and with it the pending warnings, before the bundle that turns the
// switch off arrives (plan M5a step 0b).
func (a *Agent) deleteSelfLock(context.Context, *command.Command) (string, map[string]any) {
	err := os.Remove(a.d.Layout.Join(selfLockFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return protocol.CommandFailed, map[string]any{"reason": "remove_failed"}
	}
	st := a.loadDMS()
	st.Warned = nil
	a.saveDMS(st)
	a.clearDMSWarning()
	return protocol.CommandSucceeded, map[string]any{"deleted": err == nil}
}

// runTool runs a tool of the desktop notification with a timeout; its output is not used.
func runTool(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, args[0], args[1:]...).Run() //nolint:gosec // fixed tools (systemd-run, notify-send)
}
