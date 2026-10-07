package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// dmsWorld is an agent with a 10-day switch warning 3 and 1 days before, a stored self-lock token and a clock of
// uptime the test advances.
type dmsWorld struct {
	a        *Agent
	g        *testgw.Gateway
	uptime   time.Duration
	boot     string
	notified []string
	elapsed  []time.Duration // what SelfLock was called with
}

func newDMSWorld(t *testing.T, enabled bool) *dmsWorld {
	t.Helper()
	w := &dmsWorld{g: testgw.New(t), boot: "boot-1"}
	w.a = newAgent(t, w.g)
	w.a.d.Uptime = func() (time.Duration, string, error) { return w.uptime, w.boot, nil }
	w.a.d.Notify = func(_ context.Context, msg string) { w.notified = append(w.notified, msg) }
	w.a.d.SelfLock = func(_ context.Context, env []byte, elapsed time.Duration) (string, error) {
		if string(env) != "self-lock-token" {
			t.Errorf("self-lock with %q", env)
		}
		w.elapsed = append(w.elapsed, elapsed)
		return "", nil
	}
	w.a.current = &bundle.Bundle{Keys: &bundle.Keys{TimeTicket: testgw.TicketKeys()},
		DMS: &bundle.DMS{Enabled: enabled, PeriodDays: 10, WarnDays: []int{3, 1}}}
	if err := fsutil.WriteFile(w.a.d.Layout.Join(selfLockFile), []byte("self-lock-token"), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	return w
}

// advance moves the uptime on in steps of DMSTick, ticking each.
func (w *dmsWorld) advance(d time.Duration) {
	for end := w.uptime + d; w.uptime < end; {
		w.uptime += min(time.Hour, end-w.uptime)
		w.a.tickDMS(context.Background())
	}
}

func (w *dmsWorld) issue(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(w.a.d.Layout.Join(dmsIssueFile))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestDMSWarnsThenLocks (plan M4c decision 16, gate R6 at the unit level): the device warns at the lead times and
// hands the stored self-lock over only after the period of uptime, once; a fresh time ticket resets the count and the
// warnings; a reboot adds the new boot's uptime.
func TestDMSWarnsThenLocks(t *testing.T) {
	w := newDMSWorld(t, true)
	day := 24 * time.Hour
	w.advance(7*day - time.Hour)
	if len(w.notified) != 0 || w.issue(t) != "" {
		t.Fatalf("warned before the lead time: %v", w.notified)
	}
	w.advance(time.Hour)
	if len(w.notified) != 1 || !strings.Contains(w.issue(t), "locks itself in 3 days") {
		t.Fatalf("first warning: %v / %q", w.notified, w.issue(t))
	}
	// A wall-clock jump changes nothing: only the uptime counts.
	w.a.d.Now = func() time.Time { return time.Now().Add(400 * day) }
	w.advance(2 * day)
	if len(w.notified) != 2 || len(w.elapsed) != 0 {
		t.Fatalf("second warning: %v, self-locks %v", w.notified, w.elapsed)
	}
	// A reboot: the new boot's uptime counts on.
	w.boot, w.uptime = "boot-2", 0
	w.advance(day - time.Hour)
	if len(w.elapsed) != 0 {
		t.Fatalf("self-lock before the period: %v", w.elapsed)
	}
	w.advance(time.Hour)
	if len(w.elapsed) != 1 || w.elapsed[0] < 10*day {
		t.Fatalf("self-lock %v", w.elapsed)
	}
	w.advance(2 * day)
	if len(w.elapsed) != 1 {
		t.Fatalf("self-lock handed over again: %v", w.elapsed)
	}

	// A fresh ticket resets the count and removes the warning; an older one changes nothing.
	at := time.Now().UTC().Truncate(time.Second)
	w.a.acceptTicket(testgw.SignedTicket(t, at))
	if st := w.a.loadDMS(); st.Elapsed != 0 || len(st.Warned) != 0 || st.Triggered || w.issue(t) != "" {
		t.Fatalf("after a ticket: %+v, issue %q", st, w.issue(t))
	}
	w.advance(8 * day)
	w.a.acceptTicket(testgw.SignedTicket(t, at.Add(-time.Hour)))
	if st := w.a.loadDMS(); st.Elapsed != 8*day {
		t.Fatalf("an older ticket reset the count: %+v", st)
	}

	// The count starts at the ticket, not at the tick before it.
	w.uptime += 30 * time.Second
	w.a.acceptTicket(testgw.SignedTicket(t, at.Add(time.Hour)))
	w.uptime += 30 * time.Second
	w.a.tickDMS(context.Background())
	if st := w.a.loadDMS(); st.Elapsed != 30*time.Second {
		t.Fatalf("counted from the tick before the ticket: %+v", st)
	}
}

// TestDMSOff: with the switch off nothing happens, however long the device is silent; delete_self_lock removes the
// stored token.
func TestDMSOff(t *testing.T) {
	w := newDMSWorld(t, false)
	w.advance(30 * 24 * time.Hour)
	if len(w.notified) != 0 || len(w.elapsed) != 0 || w.issue(t) != "" {
		t.Fatalf("switch off: warnings %v, self-locks %v", w.notified, w.elapsed)
	}
	status, _ := w.a.deleteSelfLock(context.Background(), &command.Command{Type: command.TypeDeleteSelfLock})
	if _, err := os.Stat(w.a.d.Layout.Join(selfLockFile)); status != protocol.CommandSucceeded || !os.IsNotExist(err) {
		t.Fatalf("delete_self_lock: %s, %v", status, err)
	}
}

// TestDMSDeleteSelfLockDropsWarnings (plan M5a step 0b): delete_self_lock removes the warnings at once, while the
// applied bundle still has the switch on, and no warning follows until the token is back.
func TestDMSDeleteSelfLockDropsWarnings(t *testing.T) {
	w := newDMSWorld(t, true)
	day := 24 * time.Hour
	w.advance(7 * day)
	if len(w.notified) != 1 || w.issue(t) == "" {
		t.Fatalf("first warning: %v / %q", w.notified, w.issue(t))
	}
	status, _ := w.a.deleteSelfLock(context.Background(), &command.Command{Type: command.TypeDeleteSelfLock})
	if status != protocol.CommandSucceeded || w.issue(t) != "" || len(w.a.loadDMS().Warned) != 0 {
		t.Fatalf("delete_self_lock: %s, issue %q, state %+v", status, w.issue(t), w.a.loadDMS())
	}
	w.advance(2*day + time.Hour)
	if len(w.notified) != 1 || w.issue(t) != "" || len(w.elapsed) != 0 {
		t.Fatalf("after delete_self_lock: warnings %v, issue %q, self-locks %v", w.notified, w.issue(t), w.elapsed)
	}
}
