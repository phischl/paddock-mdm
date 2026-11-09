package desktop

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
)

func notifyLine(uid string) string {
	return "systemd-run --machine=" + uid + "@.host --user --quiet --collect --wait notify-send --app-name=Paddock " +
		"--urgency=normal -- Summary -body"
}

// TestNotifyActiveGraphicalSessions: one systemd-run per active wayland or x11 user session, none for a tty, a
// greeter (also Ubuntu 24.04's, which is an active wayland session, PDK-878) or a session in the background; a failed
// notification is counted as not reached, never an error.
func TestNotifyActiveGraphicalSessions(t *testing.T) {
	sys := fakesys.New()
	sys.Sessions = []fakesys.Session{
		{ID: "2", UID: 811622788, User: "dave@acme.test", Class: "user", Type: "wayland", State: "active"},
		{ID: "3", UID: 1000, User: "paddock", Class: "user", Type: "x11", State: "active"},
		{ID: "4", UID: 1001, User: "erin", Class: "user", Type: "tty", State: "active"},
		{ID: "5", UID: 1002, User: "fred", Class: "user", Type: "wayland", State: "online"},
		{ID: "c1", UID: 60578, User: "gdm-greeter", Class: "greeter", State: "active"},
		{ID: "c2", UID: 120, User: "gdm", Class: "greeter", Type: "wayland", State: "active"},
		{ID: "6", UID: 1003, User: "gina", Class: "user", Type: "x11", State: "active"},
	}
	sys.Outputs = map[string]fakesys.OutputReply{
		notifyLine("811622788"): {},
		notifyLine("1000"):      {},
		notifyLine("1003"):      {Exit: 1},
	}
	n, err := Notify(context.Background(), sys, "Summary", "-body")
	if err != nil || n != (Result{Sessions: 3, Reached: 2}) {
		t.Fatalf("Notify = %+v, %v", n, err)
	}
	want := []string{notifyLine("811622788"), notifyLine("1000"), notifyLine("1003")}
	if !slices.Equal(sys.OutputCalls, want) {
		t.Fatalf("calls %q", sys.OutputCalls)
	}
}

// TestNotifyUser: only the active graphical sessions of the given user are told (a self-service operation, plan M13b
// decision 13).
func TestNotifyUser(t *testing.T) {
	sys := fakesys.New()
	sys.Sessions = []fakesys.Session{
		{ID: "2", UID: 811622788, User: "dave@acme.test", Class: "user", Type: "wayland", State: "active"},
		{ID: "3", UID: 1000, User: "paddock", Class: "user", Type: "x11", State: "active"},
		{ID: "4", UID: 1000, User: "paddock", Class: "user", Type: "tty", State: "active"},
	}
	sys.Outputs = map[string]fakesys.OutputReply{notifyLine("1000"): {}}
	n, err := NotifyUser(context.Background(), sys, 1000, "Summary", "-body")
	if err != nil || n != (Result{Sessions: 1, Reached: 1}) || !slices.Equal(sys.OutputCalls, []string{notifyLine("1000")}) {
		t.Fatalf("NotifyUser = %+v, %v, calls %q", n, err, sys.OutputCalls)
	}
}

func TestNotifyWithoutSessions(t *testing.T) {
	sys := fakesys.New()
	n, err := Notify(context.Background(), sys, "s", "b")
	if err != nil || n != (Result{}) || len(sys.OutputCalls) != 0 {
		t.Fatalf("Notify = %+v, %v, calls %v", n, err, sys.OutputCalls)
	}
}

func TestNotifyListFails(t *testing.T) {
	n, err := Notify(context.Background(), failingLoginctl{fakesys.New()}, "s", "b")
	if err == nil || n != (Result{}) {
		t.Fatalf("Notify = %+v, %v", n, err)
	}
}

type failingLoginctl struct{ *fakesys.System }

func (failingLoginctl) Loginctl(context.Context, ...string) (string, int, error) {
	return "", -1, errors.New("no logind")
}

func TestLanguage(t *testing.T) {
	for content, want := range map[string]string{
		"LANG=de_DE.UTF-8\n":                  German,
		"# generated\nLANG=\"de_AT.UTF-8\"\n": German,
		"LANGUAGE=de\nLANG=en_US.UTF-8\n":     English,
		"LANG=C.UTF-8\n":                      English,
		"":                                    English,
	} {
		sys := fakesys.New()
		sys.Files[LocaleFile] = &fakesys.File{Data: []byte(content), Mode: 0o644}
		if got := Language(sys); got != want {
			t.Errorf("Language(%q) = %s, want %s", content, got, want)
		}
	}
	if got := Language(fakesys.New()); got != English {
		t.Fatalf("without the file: %s", got)
	}
}

// TestNotifyFailureIsWarned: a session the notice cannot reach is logged at warn level with the session, the UID and
// the cause, never only at debug level (PDK-878).
func TestNotifyFailureIsWarned(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	sys := fakesys.New()
	sys.Sessions = []fakesys.Session{{ID: "3", UID: 1000, User: "paddock", Class: "user", Type: "wayland", State: "active"}}
	sys.Outputs = map[string]fakesys.OutputReply{notifyLine("1000"): {Exit: 1}}
	n, err := Notify(context.Background(), sys, "Summary", "-body")
	if err != nil || n != (Result{Sessions: 1}) {
		t.Fatalf("Notify = %+v, %v", n, err)
	}
	out := buf.String()
	for _, want := range []string{"level=WARN", "desktop notification not shown", "session=3", "uid=1000", "exit"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q lacks %q", out, want)
		}
	}
}
