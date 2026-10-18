package sessions

import (
	"context"
	"slices"
	"testing"
	"time"
)

// Output of loginctl 259 (Ubuntu 26.04): the GDM greeter, the local admin over SSH and a Himmelblau user.
const (
	listed = "     1 60578 gdm-greeter -     2673   manager-early -    no   -\n" +
		"     4  1000 paddock     -     3744   user          -    no   -\n" +
		"     7 811622788 dave@acme.test seat0 4100 user   tty2 no   -\n" +
		"    c1 60578 gdm-greeter seat0 2629   greeter       tty1 no   -\n"
	shown = "Id=1\nUser=60578\nName=gdm-greeter\nClass=manager-early\n\nId=4\nUser=1000\nName=paddock\nClass=user\n\n" +
		"Id=7\nUser=811622788\nName=dave@acme.test\nClass=user\nTimestamp=Sat 2026-10-17 10:15:02 UTC\n\nId=c1\nUser=60578\nName=gdm-greeter\nClass=greeter\n"
	passwd = "root:x:0:0:root:/root:/bin/bash\ngdm:x:975:975:Gnome Display Manager:/var/lib/gdm3:/bin/false\n" +
		"paddock:x:1000:1000:Paddock Test:/home/paddock:/bin/bash\ndave:x:1001:1001::/home/dave:/bin/bash\n"
)

func fakeLoginctl(t *testing.T) Loginctl {
	return func(_ context.Context, args ...string) (string, int, error) {
		switch {
		case slices.Equal(args, []string{"list-sessions", "--no-legend"}):
			return listed, 0, nil
		case slices.Equal(args, []string{"show-session", "1", "4", "7", "c1", "-p", "Id", "-p", "Name", "-p", "User", "-p", "Class", "-p", "Timestamp"}):
			return shown, 0, nil
		}
		t.Fatalf("unexpected loginctl %v", args)
		return "", 1, nil
	}
}

func TestListAndDirectoryUsers(t *testing.T) {
	list, err := List(context.Background(), fakeLoginctl(t))
	if err != nil || len(list) != 4 || list[2] != (Session{ID: "7", UID: 811622788, User: "dave@acme.test", Class: "user",
		Started: time.Date(2026, 10, 17, 10, 15, 2, 0, time.UTC)}) || !list[0].Started.IsZero() {
		t.Fatalf("List: %+v %v", list, err)
	}
	local := LocalUIDs([]byte(passwd))
	if local["dave"] != 1001 || len(local) != 4 {
		t.Fatalf("LocalUIDs %v", local)
	}
	tests := []struct {
		s    Session
		want bool
	}{
		{Session{User: "dave@acme.test", UID: 811622788, Class: "user"}, true},
		{Session{User: "erin@acme.test", UID: 5000, Class: "user"}, true}, // not in /etc/passwd
		{Session{User: "dave", UID: 1001, Class: "user"}, false},          // local account with the short name
		{Session{User: "paddock", UID: 1000, Class: "user"}, false},
		{Session{User: "gdm-greeter", UID: 60578, Class: "greeter"}, false},        // Ubuntu 26.04 greeter
		{Session{User: "dave@acme.test", UID: 811622788, Class: "manager"}, false}, // service manager
		{Session{User: "breakglass", UID: 70000, Class: "user"}, false},            // break-glass account
	}
	for _, tt := range tests {
		if got := IsDirectoryUser(tt.s, local, []string{"breakglass"}); got != tt.want {
			t.Errorf("IsDirectoryUser(%+v) = %v", tt.s, got)
		}
	}
}

func TestListWithoutSessions(t *testing.T) {
	list, err := List(context.Background(), func(context.Context, ...string) (string, int, error) { return "", 0, nil })
	if err != nil || list != nil {
		t.Fatalf("%v %v", list, err)
	}
}

func TestNewLoginsOncePerDay(t *testing.T) {
	list, _ := List(context.Background(), fakeLoginctl(t))
	local := LocalUIDs([]byte(passwd))
	seen := map[string]time.Time{}
	now := time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)
	if got := NewLogins(list, local, seen, now); len(got) != 1 || got[0].User != "dave@acme.test" || got[0].UID != 811622788 {
		t.Fatalf("first poll %v", got)
	}
	if got := NewLogins(list, local, seen, now.Add(23*time.Hour)); len(got) != 0 {
		t.Fatalf("reported again within 24 h: %v", got)
	}
	if got := NewLogins(list, local, seen, now.Add(24*time.Hour)); len(got) != 1 || got[0].User != "dave@acme.test" {
		t.Fatalf("not reported again after 24 h: %v", got)
	}
}

// TestNewSessionLoginsEverySession (plan M8d decision 17): with the login history on, every session of a directory
// user is reported once; a session that ended is pruned so that a new session with the same ID is reported again;
// the once-per-day entries are left alone.
func TestNewSessionLoginsEverySession(t *testing.T) {
	local := LocalUIDs([]byte(passwd))
	now := time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)
	seen := map[string]time.Time{"erin@acme.test": now}
	a := Session{ID: "7", UID: 811622788, User: "dave@acme.test", Class: "user"}
	b := Session{ID: "9", UID: 811622788, User: "dave@acme.test", Class: "user"}
	admin := Session{ID: "4", UID: 1000, User: "paddock", Class: "user"}
	if got := NewSessionLogins([]Session{a, b, admin}, local, seen, now); len(got) != 2 || got[0].ID != "7" || got[1].ID != "9" {
		t.Fatalf("first poll %v", got)
	}
	if got := NewSessionLogins([]Session{a, b, admin}, local, seen, now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("reported twice: %v", got)
	}
	if got := NewSessionLogins([]Session{b}, local, seen, now.Add(2*time.Minute)); len(got) != 0 {
		t.Fatalf("after a session ended: %v", got)
	}
	if got := NewSessionLogins([]Session{a, b}, local, seen, now.Add(3*time.Minute)); len(got) != 1 || got[0].ID != "7" {
		t.Fatalf("a new session with the ended session's ID: %v", got)
	}
	if _, ok := seen["erin@acme.test"]; !ok {
		t.Fatal("the once-per-day entry was pruned")
	}
}

func TestParseTimestamp(t *testing.T) {
	if got := parseTimestamp("Sat 2026-10-17 10:15:02 UTC"); !got.Equal(time.Date(2026, 10, 17, 10, 15, 2, 0, time.UTC)) {
		t.Fatalf("parsed %v", got)
	}
	if got := parseTimestamp("n/a"); !got.IsZero() {
		t.Fatalf("garbage parsed as %v", got)
	}
}
