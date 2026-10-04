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
		"Id=7\nUser=811622788\nName=dave@acme.test\nClass=user\n\nId=c1\nUser=60578\nName=gdm-greeter\nClass=greeter\n"
	passwd = "root:x:0:0:root:/root:/bin/bash\ngdm:x:975:975:Gnome Display Manager:/var/lib/gdm3:/bin/false\n" +
		"paddock:x:1000:1000:Paddock Test:/home/paddock:/bin/bash\ndave:x:1001:1001::/home/dave:/bin/bash\n"
)

func fakeLoginctl(t *testing.T) Loginctl {
	return func(_ context.Context, args ...string) (string, int, error) {
		switch {
		case slices.Equal(args, []string{"list-sessions", "--no-legend"}):
			return listed, 0, nil
		case slices.Equal(args, []string{"show-session", "1", "4", "7", "c1", "-p", "Id", "-p", "Name", "-p", "User", "-p", "Class"}):
			return shown, 0, nil
		}
		t.Fatalf("unexpected loginctl %v", args)
		return "", 1, nil
	}
}

func TestListAndDirectoryUsers(t *testing.T) {
	list, err := List(context.Background(), fakeLoginctl(t))
	if err != nil || len(list) != 4 || list[2] != (Session{ID: "7", UID: 811622788, User: "dave@acme.test", Class: "user"}) {
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
	if got := NewLogins(list, local, seen, now); !slices.Equal(got, []string{"dave@acme.test"}) {
		t.Fatalf("first poll %v", got)
	}
	if got := NewLogins(list, local, seen, now.Add(23*time.Hour)); len(got) != 0 {
		t.Fatalf("reported again within 24 h: %v", got)
	}
	if got := NewLogins(list, local, seen, now.Add(24*time.Hour)); !slices.Equal(got, []string{"dave@acme.test"}) {
		t.Fatalf("not reported again after 24 h: %v", got)
	}
}
