// Package sessions reads the user sessions of logind through loginctl (plan M3b decisions 10 and 11) and tells
// directory users from local accounts. It reads session IDs, user names, UIDs and session classes only, never
// process, command or session content.
package sessions

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FirstDirectoryUID is the lowest UID of a directory user; local accounts below it are never treated as directory
// users (plan M3b decisions 8 and 10). Himmelblau derives UIDs far above it.
const FirstDirectoryUID = 60000

// Session is one logind session.
type Session struct {
	ID    string
	UID   int
	User  string
	Class string // user, user-early, …, greeter, lock-screen, manager, background
}

// Loginctl runs loginctl (reconcile.System.Loginctl).
type Loginctl func(ctx context.Context, args ...string) (stdout string, exit int, err error)

// List returns the sessions of logind. It reads the IDs from `list-sessions --no-legend` and the properties from
// one `show-session`, which works alike on systemd 255 (Ubuntu 24.04, no JSON with the session class) and 259.
func List(ctx context.Context, loginctl Loginctl) ([]Session, error) {
	out, exit, err := loginctl(ctx, "list-sessions", "--no-legend")
	if err == nil && exit != 0 {
		err = fmt.Errorf("loginctl list-sessions: exit %d", exit)
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			ids = append(ids, f[0])
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	args := append([]string{"show-session"}, ids...)
	out, exit, err = loginctl(ctx, append(args, "-p", "Id", "-p", "Name", "-p", "User", "-p", "Class")...)
	if err == nil && exit != 0 {
		err = fmt.Errorf("loginctl show-session: exit %d", exit) // a session ended in between: the next pass retries
	}
	if err != nil {
		return nil, err
	}
	return parseShow(out), nil
}

// parseShow parses the property blocks of `loginctl show-session`, separated by empty lines.
func parseShow(out string) []Session {
	var list []Session
	var cur Session
	flush := func() {
		if cur.ID != "" {
			list = append(list, cur)
		}
		cur = Session{}
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			flush()
			continue
		}
		switch k {
		case "Id":
			cur.ID = v
		case "Name":
			cur.User = v
		case "User":
			cur.UID, _ = strconv.Atoi(v)
		case "Class":
			cur.Class = v
		}
	}
	flush()
	return list
}

// LocalUIDs parses /etc/passwd into name → UID.
func LocalUIDs(passwd []byte) map[string]int {
	out := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(passwd))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if uid, err := strconv.Atoi(f[2]); err == nil {
			out[f[0]] = uid
		}
	}
	return out
}

// IsDirectoryUser reports whether a session is a user session of a directory user: a session of class user (never
// a greeter, lock screen or service manager — the GDM greeter of Ubuntu 26.04 runs as a dynamic user with a UID above
// 60000) whose UID is ≥ FirstDirectoryUID or whose user is not in /etc/passwd, and that is no break-glass account
// (plan M3b decision 10).
func IsDirectoryUser(s Session, local map[string]int, breakGlass []string) bool {
	if !strings.HasPrefix(s.Class, "user") {
		return false
	}
	for _, b := range breakGlass {
		if s.User == b {
			return false
		}
	}
	if s.UID >= FirstDirectoryUID {
		return true
	}
	_, isLocal := local[s.User]
	return !isLocal
}

// ReportInterval is how often a user's login is reported at most (plan M3b decision 11).
const ReportInterval = 24 * time.Hour

// NewLogins returns the directory users of sessions that were not reported within ReportInterval and records them
// in seen (username → last report); entries older than ReportInterval are pruned. Local accounts are never reported.
func NewLogins(sessions []Session, local map[string]int, seen map[string]time.Time, now time.Time) []string {
	for user, at := range seen {
		if now.Sub(at) >= ReportInterval {
			delete(seen, user)
		}
	}
	var out []string
	for _, s := range sessions {
		if !IsDirectoryUser(s, local, nil) {
			continue
		}
		if _, ok := seen[s.User]; ok {
			continue
		}
		seen[s.User] = now
		out = append(out, s.User)
	}
	return out
}
