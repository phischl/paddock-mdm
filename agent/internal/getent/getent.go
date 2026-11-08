// Package getent parses the output of `getent passwd <key>` and `getent group <name>` strictly. An NSS module can write
// log lines to the standard output of the process that resolves a name (suspected of Himmelblau 4.0.8 while himmelblaud
// is down, PDK-892), so anything but exactly one well-formed entry is an error, never a guess.
package getent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnexpectedOutput is the error for output that is not exactly one well-formed entry.
var ErrUnexpectedOutput = errors.New("unexpected getent output")

// Passwd is one passwd entry.
type Passwd struct {
	Name string
	UID  uint32
	GID  uint32
}

// Group is one group entry.
type Group struct {
	Name    string
	GID     uint32
	Members []string
}

// ParsePasswd parses the output of `getent passwd <key>` for an exit status 0: exactly one line of seven fields with
// a name and numeric UID and GID.
func ParsePasswd(out string) (Passwd, error) {
	f, err := entry(out, 7)
	if err != nil {
		return Passwd{}, err
	}
	uid, uerr := strconv.ParseUint(f[2], 10, 32)
	gid, gerr := strconv.ParseUint(f[3], 10, 32)
	if f[0] == "" || uerr != nil || gerr != nil {
		return Passwd{}, fmt.Errorf("%w: passwd entry %q", ErrUnexpectedOutput, clip(out))
	}
	return Passwd{Name: f[0], UID: uint32(uid), GID: uint32(gid)}, nil
}

// ParseGroup parses the output of `getent group <name>` for an exit status 0: exactly one line of four fields for the
// group name, with a numeric GID and a comma-separated member list without empty or blank names.
func ParseGroup(out, name string) (Group, error) {
	f, err := entry(out, 4)
	if err != nil {
		return Group{}, err
	}
	gid, gerr := strconv.ParseUint(f[2], 10, 32)
	if f[0] != name || gerr != nil {
		return Group{}, fmt.Errorf("%w: group entry %q", ErrUnexpectedOutput, clip(out))
	}
	g := Group{Name: f[0], GID: uint32(gid)}
	if f[3] == "" {
		return g, nil
	}
	for _, m := range strings.Split(f[3], ",") {
		if m == "" || strings.ContainsAny(m, " \t") {
			return Group{}, fmt.Errorf("%w: member list %q", ErrUnexpectedOutput, clip(out))
		}
		g.Members = append(g.Members, m)
	}
	return g, nil
}

// entry splits the single line of out into exactly n colon-separated fields.
func entry(out string, n int) ([]string, error) {
	line := strings.TrimSuffix(out, "\n")
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return nil, fmt.Errorf("%w: %q", ErrUnexpectedOutput, clip(out))
	}
	f := strings.Split(line, ":")
	if len(f) != n {
		return nil, fmt.Errorf("%w: %d fields, want %d: %q", ErrUnexpectedOutput, len(f), n, clip(out))
	}
	return f, nil
}

// clip bounds the output quoted in an error, so a log flood does not end up in an event or the journal.
func clip(s string) string {
	const limit = 200
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
