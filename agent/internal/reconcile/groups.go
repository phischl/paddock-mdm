package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// privilegedGroup is one privileged local group as found on the device.
type privilegedGroup struct {
	Foreign       []string // members that are no break-glass account, in getent order
	HasBreakGlass bool     // at least one usable break-glass account is a member
}

// groupMembers returns every privileged group that exists on the device (plan M3b decision 15). Directory users that
// Himmelblau's local_groups added are members like any other. A break-glass account is never foreign, but it counts
// as present only if it is usable (usableAccount): a name in the group without a usable account must not let the
// agent remove the last real administrator.
func (s *Sudo) groupMembers(ctx context.Context, spec bundle.SudoSpec) (map[string]privilegedGroup, error) {
	out := map[string]privilegedGroup{}
	usable := map[string]bool{}
	for _, g := range spec.PrivilegedGroups {
		line, exit, err := s.Sys.Getent(ctx, "group", g)
		if err != nil {
			return nil, fmt.Errorf("getent group %s: %w", g, err)
		}
		if exit != 0 {
			continue // the group does not exist here
		}
		var pg privilegedGroup
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) >= 4 && f[3] != "" {
			for _, m := range strings.Split(f[3], ",") {
				if !slices.Contains(spec.BreakGlassAccounts, m) {
					pg.Foreign = append(pg.Foreign, m)
					continue
				}
				ok, known := usable[m]
				if !known {
					if ok, err = s.usableAccount(ctx, m); err != nil {
						return nil, err
					}
					usable[m] = ok
				}
				pg.HasBreakGlass = pg.HasBreakGlass || ok
			}
		}
		out[g] = pg
	}
	return out, nil
}

// usableAccount reports whether name is an account someone can sign in with: getent passwd resolves it and its local
// /etc/shadow entry exists and is not locked. A password field starting with '!' (passwd -l, usermod -L, or no password
// ever set) or '*' counts as locked, the same rule as passwd -S status L. The shadow file is read directly, not through
// NSS, as the local administrator does: break-glass accounts are local accounts.
func (s *Sudo) usableAccount(ctx context.Context, name string) (bool, error) {
	_, exit, err := s.Sys.Getent(ctx, "passwd", name)
	if err != nil {
		return false, fmt.Errorf("getent passwd %s: %w", name, err)
	}
	if exit != 0 {
		return false, nil
	}
	data, _, err := s.Sys.ReadFile("/etc/shadow")
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read /etc/shadow: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 2 && f[0] == name {
			return !strings.HasPrefix(f[1], "!") && !strings.HasPrefix(f[1], "*"), nil
		}
	}
	return false, nil
}

// cleanGroups removes the foreign members of every group that has a break-glass member and keeps every member of
// a group without one (never the last administrator, ADR 0008 amendment 2026-10-17); each kept member is reported
// once per daemon run as tamper.sudo_group_member with removed=false and reason last_admin.
//
// A removal is reported as tamper.sudo_group_member; removed is false for a member gpasswd could not remove (e.g. one
// that another NSS source provides) or that it must not be given: gpasswd reads "--" after -d as the user, so a name
// starting with '-' cannot be passed safely and is refused (plan M4a step 0a).
func (s *Sudo) cleanGroups(ctx context.Context, groups map[string]privilegedGroup) (bool, error) {
	removed := false
	var errs []error
	kept := map[string]bool{}
	for _, g := range sortedKeys(groups) {
		pg := groups[g]
		if !pg.HasBreakGlass {
			for _, m := range pg.Foreign {
				key := g + "/" + m
				kept[key] = true
				if !s.kept[key] {
					s.Events.emit(protocol.EventTamperSudoGroupMember, protocol.TamperSudoGroupMember{Group: g, Username: m,
						Reason: protocol.SudoGroupMemberKeptLastAdmin})
				}
			}
			continue
		}
		for _, m := range pg.Foreign {
			var err error
			if strings.HasPrefix(m, "-") {
				err = fmt.Errorf("gpasswd -d %q %s: a name starting with '-' is refused", m, g)
			} else {
				var out string
				var exit int
				out, exit, err = s.Sys.Gpasswd(ctx, "-d", m, g)
				if err == nil && exit != 0 {
					err = fmt.Errorf("gpasswd -d %s %s: exit %d: %s", m, g, exit, lastLine(out))
				}
			}
			s.Events.emit(protocol.EventTamperSudoGroupMember, protocol.TamperSudoGroupMember{Group: g, Username: m, Removed: err == nil})
			if err != nil {
				errs = append(errs, err)
				continue
			}
			removed = true
		}
	}
	// Replacing the set forgets members that are gone or whose group gained a break-glass member, so that they are
	// reported again if they are kept later.
	s.kept = kept
	return removed, errors.Join(errs...)
}
