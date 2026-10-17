package reconcile

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// privilegedGroup is one privileged local group as found on the device.
type privilegedGroup struct {
	Foreign       []string // members that are no break-glass account, in getent order
	HasBreakGlass bool     // at least one break-glass account is a member
}

// groupMembers returns every privileged group that exists on the device (plan M3b decision 15). Directory users that
// Himmelblau's local_groups added are members like any other.
func (s *Sudo) groupMembers(ctx context.Context, spec bundle.SudoSpec) (map[string]privilegedGroup, error) {
	out := map[string]privilegedGroup{}
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
				if slices.Contains(spec.BreakGlassAccounts, m) {
					pg.HasBreakGlass = true
				} else {
					pg.Foreign = append(pg.Foreign, m)
				}
			}
		}
		out[g] = pg
	}
	return out, nil
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
