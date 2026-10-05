package reconcile

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// groupMembers returns, per privileged group that exists on the device, the members that are no break-glass account
// (plan M3b decision 15). Directory users that Himmelblau's local_groups added are members like any other.
func (s *Sudo) groupMembers(ctx context.Context, spec bundle.SudoSpec) (map[string][]string, error) {
	out := map[string][]string{}
	for _, g := range spec.PrivilegedGroups {
		line, exit, err := s.Sys.Getent(ctx, "group", g)
		if err != nil {
			return nil, fmt.Errorf("getent group %s: %w", g, err)
		}
		if exit != 0 {
			continue // the group does not exist here
		}
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 || f[3] == "" {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if !slices.Contains(spec.BreakGlassAccounts, m) {
				out[g] = append(out[g], m)
			}
		}
	}
	return out, nil
}

// cleanGroups removes the members (`gpasswd -d`) and reports each as tamper.sudo_group_member; removed is false for a
// member gpasswd could not remove (e.g. one that another NSS source provides) or that it must not be given: gpasswd
// reads "--" after -d as the user, so a name starting with '-' cannot be passed safely and is refused (plan M4a step
// 0a).
func (s *Sudo) cleanGroups(ctx context.Context, members map[string][]string) (bool, error) {
	removed := false
	var errs []error
	for _, g := range sortedKeys(members) {
		for _, m := range members[g] {
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
	return removed, errors.Join(errs...)
}
