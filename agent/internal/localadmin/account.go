package localadmin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// account is the local administrator as the device has it.
type account struct {
	exists  bool
	shell   string
	hash    string // password hash field of /etc/shadow
	expire  string // account expiration field of /etc/shadow ("" = never)
	group   string // sudo or wheel
	inGroup bool
}

// hashSHA256 is the hex SHA-256 of the password hash field, "" without account.
func (a account) hashSHA256() string {
	if !a.exists {
		return ""
	}
	return sha256Hex(a.hash)
}

// locked reports a locked or disabled account: a hash passwd -l or usermod -L marked, no password, or an expiry.
func (a account) locked() bool {
	return a.hash == "" || strings.HasPrefix(a.hash, "!") || strings.HasPrefix(a.hash, "*") || a.expire != ""
}

// adminGroup is the group that grants sudo: sudo (Debian, Ubuntu) or wheel.
func (m *Manager) adminGroup(ctx context.Context) (string, error) {
	for _, g := range []string{"sudo", "wheel"} {
		_, exit, err := m.Sys.Getent(ctx, "group", g)
		if err != nil {
			return "", err
		}
		if exit == 0 {
			return g, nil
		}
	}
	return "", ErrNoAdminGroup
}

// read returns the account from NSS and /etc/shadow.
func (m *Manager) read(ctx context.Context, name string) (account, error) {
	var a account
	group, err := m.adminGroup(ctx)
	if err != nil {
		return a, err
	}
	a.group = group
	out, exit, err := m.Sys.Getent(ctx, "passwd", name)
	if err != nil {
		return a, fmt.Errorf("getent passwd %s: %w", name, err)
	}
	if exit != 0 {
		return a, nil
	}
	f := strings.Split(strings.TrimSpace(out), ":")
	if len(f) < 7 {
		return a, fmt.Errorf("getent passwd %s: unexpected entry", name)
	}
	a.exists, a.shell = true, f[6]
	shadow, _, err := m.Sys.ReadFile("/etc/shadow")
	if err != nil {
		return a, fmt.Errorf("read /etc/shadow: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(shadow))
	for sc.Scan() {
		s := strings.Split(sc.Text(), ":")
		if len(s) >= 8 && s[0] == name {
			a.hash, a.expire = s[1], s[7]
			break
		}
	}
	members, exit, err := m.Sys.Getent(ctx, "group", group)
	if err != nil {
		return a, fmt.Errorf("getent group %s: %w", group, err)
	}
	if g := strings.Split(strings.TrimSpace(members), ":"); exit == 0 && len(g) >= 4 {
		a.inGroup = slices.Contains(strings.Split(g[3], ","), name)
	}
	return a, nil
}

// ensure creates a missing account (home 0700, shell Shell, member of the admin group) with a locked password; the
// first rotation sets one. A missing account that had a password is reported as tampered.
func (m *Manager) ensure(ctx context.Context, name string) (account, error) {
	a, err := m.read(ctx, name)
	if err != nil || a.exists {
		return a, err
	}
	if m.State.Generation > 0 {
		m.tampered(protocol.LocalAdminFieldMissing)
	}
	if err := m.tool(ctx, "useradd", "-m", "-K", "HOME_MODE=0700", "-s", Shell, "-G", a.group, "--", name); err != nil {
		return a, err
	}
	if err := m.tool(ctx, "passwd", "-l", "--", name); err != nil {
		return a, err
	}
	slog.InfoContext(ctx, "local administrator account created", "username", name, "group", a.group)
	return m.read(ctx, name)
}

// inspect compares the account with the state of the last rotation, reports every changed field once
// (tamper.local_admin_changed) and repairs shell, group and expiry at once. It reports whether the password needs a
// rotation (changed hash or locked account). Before the first rotation the account is locked on purpose.
func (m *Manager) inspect(ctx context.Context, a account) bool {
	if m.State.Generation == 0 {
		return false
	}
	changed := map[string]bool{
		protocol.LocalAdminFieldPassword: a.hashSHA256() != m.State.ShadowSHA256,
		protocol.LocalAdminFieldLocked:   a.locked(),
		protocol.LocalAdminFieldShell:    a.shell != Shell,
		protocol.LocalAdminFieldGroup:    !a.inGroup,
	}
	for _, field := range []string{protocol.LocalAdminFieldPassword, protocol.LocalAdminFieldLocked, protocol.LocalAdminFieldShell, protocol.LocalAdminFieldGroup} {
		if changed[field] {
			m.tampered(field)
		}
	}
	if changed[protocol.LocalAdminFieldShell] || changed[protocol.LocalAdminFieldGroup] || a.expire != "" {
		m.repairAccount(ctx, m.State.Username)
		if repaired, err := m.read(ctx, m.State.Username); err == nil {
			m.State.Tampered = slices.DeleteFunc(m.State.Tampered, func(f string) bool {
				return (f == protocol.LocalAdminFieldShell && repaired.shell == Shell) || (f == protocol.LocalAdminFieldGroup && repaired.inGroup)
			})
			m.save()
		}
	}
	return changed[protocol.LocalAdminFieldPassword] || changed[protocol.LocalAdminFieldLocked]
}

// tampered reports a changed field once until a rotation or a repair cleared it.
func (m *Manager) tampered(field string) {
	if slices.Contains(m.State.Tampered, field) {
		return
	}
	m.State.Tampered = append(m.State.Tampered, field)
	m.save()
	m.Emit(protocol.EventTamperLocalAdminChanged, protocol.TamperLocalAdminChanged{Field: field})
}

// repairAccount restores shell, admin group membership and removes an expiry; failures are logged and retried at
// the next tick.
func (m *Manager) repairAccount(ctx context.Context, name string) {
	group, err := m.adminGroup(ctx)
	if err != nil {
		slog.WarnContext(ctx, "local administrator repair", "error", err)
		return
	}
	for _, args := range [][]string{{"-s", Shell, "--", name}, {"-a", "-G", group, "--", name}, {"-e", "", "--", name}} {
		if err := m.tool(ctx, "usermod", args...); err != nil {
			slog.WarnContext(ctx, "local administrator repair failed", "error", err)
		}
	}
}

// tool runs an account tool and turns a non-zero exit into an error.
func (m *Manager) tool(ctx context.Context, tool string, args ...string) error {
	out, exit, err := m.Sys.UserTool(ctx, tool, args...)
	if err == nil && exit != 0 {
		err = fmt.Errorf("%s %s: exit %d: %s", tool, strings.Join(args, " "), exit, strings.TrimSpace(out))
	}
	return err
}
