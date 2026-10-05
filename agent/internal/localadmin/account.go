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

// localEntry returns the fields of name's line in a colon-separated local database file (nil if absent).
func (m *Manager) localEntry(path, name string) ([]string, error) {
	data, _, err := m.Sys.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if f := strings.Split(sc.Text(), ":"); len(f) > 1 && f[0] == name {
			return f, nil
		}
	}
	return nil, nil
}

// adminGroup is the local group that grants sudo: sudo (Debian, Ubuntu) or wheel.
func (m *Manager) adminGroup() (string, error) {
	for _, g := range []string{"sudo", "wheel"} {
		f, err := m.localEntry("/etc/group", g)
		if err != nil {
			return "", err
		}
		if f != nil {
			return g, nil
		}
	}
	return "", ErrNoAdminGroup
}

// read returns the local account from /etc/passwd, /etc/shadow and /etc/group.
func (m *Manager) read(_ context.Context, name string) (account, error) {
	var a account
	group, err := m.adminGroup()
	if err != nil {
		return a, err
	}
	a.group = group
	pw, err := m.localEntry("/etc/passwd", name)
	if err != nil || pw == nil {
		return a, err
	}
	if len(pw) < 7 {
		return a, fmt.Errorf("/etc/passwd: unexpected entry of %s", name)
	}
	a.exists, a.shell = true, pw[6]
	if sh, err := m.localEntry("/etc/shadow", name); err != nil {
		return a, err
	} else if len(sh) >= 8 {
		a.hash, a.expire = sh[1], sh[7]
	}
	gr, err := m.localEntry("/etc/group", group)
	if err != nil {
		return a, err
	}
	if len(gr) >= 4 {
		a.inGroup = slices.Contains(strings.Split(gr[3], ","), name)
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
	// --prefix /. makes useradd check the local files instead of NSS, which Himmelblau answers for any name ("/"
	// alone would mean no prefix); everything else is created as without it.
	if err := m.tool(ctx, "useradd", "--prefix", "/.", "-m", "-K", "HOME_MODE=0700", "-s", Shell, "-G", a.group, "--", name); err != nil {
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
	group, err := m.adminGroup()
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
