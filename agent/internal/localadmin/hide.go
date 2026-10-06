package localadmin

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"strings"
)

// AccountsServiceUsers is AccountsService's directory of per-user files; GDM lists the users AccountsService reports.
const AccountsServiceUsers = "/var/lib/AccountsService/users"

// hiddenUser marks the account as a system account, which AccountsService (and so the GDM user list) leaves out;
// "Not listed?" at GDM, text consoles and SSH still accept it (plan M4a.1 decision 4).
const hiddenUser = "[User]\nSystemAccount=true\n"

// hide keeps the account off the login screen's user list. The file is protected: a missing file or one without
// SystemAccount=true is rewritten and AccountsService restarted, as it reads the file only when it loads a user.
// Keys AccountsService adds itself after a login (icon, input sources) are kept while SystemAccount stays true.
// Without AccountsService there is no user list to hide from.
func (m *Manager) hide(ctx context.Context, name string) {
	if _, info, err := m.Sys.ReadFile(AccountsServiceUsers); err != nil || info == nil || !info.IsDir() {
		return
	}
	path := AccountsServiceUsers + "/" + name
	if data, _, err := m.Sys.ReadFile(path); err == nil && systemAccount(data) {
		return
	}
	// AccountsService keeps its files 0600 root:root.
	if err := m.Sys.WriteFileAtomic(path, []byte(hiddenUser), 0o600, 0, 0); err != nil {
		slog.WarnContext(ctx, "hiding the local administrator from the login screen failed", "error", err)
		return
	}
	if out, exit, err := m.Sys.Systemctl(ctx, "try-restart", "accounts-daemon.service"); err != nil || exit != 0 {
		slog.WarnContext(ctx, "restarting AccountsService failed", "exit", exit, "output", strings.TrimSpace(out), "error", err)
		return
	}
	slog.InfoContext(ctx, "local administrator hidden from the login screen", "username", name)
}

// systemAccount reports whether an AccountsService user file sets SystemAccount=true in its [User] group.
func systemAccount(data []byte) bool {
	group := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			group = line
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && group == "[User]" && strings.TrimSpace(k) == "SystemAccount" {
			return strings.TrimSpace(v) == "true"
		}
	}
	return false
}
