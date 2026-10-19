package uninstall

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// adminGroups are the groups whose members administer an Ubuntu or Debian system through sudo.
var adminGroups = []string{"sudo", "admin", "wheel"}

// localAdmin removes the managed local administrator unless it is the last local administrator (the guard of plan
// M8d decision 40 step 7). The account's home directory stays: the helper never deletes below /home.
func (h *Helper) localAdmin(ctx context.Context) (result, step string) {
	if h.LocalAdmin == "" {
		return LocalAdminKept, stepSkipped
	}
	other, err := h.otherAdmin(h.LocalAdmin)
	if err != nil {
		return LocalAdminKept, failed("%v", err)
	}
	if other == "" {
		return LocalAdminKeptLastAdmin, stepDone
	}
	if err := h.run(ctx, "userdel", "--", h.LocalAdmin); err != nil {
		return LocalAdminKept, failed("%v", err)
	}
	if err := os.Remove(h.path(filepath.Join("/var/lib/AccountsService/users", h.LocalAdmin))); err != nil && !os.IsNotExist(err) {
		return LocalAdminRemoved, failed("%v", err)
	}
	return LocalAdminRemoved, stepDone
}

// otherAdmin returns a local account other than name that can still administer the device: UID 1000–59999, a login
// shell, a usable password hash in /etc/shadow and membership in sudo, admin or wheel (primary group or member). It
// reads the local files only, never NSS: a directory account is not a local administrator. "" when there is none.
func (h *Helper) otherAdmin(name string) (string, error) {
	passwd, err := h.table("/etc/passwd")
	if err != nil {
		return "", err
	}
	shadow, err := h.table("/etc/shadow")
	if err != nil {
		return "", err
	}
	groups, err := h.table("/etc/group")
	if err != nil {
		return "", err
	}
	adminGIDs, members := map[string]bool{}, map[string]bool{}
	for _, g := range groups {
		if len(g) < 4 || !slices.Contains(adminGroups, g[0]) {
			continue
		}
		adminGIDs[g[2]] = true
		for _, m := range strings.Split(g[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members[m] = true
			}
		}
	}
	hashes := map[string]string{}
	for _, s := range shadow {
		if len(s) >= 2 {
			hashes[s[0]] = s[1]
		}
	}
	for _, p := range passwd {
		if len(p) < 7 || p[0] == name {
			continue
		}
		uid, err := strconv.Atoi(p[2])
		shell, hash := p[6], hashes[p[0]]
		switch {
		case err != nil || uid < 1000 || uid >= 60000:
		case strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") || shell == "":
		case hash == "" || strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*"):
		case adminGIDs[p[3]] || members[p[0]]:
			return p[0], nil
		}
	}
	return "", nil
}

// table reads a colon-separated system file below Root.
func (h *Helper) table(file string) ([][]string, error) {
	data, err := os.ReadFile(h.path(file))
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Split(line, ":"))
	}
	return out, nil
}
