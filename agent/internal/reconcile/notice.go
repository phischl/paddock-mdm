package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"unicode/utf8"
)

// The files of the login notice (plan M4a decision 19); all are protected: drift is restored.
const (
	NoticeGDM       = "/etc/dconf/db/gdm.d/90-paddock-notice"
	NoticeIssue     = "/etc/issue.d/90-paddock.issue"
	NoticeSSH       = "/etc/paddock/notice"
	NoticeSSHConfig = "/etc/ssh/sshd_config.d/90-paddock-banner.conf"
	// GDMProfile is the greeter's dconf profile. The distribution's profile has no system database, so the greeter
	// reads gdm.d only with this one; the agent never relies on another package (himmelblau-qr-greeter) creating it.
	GDMProfile = "/etc/dconf/profile/gdm"
)

// gdmProfileDefault is the distribution's greeter profile, the base of GDMProfile; gdmSystemDB is the line that makes
// the greeter read gdm.d.
const (
	gdmProfileDefault = "/usr/share/dconf/profile/gdm"
	gdmSystemDB       = "system-db:gdm"
)

// noticeFiles are the notice files in a fixed order.
var noticeFiles = []string{NoticeGDM, NoticeIssue, NoticeSSH, NoticeSSHConfig}

const managedHeader = "# Managed by Paddock. Do not edit: local changes are reverted.\n"

// validNotice is plain text: at most 2000 characters, no control characters but line breaks and tabs.
func validNotice(text string) bool {
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > 2000 {
		return false
	}
	for _, r := range text {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			return false
		}
	}
	return true
}

// renderNotice returns the desired content of every notice file; nil means absent. The GDM banner needs GDM and its
// greeter profile, the SSH banner an SSH server; an empty text removes every file but the profile.
func (l *Login) renderNotice(text string) map[string][]byte {
	want := map[string][]byte{}
	if text == "" {
		return want
	}
	if l.Sys.PackageInstalled("gdm3") {
		want[NoticeGDM] = []byte(managedHeader + "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=" +
			gvariantString(text) + "\n")
		want[GDMProfile] = l.gdmProfile()
	}
	// agetty expands backslash sequences in issue files.
	want[NoticeIssue] = []byte(strings.ReplaceAll(text, `\`, `\\`) + "\n\n")
	if l.Sys.PackageInstalled("openssh-server") {
		want[NoticeSSH] = []byte(text + "\n")
		want[NoticeSSHConfig] = []byte(managedHeader + "Banner " + NoticeSSH + "\n")
	}
	return want
}

// gvariantString quotes s as a GVariant string for a dconf keyfile.
func gvariantString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\t", `\t`)
	return "'" + r.Replace(s) + "'"
}

// gdmProfile returns the greeter profile with gdmSystemDB: the existing one, else the distribution's, else a user
// database only.
func (l *Login) gdmProfile() []byte {
	data, _, err := l.Sys.ReadFile(GDMProfile)
	if err != nil || data == nil {
		data, _, err = l.Sys.ReadFile(gdmProfileDefault)
	}
	if err != nil || data == nil {
		data = []byte("user-db:user\n")
	}
	return withSystemDB(data)
}

// withSystemDB returns profile unchanged if it has gdmSystemDB, otherwise with the line added after the user database
// (the first database is the writable one) or, without one, first.
func withSystemDB(profile []byte) []byte {
	lines := strings.SplitAfter(string(profile), "\n")
	at := 0
	for i, line := range lines {
		if strings.TrimSpace(line) == gdmSystemDB {
			return profile
		}
		if at == 0 && strings.HasPrefix(line, "user-db:") {
			at = i + 1
		}
	}
	if at > 0 && !strings.HasSuffix(lines[at-1], "\n") {
		lines[at-1] += "\n"
	}
	return []byte(strings.Join(slices.Insert(lines, at, gdmSystemDB+"\n"), ""))
}

// noticeChanges lists the notice files that differ from want. The greeter profile is only checked while the GDM
// banner needs it and never removed.
func (l *Login) noticeChanges(want map[string][]byte) []string {
	var out []string
	for _, path := range noticeFiles {
		if !l.fileIs(path, want[path]) {
			out = append(out, path)
		}
	}
	if want[GDMProfile] != nil && !l.fileIs(GDMProfile, want[GDMProfile]) {
		out = append(out, GDMProfile)
	}
	return out
}

// applyNotice writes or removes the notice files, compiles the dconf databases after a GDM change and reloads a
// running SSH server after an SSH change. It reports whether anything changed.
func (l *Login) applyNotice(ctx context.Context, text string) (bool, error) {
	want := l.renderNotice(text)
	changes := l.noticeChanges(want)
	if len(changes) == 0 {
		return false, nil
	}
	var errs []error
	gdm, ssh := false, false
	for _, path := range changes {
		var err error
		if want[path] == nil {
			if err = l.Sys.Remove(path); errors.Is(err, fs.ErrNotExist) {
				err = nil
			}
		} else {
			err = l.Sys.WriteFileAtomic(path, want[path], 0o644, 0, 0)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("notice %s: %w", path, err))
		}
		gdm = gdm || path == NoticeGDM || path == GDMProfile
		ssh = ssh || path == NoticeSSH || path == NoticeSSHConfig
	}
	if gdm && l.Sys.PackageInstalled("dconf-cli") {
		if out, exit, err := l.Sys.Dconf(ctx, "update"); err != nil || exit != 0 {
			errs = append(errs, fmt.Errorf("dconf update: exit %d: %s %v", exit, lastLine(out), err))
		}
	}
	if ssh && l.Sys.PackageInstalled("openssh-server") {
		// Only a running server is reloaded; a socket-activated one reads the configuration per connection.
		if out, exit, err := l.Sys.Systemctl(ctx, "try-reload-or-restart", "ssh.service"); err != nil || exit != 0 {
			errs = append(errs, fmt.Errorf("reload ssh: exit %d: %s %v", exit, lastLine(out), err))
		}
	}
	return true, errors.Join(errs...)
}
