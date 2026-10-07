package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	allowed := []string{
		"/etc/motd", "/etc/chrony/chrony.conf", "/usr/local/etc/app.conf", "/opt/vendor/config.ini",
		"/etc/systemd/system/backup.service", "/etc/sudoers-not-really", "/etc/passwd.d/x", "/etc/aptitude.conf",
	}
	for _, p := range allowed {
		if err := ValidatePath(p); err != nil {
			t.Errorf("%s rejected: %v", p, err)
		}
	}
	rejected := []string{
		"", "etc/motd", "/etc", "/etc/", "/opt/", "/usr/local/etc/", "/var/lib/x", "/usr/bin/sudo", "/root/.ssh/x",
		"/etc/../root/x", "/etc/./motd", "/etc//motd", "/etc/motd/", "/etc/a/../b",
		"/etc/sudoers", "/etc/sudoers.d/paddock", "/etc/sudoers.d", "/etc/pam.d/common-auth", "/etc/security/limits.conf",
		"/etc/nsswitch.conf", "/etc/himmelblau/himmelblau.conf", "/etc/paddock/trust.json", "/etc/paddock",
		"/opt/paddock/bin/paddockd", "/opt/paddock", "/etc/crypttab", "/etc/fstab", "/etc/passwd", "/etc/shadow",
		"/etc/group", "/etc/gshadow", "/etc/apt/sources.list", "/etc/apt", "/etc/systemd/system/paddockd.service",
		"/etc/systemd/system/paddock-supervisor.service", "/opt/orbit/secret.txt", "/opt/orbit", "/etc/default/orbit",
		"/etc/systemd/system/orbit.service.d/90-paddock.conf", "/etc/systemd/system/orbit.service", "/etc/mo\ntd", "/etc/mo\x00td", "/etc/a\\b",
		"/etc/" + strings.Repeat("a", 1100),
	}
	for _, p := range rejected {
		if err := ValidatePath(p); !errors.Is(err, ErrPathNotAllowed) {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestValidateModeOwner(t *testing.T) {
	for _, m := range []string{"0644", "0600", "0755", "0000", "0777"} {
		if ValidateMode(m) != nil {
			t.Errorf("mode %s rejected", m)
		}
	}
	for _, m := range []string{"644", "4755", "2755", "1777", "0844", "06444", "", "0o644"} {
		if ValidateMode(m) == nil {
			t.Errorf("mode %s accepted", m)
		}
	}
	for _, o := range []string{"root", "_chrony", "www-data", "a", strings.Repeat("a", 32)} {
		if ValidateOwner(o) != nil {
			t.Errorf("owner %s rejected", o)
		}
	}
	for _, o := range []string{"", "Root", "1user", "us er", strings.Repeat("a", 33), "user$"} {
		if ValidateOwner(o) == nil {
			t.Errorf("owner %q accepted", o)
		}
	}
}

func TestValidateUnit(t *testing.T) {
	for _, u := range []string{"chrony.service", "backup.timer", "cups.socket", "watch.path", "getty@tty1.service"} {
		if ValidateUnit(u) != nil {
			t.Errorf("unit %s rejected", u)
		}
	}
	for _, u := range []string{
		"chrony", "x.mount", "x.target", "paddockd.service", "Paddock.service", "himmelblaud.service",
		"fleet-osquery.service", "orbit.service", "ssh.service", "sshd.socket", "gdm.service", "systemd-timesyncd.service",
		"a b.service", "../x.service", "",
	} {
		if !errors.Is(ValidateUnit(u), ErrUnitNotAllowed) {
			t.Errorf("unit %q accepted", u)
		}
	}
}
