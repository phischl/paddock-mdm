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

// testRoots are the operator roots of the classification vectors.
var testRoots = []string{"/etc/myapp/", "/usr/local/etc/tool/", "/opt/myapp/"}

// classifyVectors are the test vectors of plan M8s §6.2 and its amendment of 2026-10-16 (decision 7a), classified
// with testRoots.
var classifyVectors = []struct {
	path, mode string
	want       Tier
}{
	{"/etc/ld.so.preload", "0644", TierDenied},
	{"/etc/tmpfiles.d/x.conf", "0644", TierDenied},
	{"/etc/systemd/system/sshd.service.d/override.conf", "0644", TierDenied},
	{"/etc/polkit-1/rules.d/10.rules", "0644", TierDenied},
	{"/etc/sudo.conf", "0644", TierDenied},
	{"/etc/apparmor.d/usr.bin.x", "0644", TierDenied},
	{"/opt/paddock/x", "0644", TierDenied},
	{"/var/lib/x", "0644", TierDenied},
	{"/etc", "0644", TierDenied},
	{"/etc/sudoers.d/x", "0755", TierDenied},
	{"/etc/systemd/system/service.d/10-env.conf", "0644", TierDenied},
	{"/etc/systemd/system.control/myapp.service.d/50-x.conf", "0644", TierDenied},
	{"/etc/systemd/system.attached/x.service", "0644", TierDenied},
	{"/etc/myapp/lib/Helper.pm", "0644", TierSensitive},
	{"/etc/myapp/index.php", "0644", TierSensitive},
	{"/etc/myapp/rc.bash", "0644", TierSensitive},
	{"/etc/myapp/rc.zsh", "0644", TierSensitive},
	{"/opt/myapp/app.mjs", "0644", TierSensitive},
	{"/opt/myapp/app.cjs", "0644", TierSensitive},
	{"/etc/systemd/system/timer.d/x.conf", "0644", TierDenied},
	{"/etc/systemd/system/scope.d/x.conf", "0644", TierDenied},
	{"/usr/local/lib/systemd/system/service.d/x.conf", "0644", TierDenied},
	{"/etc/systemd/system/myapp.service.d/10.conf", "0644", TierSensitive},
	{"/etc/cron.d/backup", "0644", TierSensitive},
	{"/etc/systemd/system/myapp.service", "0644", TierSensitive},
	{"/etc/profile.d/proxy.sh", "0644", TierSensitive},
	{"/etc/ssh/sshd_config.d/10.conf", "0644", TierSensitive},
	{"/etc/foo.conf", "0644", TierSensitive},
	{"/etc/foo.d/bar.conf", "0644", TierSensitive},
	{"/etc/myapp/hook.sh", "0755", TierSensitive},
	{"/opt/myapp/bin/run", "0750", TierSensitive},
	{"/etc/myapp/app.conf", "0755", TierSensitive},
	{"/etc/myapp/app.conf", "0601", TierSensitive},
	{"/etc/crontab", "0644", TierSensitive},
	{"/etc/default/cron", "0644", TierSensitive},
	{"/etc/dpkg/dpkg.cfg.d/x", "0644", TierSensitive},
	{"/etc/other/app.conf", "0644", TierSensitive},
	{"/etc/myapp/plugin.so", "0644", TierSensitive},
	{"/etc/myapp/libx.so.1", "0644", TierSensitive},
	{"/opt/myapp/lib/site.py", "0644", TierSensitive},
	{"/opt/myapp/lib/x.pth", "0644", TierSensitive},
	{"/etc/myapp/conf.d/10.conf", "0644", TierSensitive},
	{"/etc/myapp/app.conf", "0644", TierOrdinary},
	{"/usr/local/etc/tool/tool.toml", "0644", TierOrdinary},
	{"/opt/myapp/conf/settings.ini", "0640", TierOrdinary},
}

func TestClassify(t *testing.T) {
	for _, v := range classifyVectors {
		t.Run(string(v.want)+":"+v.path+":"+v.mode, func(t *testing.T) {
			got, err := Classify(v.path, v.mode, testRoots)
			if err != nil || got != v.want {
				t.Fatalf("Classify(%q, %q) = %q, %v; want %q", v.path, v.mode, got, err, v.want)
			}
			if denied := errors.Is(ValidatePath(v.path), ErrPathNotAllowed); denied != (v.want == TierDenied) {
				t.Fatalf("ValidatePath(%q) denied = %v, want %v", v.path, denied, v.want == TierDenied)
			}
		})
	}
	// Without operator roots nothing is ordinary (sensitive is the default), and a stored root that the rules refuse
	// counts as none.
	if got, _ := Classify("/etc/myapp/app.conf", "0644", nil); got != TierSensitive {
		t.Errorf("without roots: %s", got)
	}
	for _, invalid := range []string{"/etc/", "/", "", "/opt/", "/etc/apt/", "/etc/myapp"} {
		if got, _ := Classify("/etc/myapp/app.conf", "0644", []string{invalid}); got == TierOrdinary {
			t.Errorf("invalid root %q yields ordinary", invalid)
		}
	}
	for _, bad := range [][2]string{
		{"../etc/x", "0644"}, {"/etc/x", "0abc"}, {"/etc/x", "644"}, {"/etc/x", "4755"}, {"", "0644"},
		{"/etc/a/../b", "0644"}, {"/etc/mo\ntd", "0644"},
	} {
		if _, err := Classify(bad[0], bad[1], testRoots); !errors.Is(err, ErrPathNotAllowed) {
			t.Errorf("Classify(%q, %q) = %v, want ErrPathNotAllowed", bad[0], bad[1], err)
		}
	}
}

func TestValidateOperatorRoot(t *testing.T) {
	for _, ok := range []string{"/etc/myapp/", "/etc/myapp/conf/", "/usr/local/etc/tool/", "/usr/local/etc/myapp/conf/", "/opt/vendor/", "/etc/paddock-gates/",
		"/opt/paddock-gates/", "/etc/shellsx/"} {
		if err := ValidateOperatorRoot(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "/etc/", "/opt/", "/usr/local/etc/", "/etc/myapp", "etc/myapp/", "/etc//myapp/", "/etc/a/../b/", "/var/lib/x/",
		"/etc/sudoers.d/", "/etc/systemd/system/", "/etc/apt/", "/etc/dpkg/", "/etc/default/", "/etc/grub.d/", "/etc/python3.12/",
		"/etc/yum.repos.d/", "/etc/bash_completion.d/", "/etc/profile.d/", "/etc/gdm3/", "/etc/ssh/", "/etc/cron.d/",
		"/etc/sysctl.d/", "/etc/NetworkManager/", "/etc/ssl/", "/etc/pki/", "/etc/dbus-1/", "/opt/paddock/", "/opt/paddock/x/",
		"/etc/X11/", "/etc/ca-certificates/", "/etc/logrotate.d/", "/etc/network/",
		"/etc/dhcp/", "/etc/openvpn/", "/etc/netplan/", "/etc/wpa_supplicant/", "/etc/sssd/", "/etc/samba/", "/etc/ldap/",
		"/etc/openldap/", "/etc/audisp/", "/etc/skel/", "/etc/csh.login.d/", "/etc/tcsh/", "/etc/ksh/", "/etc/php/8.3/",
		"/etc/systemd/system.control/",
		"/usr/local/etc/ssh/", "/usr/local/etc/sudoers.d/", "/usr/local/etc/pam.d/", "/usr/local/etc/security/",
		"/usr/local/etc/systemd/", "/usr/local/etc/cron.d/", "/usr/local/etc/profile.d/", "/usr/local/etc/bash_completion.d/",
		"/usr/local/etc/zsh/", "/usr/local/etc/python3.12/", "/usr/local/etc/php/", "/usr/local/etc/apt/",
		"/usr/local/etc/default/", "/usr/local/etc/X11/", "/usr/local/etc/openvpn/", "/usr/local/etc/skel/",
	} {
		if err := ValidateOperatorRoot(bad); !errors.Is(err, ErrOperatorRoot) {
			t.Errorf("%q accepted", bad)
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
