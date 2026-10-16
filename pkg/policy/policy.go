// Package policy is the device path and unit policy (plan M2a decision 8): which files Paddock may manage, in which
// tier (ADR 0034 decision 2), and which systemd units it may control. The server enforces it when definitions are saved; the agent enforces it again
// before it touches the device (defence in depth, plan M2b decision 10).
package policy

import (
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Policy errors.
var (
	ErrPathNotAllowed = errors.New("path must be an absolute, normalized path below /etc/, /usr/local/etc/ or /opt/ and outside the denied paths")
	ErrUnitNotAllowed = errors.New("unit must be a .service, .timer, .socket or .path unit not managed by Paddock, Himmelblau, Fleet (fleet*, orbit*), SSH, GDM or systemd")
	ErrInvalidMode    = errors.New("mode must be four octal digits without setuid, setgid or sticky bit, e.g. 0644")
	ErrInvalidOwner   = errors.New("owner and group must match ^[a-z_][a-z0-9_-]{0,31}$")
)

// Tier of a managed-file path (ADR 0034 decision 2).
type Tier string

// The three tiers, from the least to the most restricted.
const (
	TierOrdinary  Tier = "ordinary"  // RolesWrite, no step-up
	TierSensitive Tier = "sensitive" // org_admin with a step-up
	TierDenied    Tier = "denied"    // refused by server and agent
)

// allowedRoots are the directories below which files may be managed.
var allowedRoots = []string{"/etc/", "/usr/local/etc/", "/opt/"}

// The path catalog of plan M8s §6.2. Denied paths belong to a protected area on the device (CLAUDE.md), to Paddock
// or fleetd, to the patch management (/etc/apt/), or change the loader, the boot chain, the kernel or the identity
// of the device; sensitive paths run code as root or change how users and the network start, but are legitimate
// management tasks. A directory entry ends in "/" and covers everything below it; a prefix entry covers every path
// that starts with it.
var (
	deniedFiles = []string{
		"/etc/sudoers", "/etc/sudo.conf", "/etc/sudo_logsrvd.conf", "/etc/nsswitch.conf", "/etc/crypttab", "/etc/fstab",
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/default/orbit", "/etc/default/grub",
		"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/krb5.conf", "/etc/login.defs", "/etc/shells", "/etc/securetty",
		"/etc/environment", "/etc/sysctl.conf", "/etc/systemd/system.conf",
	}
	deniedDirs = []string{
		"/etc/sudoers.d/", "/etc/pam.d/", "/etc/security/", "/etc/himmelblau/", "/etc/paddock/", "/opt/paddock/",
		"/etc/apt/", "/opt/orbit/", "/etc/ld.so.conf.d/", "/etc/tmpfiles.d/", "/etc/dracut.conf.d/",
		"/etc/initramfs-tools/", "/etc/cryptsetup-initramfs/", "/etc/kernel/", "/etc/grub.d/",
		"/etc/systemd/system.conf.d/", "/etc/systemd/system-generators/", "/etc/systemd/system-preset/",
		"/etc/modprobe.d/", "/etc/modules-load.d/", "/etc/sysctl.d/", "/etc/apparmor.d/", "/etc/udev/rules.d/",
		"/etc/polkit-1/",
	}
	deniedPrefixes = []string{
		"/etc/systemd/system/paddock", "/etc/systemd/system/orbit", "/etc/systemd/system/himmelblau",
		"/etc/systemd/system/fleet", "/etc/systemd/system/ssh", "/etc/systemd/system/gdm",
		"/etc/systemd/system/systemd-", "/etc/systemd/system/sudo",
	}
	sensitiveFiles = []string{"/etc/crontab", "/etc/bash.bashrc", "/etc/logrotate.conf"}
	sensitiveDirs  = []string{
		"/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/",
		"/etc/systemd/", "/etc/profile.d/", "/etc/X11/Xsession.d/", "/etc/xdg/autostart/", "/etc/ssh/",
		"/etc/NetworkManager/dispatcher.d/", "/etc/network/", "/etc/logrotate.d/",
	}
)

// Classify returns the tier of path with mode (four octal digits). A malformed path or mode is ErrPathNotAllowed.
// The order is: malformed → error; outside the allowed roots → TierDenied; denied catalog → TierDenied;
// sensitive catalog, a file directly in /etc/, any /etc/<name>.d/ directory, or any execute bit in mode →
// TierSensitive; otherwise TierOrdinary.
func Classify(p, mode string) (Tier, error) {
	if len(p) > 1024 || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "..") ||
		!modePattern.MatchString(mode) {
		return "", ErrPathNotAllowed
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return "", ErrPathNotAllowed
		}
	}
	below := false
	for _, root := range allowedRoots {
		if strings.HasPrefix(p, root) && len(p) > len(root) {
			below = true
		}
	}
	if !below || slices.Contains(deniedFiles, p) || inDirs(p, deniedDirs) {
		return TierDenied, nil
	}
	for _, prefix := range deniedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return TierDenied, nil
		}
	}
	if slices.Contains(sensitiveFiles, p) || inDirs(p, sensitiveDirs) || executable(mode) {
		return TierSensitive, nil
	}
	if rest, ok := strings.CutPrefix(p, "/etc/"); ok {
		first, _, nested := strings.Cut(rest, "/")
		if !nested || strings.HasSuffix(first, ".d") {
			return TierSensitive, nil
		}
	}
	return TierOrdinary, nil
}

// ValidatePath is the denied-only check that the agent repeats before it touches the device: it is
// ErrPathNotAllowed when Classify(p, "0644") is TierDenied or an error.
func ValidatePath(p string) error {
	if t, err := Classify(p, "0644"); err != nil || t == TierDenied {
		return ErrPathNotAllowed
	}
	return nil
}

func inDirs(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p+"/", d) {
			return true
		}
	}
	return false
}

// executable reports any execute bit of a mode that matched modePattern.
func executable(mode string) bool {
	for _, c := range mode[1:] {
		if (c-'0')%2 == 1 {
			return true
		}
	}
	return false
}

var (
	modePattern  = regexp.MustCompile(`^0[0-7]{3}$`)
	ownerPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	unitPattern  = regexp.MustCompile(`^[a-zA-Z0-9@._-]+\.(service|timer|socket|path)$`)
)

// reservedUnitPrefixes are units that belong to Paddock or to components whose configuration is protected.
var reservedUnitPrefixes = []string{"paddock", "himmelblau", "fleet", "orbit", "ssh", "gdm", "systemd-"}

// ValidateMode checks the file mode.
func ValidateMode(m string) error {
	if !modePattern.MatchString(m) {
		return ErrInvalidMode
	}
	return nil
}

// ValidateOwner checks an owner or group name.
func ValidateOwner(name string) error {
	if !ownerPattern.MatchString(name) {
		return ErrInvalidOwner
	}
	return nil
}

// ValidateUnit checks a systemd unit name.
func ValidateUnit(name string) error {
	if len(name) > 255 || !unitPattern.MatchString(name) {
		return ErrUnitNotAllowed
	}
	lower := strings.ToLower(name)
	for _, prefix := range reservedUnitPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return ErrUnitNotAllowed
		}
	}
	return nil
}
