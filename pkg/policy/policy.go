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
	TierOrdinary  Tier = "ordinary"  // below an operator root: RolesWrite, no step-up
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
		// Runtime units and drop-ins that systemctl set-property and the transient unit API write; they apply to every
		// unit, Paddock's included (plan M8s decision 7h-ter).
		"/etc/systemd/system.control/", "/etc/systemd/system.attached/",
		// Type-wide drop-ins apply to every unit of their type, Paddock's own included (plan M8s decision 7h-bis).
		"/etc/systemd/system/service.d/", "/etc/systemd/system/socket.d/", "/etc/systemd/system/timer.d/", "/etc/systemd/system/path.d/", "/etc/systemd/system/mount.d/", "/etc/systemd/system/automount.d/", "/etc/systemd/system/swap.d/", "/etc/systemd/system/target.d/", "/etc/systemd/system/slice.d/", "/etc/systemd/system/scope.d/",
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

// Classify returns the tier of path with mode (four octal digits) for an organization with operatorRoots (directory
// prefixes ending in "/", see ValidateOperatorRoot). A malformed path or mode is ErrPathNotAllowed. The order is:
// malformed → error; outside the allowed roots → TierDenied; denied catalog → TierDenied; sensitive catalog →
// TierSensitive; not below any operator root → TierSensitive; below an operator root but with an execute bit, a
// script or shared-object suffix, or a path component ending in ".d" → TierSensitive; otherwise TierOrdinary (ADR
// 0034 amendment 2026-10-16, plan M8s decision 7a).
func Classify(p, mode string, operatorRoots []string) (Tier, error) {
	if !wellFormed(p) || !modePattern.MatchString(mode) {
		return "", ErrPathNotAllowed
	}
	if denied(p) {
		return TierDenied, nil
	}
	if slices.Contains(sensitiveFiles, p) || inDirs(p, sensitiveDirs) {
		return TierSensitive, nil
	}
	// A stored root that the current rules refuse counts as no root: the tier can only fall back to sensitive.
	below := func(root string) bool { return strings.HasPrefix(p, root) && ValidateOperatorRoot(root) == nil }
	if !slices.ContainsFunc(operatorRoots, below) ||
		executable(mode) || codeSuffix(p) || dotDComponent(p) {
		return TierSensitive, nil
	}
	return TierOrdinary, nil
}

// ValidatePath is the denied-only check that the agent repeats before it touches the device: it is
// ErrPathNotAllowed for a malformed path and for a path outside the allowed roots or in the denied catalog.
func ValidatePath(p string) error {
	if !wellFormed(p) || denied(p) {
		return ErrPathNotAllowed
	}
	return nil
}

func wellFormed(p string) bool {
	if len(p) > 1024 || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "..") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return false
		}
	}
	return true
}

// denied: outside the allowed roots or in the denied catalog; mode and operator roots never change it.
func denied(p string) bool {
	below := slices.ContainsFunc(allowedRoots, func(root string) bool { return strings.HasPrefix(p, root) && len(p) > len(root) })
	if !below || slices.Contains(deniedFiles, p) || inDirs(p, deniedDirs) {
		return true
	}
	return slices.ContainsFunc(deniedPrefixes, func(prefix string) bool { return strings.HasPrefix(p, prefix) })
}

// codeSuffixes are file names that interpreters or the loader run or load (plan M8s decision 7a).
var codeSuffixes = []string{".so", ".py", ".pth", ".sh", ".pl", ".pm", ".rb", ".lua", ".js", ".mjs", ".cjs", ".php", ".bash", ".zsh"}

func codeSuffix(p string) bool {
	name := path.Base(p)
	return strings.Contains(name, ".so.") || slices.ContainsFunc(codeSuffixes, func(s string) bool { return strings.HasSuffix(name, s) })
}

func dotDComponent(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(c string) bool { return strings.HasSuffix(c, ".d") })
}

// ErrOperatorRoot is the message of a refused operator root.
var ErrOperatorRoot = errors.New("an operator root must be a directory below /etc/<name>/, /usr/local/etc/<name>/ or /opt/<name>/ ending in /, outside the denied and sensitive paths and the never-operator directories")

// neverOperator are directories that are never operator roots (plan M8s decision 7b); an entry ending in "*" matches
// every name that starts with it.
var neverOperator = []string{
	"/etc/apt/", "/etc/dpkg/", "/etc/dnf/", "/etc/yum*", "/etc/pacman*", "/etc/default/", "/etc/grub*", "/etc/python*",
	"/etc/perl*", "/etc/ruby*", "/etc/zsh/", "/etc/fish/", "/etc/bash*", "/etc/profile*", "/etc/lightdm/", "/etc/gdm*",
	"/etc/sddm*", "/etc/xdg/", "/etc/X11/", "/etc/audit/", "/etc/selinux/", "/etc/apparmor*", "/etc/firewalld/",
	"/etc/nftables*", "/etc/iptables/", "/etc/ufw/", "/etc/NetworkManager/", "/etc/ssl/", "/etc/ca-certificates*",
	"/etc/pki/", "/etc/ssh/", "/etc/pam.d/", "/etc/security/", "/etc/himmelblau/", "/etc/sudoers*", "/etc/systemd/",
	"/etc/cron*", "/etc/polkit-1/", "/etc/dbus-1/", "/etc/udev/", "/etc/modprobe.d/", "/etc/sysctl*", "/etc/paddock/",
	"/opt/paddock/",
	// Plan M8s decision 7h-ter: network, directory and authentication clients, audit dispatch, new-user skeletons,
	// further shells and interpreters.
	"/etc/dhcp/", "/etc/openvpn/", "/etc/netplan/", "/etc/wpa_supplicant/", "/etc/sssd/", "/etc/samba/", "/etc/ldap/",
	"/etc/openldap/", "/etc/audisp/", "/etc/skel/", "/etc/csh*", "/etc/tcsh*", "/etc/ksh*", "/etc/php*",
	// Service environment files and container runtimes (plan M8s fix round 3).
	"/etc/sysconfig/", "/etc/docker/", "/etc/containers/",
}

// ValidateOperatorRoot checks one operator root (plan M8s decision 7b): a normalized directory of the form
// /etc/<name>/…, /usr/local/etc/<name>/… or /opt/<name>/… with a trailing slash that neither is, contains nor lies
// below a denied or sensitive catalog entry, and lies outside the never-operator directories, below /etc/ and
// /usr/local/etc/ alike.
func ValidateOperatorRoot(root string) error {
	dir := strings.TrimSuffix(root, "/")
	if !strings.HasSuffix(root, "/") || !wellFormed(dir) || dir+"/" != root {
		return ErrOperatorRoot
	}
	if !slices.ContainsFunc(allowedRoots, func(base string) bool { return strings.HasPrefix(root, base) && len(root) > len(base)+1 }) {
		return ErrOperatorRoot
	}
	related := func(entry string) bool { return strings.HasPrefix(entry, root) || strings.HasPrefix(root, entry) }
	relatedFile := func(file string) bool { return strings.HasPrefix(file, root) || strings.HasPrefix(root, file+"/") }
	if slices.ContainsFunc(deniedFiles, relatedFile) || slices.ContainsFunc(sensitiveFiles, relatedFile) {
		return ErrOperatorRoot
	}
	for _, list := range [][]string{deniedDirs, deniedPrefixes, sensitiveDirs} {
		if slices.ContainsFunc(list, related) {
			return ErrOperatorRoot
		}
	}
	for _, never := range neverOperator {
		// Software built for /usr/local reads the same configuration below /usr/local/etc/, so every /etc/ entry
		// applies there as well (plan M8s decision 7h-ter).
		entries := []string{never}
		if rest, ok := strings.CutPrefix(never, "/etc/"); ok {
			entries = append(entries, "/usr/local/etc/"+rest)
		}
		for _, entry := range entries {
			if prefix, ok := strings.CutSuffix(entry, "*"); ok {
				if strings.HasPrefix(root, prefix) {
					return ErrOperatorRoot
				}
			} else if related(entry) {
				return ErrOperatorRoot
			}
		}
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
