// Package policy is the device path and unit policy (plan M2a decision 8): which files Paddock may manage and which
// systemd units it may control. The server enforces it when definitions are saved; the agent enforces it again
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
	ErrPathNotAllowed = errors.New("path must be an absolute, normalized path below /etc/, /usr/local/etc/ or /opt/ and outside the protected areas")
	ErrUnitNotAllowed = errors.New("unit must be a .service, .timer, .socket or .path unit not managed by Paddock, Himmelblau, Fleet (fleet*, orbit*), SSH, GDM or systemd")
	ErrInvalidMode    = errors.New("mode must be four octal digits without setuid, setgid or sticky bit, e.g. 0644")
	ErrInvalidOwner   = errors.New("owner and group must match ^[a-z_][a-z0-9_-]{0,31}$")
)

// allowedRoots are the directories below which files may be managed.
var allowedRoots = []string{"/etc/", "/usr/local/etc/", "/opt/"}

// protectedFiles and protectedDirs are system-critical or reserved (CLAUDE.md "Protected areas on the device";
// /etc/apt/ is reserved for patch management in M5).
var (
	protectedFiles = []string{
		"/etc/sudoers", "/etc/nsswitch.conf", "/etc/crypttab", "/etc/fstab", "/etc/passwd", "/etc/shadow",
		"/etc/group", "/etc/gshadow", "/etc/default/orbit",
	}
	protectedDirs = []string{
		"/etc/sudoers.d/", "/etc/pam.d/", "/etc/security/", "/etc/himmelblau/", "/etc/paddock/", "/opt/paddock/",
		"/etc/apt/", "/opt/orbit/",
	}
	// fleetd's unit and drop-ins (plan M5a decision 5) as well as Paddock's own units.
	protectedPrefixes = []string{"/etc/systemd/system/paddock", "/etc/systemd/system/orbit"}
)

// ValidatePath enforces the file path policy.
func ValidatePath(p string) error {
	if len(p) > 1024 || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "..") {
		return ErrPathNotAllowed
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return ErrPathNotAllowed
		}
	}
	below := false
	for _, root := range allowedRoots {
		if strings.HasPrefix(p, root) && len(p) > len(root) {
			below = true
		}
	}
	if !below || slices.Contains(protectedFiles, p) {
		return ErrPathNotAllowed
	}
	for _, d := range protectedDirs {
		if strings.HasPrefix(p+"/", d) {
			return ErrPathNotAllowed
		}
	}
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return ErrPathNotAllowed
		}
	}
	return nil
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
