// Package managedconfig holds the rules of managed files and systemd units (plan M2a decisions 7 and 8): which
// paths, modes, owners and units are allowed, and which definition applies to a device.
package managedconfig

import (
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/bundle"
)

// MaxContentBytes bounds the content of a managed file.
const MaxContentBytes = 64 << 10

// Validation errors. ErrPathNotAllowed and ErrUnitNotAllowed map to 422 path_not_allowed and unit_not_allowed.
var (
	ErrPathNotAllowed  = errors.New("path must be an absolute, normalized path below /etc/, /usr/local/etc/ or /opt/ and outside the protected areas")
	ErrUnitNotAllowed  = errors.New("unit must be a .service, .timer, .socket or .path unit not managed by Paddock, Himmelblau, Fleet, SSH, GDM or systemd")
	ErrInvalidMode     = errors.New("mode must be four octal digits without setuid, setgid or sticky bit, e.g. 0644")
	ErrInvalidOwner    = errors.New("owner and group must match ^[a-z_][a-z0-9_-]{0,31}$")
	ErrInvalidContent  = errors.New("content must be UTF-8 text without NUL characters")
	ErrContentTooLarge = errors.New("content must be at most 64 KiB")
)

// allowedRoots are the directories below which files may be managed.
var allowedRoots = []string{"/etc/", "/usr/local/etc/", "/opt/"}

// protectedFiles and protectedDirs are system-critical or reserved (CLAUDE.md "Protected areas on the device";
// /etc/apt/ is reserved for patch management in M5).
var (
	protectedFiles = []string{
		"/etc/sudoers", "/etc/nsswitch.conf", "/etc/crypttab", "/etc/fstab", "/etc/passwd", "/etc/shadow",
		"/etc/group", "/etc/gshadow",
	}
	protectedDirs = []string{
		"/etc/sudoers.d/", "/etc/pam.d/", "/etc/security/", "/etc/himmelblau/", "/etc/paddock/", "/opt/paddock/",
		"/etc/apt/",
	}
	protectedPrefixes = []string{"/etc/systemd/system/paddock"}
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
var reservedUnitPrefixes = []string{"paddock", "himmelblau", "fleet", "ssh", "gdm", "systemd-"}

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

// ValidateContent checks size and encoding of the file content.
func ValidateContent(c string) error {
	if len(c) > MaxContentBytes {
		return ErrContentTooLarge
	}
	if !utf8.ValidString(c) || strings.ContainsRune(c, 0) {
		return ErrInvalidContent
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

// File is a managed file definition. GroupID nil means every device of the organization.
type File struct {
	ID      uuid.UUID
	GroupID *uuid.UUID
	Path    string
	Mode    string
	Owner   string
	Group   string
	Content string
}

// Unit is a managed systemd unit definition. GroupID nil means every device of the organization.
type Unit struct {
	ID      uuid.UUID
	GroupID *uuid.UUID
	Unit    string
	Enabled bool
	Active  bool
}

// Conflict reports definitions of several device groups for the same resource; Winner applies.
type Conflict struct {
	Resource string // "file:<path>" or "unit:<name>"
	Winner   uuid.UUID
	Losers   []uuid.UUID
}

// Effective is the managed configuration that applies to one device, sorted by resource ID.
type Effective struct {
	Files     []File
	Units     []Unit
	Conflicts []Conflict
}

// Resolve selects the definitions that apply to a device that is a member of groups. Per path or unit the most
// specific scope wins (device group over organization); among several device groups the definition with the
// lexicographically smallest ID wins and the others are reported as a conflict — never merged.
func Resolve(files []File, units []Unit, groups []uuid.UUID) Effective {
	var e Effective
	var fileConflicts, unitConflicts []Conflict
	e.Files, fileConflicts = resolve(files, groups, func(f File) (string, uuid.UUID, *uuid.UUID) {
		return "file:" + f.Path, f.ID, f.GroupID
	})
	e.Units, unitConflicts = resolve(units, groups, func(u Unit) (string, uuid.UUID, *uuid.UUID) {
		return "unit:" + u.Unit, u.ID, u.GroupID
	})
	e.Conflicts = append(e.Conflicts, fileConflicts...)
	e.Conflicts = append(e.Conflicts, unitConflicts...)
	return e
}

func resolve[T any](defs []T, groups []uuid.UUID, key func(T) (string, uuid.UUID, *uuid.UUID)) ([]T, []Conflict) {
	type candidates struct {
		org    []T
		scoped []T
	}
	byKey := map[string]*candidates{}
	for _, d := range defs {
		k, _, group := key(d)
		if group != nil && !slices.Contains(groups, *group) {
			continue
		}
		c := byKey[k]
		if c == nil {
			c = &candidates{}
			byKey[k] = c
		}
		if group == nil {
			c.org = append(c.org, d)
		} else {
			c.scoped = append(c.scoped, d)
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []T
	var conflicts []Conflict
	for _, k := range keys {
		c := byKey[k]
		pool := c.org
		if len(c.scoped) > 0 {
			pool = c.scoped
		}
		slices.SortFunc(pool, func(a, b T) int {
			_, ia, _ := key(a)
			_, ib, _ := key(b)
			return strings.Compare(ia.String(), ib.String())
		})
		out = append(out, pool[0])
		if len(pool) > 1 {
			_, winner, _ := key(pool[0])
			conflict := Conflict{Resource: k, Winner: winner}
			for _, l := range pool[1:] {
				_, id, _ := key(l)
				conflict.Losers = append(conflict.Losers, id)
			}
			conflicts = append(conflicts, conflict)
		}
	}
	return out, conflicts
}

// Resources renders the bundle resources of an effective configuration: the fixed time resource (NTP enabled) and
// every file and unit, sorted by resource ID. Compiler and effective-config API share it, so both show the same.
func Resources(e Effective) ([]bundle.Resource, error) {
	tr, err := bundle.TimeResource(bundle.TimeSpec{NTP: true})
	if err != nil {
		return nil, err
	}
	out := []bundle.Resource{tr}
	for _, f := range e.Files {
		r, err := bundle.FileResource(bundle.FileSpec{Path: f.Path, Mode: f.Mode, Owner: f.Owner, Group: f.Group, Content: f.Content})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	for _, u := range e.Units {
		r, err := bundle.UnitResource(bundle.UnitSpec{Unit: u.Unit, Enabled: u.Enabled, Active: u.Active})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	bundle.SortResources(out)
	return out, nil
}
