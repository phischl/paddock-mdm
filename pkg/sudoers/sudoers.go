// Package sudoers is the reference renderer of the per-user sudoers files (architecture §10.3, plan M3a decisions 16
// and 17). The bundle carries structured entries; the device renders each entry with the user's numeric UID as user
// spec, so a local account with the same short name can never match. The compiler renders every entry with a
// placeholder UID and validates it with visudo before signing.
package sudoers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/paddock-mdm/paddock/pkg/canonicaljson"
)

// Classes of an entry. Entries exist only for users with a class other than none.
const (
	ClassRestricted = "restricted"
	ClassFull       = "full"
)

// Lecture values (sudoers option lecture).
const (
	LectureAlways = "always"
	LectureOnce   = "once"
	LectureNever  = "never"
)

// LectureFile is the device path of the organization's lecture text.
const LectureFile = "/etc/paddock/sudo_lecture"

// PlaceholderUID is the UID the compiler renders with for validation (the highest UID that is not -1).
const PlaceholderUID uint32 = 4294967294

// MaxTimestampTimeoutMin bounds Entry.TimestampTimeoutMin.
const MaxTimestampTimeoutMin = 60

// Entry is the effective sudo profile of one user on one device (bundle resource sudo, plan M3a decision 16).
type Entry struct {
	Username            string   `json:"username"`
	Class               string   `json:"class"`
	RootEquivalent      bool     `json:"root_equivalent"`
	Commands            []string `json:"commands"`
	RequirePassword     bool     `json:"require_password"`
	TimestampTimeoutMin int      `json:"timestamp_timeout_min"`
	Lecture             string   `json:"lecture"`
	ProfileDigest       string   `json:"profile_digest"`
}

// Validation errors.
var (
	ErrUsername   = errors.New("sudoers: username must be a lowercase name without whitespace, control or sudoers meta characters")
	ErrClass      = errors.New("sudoers: class must be restricted or full")
	ErrCommand    = errors.New("sudoers: command must be an absolute path with optional arguments, without ALL, '!', '#', control or sudoers meta characters ,:=\\")
	ErrNoCommands = errors.New("sudoers: a restricted entry needs at least one command")
	ErrScalars    = errors.New("sudoers: timestamp_timeout_min must be 0–60 and lecture always, once or never")
)

var (
	usernamePattern = regexp.MustCompile(`^[a-z0-9._@+-]{1,256}$`)
	commandPattern  = regexp.MustCompile(`^/[^\s]+( .*)?$`)
)

// ValidateCommand checks one command of a restricted profile (plan M3a decision 12): an absolute path with optional
// arguments, no ALL, no negation and none of the characters sudoers treats as separators. '#' is refused too: after
// whitespace it starts a comment, which would silently turn "/usr/bin/x #y" into /usr/bin/x with any arguments.
func ValidateCommand(c string) error {
	if len(c) > 1024 || !commandPattern.MatchString(c) || strings.ContainsAny(c, "!#,:=\\") {
		return ErrCommand
	}
	for _, r := range c {
		if r < 0x20 || r == 0x7f {
			return ErrCommand
		}
	}
	for _, field := range strings.Fields(c) {
		if field == "ALL" {
			return ErrCommand
		}
	}
	return nil
}

// Validate checks every field Render writes into the file.
func Validate(e Entry) error {
	if !usernamePattern.MatchString(e.Username) {
		return ErrUsername
	}
	if e.TimestampTimeoutMin < 0 || e.TimestampTimeoutMin > MaxTimestampTimeoutMin {
		return ErrScalars
	}
	switch e.Lecture {
	case LectureAlways, LectureOnce, LectureNever:
	default:
		return ErrScalars
	}
	switch e.Class {
	case ClassFull:
	case ClassRestricted:
		if len(e.Commands) == 0 {
			return ErrNoCommands
		}
		for _, c := range e.Commands {
			if err := ValidateCommand(c); err != nil {
				return fmt.Errorf("%w: %q", err, c)
			}
		}
	default:
		return ErrClass
	}
	if e.ProfileDigest != "" && !digestPattern.MatchString(e.ProfileDigest) {
		return errors.New("sudoers: profile_digest must be 64 lowercase hex characters")
	}
	return nil
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Flavor is the sudo implementation of a device (plan M3b, answer to question 1).
type Flavor string

// Flavors. SudoRS (sudo-rs, the default sudo of Ubuntu 26.04) does not know the setting lecture_file; its users see
// sudo's default lecture.
const (
	Classic Flavor = "classic"
	SudoRS  Flavor = "sudo-rs"
)

// Flavors are the supported flavors; the compiler validates every entry in each of them.
var Flavors = []Flavor{Classic, SudoRS}

// ErrFlavor is returned for an unknown flavor.
var ErrFlavor = errors.New("sudoers: flavor must be classic or sudo-rs")

// MaxSudoRSUID is the largest numeric user sudo-rs 0.2.x handles: longer #uid tokens are a syntax error in Defaults
// and never match in rules. Paddock keeps directory UIDs below it (Himmelblau idmap_range).
const MaxSudoRSUID = 999999999

// ErrUIDTooLarge is returned for a UID over MaxSudoRSUID in the SudoRS flavor.
var ErrUIDTooLarge = errors.New("uid exceeds sudo-rs limit")

// Render returns the sudoers file of e for the user with the numeric uid in the given flavor. A full entry grants ALL;
// a restricted entry lists its commands in the given order. Without require_password the commands are tagged NOPASSWD.
// The flavors differ only in the lecture_file setting, which SudoRS leaves out.
func Render(e Entry, uid uint32, flavor Flavor) ([]byte, error) {
	if flavor != Classic && flavor != SudoRS {
		return nil, ErrFlavor
	}
	if err := Validate(e); err != nil {
		return nil, err
	}
	if flavor == SudoRS && uid > MaxSudoRSUID {
		return nil, ErrUIDTooLarge
	}
	user := fmt.Sprintf("#%d", uid)
	lectureFile := ""
	if flavor == Classic {
		lectureFile = ", lecture_file=" + LectureFile
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Managed by Paddock. Do not edit. User %s, profile digest %s\n", e.Username, e.ProfileDigest)
	fmt.Fprintf(&b, "Defaults:%s lecture=%s%s, timestamp_timeout=%d\n", user, e.Lecture, lectureFile, e.TimestampTimeoutMin)
	cmds := "ALL"
	if e.Class == ClassRestricted {
		cmds = strings.Join(e.Commands, ", ")
	}
	tag := ""
	if !e.RequirePassword {
		tag = "NOPASSWD: "
	}
	fmt.Fprintf(&b, "%s ALL=(root) %s%s\n", user, tag, cmds)
	return b.Bytes(), nil
}

// FileName is the file of username in /etc/sudoers.d: paddock-u-<first 16 hex characters of sha256(username)>. sudo
// ignores files whose names contain "." or end in "~", so usernames never appear in file names.
func FileName(username string) string {
	sum := sha256.Sum256([]byte(username))
	return "paddock-u-" + hex.EncodeToString(sum[:])[:16]
}

// Digest is the profile digest of e: the hex SHA-256 of the canonical JSON of e without its profile_digest.
func Digest(e Entry) (string, error) {
	e.ProfileDigest = ""
	if e.Commands == nil {
		e.Commands = []string{}
	}
	c, err := canonicaljson.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}
