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

// Render returns the sudoers file of e for the user with the numeric uid. A full entry grants ALL; a restricted
// entry lists its commands in the given order. Without require_password the commands are tagged NOPASSWD.
func Render(e Entry, uid uint32) ([]byte, error) {
	if err := Validate(e); err != nil {
		return nil, err
	}
	user := fmt.Sprintf("#%d", uid)
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Managed by Paddock. Do not edit. User %s, profile digest %s\n", e.Username, e.ProfileDigest)
	fmt.Fprintf(&b, "Defaults:%s lecture=%s, lecture_file=%s, timestamp_timeout=%d\n", user, e.Lecture, LectureFile,
		e.TimestampTimeoutMin)
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
