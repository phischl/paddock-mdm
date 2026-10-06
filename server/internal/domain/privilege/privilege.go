// Package privilege holds permission profiles, their assignments and the effective profile of a user on a device
// (architecture §10.2, ADR 0008, plan M3a decisions 12 and 13). Everything here is pure: no I/O, and the same inputs
// in any order give the same output.
package privilege

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/sudoers"
)

// Class is the privilege class of a profile: none < restricted < full.
type Class string

// Classes.
const (
	ClassNone       Class = "none"
	ClassRestricted Class = "restricted"
	ClassFull       Class = "full"
)

func (c Class) rank() int {
	switch c {
	case ClassRestricted:
		return 1
	case ClassFull:
		return 2
	}
	return 0
}

// Lecture is the sudo lecture option: always is the most restrictive, never the least.
type Lecture string

// Lecture values.
const (
	LectureAlways Lecture = sudoers.LectureAlways
	LectureOnce   Lecture = sudoers.LectureOnce
	LectureNever  Lecture = sudoers.LectureNever
)

func (l Lecture) valid() bool { return l == LectureAlways || l == LectureOnce || l == LectureNever }

func (l Lecture) rank() int {
	switch l {
	case LectureAlways:
		return 2
	case LectureOnce:
		return 1
	}
	return 0
}

// SubjectType is whom an assignment applies to.
type SubjectType string

// Subject types; their order is also the precedence of scalars (user over group over global).
const (
	SubjectGlobal SubjectType = "global"
	SubjectGroup  SubjectType = "group"
	SubjectUser   SubjectType = "user"
)

func (s SubjectType) rank() int {
	switch s {
	case SubjectGroup:
		return 1
	case SubjectUser:
		return 2
	}
	return 0
}

// Profile is a permission profile.
type Profile struct {
	ID                  uuid.UUID
	Name                string
	Class               Class
	Commands            []string
	RequirePassword     bool
	TimestampTimeoutMin int
	Lecture             Lecture
}

// Assignment assigns a profile to everyone (global), a group or a user, optionally only on the devices of one device
// group (DeviceGroupID, uuid.Nil = every device).
type Assignment struct {
	ID            uuid.UUID
	ProfileID     uuid.UUID
	SubjectType   SubjectType
	SubjectID     uuid.UUID // uuid.Nil for global
	DeviceGroupID uuid.UUID
}

// Bounds of a profile.
const (
	MaxCommands = 100
	MaxNameLen  = 100
)

// Validation errors. ErrInvalidCommand is reported as 422 invalid_command, the others as 400 invalid_request.
var (
	ErrInvalidCommand  = errors.New("invalid command")
	ErrInvalidName     = errors.New("name must be 1 to 100 characters")
	ErrInvalidClass    = errors.New("class must be none, restricted or full")
	ErrCommandsByClass = fmt.Errorf("a restricted profile needs 1 to %d distinct commands; none and full profiles have no commands", MaxCommands)
	ErrInvalidScalars  = errors.New("timestamp_timeout_min must be 0 to 60 and lecture always, once or never")
	ErrInvalidSubject  = errors.New("a global assignment has no subject; group and user assignments need one")
)

// NormalizeProfile trims the name and the commands and removes duplicate commands, keeping their order.
func NormalizeProfile(p Profile) Profile {
	p.Name = strings.TrimSpace(p.Name)
	var cmds []string
	for _, c := range p.Commands {
		if c = strings.TrimSpace(c); !slices.Contains(cmds, c) {
			cmds = append(cmds, c)
		}
	}
	p.Commands = cmds
	return p
}

// ValidateProfile checks a normalized profile.
func ValidateProfile(p Profile) error {
	if n := utf8.RuneCountInString(p.Name); n < 1 || n > MaxNameLen {
		return ErrInvalidName
	}
	switch p.Class {
	case ClassRestricted:
		if len(p.Commands) == 0 || len(p.Commands) > MaxCommands {
			return ErrCommandsByClass
		}
		for _, c := range p.Commands {
			if err := sudoers.ValidateCommand(c); err != nil {
				return fmt.Errorf("%w %q: %v", ErrInvalidCommand, c, err)
			}
		}
	case ClassNone, ClassFull:
		if len(p.Commands) > 0 {
			return ErrCommandsByClass
		}
	default:
		return ErrInvalidClass
	}
	if p.TimestampTimeoutMin < 0 || p.TimestampTimeoutMin > sudoers.MaxTimestampTimeoutMin || !p.Lecture.valid() {
		return ErrInvalidScalars
	}
	return nil
}

// InvalidCommands returns the commands that fail the command check, in their order. A profile stored before the check
// was tightened can hold them (plan M3.1 decision 1): the portal reports such a profile as invalid, and the compiler
// omits the sudo entries that would contain them.
func InvalidCommands(commands []string) []string {
	var out []string
	for _, c := range commands {
		if sudoers.ValidateCommand(c) != nil {
			out = append(out, c)
		}
	}
	return out
}

// ValidateAssignmentSubject checks the subject type and the presence of the subject.
func ValidateAssignmentSubject(t SubjectType, id uuid.UUID) error {
	switch t {
	case SubjectGlobal:
		if id != uuid.Nil {
			return ErrInvalidSubject
		}
	case SubjectGroup, SubjectUser:
		if id == uuid.Nil {
			return ErrInvalidSubject
		}
	default:
		return ErrInvalidSubject
	}
	return nil
}

// Subject is the subject of an assignment in a derivation; ID is nil for global assignments.
type Subject struct {
	Type SubjectType `json:"type"`
	ID   *uuid.UUID  `json:"id"`
}

// Derivation kinds.
const (
	DerivedClass   = "class"
	DerivedCommand = "command"
	DerivedScalar  = "scalar"
)

// Derivation records which assignment granted one part of an effective profile: the class, a command (Item = the
// command) or a scalar (Item = require_password, timestamp_timeout_min or lecture).
type Derivation struct {
	Kind         string    `json:"kind"`
	Item         string    `json:"item"`
	Value        string    `json:"value"`
	AssignmentID uuid.UUID `json:"assignment_id"`
	ProfileID    uuid.UUID `json:"profile_id"`
	Subject      Subject   `json:"subject"`
}

// EffectiveProfile is the merged profile of one user on one device.
type EffectiveProfile struct {
	// Class is the merged class; ReportedClass is full when a restricted profile is root-equivalent, which is how
	// detection and the portal treat it.
	Class                  Class        `json:"class"`
	ReportedClass          Class        `json:"reported_class"`
	RootEquivalent         bool         `json:"root_equivalent"`
	RootEquivalentCommands []string     `json:"root_equivalent_commands"`
	CatalogVersion         int          `json:"catalog_version"`
	Commands               []string     `json:"commands"`
	RequirePassword        bool         `json:"require_password"`
	TimestampTimeoutMin    int          `json:"timestamp_timeout_min"`
	Lecture                Lecture      `json:"lecture"`
	Derivation             []Derivation `json:"derivation"`
}

// Input is everything the effective profile of a user on a device depends on.
type Input struct {
	UserID       uuid.UUID
	UserGroups   []uuid.UUID // groups the user is a member of
	DeviceGroups []uuid.UUID // device groups the device is a member of
	Assignments  []Assignment
	Profiles     []Profile
}

// Effective merges the profiles that apply to a user on a device (architecture §10.2): assignments scoped to a device
// group the device is not in are ignored; class = max; commands = sorted union; scalars come from the most specific
// subject level present (user over group over global) and, within that level, the most restrictive value wins
// (require_password true, lowest timestamp_timeout_min, lecture always > once > never). Without any applicable
// assignment the class is none with the most restrictive scalars.
func Effective(in Input) EffectiveProfile {
	profiles := map[uuid.UUID]Profile{}
	for _, p := range in.Profiles {
		profiles[p.ID] = p
	}
	type applied struct {
		a Assignment
		p Profile
	}
	var apps []applied
	seen := map[uuid.UUID]bool{}
	for _, a := range in.Assignments {
		p, ok := profiles[a.ProfileID]
		if !ok || seen[a.ID] || !applies(a, in) {
			continue
		}
		seen[a.ID] = true
		apps = append(apps, applied{a, p})
	}
	out := EffectiveProfile{
		Class: ClassNone, CatalogVersion: CatalogVersion, Commands: []string{}, RootEquivalentCommands: []string{},
		RequirePassword: true, Lecture: LectureAlways, Derivation: []Derivation{},
	}
	if len(apps) == 0 {
		out.ReportedClass = ClassNone
		return out
	}
	derive := func(kind, item, value string, x applied) {
		out.Derivation = append(out.Derivation, Derivation{
			Kind: kind, Item: item, Value: value, AssignmentID: x.a.ID, ProfileID: x.p.ID, Subject: subjectOf(x.a),
		})
	}

	for _, x := range apps {
		if x.p.Class.rank() > out.Class.rank() {
			out.Class = x.p.Class
		}
		for _, c := range x.p.Commands {
			out.Commands = append(out.Commands, c)
			derive(DerivedCommand, c, c, x)
		}
	}
	slices.Sort(out.Commands)
	out.Commands = slices.Compact(out.Commands)

	level := 0
	for _, x := range apps {
		level = max(level, x.a.SubjectType.rank())
	}
	var top []applied
	for _, x := range apps {
		if x.p.Class == out.Class {
			derive(DerivedClass, "class", string(out.Class), x)
		}
		if x.a.SubjectType.rank() == level {
			top = append(top, x)
		}
	}
	out.RequirePassword = false
	out.TimestampTimeoutMin = sudoers.MaxTimestampTimeoutMin
	out.Lecture = LectureNever
	for _, x := range top {
		out.RequirePassword = out.RequirePassword || x.p.RequirePassword
		out.TimestampTimeoutMin = min(out.TimestampTimeoutMin, x.p.TimestampTimeoutMin)
		if x.p.Lecture.rank() > out.Lecture.rank() {
			out.Lecture = x.p.Lecture
		}
	}
	for _, x := range top {
		if x.p.RequirePassword == out.RequirePassword {
			derive(DerivedScalar, "require_password", strconv.FormatBool(out.RequirePassword), x)
		}
		if x.p.TimestampTimeoutMin == out.TimestampTimeoutMin {
			derive(DerivedScalar, "timestamp_timeout_min", strconv.Itoa(out.TimestampTimeoutMin), x)
		}
		if x.p.Lecture == out.Lecture {
			derive(DerivedScalar, "lecture", string(out.Lecture), x)
		}
	}
	slices.SortFunc(out.Derivation, compareDerivation)

	out.RootEquivalentCommands = RootEquivalentCommands(out.Commands)
	if out.RootEquivalentCommands == nil {
		out.RootEquivalentCommands = []string{}
	}
	out.RootEquivalent = len(out.RootEquivalentCommands) > 0
	out.ReportedClass = out.Class
	if out.Class == ClassRestricted && out.RootEquivalent {
		out.ReportedClass = ClassFull
	}
	return out
}

func applies(a Assignment, in Input) bool {
	if a.DeviceGroupID != uuid.Nil && !slices.Contains(in.DeviceGroups, a.DeviceGroupID) {
		return false
	}
	switch a.SubjectType {
	case SubjectGlobal:
		return true
	case SubjectGroup:
		return slices.Contains(in.UserGroups, a.SubjectID)
	case SubjectUser:
		return a.SubjectID == in.UserID
	}
	return false
}

func subjectOf(a Assignment) Subject {
	if a.SubjectType == SubjectGlobal {
		return Subject{Type: a.SubjectType}
	}
	id := a.SubjectID
	return Subject{Type: a.SubjectType, ID: &id}
}

func compareDerivation(a, b Derivation) int {
	return cmp.Or(
		cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Item, b.Item),
		cmp.Compare(a.AssignmentID.String(), b.AssignmentID.String()),
	)
}

// MaxReportedClass returns the higher of two classes (for the highest class of a user over all devices).
func MaxReportedClass(a, b Class) Class {
	if b.rank() > a.rank() {
		return b
	}
	return a
}

// SudoEntry is the sudo bundle entry of username, or false for class none (no entry, plan M3a decision 16). Full
// entries carry no commands.
func (e EffectiveProfile) SudoEntry(username string) (sudoers.Entry, bool, error) {
	if e.Class == ClassNone {
		return sudoers.Entry{}, false, nil
	}
	entry := sudoers.Entry{
		Username: username, Class: string(e.Class), RootEquivalent: e.RootEquivalent, Commands: []string{},
		RequirePassword: e.RequirePassword, TimestampTimeoutMin: e.TimestampTimeoutMin, Lecture: string(e.Lecture),
	}
	if e.Class == ClassRestricted {
		entry.Commands = slices.Clone(e.Commands)
	}
	digest, err := sudoers.Digest(entry)
	if err != nil {
		return sudoers.Entry{}, false, err
	}
	entry.ProfileDigest = digest
	return entry, true, nil
}
