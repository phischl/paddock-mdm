// Package declarative is the declarative configuration of an organization (paddock.yml, plan M6c decisions 13–15):
// the document, its schema validation and the diff between the current and the desired configuration.
package declarative

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:generate cp ../../../../api/schema/paddock.v1.json paddock.v1.json

// Schema is api/schema/paddock.v1.json (JSON Schema draft 2020-12), the source of truth of the document.
//
//go:embed paddock.v1.json
var Schema []byte

// Constants of the document header.
const (
	APIVersion = "paddock/v1"
	Kind       = "OrganizationConfig"
	schemaURL  = "https://paddock-mdm.invalid/schema/paddock.v1.json"
)

// MaxViolations bounds the violations a ValidationError reports.
const MaxViolations = 20

// Document is an organization's configuration. A nil section is absent (untouched); an empty slice is present and
// empty (delete all).
type Document struct {
	APIVersion         string               `json:"api_version"`
	Kind               string               `json:"kind"`
	Settings           *Settings            `json:"settings,omitempty"`
	DeviceGroups       *[]DeviceGroup       `json:"device_groups,omitempty"`
	PermissionProfiles *[]PermissionProfile `json:"permission_profiles,omitempty"`
	ManagedFiles       *[]ManagedFile       `json:"managed_files,omitempty"`
	ManagedUnits       *[]ManagedUnit       `json:"managed_units,omitempty"`
	PackageHolds       *[]PackageHold       `json:"package_holds,omitempty"`
	ProfileAssignments *[]ProfileAssignment `json:"profile_assignments,omitempty"`
}

// Settings are the organization's settings sections.
type Settings struct {
	Login   *LoginSettings  `json:"login,omitempty"`
	Updates *UpdateSettings `json:"updates,omitempty"`
}

// LoginSettings are the fields of PUT /api/v1/settings/login.
type LoginSettings struct {
	HelloEnabled           bool     `json:"hello_enabled"`
	HelloPinMinLength      int      `json:"hello_pin_min_length"`
	UserLockSessionAction  string   `json:"user_lock_session_action"`
	BreakGlassAccounts     []string `json:"break_glass_accounts"`
	SudoersDAllowlist      []string `json:"sudoers_d_allowlist"`
	SudoLectureText        string   `json:"sudo_lecture_text"`
	LocalAdminUsername     string   `json:"local_admin_username"`
	LocalAdminRotationDays int      `json:"local_admin_rotation_days"`
	RotateAfterRevealHours *int     `json:"rotate_after_reveal_hours"`
	NoticeText             string   `json:"notice_text"`
	BootPinMinLength       int      `json:"boot_pin_min_length"`
}

// UpdateSettings are the fields of PUT /api/v1/settings/updates.
type UpdateSettings struct {
	SecurityDailyAt       string `json:"security_daily_at"`
	RegularSchedule       string `json:"regular_schedule"`
	RegularUpdatesEnabled bool   `json:"regular_updates_enabled"`
	MaxRandomDelayMin     int    `json:"max_random_delay_min"`
	StalenessWarningH     int    `json:"staleness_warning_h"`
	StalenessCriticalH    int    `json:"staleness_critical_h"`
}

// DeviceGroup is a device group; key: Name.
type DeviceGroup struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// PermissionProfile is a permission profile; key: Name.
type PermissionProfile struct {
	Name                string   `json:"name"`
	Class               string   `json:"class"`
	Commands            []string `json:"commands"`
	RequirePassword     bool     `json:"require_password"`
	TimestampTimeoutMin int      `json:"timestamp_timeout_min"`
	Lecture             string   `json:"lecture"`
}

// ManagedFile is a managed file; key: DeviceGroup and Path.
type ManagedFile struct {
	Path        string  `json:"path"`
	DeviceGroup *string `json:"device_group"`
	Mode        string  `json:"mode"`
	Owner       string  `json:"owner"`
	Group       string  `json:"group"`
	Content     string  `json:"content"`
}

// ManagedUnit is a managed systemd unit; key: DeviceGroup and Unit.
type ManagedUnit struct {
	Unit        string  `json:"unit"`
	DeviceGroup *string `json:"device_group"`
	Enabled     bool    `json:"enabled"`
	Active      bool    `json:"active"`
}

// PackageHold is a package hold; key: DeviceGroup and Package.
type PackageHold struct {
	Package     string  `json:"package"`
	Version     *string `json:"version"`
	DeviceGroup *string `json:"device_group"`
	Reason      string  `json:"reason"`
}

// ProfileAssignment assigns a permission profile; key: Profile, Subject and DeviceGroup.
type ProfileAssignment struct {
	Profile     string  `json:"profile"`
	Subject     Subject `json:"subject"`
	DeviceGroup *string `json:"device_group"`
}

// Subject types of a profile assignment.
const (
	SubjectGlobal = "global"
	SubjectGroup  = "group"
	SubjectUser   = "user"
)

// Subject is who a profile is assigned to: everyone, a user group (by slug) or a user (by username).
type Subject struct {
	Type     string `json:"type"`
	Slug     string `json:"slug,omitempty"`
	Username string `json:"username,omitempty"`
}

// The defaults of optional item fields equal the defaults of the per-resource create endpoints.

// UnmarshalJSON fills the defaults of absent fields.
func (p *PermissionProfile) UnmarshalJSON(b []byte) error {
	type plain PermissionProfile
	v := plain{Commands: []string{}, RequirePassword: true, TimestampTimeoutMin: 5, Lecture: "once"}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = PermissionProfile(v)
	return nil
}

// UnmarshalJSON fills the defaults of absent fields.
func (f *ManagedFile) UnmarshalJSON(b []byte) error {
	type plain ManagedFile
	v := plain{Mode: "0644", Owner: "root", Group: "root"}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*f = ManagedFile(v)
	return nil
}

// UnmarshalJSON fills the defaults of absent fields.
func (u *ManagedUnit) UnmarshalJSON(b []byte) error {
	type plain ManagedUnit
	v := plain{Enabled: true, Active: true}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*u = ManagedUnit(v)
	return nil
}

// Violation is one schema violation: a JSON pointer into the document and a message.
type Violation struct {
	Path    string
	Message string
}

// ValidationError lists the schema violations of a document (at most MaxViolations).
type ValidationError struct{ Violations []Violation }

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Violations))
	for i, v := range e.Violations {
		parts[i] = v.Path + ": " + v.Message
	}
	return strings.Join(parts, "; ")
}

// ValidateJSON validates raw against the schema; a violation is a *ValidationError.
func ValidateJSON(raw []byte) error {
	schema, err := compileSchema()
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return &ValidationError{Violations: []Violation{{Path: "/", Message: "not a JSON document: " + err.Error()}}}
	}
	err = schema.Validate(inst)
	var verr *jsonschema.ValidationError
	if errors.As(err, &verr) {
		return &ValidationError{Violations: violations(verr)}
	}
	return err
}

// compileSchema compiles Schema; it takes about a millisecond, so the package keeps no compiled state.
func compileSchema() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema))
	if err != nil {
		return nil, fmt.Errorf("declarative: schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, doc); err != nil {
		return nil, fmt.Errorf("declarative: schema: %w", err)
	}
	s, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("declarative: schema: %w", err)
	}
	return s, nil
}

// violations flattens a validation error into its messages (English), at most MaxViolations.
func violations(e *jsonschema.ValidationError) []Violation {
	var out []Violation
	for _, u := range e.BasicOutput().Errors {
		if u.Error == nil || len(out) >= MaxViolations {
			continue
		}
		path := u.InstanceLocation
		if path == "" {
			path = "/"
		}
		out = append(out, Violation{Path: path, Message: u.Error.String()})
	}
	return out
}

// Decode decodes a document that passed ValidateJSON; absent optional item fields get their defaults.
func Decode(raw []byte) (Document, error) {
	var d Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Document{}, fmt.Errorf("declarative: decode: %w", err)
	}
	return d, nil
}
