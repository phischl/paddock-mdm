// Package bundle defines the bundle schemas — the signed desired state of one device — and their verification on the
// device (architecture §7.2, plan M2a §6.3). Schema v2 adds the resources login and sudo (plan M3a decision 14a); the
// compiler renders v2 only for agents that report it (architecture §21).
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/sudoers"
)

// SchemaVersion is the schema version the agent of this release accepts (Verify) and reports in its check-in.
const SchemaVersion = 1

// SchemaVersion2 is v1 plus the resources login and sudo (plan M3a decision 14a).
const SchemaVersion2 = 2

// PayloadType is the DSSE payload type of bundles.
const PayloadType = "application/vnd.paddock.bundle.v1+json"

// Resource types.
const (
	TypeTime        = "time"
	TypeFile        = "file"
	TypeSystemdUnit = "systemd_unit"
	TypeLogin       = "login" // schema v2
	TypeSudo        = "sudo"  // schema v2
	// TypeUpdates is the type and ID of the resource the agent makes of the updates section (plan M5b decision 4).
	TypeUpdates = "updates"
	// TypeHostname is the type and ID of the resource the agent makes of the hostname section (plan M8h decision 10).
	TypeHostname = "hostname"
	// TypeWatch is the type and ID of the resource the agent makes of the watch section (plan M9 decision 39).
	TypeWatch = "watch"
	// TypeSoftware is the type and ID of the resource the agent makes of the software section (ADR 0042 decision 2).
	TypeSoftware = "software"
)

// Bundle is the desired state of one device.
type Bundle struct {
	SchemaVersion  int        `json:"schema_version"`
	BundleVersion  int64      `json:"bundle_version"`
	DeviceID       string     `json:"device_id"`
	OrganizationID string     `json:"organization_id"`
	IssuedAt       time.Time  `json:"issued_at"` // not part of ContentSHA256
	Agent          AgentCfg   `json:"agent"`
	Resources      []Resource `json:"resources"` // sorted by ID
	// Keys are the public keys the agent trusts for commands and encrypts escrowed secrets to (schema v2 only, plan
	// M4a decision 5). Agents that do not know them ignore the field.
	Keys *Keys `json:"keys,omitempty"`
	// Revocation is the revocation section (schema v2 only, plan M4c decisions 1 and 3). Agents that do not know it
	// ignore the field.
	Revocation *Revocation `json:"revocation,omitempty"`
	// DMS is the organization's dead man's switch (schema v2 only, plan M4c decisions 15 and 16).
	DMS *DMS `json:"dms,omitempty"`
	// Inventory enrolls the device into the inventory system (schema v2 only, plan M5a decision 4). Agents that do
	// not know it ignore the field.
	Inventory *Inventory `json:"inventory,omitempty"`
	// Updates configures security updates, regular updates and package holds (schema v2 only, plan M5b decision 4).
	// It is a section, not a resource, so agents that do not know it ignore it instead of rejecting the bundle.
	Updates *UpdatesSpec `json:"updates,omitempty"`
	// Disk is the disk encryption policy of the device (schema v2 only, plan M8d decision 46). Agents that do not know
	// it ignore it.
	Disk *DiskSpec `json:"disk,omitempty"`
	// Hostname is the device's managed name (schema v2 only, ADR 0041). Agents that do not know the section ignore
	// it; a device without a managed name has no section.
	Hostname *HostnameSpec `json:"hostname,omitempty"`
	// Mode is ModeEnforce (absent) or ModeReportOnly; the agent reports a report-only bundle without applying it.
	Mode string `json:"mode,omitempty"`
	// Watch is the organization's presence policy: third-party units the agent reports when they stop (schema v2 only,
	// plan M9 decision 39). Agents that do not know the section ignore it; an organization without watched units has no
	// section.
	Watch *WatchSpec `json:"watch,omitempty"`
	// Software is the device's desired software state: package sources and packages with their intents (schema v2
	// only, ADR 0042 decision 2). Agents that do not know the section ignore it; a device without an applicable
	// assignment has no section.
	Software *SoftwareSpec `json:"software,omitempty"`
}

// WatchSpec is the watch section: the systemd services of third-party agents (an EDR or SIEM agent) the device only
// observes and reports, never installs or restarts.
type WatchSpec struct {
	Units []string `json:"units"`
}

// WatchResource turns the watch section into the resource the agent plans and applies.
func WatchResource(s WatchSpec) (Resource, error) {
	return resource(TypeWatch, TypeWatch, s)
}

// Bundle modes. The enforce mode is the empty value so that bundles without the field keep their content hash.
const (
	ModeEnforce    = ""
	ModeReportOnly = "report_only"
)

// HostnameSpec is the hostname section: the device's managed name (ADR 0041).
type HostnameSpec struct {
	Name string `json:"name"`
}

// MaxHostname is the length limit of a device name (one DNS label; Linux limits the hostname to 64 bytes).
const MaxHostname = 63

var hostnameLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname reports whether name is a lowercase RFC 1123 label of 1 to 63 characters that is not "localhost".
func ValidHostname(name string) bool {
	return len(name) <= MaxHostname && hostnameLabel.MatchString(name) && name != "localhost"
}

// HostnameResource turns the hostname section into the resource the agent plans and applies.
func HostnameResource(s HostnameSpec) (Resource, error) {
	return resource(TypeHostname, TypeHostname, s)
}

// DiskSpec is the disk encryption policy of a device: the unlock mode its keyslots must match and the boot PIN
// length an in-place encryption asks for (plan M8e decision 11; agents before M8e ignore it).
type DiskSpec struct {
	UnlockMode       string `json:"unlock_mode"`
	BootPINMinLength int    `json:"boot_pin_min_length,omitempty"`
}

// Disk unlock modes of DiskSpec (ADR 0038 decision 1).
const (
	UnlockModeTPMPIN  = "tpm_pin"
	UnlockModeTPMOnly = "tpm_only"
)

// Inventory is fleetd's installation and enrollment. The enroll secret only lets a host enroll into Fleet; Paddock
// ignores hosts it cannot map to a device (architecture §15).
type Inventory struct {
	FleetURL     string           `json:"fleet_url"`
	EnrollSecret string           `json:"enroll_secret"`
	Package      InventoryPackage `json:"package"`
}

// InventoryPackage is the fleetd Debian package (amd64) in Paddock's package store: URLPath is relative to
// https://bundles.<domain>/, e.g. packages/1.2.0/fleet-osquery_1.48.0_amd64.deb.
type InventoryPackage struct {
	Version string `json:"version"`
	URLPath string `json:"url_path"`
	SHA256  string `json:"sha256"`
}

// DMS configures the dead man's switch of a device: when enabled, a device that has not accepted a time ticket for
// PeriodDays of uptime locks itself with its stored self-lock token; it warns WarnDays before.
type DMS struct {
	Enabled    bool  `json:"enabled"`
	PeriodDays int   `json:"period_days"`
	WarnDays   []int `json:"warn_days"`
}

// Revocation is the revocation section of a schema v2 bundle.
type Revocation struct {
	// Enabled is the server's feature flag PADDOCK_REVOCATION_ENABLED: the agent writes /etc/paddock/revoke-enabled
	// only while it is true (plan M4c decision 1).
	Enabled bool `json:"enabled"`
	// Keys are the revocation-signing public keys. A device pins them only if it has no revocation trust anchor yet
	// (enrolled before M4c, trust on first use); it never replaces a pinned anchor with them (plan M4c decision 3).
	Keys []SigningKey `json:"keys"`
}

// Keys is the top-level keys object of a schema v2 bundle (plan M4a decision 5).
type Keys struct {
	// CommandSigning are all active versions of the command-signing key.
	CommandSigning []SigningKey `json:"command_signing"`
	// EscrowWrap is the latest version of the escrow-wrap key that devices encrypt escrowed secrets to.
	EscrowWrap *EncryptionKey `json:"escrow_wrap,omitempty"`
	// TimeTicket are all active versions of the time-ticket key (plan M4c decision 14).
	TimeTicket []SigningKey `json:"time_ticket,omitempty"`
}

// EncryptionKey is an RSA public key with its key ID, e.g. "escrow-wrap:v1".
type EncryptionKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// SigningKey is an Ed25519 public key with its DSSE key ID, e.g. "command-signing:v1".
type SigningKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // standard base64 raw Ed25519 public key
}

// AgentCfg configures the agent itself.
type AgentCfg struct {
	CheckinIntervalS int `json:"checkin_interval_s"`
	// UpdatePolicy is the agent update policy of the device (ADR 0037 decision 1): "" (absent) and automatic follow the
	// rollout waves, manual installs an offered release only when an administrator requested it for the device.
	UpdatePolicy string `json:"update_policy,omitempty"`
	// SupervisorPackages are the paddock-supervisor packages of the current release by arch (plan M8d decision 30):
	// the agent installs the one of its arch after its own update to that release, as the policy allows.
	SupervisorPackages map[string]PackageRef `json:"supervisor_packages,omitempty"`
}

// PackageRef is a Debian package on the public package store (https://bundles.<domain>/<url_path>).
type PackageRef struct {
	Version string `json:"version"`
	URLPath string `json:"url_path"`
	SHA256  string `json:"sha256"`
}

// Agent update policies of AgentCfg.UpdatePolicy.
const (
	UpdatePolicyAutomatic = "automatic"
	UpdatePolicyManual    = "manual"
)

// Resource is one managed resource.
type Resource struct {
	ID   string          `json:"id"`   // "time", "file:<path>", "unit:<name>"
	Type string          `json:"type"` // TypeTime | TypeFile | TypeSystemdUnit
	Spec json.RawMessage `json:"spec"`
}

// FileSpec is the spec of a TypeFile resource.
type FileSpec struct {
	Path          string `json:"path"`
	Mode          string `json:"mode"`
	Owner         string `json:"owner"`
	Group         string `json:"group"`
	Content       string `json:"content"`
	ContentSHA256 string `json:"content_sha256"` // hex
}

// UnitSpec is the spec of a TypeSystemdUnit resource.
type UnitSpec struct {
	Unit    string `json:"unit"`
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
}

// TimeSpec is the spec of the TypeTime resource.
type TimeSpec struct {
	NTP bool `json:"ntp"`
}

// LoginSpec is the spec of the TypeLogin resource (id "login", plan M3a decision 15).
type LoginSpec struct {
	Provider   string         `json:"provider"` // "himmelblau"
	Himmelblau HimmelblauSpec `json:"himmelblau"`
	Suspended  bool           `json:"suspended"`
	// LockedUsers are the locked users among the users affected on this device, sorted.
	LockedUsers        []string `json:"locked_users"`
	SessionAction      string   `json:"session_action"` // lock_screen | terminate
	BreakGlassAccounts []string `json:"break_glass_accounts"`
	// LocalAdmin is the managed local administrator account (plan M4a decision 14); agents of earlier releases
	// ignore it. Its username is always one of BreakGlassAccounts.
	LocalAdmin *LocalAdminSpec `json:"local_admin,omitempty"`
	// Notice is the login notice (plan M4a decision 19): plain text, "" for none.
	Notice string `json:"notice,omitempty"`
	// ReportEverySession makes the agent report every session start instead of once per user and 24 hours, while
	// the organization records its login history (plan M8d decision 17); agents of earlier releases ignore it.
	ReportEverySession bool `json:"report_every_session,omitempty"`
}

// LocalAdminSpec is the managed local administrator of the login resource.
type LocalAdminSpec struct {
	Username     string `json:"username"`
	RotationDays int    `json:"rotation_days"`
}

// Login providers and session actions of LoginSpec.
const (
	ProviderHimmelblau      = "himmelblau"
	SessionActionLockScreen = "lock_screen"
	SessionActionTerminate  = "terminate"
)

// HimmelblauSpec are the himmelblau.conf values Paddock owns (architecture §9.3).
type HimmelblauSpec struct {
	OIDCIssuerURL string `json:"oidc_issuer_url"`
	AppID         string `json:"app_id"`
	Domain        string `json:"domain"`
	// PamAllowGroups is written explicitly, also when empty: an empty value denies everyone, a missing line allows
	// everyone (PoC M1 C3).
	PamAllowGroups    []string `json:"pam_allow_groups"`
	EnableHello       bool     `json:"enable_hello"`
	HelloPinMinLength int      `json:"hello_pin_min_length"`
	// PackageVersion is the Himmelblau release the device installs from the official repository (plan M3b
	// decision 6), e.g. "4.0.4"; see ValidHimmelblauVersion.
	PackageVersion string `json:"package_version"`
}

// himmelblauVersion is a Himmelblau release number; it becomes part of the repository URL on the device.
var himmelblauVersion = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)

// ValidHimmelblauVersion reports whether v is a release number such as 4.0.4.
func ValidHimmelblauVersion(v string) bool { return himmelblauVersion.MatchString(v) }

// SudoSpec is the spec of the TypeSudo resource (id "sudo", plan M3a decision 16). The device renders each entry
// with pkg/sudoers.
type SudoSpec struct {
	LectureText        string          `json:"lecture_text"`
	Entries            []sudoers.Entry `json:"entries"` // sorted by username
	PrivilegedGroups   []string        `json:"privileged_groups"`
	SudoersDAllowlist  []string        `json:"sudoers_d_allowlist"`
	BreakGlassAccounts []string        `json:"break_glass_accounts"`
}

// UpdatesSpec is the updates section (plan M5b decision 4): the schedule of daily
// security updates (unattended-upgrades, local device time) and of regular updates (paddock-updates.timer), and the
// packages held on the device.
type UpdatesSpec struct {
	SecurityDailyAt       string `json:"security_daily_at"` // HH:MM, see ValidTimeOfDay
	RegularSchedule       string `json:"regular_schedule"`  // see ValidSchedule
	RegularUpdatesEnabled bool   `json:"regular_updates_enabled"`
	MaxRandomDelayMin     int    `json:"max_random_delay_min"`
	Holds                 []Hold `json:"holds"` // sorted by package
}

// Hold is a held package: Version nil holds the installed version (apt-mark hold), a version pins it (apt
// preferences, Pin-Priority 1001).
type Hold struct {
	Package string  `json:"package"`
	Version *string `json:"version"`
}

// MaxRandomDelayMin bounds UpdatesSpec.MaxRandomDelayMin.
const MaxRandomDelayMin = 720

var (
	packageName    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	packageVersion = regexp.MustCompile(`^[A-Za-z0-9.+:~-]+$`)
	timeOfDay      = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	weekdays       = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
)

// maxPackageField bounds package names and versions.
const maxPackageField = 128

// ValidPackage reports whether name is a Debian package name; it becomes an argument of apt-mark and apt-get and a
// line of apt and unattended-upgrades configuration on the device.
func ValidPackage(name string) bool {
	return len(name) <= maxPackageField && packageName.MatchString(name)
}

// ValidPackageVersion reports whether v is a Debian package version.
func ValidPackageVersion(v string) bool {
	return len(v) <= maxPackageField && packageVersion.MatchString(v)
}

// ValidTimeOfDay reports whether s is a time of day HH:MM (24 h).
func ValidTimeOfDay(s string) bool { return timeOfDay.MatchString(s) }

// ValidSchedule reports whether s is in the subset of systemd OnCalendar expressions Paddock accepts (plan M5b
// decision 1): an optional comma-separated list of distinct weekdays (Mon … Sun) followed by HH:MM, e.g. "Sat 04:00",
// "Mon,Thu 12:30" or "02:00" (every day).
func ValidSchedule(s string) bool {
	days, at, ok := strings.Cut(s, " ")
	if !ok {
		return ValidTimeOfDay(s)
	}
	if !ValidTimeOfDay(at) {
		return false
	}
	seen := map[string]bool{}
	for _, d := range strings.Split(days, ",") {
		if !slices.Contains(weekdays, d) || seen[d] {
			return false
		}
		seen[d] = true
	}
	return true
}

// ValidateUpdates checks every field of an updates spec.
func ValidateUpdates(s UpdatesSpec) error {
	switch {
	case !ValidTimeOfDay(s.SecurityDailyAt):
		return fmt.Errorf("bundle: invalid security_daily_at %q", s.SecurityDailyAt)
	case !ValidSchedule(s.RegularSchedule):
		return fmt.Errorf("bundle: invalid regular_schedule %q", s.RegularSchedule)
	case s.MaxRandomDelayMin < 0 || s.MaxRandomDelayMin > MaxRandomDelayMin:
		return fmt.Errorf("bundle: invalid max_random_delay_min %d", s.MaxRandomDelayMin)
	}
	for _, h := range s.Holds {
		if !ValidPackage(h.Package) || (h.Version != nil && !ValidPackageVersion(*h.Version)) {
			return fmt.Errorf("bundle: invalid hold %q", h.Package)
		}
	}
	return nil
}

// UpdatesResource turns the updates section into the resource the agent plans and applies. Nil holds are encoded as
// an empty list.
func UpdatesResource(s UpdatesSpec) (Resource, error) {
	if s.Holds == nil {
		s.Holds = []Hold{}
	}
	return resource(TypeUpdates, TypeUpdates, s)
}

// SoftwareSpec is the software section (ADR 0042 decision 2): the APT sources the device needs and the packages with
// their intents. Sources and Packages are sorted by slug and package.
type SoftwareSpec struct {
	Sources  []SoftwareSource  `json:"sources"`
	Packages []SoftwarePackage `json:"packages"`
	// Windows are the maintenance windows of the device: the union of its device groups' windows (plan M13c decisions
	// 5 and Q17). Absent means no window: the policy applies at any time. Additive to schema 2 (ADR 0013): an agent
	// before PDK-809 ignores it and applies at once.
	Windows []SoftwareWindow `json:"windows,omitempty"`
	// Repository is the read credential of the organization's Paddock repository (plan M13c decision 15, ADR 0050
	// decision 4), present while a source of the section is that repository. The agent writes it to
	// /etc/apt/auth.conf.d/paddock-repo.conf. Additive to schema 2 (ADR 0013): an agent before PDK-812 ignores it, and
	// apt then fails that source with 401 (source_unreachable) and nothing else.
	Repository *SoftwareRepositoryAuth `json:"repository,omitempty"`
	// RequestWithdraw is the server's capability flag for software.request_withdrawn (PDK-811b, decisions §54): set,
	// the agent reports a withdrawn request, and the server closes it; absent, the withdrawal stays on the device.
	// Additive to schema 2 (ADR 0013); the compiler sets it with a package that requires approval, which an agent
	// before the compiler's approval gate never gets (A10-17).
	RequestWithdraw bool `json:"request_withdraw,omitempty"`
}

// SoftwareRepositoryAuth is an apt basic-auth entry: Host is the machine of apt's auth.conf, the source URI without
// its https:// scheme (host, optional port and path, ending in "/").
type SoftwareRepositoryAuth struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// SoftwareSource is an APT source the device writes as a deb822 file with its keyring, or a Flatpak remote (Kind
// SoftwareSourceFlatpak, plan M13b decision 7) with exactly one URI and no suites, components or architectures.
type SoftwareSource struct {
	Slug          string   `json:"slug"`
	Kind          string   `json:"kind,omitempty"` // "" = APT, SoftwareSourceFlatpak
	URIs          []string `json:"uris"`           // https only
	Suites        []string `json:"suites"`
	Components    []string `json:"components"`
	Architectures []string `json:"architectures"` // empty = apt's default
	Keyring       string   `json:"keyring"`       // standard base64 of the binary OpenPGP public key
	Fingerprint   string   `json:"fingerprint"`   // 40 uppercase hexadecimal characters
}

// Intents of SoftwarePackage.Intent.
const (
	SoftwareRequired  = "required"
	SoftwareUninstall = "uninstall"
	SoftwareHold      = "hold"
	SoftwareForbid    = "forbid"
	// SoftwareAvailable offers the package to the users of its Audience to install and remove themselves (plan M13b
	// decision 7).
	SoftwareAvailable = "available"
)

// Kinds of SoftwareSource.Kind and scopes of SoftwarePackage.Scope (plan M13b decision 7).
const (
	SoftwareSourceFlatpak = "flatpak"
	SoftwareScopeSystem   = "system"
	SoftwareScopeUser     = "user"
)

// MaxSoftwareAudience bounds the user names of an audience (plan M13b R2, decision Q13); the compiler caps a larger
// audience and warns.
const MaxSoftwareAudience = 200

// SoftwareRuntimeEntryID is the catalog_entry_id of a package the compiler adds itself, such as the flatpak runtime
// (plan M13b decision 9): it is not an entry of the organization, and the agent reports it as system-managed.
const SoftwareRuntimeEntryID = "00000000-0000-0000-0000-000000000000"

// SoftwareAudience names who may see and install an available package: everyone (All) or the listed users (lower-case
// UPNs, sorted, at most MaxSoftwareAudience).
type SoftwareAudience struct {
	All   bool     `json:"all,omitempty"`
	Users []string `json:"users,omitempty"`
}

// SoftwarePackage is the desired state of one package.
type SoftwarePackage struct {
	// Package is the APT package; FlatpakRef the Flatpak application ID of a package from a Flatpak source, in Scope
	// ("" = system). A package names exactly one of them.
	Package    string `json:"package"`
	FlatpakRef string `json:"flatpak_ref,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Intent     string `json:"intent"`
	// Version is the version a required package is pinned to or a hold keeps; nil otherwise.
	Version *string `json:"version"`
	// Source is the slug of a Sources entry, "" for the distribution's own repositories.
	Source         string `json:"source"`
	CatalogEntryID string `json:"catalog_entry_id"`
	// SupersededHold marks a forbid or uninstall result that superseded a package hold of the same package on this
	// device: the hold is left out of the updates section so the removal is not refused by apt-mark, and the agent
	// reports the overlap in the software resource's status (architect decision 2026-11-02). Absent otherwise.
	SupersededHold bool `json:"superseded_hold,omitempty"`
	// Audience is set for an available package only.
	Audience *SoftwareAudience `json:"audience,omitempty"`
	// Users are the targeted users (lower-case UPNs, sorted, 1 to MaxSoftwareAudience, ValidAudienceUser) of a
	// user-scope Flatpak application with intent required, forbid or uninstall: the agent acts for these users only.
	// Such an application without Users acts in system scope, never for every user (architect decision A10-11).
	// Absent otherwise; additive to schema 2 (ADR 0013), and an agent before the compiler's self-service gate never
	// gets a Flatpak application (A10-6). A pointer like Audience, so SoftwarePackage stays comparable.
	Users *[]string `json:"users,omitempty"`
	// IconSHA256 is the hex SHA-256 of the catalog entry's PNG icon, which the device fetches through GET
	// /v1/catalog/{entry_id}/icon and may check against it; absent when the entry has no icon. A content change of the
	// icon thereby changes the bundle (architect decision A10-14, PDK-935); additive to schema 2 (ADR 0013), and only an
	// agent from the compiler's self-service gate gets it.
	IconSHA256 string `json:"icon_sha256,omitempty"`
	// Approval is SoftwareApprovalRequired for an available package whose users must ask an administrator before they
	// install it (plan M13c decision 9); absent otherwise. Additive to schema 2 (ADR 0013): only a server that knows
	// approvals renders it, and an agent before the compiler's self-service gate never gets an available package.
	Approval string `json:"approval,omitempty"`
	// Approved are the users of the audience who may install without a request (lower-case UPNs, sorted, 1 to
	// MaxSoftwareAudience, ValidAudienceUser): those an administrator approved and those another catalog entry offers
	// the same package to without approval; only with Approval. A pointer like Audience, so SoftwarePackage stays
	// comparable.
	Approved *[]string `json:"approved,omitempty"`
	// Denied are the users of the audience whose request an administrator denied on this device, each with the
	// administrator's reason (sorted by user, 1 to MaxSoftwareAudience, ValidAudienceUser, none of them in Approved);
	// only with Approval (architect decision A10-27). The agent shows each user only their own entry. The reason is
	// untrusted text: the agent strips control characters before it shows it. Additive to schema 2 (ADR 0013); an
	// agent before the compiler's approval gate never gets a package that requires approval (A10-6).
	Denied *[]SoftwareDenial `json:"denied,omitempty"`
	// Urgent marks a package of an assignment an administrator marked urgent with a step-up (plan M13c decision 7):
	// the agent applies it outside the maintenance windows too. Absent otherwise.
	Urgent bool `json:"urgent,omitempty"`
}

// SoftwareDenial is one user's denied request of a package that requires approval (architect decision A10-27).
type SoftwareDenial struct {
	User   string `json:"user"`
	Reason string `json:"reason"`
}

// MaxSoftwareDenialReason bounds the reason of a SoftwareDenial in characters, the limit of
// software_request.decision_reason (plan M13c decision 8).
const MaxSoftwareDenialReason = 500

// SoftwareApprovalRequired is the only value of SoftwarePackage.Approval (plan M13c decision 9).
const SoftwareApprovalRequired = "required"

// Limits of the software section (plan M13a decisions 2 and 8).
const (
	maxSourceURIs     = 4
	maxSourceURI      = 512
	maxSourceSuites   = 8
	maxSourceComps    = 8
	maxSourceArchs    = 2
	maxSourceKeyring  = 65536
	sourceArchAMD64   = "amd64"
	sourceArchARM64   = "arm64"
	sourceSchemeHTTPS = "https://"
)

var (
	sourceSlug        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)
	sourceSuite       = regexp.MustCompile(`^[A-Za-z0-9./_-]{1,64}$`)
	sourceComponent   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	sourceFingerprint = regexp.MustCompile(`^[0-9A-F]{40}$`)
	// The parts of a repository credential become one line of apt's auth.conf: no white space, no quotes.
	repositoryHost     = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*/$`)
	repositoryUser     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	repositoryPassword = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
	catalogEntryID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	iconSHA256         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	flatpakRef         = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*){2,}$`)
)

// Limits of a Flatpak application ID and of an audience's user name (plan M13b decisions 3 and 7). The user name
// limit is the one of app_user.username (characters, not bytes), so every user the server stores fits an audience.
const (
	maxFlatpakRef       = 255
	maxAudienceUsername = 256
)

// ValidateSoftware checks every field of a software section: the source rules the server applies on upload (plan
// M13a decision 2, plan M13b decision 5 for Flatpak remotes), the package and intent rules (M13a decisions 8 and 9),
// the protected packages (RefusedIntent), unique slugs and packages, and that every source a package names is in
// Sources. A package names either an APT package or a Flatpak application (of a Flatpak source when it is required or
// available); an available package has an audience of everyone or of 1 to MaxSoftwareAudience sorted user names
// (ValidAudienceUser), and no other package has one (plan M13b decision 7); a user-scope Flatpak application with
// intent required, forbid or uninstall may name Users with the same limits, and no other package does (A10-11); only an
// available package requires approval and lists its approved users with the same limits (plan M13c decision 9). It does not compare a keyring with its
// fingerprint; the agent does that per source. Windows are at most MaxSoftwareWindows, each ValidateSoftwareWindow.
func ValidateSoftware(s SoftwareSpec) error {
	if len(s.Windows) > MaxSoftwareWindows {
		return fmt.Errorf("bundle: more than %d software windows", MaxSoftwareWindows)
	}
	for i, w := range s.Windows {
		if err := ValidateSoftwareWindow(w); err != nil {
			return fmt.Errorf("bundle: software window %d: %w", i, err)
		}
	}
	kinds := make(map[string]string, len(s.Sources))
	for _, src := range s.Sources {
		if err := validateSoftwareSource(src); err != nil {
			return err
		}
		if _, ok := kinds[src.Slug]; ok {
			return fmt.Errorf("bundle: duplicate software source %q", src.Slug)
		}
		kinds[src.Slug] = src.Kind
	}
	if err := validateRepositoryAuth(s); err != nil {
		return err
	}
	var names []string
	for _, p := range s.Packages {
		name, err := validateSoftwareName(p, kinds)
		if err != nil {
			return err
		}
		if slices.Contains(names, name) {
			return fmt.Errorf("bundle: duplicate software package %q", name)
		}
		names = append(names, name)
		switch p.Intent {
		case SoftwareRequired, SoftwareHold:
			if p.Version != nil && !ValidPackageVersion(*p.Version) {
				return fmt.Errorf("bundle: invalid version of software package %q", name)
			}
		case SoftwareUninstall, SoftwareForbid, SoftwareAvailable:
			if p.Version != nil {
				return fmt.Errorf("bundle: software package %q with intent %s must not have a version", name, p.Intent)
			}
		default:
			return fmt.Errorf("bundle: invalid intent %q of software package %q", p.Intent, name)
		}
		if err := validateAudience(p, name); err != nil {
			return err
		}
		if err := validateUsers(p, name); err != nil {
			return err
		}
		if err := validateApproval(p, name); err != nil {
			return err
		}
		if err := validateDenied(p, name); err != nil {
			return err
		}
		if p.FlatpakRef == "" && RefusedIntent(p.Package, p.Intent) {
			return fmt.Errorf("bundle: software package %q is protected against intent %s", p.Package, p.Intent)
		}
		if p.SupersededHold && p.Intent != SoftwareForbid && p.Intent != SoftwareUninstall {
			return fmt.Errorf("bundle: software package %q with intent %s cannot supersede a hold", name, p.Intent)
		}
		if !catalogEntryID.MatchString(p.CatalogEntryID) {
			return fmt.Errorf("bundle: invalid catalog_entry_id of software package %q", name)
		}
		if p.IconSHA256 != "" && (!iconSHA256.MatchString(p.IconSHA256) || p.CatalogEntryID == SoftwareRuntimeEntryID) {
			return fmt.Errorf("bundle: invalid icon_sha256 of software package %q", name)
		}
	}
	return nil
}

// validateRepositoryAuth checks the repository credential: it names the host and path of an APT source of the section,
// so the agent never writes a credential for a host no source fetches from.
func validateRepositoryAuth(s SoftwareSpec) error {
	r := s.Repository
	if r == nil {
		return nil
	}
	if !repositoryHost.MatchString(r.Host) || !repositoryUser.MatchString(r.Username) || !repositoryPassword.MatchString(r.Password) {
		return errors.New("bundle: invalid software repository credential")
	}
	for _, src := range s.Sources {
		if src.Kind != SoftwareSourceFlatpak && slices.Contains(src.URIs, "https://"+r.Host) {
			return nil
		}
	}
	return errors.New("bundle: the software repository credential names no source of the section")
}

// validateSoftwareName checks what a package installs and from which source, and returns its name for messages and
// the duplicate check: the APT package, or the Flatpak application ID with its scope, which names its Flatpak source
// when it is required or available. An APT package never names a Flatpak source.
func validateSoftwareName(p SoftwarePackage, kinds map[string]string) (string, error) {
	kind, known := kinds[p.Source]
	if p.Source != "" && !known {
		return "", fmt.Errorf("bundle: software package %q names the unknown source %q", p.Package+p.FlatpakRef, p.Source)
	}
	if p.FlatpakRef == "" {
		if !ValidPackage(p.Package) {
			return "", fmt.Errorf("bundle: invalid software package %q", p.Package)
		}
		if p.Scope != "" {
			return "", fmt.Errorf("bundle: software package %q must not have a scope", p.Package)
		}
		if kind == SoftwareSourceFlatpak {
			return "", fmt.Errorf("bundle: software package %q names the flatpak source %q", p.Package, p.Source)
		}
		return p.Package, nil
	}
	if p.Package != "" {
		return "", fmt.Errorf("bundle: software package %q must not also name the flatpak_ref %q", p.Package, p.FlatpakRef)
	}
	if len(p.FlatpakRef) > maxFlatpakRef || !flatpakRef.MatchString(p.FlatpakRef) {
		return "", fmt.Errorf("bundle: invalid flatpak_ref %q", p.FlatpakRef)
	}
	if p.Scope != "" && p.Scope != SoftwareScopeSystem && p.Scope != SoftwareScopeUser {
		return "", fmt.Errorf("bundle: flatpak_ref %q has an invalid scope %q", p.FlatpakRef, p.Scope)
	}
	// Only a required or available application brings its remote; forbid, uninstall and hold act on an installed one
	// and never add Flatpak to a device (architect decision A10-7).
	if kind != SoftwareSourceFlatpak && (p.Source != "" || p.Intent == SoftwareRequired || p.Intent == SoftwareAvailable) {
		return "", fmt.Errorf("bundle: flatpak_ref %q must name a flatpak source", p.FlatpakRef)
	}
	return "flatpak:" + p.FlatpakRef, nil
}

// validateAudience checks the audience of a package: required for an available package and absent otherwise; either
// everyone or 1 to MaxSoftwareAudience distinct lower-case user names in ascending order.
func validateAudience(p SoftwarePackage, name string) error {
	a := p.Audience
	if p.Intent != SoftwareAvailable {
		if a != nil {
			return fmt.Errorf("bundle: software package %q with intent %s must not have an audience", name, p.Intent)
		}
		return nil
	}
	switch {
	case a == nil || !a.All && len(a.Users) == 0:
		return fmt.Errorf("bundle: available software package %q needs an audience", name)
	case a.All && len(a.Users) > 0:
		return fmt.Errorf("bundle: the audience of software package %q is either all or users", name)
	case len(a.Users) > MaxSoftwareAudience:
		return fmt.Errorf("bundle: the audience of software package %q has more than %d users", name, MaxSoftwareAudience)
	}
	for i, u := range a.Users {
		if !ValidAudienceUser(u) || i > 0 && a.Users[i-1] >= u {
			return fmt.Errorf("bundle: the audience of software package %q has an invalid or unsorted user %q", name, u)
		}
	}
	return nil
}

// validateUsers checks the Users of a package: only a user-scope Flatpak application with intent required, forbid or
// uninstall names them, as 1 to MaxSoftwareAudience distinct user names in ascending order (architect decision A10-11).
// An empty list is refused rather than read as system scope, so the two meanings never share a spelling.
func validateUsers(p SoftwarePackage, name string) error {
	if p.Users == nil {
		return nil
	}
	users := *p.Users
	targeted := p.FlatpakRef != "" && p.Scope == SoftwareScopeUser &&
		(p.Intent == SoftwareRequired || p.Intent == SoftwareForbid || p.Intent == SoftwareUninstall)
	switch {
	case !targeted:
		return fmt.Errorf("bundle: software package %q with intent %s and scope %q must not have users", name, p.Intent, p.Scope)
	case len(users) == 0 || len(users) > MaxSoftwareAudience:
		return fmt.Errorf("bundle: software package %q must have 1 to %d users", name, MaxSoftwareAudience)
	}
	for i, u := range users {
		if !ValidAudienceUser(u) || i > 0 && users[i-1] >= u {
			return fmt.Errorf("bundle: the users of software package %q have an invalid or unsorted user %q", name, u)
		}
	}
	return nil
}

// validateApproval checks the approval of a package: only an available package requires approval, and only such a
// package lists the approved users, as 1 to MaxSoftwareAudience distinct user names in ascending order (plan M13c
// decision 9).
func validateApproval(p SoftwarePackage, name string) error {
	switch {
	case p.Approval != "" && p.Approval != SoftwareApprovalRequired:
		return fmt.Errorf("bundle: software package %q has an invalid approval %q", name, p.Approval)
	case p.Approval != "" && p.Intent != SoftwareAvailable:
		return fmt.Errorf("bundle: software package %q with intent %s must not require approval", name, p.Intent)
	case p.Approved == nil:
		return nil
	case p.Approval == "":
		return fmt.Errorf("bundle: software package %q lists approved users without requiring approval", name)
	case len(*p.Approved) == 0 || len(*p.Approved) > MaxSoftwareAudience:
		return fmt.Errorf("bundle: software package %q must have 1 to %d approved users", name, MaxSoftwareAudience)
	}
	approved := *p.Approved
	for i, u := range approved {
		if !ValidAudienceUser(u) || i > 0 && approved[i-1] >= u {
			return fmt.Errorf("bundle: the approved users of software package %q have an invalid or unsorted user %q", name, u)
		}
	}
	return nil
}

// validateDenied checks the denied users of a package: only a package that requires approval lists them, as 1 to
// MaxSoftwareAudience distinct user names in ascending order that are not approved, each with a reason of valid UTF-8
// of at most MaxSoftwareDenialReason characters (architect decision A10-27).
func validateDenied(p SoftwarePackage, name string) error {
	switch {
	case p.Denied == nil:
		return nil
	case p.Approval == "":
		return fmt.Errorf("bundle: software package %q lists denied users without requiring approval", name)
	case len(*p.Denied) == 0 || len(*p.Denied) > MaxSoftwareAudience:
		return fmt.Errorf("bundle: software package %q must have 1 to %d denied users", name, MaxSoftwareAudience)
	}
	denied := *p.Denied
	for i, d := range denied {
		if !ValidAudienceUser(d.User) || i > 0 && denied[i-1].User >= d.User {
			return fmt.Errorf("bundle: the denied users of software package %q have an invalid or unsorted user %q", name, d.User)
		}
		if p.Approved != nil && slices.Contains(*p.Approved, d.User) {
			return fmt.Errorf("bundle: software package %q lists user %q as approved and denied", name, d.User)
		}
		if !utf8.ValidString(d.Reason) || utf8.RuneCountInString(d.Reason) > MaxSoftwareDenialReason {
			return fmt.Errorf("bundle: the denial reason of user %q of software package %q is not valid UTF-8 of at most %d characters",
				d.User, name, MaxSoftwareDenialReason)
		}
	}
	return nil
}

// ValidAudienceUser reports whether an audience can name user name u: valid UTF-8 of 1 to 256 characters, lower case,
// without white space. The compiler leaves out an owner whose name fails it instead of failing the device's bundle.
func ValidAudienceUser(u string) bool {
	return u != "" && utf8.ValidString(u) && utf8.RuneCountInString(u) <= maxAudienceUsername && u == strings.ToLower(u) &&
		!strings.ContainsFunc(u, unicode.IsSpace)
}

func validateSoftwareSource(src SoftwareSource) error {
	if !sourceSlug.MatchString(src.Slug) {
		return fmt.Errorf("bundle: invalid software source slug %q", src.Slug)
	}
	if len(src.URIs) < 1 || len(src.URIs) > maxSourceURIs {
		return fmt.Errorf("bundle: software source %q must have 1 to %d uris", src.Slug, maxSourceURIs)
	}
	for _, raw := range src.URIs {
		if err := CheckSourceURI(raw); err != nil {
			return fmt.Errorf("bundle: software source %q: %w", src.Slug, err)
		}
	}
	switch src.Kind {
	case "":
		if err := validateAPTSource(src); err != nil {
			return err
		}
	case SoftwareSourceFlatpak:
		if len(src.URIs) != 1 || len(src.Suites) > 0 || len(src.Components) > 0 || len(src.Architectures) > 0 {
			return fmt.Errorf("bundle: flatpak source %q must have exactly one uri and no suites, components or architectures", src.Slug)
		}
	default:
		return fmt.Errorf("bundle: software source %q has an invalid kind %q", src.Slug, src.Kind)
	}
	keyring, err := base64.StdEncoding.Strict().DecodeString(src.Keyring)
	if err != nil || len(keyring) == 0 || len(keyring) > maxSourceKeyring {
		return fmt.Errorf("bundle: software source %q has an invalid keyring", src.Slug)
	}
	if !sourceFingerprint.MatchString(src.Fingerprint) {
		return fmt.Errorf("bundle: software source %q has an invalid fingerprint", src.Slug)
	}
	return nil
}

// validateAPTSource checks the suites, components and architectures of an APT source.
func validateAPTSource(src SoftwareSource) error {
	if len(src.Suites) < 1 || len(src.Suites) > maxSourceSuites {
		return fmt.Errorf("bundle: software source %q must have 1 to %d suites", src.Slug, maxSourceSuites)
	}
	flat := 0
	for i, suite := range src.Suites {
		if !sourceSuite.MatchString(suite) || slices.Contains(src.Suites[:i], suite) ||
			slices.Contains(strings.Split(suite, "/"), "..") {
			return fmt.Errorf("bundle: software source %q has an invalid suite %q", src.Slug, suite)
		}
		if strings.HasSuffix(suite, "/") {
			flat++
		}
	}
	if len(src.Components) > maxSourceComps {
		return fmt.Errorf("bundle: software source %q must have at most %d components", src.Slug, maxSourceComps)
	}
	for i, c := range src.Components {
		if !sourceComponent.MatchString(c) || slices.Contains(src.Components[:i], c) {
			return fmt.Errorf("bundle: software source %q has an invalid component %q", src.Slug, c)
		}
	}
	// apt refuses a flat suite next to components and a non-flat suite without them; either stops every apt run.
	if (flat > 0 && (flat < len(src.Suites) || len(src.Components) > 0)) || (flat == 0 && len(src.Components) == 0) {
		return fmt.Errorf("bundle: software source %q mixes flat and non-flat suites or components", src.Slug)
	}
	if len(src.Architectures) > maxSourceArchs {
		return fmt.Errorf("bundle: software source %q must have at most %d architectures", src.Slug, maxSourceArchs)
	}
	for i, a := range src.Architectures {
		if (a != sourceArchAMD64 && a != sourceArchARM64) || slices.Contains(src.Architectures[:i], a) {
			return fmt.Errorf("bundle: software source %q has an invalid architecture %q", src.Slug, a)
		}
	}
	return nil
}

// CheckSourceURI checks one URI of a software source: https, at most 512 bytes, a host, no user info, query or
// fragment, a port from 1 to 65535 when one is given, and none of white space, quotes, angle brackets, invalid UTF-8,
// U+FFFD or the runes InvisibleInURI names. It is the one rule for the upload (server/internal/domain/software) and
// for the bundle: the URI becomes a field of a deb822 file on the device and is shown next to the trust decision.
func CheckSourceURI(raw string) error {
	if !strings.HasPrefix(raw, sourceSchemeHTTPS) {
		return errors.New("uris must use https")
	}
	if len(raw) > maxSourceURI {
		return fmt.Errorf("uris must be at most %d characters", maxSourceURI)
	}
	if strings.ContainsFunc(raw, unicode.IsSpace) || strings.ContainsAny(raw, "?#") {
		return errors.New("uris must not contain white space, a query or a fragment")
	}
	if strings.ContainsAny(raw, `"<>`) {
		return errors.New(`uris must not contain ", < or >`)
	}
	if !utf8.ValidString(raw) || strings.ContainsFunc(raw, InvisibleInURI) {
		return errors.New("uris must not contain control, format, invisible, replacement or line separator characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return errors.New("uris must be https://host[/path] without user info")
	}
	if p := u.Port(); p != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("uris must use a port from 1 to 65535")
		}
	}
	return nil
}

// InvisibleInURI reports runes a source URI must not contain: controls, format and line or paragraph separators,
// default-ignorable and variation-selector runes, the tag block (listed whole because its unassigned code points have
// no property), runes that render as blanks without being white space (U+2800, the Hangul fillers), and U+FFFD, the
// mark of text that was not valid UTF-8 somewhere on its way.
func InvisibleInURI(r rune) bool {
	switch r {
	case '\u115F', '\u1160', '\u3164', '\uFFA0', '\u2800', unicode.ReplacementChar:
		return true
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Other_Default_Ignorable_Code_Point,
		unicode.Variation_Selector) || (r >= 0xE0000 && r <= 0xE007F)
}

// SoftwareResource turns the software section into the resource the agent plans and applies. Nil lists are encoded
// as empty lists.
func SoftwareResource(s SoftwareSpec) (Resource, error) {
	if s.Sources == nil {
		s.Sources = []SoftwareSource{}
	}
	if s.Packages == nil {
		s.Packages = []SoftwarePackage{}
	}
	return resource(TypeSoftware, TypeSoftware, s)
}

// FileResource builds a file resource; ContentSHA256 is computed from Content.
func FileResource(s FileSpec) (Resource, error) {
	sum := sha256.Sum256([]byte(s.Content))
	s.ContentSHA256 = hex.EncodeToString(sum[:])
	return resource("file:"+s.Path, TypeFile, s)
}

// UnitResource builds a systemd unit resource.
func UnitResource(s UnitSpec) (Resource, error) { return resource("unit:"+s.Unit, TypeSystemdUnit, s) }

// TimeResource builds the time resource.
func TimeResource(s TimeSpec) (Resource, error) { return resource("time", TypeTime, s) }

// LoginResource builds the login resource (schema v2). Nil lists are encoded as empty lists.
func LoginResource(s LoginSpec) (Resource, error) {
	s.Himmelblau.PamAllowGroups = nonNil(s.Himmelblau.PamAllowGroups)
	s.LockedUsers = nonNil(s.LockedUsers)
	s.BreakGlassAccounts = nonNil(s.BreakGlassAccounts)
	return resource("login", TypeLogin, s)
}

// SudoResource builds the sudo resource (schema v2). Nil lists are encoded as empty lists.
func SudoResource(s SudoSpec) (Resource, error) {
	if s.Entries == nil {
		s.Entries = []sudoers.Entry{}
	}
	for i := range s.Entries {
		s.Entries[i].Commands = nonNil(s.Entries[i].Commands)
	}
	s.PrivilegedGroups = nonNil(s.PrivilegedGroups)
	s.SudoersDAllowlist = nonNil(s.SudoersDAllowlist)
	s.BreakGlassAccounts = nonNil(s.BreakGlassAccounts)
	return resource("sudo", TypeSudo, s)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func resource(id, typ string, spec any) (Resource, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return Resource{}, fmt.Errorf("bundle: encode %s: %w", id, err)
	}
	return Resource{ID: id, Type: typ, Spec: b}, nil
}

// SortResources orders resources by ID as the schema requires.
func SortResources(rs []Resource) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
}

// Encode returns the canonical JSON payload (RFC 8785).
func Encode(b Bundle) ([]byte, error) {
	b.IssuedAt = b.IssuedAt.UTC()
	return canonicaljson.Marshal(b)
}

// ContentSHA256 hashes the canonical payload without issued_at and bundle_version, so two renders of the same
// desired state have the same hash (plan M2a decision 13).
func ContentSHA256(b Bundle) ([32]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return [32]byte{}, fmt.Errorf("bundle: encode: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return [32]byte{}, fmt.Errorf("bundle: encode: %w", err)
	}
	delete(m, "issued_at")
	delete(m, "bundle_version")
	c, err := canonicaljson.Marshal(m)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(c), nil
}

// Trust holds the trusted bundle-signing keys by key ID.
type Trust struct{ Keys map[string]ed25519.PublicKey }

// TrustFromKeys builds a Trust from the keys of an enrollment configuration.
func TrustFromKeys(keys []protocol.BundleKey) (Trust, error) {
	t := Trust{Keys: map[string]ed25519.PublicKey{}}
	for _, k := range keys {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return Trust{}, fmt.Errorf("bundle: invalid public key %q", k.KeyID)
		}
		t.Keys[k.KeyID] = pub
	}
	if len(t.Keys) == 0 {
		return Trust{}, errors.New("bundle: no trusted keys")
	}
	return t, nil
}

// Verification errors.
var (
	ErrSignature   = errors.New("bundle: signature invalid or not from a trusted key")
	ErrWrongDevice = errors.New("bundle: device or organization does not match")
	ErrDowngrade   = errors.New("bundle: version not newer than the applied one")
	ErrSchema      = errors.New("bundle: unsupported payload type, schema or encoding")
)

// Verify checks, in this order, the DSSE signature against any trusted key and the payload type, device and
// organization, version > minVersion and the schema version (SchemaVersion). It returns the decoded bundle or one of
// ErrSignature, ErrWrongDevice, ErrDowngrade, ErrSchema.
func Verify(envelope []byte, trust Trust, deviceID, orgID string, minVersion int64) (*Bundle, error) {
	return VerifyVersions(envelope, trust, deviceID, orgID, minVersion, []int{SchemaVersion})
}

// VerifyVersions is Verify for a reader that accepts the schema versions in accepted.
func VerifyVersions(envelope []byte, trust Trust, deviceID, orgID string, minVersion int64, accepted []int) (*Bundle, error) {
	env, payload, err := dsse.Decode(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if _, err := env.VerifyEd25519(payload, trust.Keys); err != nil {
		return nil, ErrSignature
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("%w: payload type %q", ErrSchema, env.PayloadType)
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	if b.DeviceID != deviceID || b.OrganizationID != orgID {
		return nil, ErrWrongDevice
	}
	if b.BundleVersion <= minVersion {
		return nil, fmt.Errorf("%w: %d <= %d", ErrDowngrade, b.BundleVersion, minVersion)
	}
	if !slices.Contains(accepted, b.SchemaVersion) {
		return nil, fmt.Errorf("%w: schema_version %d", ErrSchema, b.SchemaVersion)
	}
	if b.Mode != ModeEnforce && b.Mode != ModeReportOnly {
		return nil, fmt.Errorf("%w: mode %q", ErrSchema, b.Mode)
	}
	return &b, nil
}
