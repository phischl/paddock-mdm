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
	"regexp"
	"slices"
	"sort"
	"time"

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
}

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
	return &b, nil
}
