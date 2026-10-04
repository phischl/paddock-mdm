// Package bundle defines bundle schema v1 — the signed desired state of one device — and its verification on the
// device (architecture §7.2, plan M2a §6.3).
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
	"sort"
	"time"

	"github.com/paddock-mdm/paddock/pkg/canonicaljson"
	"github.com/paddock-mdm/paddock/pkg/dsse"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// SchemaVersion is the schema version this package produces and accepts.
const SchemaVersion = 1

// PayloadType is the DSSE payload type of bundles.
const PayloadType = "application/vnd.paddock.bundle.v1+json"

// Resource types.
const (
	TypeTime        = "time"
	TypeFile        = "file"
	TypeSystemdUnit = "systemd_unit"
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
// organization, version > minVersion and the schema version. It returns the decoded bundle or one of ErrSignature,
// ErrWrongDevice, ErrDowngrade, ErrSchema.
func Verify(envelope []byte, trust Trust, deviceID, orgID string, minVersion int64) (*Bundle, error) {
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
	if b.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %d", ErrSchema, b.SchemaVersion)
	}
	return &b, nil
}
