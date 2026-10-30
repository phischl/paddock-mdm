// Package auditevidence defines the evidence package (export.json) and the manifest file of the audit chain as the
// offline verifier and the server share them (plan M10 §6.5). Standard library and pkg/canonicaljson only.
package auditevidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
)

// ExportSchema is the schema of export.json.
const ExportSchema = "paddock.audit-export.v1"

// ManifestSchema is the schema of a daily manifest of the audit chain.
const ManifestSchema = "paddock.audit-manifest.v1"

// EventSchema is the schema of one audit event in events.jsonl.
const EventSchema = "paddock.audit.v1"

// Actor is the requester of an export.
type Actor struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Display string `json:"display,omitempty"`
}

// Day describes one recording day of the package.
type Day struct {
	Day            string `json:"day"`
	ManifestKey    string `json:"manifest_key"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ObjectCount    int    `json:"object_count"`
	EventCount     int    `json:"event_count"`
}

// Object describes one audit object of the package.
type Object struct {
	Key        string `json:"key"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	EventCount int    `json:"event_count"`
}

// Run is one recorded verification run of the audit writer that covered days of the range.
type Run struct {
	RunID     string    `json:"run_id"`
	StartedAt time.Time `json:"started_at"`
	FromDay   string    `json:"from_day"`
	ToDay     string    `json:"to_day"`
	OK        bool      `json:"ok"`
	Problems  []string  `json:"problems"`
}

// Verification is the server-side verification at build time.
type Verification struct {
	OK         bool      `json:"ok"`
	Problems   []string  `json:"problems"`
	VerifiedAt time.Time `json:"verified_at"`
	Verifier   string    `json:"verifier"`
	Runs       []Run     `json:"runs"`
}

// Key is one version of the audit-chain public key.
type Key struct {
	KeyVersion  int    `json:"key_version"`
	PublicKey   []byte `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// Export is export.json. The organization is named by its ID only: a slug can change and the package must not claim
// a value the audit domain cannot vouch for (plan M10 amendment 2026-10-30, PDK-143).
type Export struct {
	Schema         string       `json:"schema"`
	ExportID       string       `json:"export_id"`
	OrganizationID string       `json:"organization_id"`
	FromDay        string       `json:"from_day"`
	ToDay          string       `json:"to_day"`
	RequestedBy    Actor        `json:"requested_by"`
	RequestedAt    time.Time    `json:"requested_at"`
	CreatedAt      time.Time    `json:"created_at"`
	Purpose        string       `json:"purpose"`
	Generator      string       `json:"generator"`
	Days           []Day        `json:"days"`
	Objects        []Object     `json:"objects"`
	EventCount     int          `json:"event_count"`
	EventsSHA256   string       `json:"events_sha256"`
	ChainAnchor    *string      `json:"chain_anchor"`
	Verification   Verification `json:"verification"`
	Keys           []Key        `json:"keys"`
}

// Signature is export.sig.
type Signature struct {
	Signature  string `json:"signature"`
	KeyVersion int    `json:"key_version"`
}

// ManifestObject is one object entry of a manifest.
type ManifestObject struct {
	Key        string `json:"key"`
	SHA256     string `json:"sha256"`
	EventCount int    `json:"event_count"`
}

// Manifest is the signed daily summary of one organization.
type Manifest struct {
	Schema             string           `json:"schema"`
	OrganizationID     string           `json:"organization_id"`
	Day                string           `json:"day"`
	Objects            []ManifestObject `json:"objects"`
	PrevManifestSHA256 *string          `json:"prev_manifest_sha256"`
}

// ManifestFile is the stored object org/<org>/manifests/<day>.json.
type ManifestFile struct {
	Manifest   json.RawMessage `json:"manifest"`
	Signature  string          `json:"signature"`
	KeyVersion int             `json:"key_version"`
}

// Fingerprint is the lowercase hex SHA-256 of a public key.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// VerifySignature checks an OpenBao Transit ed25519 signature "vault:v<N>:<base64>" of message with key version.
func VerifySignature(keys map[int][]byte, version int, sig string, message []byte) bool {
	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || parts[1] != fmt.Sprintf("v%d", version) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	pub, ok := keys[version]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, message, raw)
}

// ExportDigest is the SHA-256 of the canonical bytes of export.json, the message export.sig signs.
func ExportDigest(canonical []byte) [32]byte {
	return sha256.Sum256(canonical)
}

// ManifestDigest returns the canonical bytes of file.Manifest and their SHA-256, the message the manifest signature
// signs and the value the next day's prev_manifest_sha256 links to.
func ManifestDigest(file ManifestFile) ([]byte, [32]byte, error) {
	canonical, err := canonicaljson.Transform(file.Manifest)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return canonical, sha256.Sum256(canonical), nil
}

// ObjectPath maps the store key org/<org>/… of an object of organizationID to its package path objects/…; a key
// outside the organization's prefix, or one with a ".." segment, an absolute remainder or a backslash, is an error.
func ObjectPath(organizationID, key string) (string, error) {
	prefix := "org/" + organizationID + "/"
	rest, ok := strings.CutPrefix(key, prefix)
	if !ok || rest == "" || organizationID == "" {
		return "", fmt.Errorf("auditevidence: object %q is outside the prefix %s", key, prefix)
	}
	// The path becomes a tar member name that an auditor extracts; it must not escape objects/.
	if strings.HasPrefix(rest, "/") || strings.Contains(rest, "\\") || slices.Contains(strings.Split(rest, "/"), "..") {
		return "", fmt.Errorf("auditevidence: object %q is not a plain relative path", key)
	}
	return "objects/" + rest, nil
}
