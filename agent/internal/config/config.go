// Package config reads and writes the agent configuration: /etc/paddock/agent.yml, /etc/paddock/trust.json,
// /etc/paddock/revoke-trust.json and the enrollment configuration an administrator downloads from the portal (plan
// M2b decisions 6 and 7, plan M4c decision 3).
package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
)

// Drift interval bounds (plan M2b decision 11).
const (
	DefaultDriftInterval = 300 * time.Second
	devMinDriftInterval  = 30 * time.Second
)

// Agent is /etc/paddock/agent.yml.
type Agent struct {
	ServerURL      string
	OrganizationID string
	Proxy          string        // optional HTTP(S) proxy URL
	DriftInterval  time.Duration // default DefaultDriftInterval
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// MinDriftInterval is the smallest drift interval agent.yml may set: 30 s in development builds, the default
// otherwise.
func MinDriftInterval() time.Duration {
	if buildinfo.Dev {
		return devMinDriftInterval
	}
	return DefaultDriftInterval
}

// Validate checks the configuration.
func (a Agent) Validate() error {
	u, err := url.Parse(a.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("server_url must be an https URL, got %q", a.ServerURL)
	}
	if !uuidPattern.MatchString(a.OrganizationID) {
		return fmt.Errorf("organization_id must be a lowercase UUID, got %q", a.OrganizationID)
	}
	if a.Proxy != "" {
		if p, err := url.Parse(a.Proxy); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return fmt.Errorf("proxy must be an http or https URL, got %q", a.Proxy)
		}
	}
	if a.DriftInterval < MinDriftInterval() {
		return fmt.Errorf("drift_interval_s must be at least %d", int(MinDriftInterval().Seconds()))
	}
	return nil
}

// ParseAgent parses agent.yml. The file is a flat YAML mapping of scalar values ("key: value", comments with "#");
// unknown keys are rejected so that typos do not go unnoticed.
func ParseAgent(data []byte) (Agent, error) {
	a := Agent{DriftInterval: DefaultDriftInterval}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return Agent{}, fmt.Errorf("agent.yml line %d: expected \"key: value\"", n)
		}
		value = unquote(strings.TrimSpace(value))
		switch strings.TrimSpace(key) {
		case "server_url":
			a.ServerURL = value
		case "organization_id":
			a.OrganizationID = value
		case "proxy":
			a.Proxy = value
		case "drift_interval_s":
			s, err := strconv.Atoi(value)
			if err != nil {
				return Agent{}, fmt.Errorf("agent.yml line %d: drift_interval_s must be an integer", n)
			}
			a.DriftInterval = time.Duration(s) * time.Second
		default:
			return Agent{}, fmt.Errorf("agent.yml line %d: unknown key %q", n, strings.TrimSpace(key))
		}
	}
	if err := sc.Err(); err != nil {
		return Agent{}, err
	}
	return a, a.Validate()
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}

// LoadAgent reads and validates agent.yml.
func LoadAgent(path string) (Agent, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path of the agent layout
	if err != nil {
		return Agent{}, fmt.Errorf("read agent configuration: %w", err)
	}
	a, err := ParseAgent(data)
	if err != nil {
		return Agent{}, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

// Marshal renders agent.yml.
func (a Agent) Marshal() []byte {
	var b strings.Builder
	b.WriteString("# Paddock agent configuration, written by `paddockd enroll`.\n")
	fmt.Fprintf(&b, "server_url: %q\norganization_id: %q\n", a.ServerURL, a.OrganizationID)
	if a.Proxy != "" {
		fmt.Fprintf(&b, "proxy: %q\n", a.Proxy)
	}
	if a.DriftInterval != DefaultDriftInterval {
		fmt.Fprintf(&b, "drift_interval_s: %d\n", int(a.DriftInterval.Seconds()))
	}
	return []byte(b.String())
}

// SaveAgent writes agent.yml atomically (0644; it holds no secret).
func SaveAgent(path string, a Agent) error {
	return fsutil.WriteFile(path, a.Marshal(), 0o644, 0o755)
}

// TrustFile is /etc/paddock/trust.json.
type TrustFile struct {
	BundleKeys []protocol.BundleKey `json:"bundle_keys"`
}

// LoadTrust reads trust.json.
func LoadTrust(path string) (bundle.Trust, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path of the agent layout
	if err != nil {
		return bundle.Trust{}, fmt.Errorf("read trust anchor: %w", err)
	}
	var f TrustFile
	if err := json.Unmarshal(data, &f); err != nil {
		return bundle.Trust{}, fmt.Errorf("%s: %w", path, err)
	}
	return bundle.TrustFromKeys(f.BundleKeys)
}

// SaveTrust writes trust.json atomically (0644; public keys only).
func SaveTrust(path string, keys []protocol.BundleKey) error {
	data, err := json.MarshalIndent(TrustFile{BundleKeys: keys}, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFile(path, append(data, '\n'), 0o644, 0o755)
}

// SaveRevokeTrust writes revoke-trust.json atomically (0644; public keys only): the revocation-signing keys
// paddock-revoke trusts (plan M4c decision 3). keys must be valid.
func SaveRevokeTrust(path string, keys []protocol.BundleKey) error {
	f := revocation.TrustFile{RevocationKeys: make([]revocation.Key, len(keys))}
	for i, k := range keys {
		f.RevocationKeys[i] = revocation.Key{KeyID: k.KeyID, PublicKey: k.PublicKey}
	}
	if _, err := revocation.TrustFromKeys(f.RevocationKeys); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFile(path, append(data, '\n'), 0o644, 0o755)
}

// ErrEnrollmentConfig marks an invalid enrollment configuration.
var ErrEnrollmentConfig = errors.New("invalid enrollment configuration")

// ParseEnrollment parses and validates an enrollment configuration (the JSON document from the portal).
func ParseEnrollment(data []byte) (protocol.EnrollmentConfig, error) {
	var c protocol.EnrollmentConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%w: %v", ErrEnrollmentConfig, err)
	}
	if err := (Agent{ServerURL: c.ServerURL, OrganizationID: c.OrganizationID, DriftInterval: DefaultDriftInterval}).Validate(); err != nil {
		return c, fmt.Errorf("%w: %v", ErrEnrollmentConfig, err)
	}
	if c.Token == "" {
		return c, fmt.Errorf("%w: token is empty", ErrEnrollmentConfig)
	}
	if _, err := bundle.TrustFromKeys(c.BundleKeys); err != nil {
		return c, fmt.Errorf("%w: %v", ErrEnrollmentConfig, err)
	}
	for _, k := range c.RevocationKeys { // optional: configurations created before M4c have none
		if _, err := revocation.TrustFromKeys([]revocation.Key{{KeyID: k.KeyID, PublicKey: k.PublicKey}}); err != nil {
			return c, fmt.Errorf("%w: %v", ErrEnrollmentConfig, err)
		}
	}
	return c, nil
}
