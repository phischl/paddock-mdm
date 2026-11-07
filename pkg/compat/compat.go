// Package compat holds the previous-release fixtures of the upgrade guarantee (ADR 0047 decision 2, plan M16 decision
// 2): what a release put on the wire and into the audit database, signed with a fixture key, kept under testdata/ so
// the next release can prove it still reads it. Generate writes one release's directory; make compat-fixtures calls it
// at release time.
package compat

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/sudoers"
)

// Fixture file names inside testdata/<release>/. The bundles are bundle-schema-<n>.json.
const (
	MetaFile        = "meta.json"
	CheckinFile     = "checkin.json"
	EventsFile      = "events.json"
	CommandsFile    = "commands.json"
	AuditInsertFile = "audit-insert.sql"
)

// BundleFile is the file name of the bundle of a schema version.
func BundleFile(schema int) string { return fmt.Sprintf("bundle-schema-%d.json", schema) }

// Meta names the identities and the public keys the fixtures verify with. The keys are derived from a public seed
// string: they sign nothing but the fixtures.
type Meta struct {
	Release        string               `json:"release"`
	DeviceID       string               `json:"device_id"`
	OrganizationID string               `json:"organization_id"`
	SchemaVersions []int                `json:"schema_versions"`
	BundleKeys     []protocol.BundleKey `json:"bundle_keys"`
	CommandKeys    []bundle.SigningKey  `json:"command_keys"`
	// CommandVerifyAt is a time inside every command's lifetime, the clock the verification runs on.
	CommandVerifyAt time.Time `json:"command_verify_at"`
}

// CommandFixture is one signed command; Envelope is the DSSE envelope as the server sent it.
type CommandFixture struct {
	Type     string          `json:"type"`
	Envelope json.RawMessage `json:"envelope"`
}

// Fixed identities of every fixture release.
const (
	deviceID = "0190f000-0000-7000-8000-00000000d001"
	orgID    = "0190f000-0000-7000-8000-00000000a001"
)

var issuedAt = time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)

// SchemaVersions are the bundle schema versions the fixtures are generated for. The agent's accepted list is
// apply.SchemaVersions; agent/internal/apply checks every fixture bundle against it, pkg must not import the agent.
var SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}

func fixtureKey(release, purpose string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("paddock compat fixture " + purpose + " " + release))
	return ed25519.NewKeyFromSeed(seed[:])
}

// Generate writes the fixtures of release into dir (created if missing): one signed bundle per schema version, the
// check-in and events bodies of the agent, one signed command per registered type and the audit insert statement the
// audit writer of the release runs (auditInsert). The output is deterministic, so a regeneration changes files only
// when the wire format changed.
func Generate(dir, release, auditInsert string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	bundleKey, commandKey := fixtureKey(release, "bundle"), fixtureKey(release, "command")
	meta := Meta{
		Release: release, DeviceID: deviceID, OrganizationID: orgID, SchemaVersions: SchemaVersions,
		BundleKeys: []protocol.BundleKey{{KeyID: "bundle-signing:fixture",
			PublicKey: base64.StdEncoding.EncodeToString(bundleKey.Public().(ed25519.PublicKey))}},
		CommandKeys: []bundle.SigningKey{{KeyID: "command-signing:fixture",
			PublicKey: base64.StdEncoding.EncodeToString(commandKey.Public().(ed25519.PublicKey))}},
		CommandVerifyAt: issuedAt.Add(time.Hour),
	}
	if err := writeJSON(filepath.Join(dir, MetaFile), meta); err != nil {
		return err
	}
	for _, schema := range SchemaVersions {
		b, err := sampleBundle(schema, commandKey)
		if err != nil {
			return err
		}
		payload, err := bundle.Encode(b)
		if err != nil {
			return err
		}
		env, err := dsse.New(bundle.PayloadType, payload,
			dsse.SignEd25519(bundleKey, meta.BundleKeys[0].KeyID, bundle.PayloadType, payload)).Encode()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, BundleFile(schema)), append(env, '\n'), 0o600); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(dir, CheckinFile), protocol.CheckinRequest{
		AppliedBundleVersion: 1, AgentVersion: release, SchemaVersions: SchemaVersions,
		Health: json.RawMessage(`{"agent":"ok","units":{"paddock-agent.service":"active"}}`), EventSeqHigh: 3,
		Arch: protocol.ArchAMD64, OSRelease: map[string]string{"id": "ubuntu", "version_id": "26.04"},
	}); err != nil {
		return err
	}
	events := protocol.EventsRequest{}
	for i, typ := range protocol.EventTypes {
		events.Events = append(events.Events, protocol.Event{
			EventSeq: int64(i + 1), Type: typ, OccurredAt: issuedAt.Add(time.Duration(i) * time.Second),
			Data: json.RawMessage(`{}`),
		})
	}
	if err := writeJSON(filepath.Join(dir, EventsFile), events); err != nil {
		return err
	}
	commands, err := sampleCommands(commandKey, meta.CommandKeys[0].KeyID)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, CommandsFile), commands); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, AuditInsertFile), []byte(auditInsert), 0o600)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func sampleCommands(key ed25519.PrivateKey, keyID string) ([]CommandFixture, error) {
	params := map[string]string{
		command.TypeInstallNow:       `{"packages":["htop"]}`,
		command.TypeUninstall:        `{"mode":"leave"}`,
		command.TypeEncryptDisk:      `{"conversion_id":"0190f000-0000-7000-8000-00000000c0c0"}`,
		command.TypeEncryptDiskAbort: `{"conversion_id":"0190f000-0000-7000-8000-00000000c0c0"}`,
		command.TypeCollectStatus:    `{"reason":"fixture","request_id":"0190f000-0000-7000-8000-0000000000c1"}`,
	}
	var out []CommandFixture
	for i, typ := range command.Types() {
		life, ok := command.Lifetime(typ)
		if !ok {
			return nil, fmt.Errorf("compat: command type %s has no lifetime", typ)
		}
		c := command.Command{
			CommandID: fmt.Sprintf("0190f000-0000-7000-8000-0000000000c%d", i+1), DeviceID: deviceID,
			OrganizationID: orgID, Type: typ, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(life),
		}
		if p := params[typ]; p != "" {
			c.Params = json.RawMessage(p)
		}
		payload, err := command.Encode(c)
		if err != nil {
			return nil, err
		}
		env, err := dsse.New(command.PayloadType, payload, dsse.SignEd25519(key, keyID, command.PayloadType, payload)).Encode()
		if err != nil {
			return nil, err
		}
		out = append(out, CommandFixture{Type: typ, Envelope: env})
	}
	return out, nil
}

// sampleBundle is a bundle of the schema with every resource and section the schema carries.
func sampleBundle(schema int, commandKey ed25519.PrivateKey) (bundle.Bundle, error) {
	b := bundle.Bundle{
		SchemaVersion: schema, BundleVersion: 1, DeviceID: deviceID, OrganizationID: orgID, IssuedAt: issuedAt,
		Agent: bundle.AgentCfg{CheckinIntervalS: 300},
	}
	builders := []func() (bundle.Resource, error){
		func() (bundle.Resource, error) { return bundle.TimeResource(bundle.TimeSpec{NTP: true}) },
		func() (bundle.Resource, error) {
			return bundle.FileResource(bundle.FileSpec{Path: "/etc/paddock/motd", Mode: "0644", Owner: "root",
				Group: "root", Content: "managed by Paddock\n"})
		},
		func() (bundle.Resource, error) {
			return bundle.UnitResource(bundle.UnitSpec{Unit: "chrony.service", Enabled: true, Active: true})
		},
	}
	if schema >= bundle.SchemaVersion2 {
		builders = append(builders, func() (bundle.Resource, error) {
			return bundle.LoginResource(bundle.LoginSpec{Provider: bundle.ProviderHimmelblau,
				Himmelblau: bundle.HimmelblauSpec{OIDCIssuerURL: "https://idp.example.org/application/o/paddock/",
					AppID: "fixture", Domain: "example.org", PamAllowGroups: []string{"paddock-users"},
					EnableHello: true, HelloPinMinLength: 6, PackageVersion: "4.0.4"},
				SessionAction: bundle.SessionActionLockScreen, BreakGlassAccounts: []string{"paddock-admin"},
				LocalAdmin: &bundle.LocalAdminSpec{Username: "paddock-admin", RotationDays: 30}, Notice: "Fixture notice"})
		}, func() (bundle.Resource, error) {
			return bundle.SudoResource(bundle.SudoSpec{LectureText: "Fixture lecture",
				Entries: []sudoers.Entry{{Username: "alice", Class: "standard", Commands: []string{"/usr/bin/apt"},
					RequirePassword: true, TimestampTimeoutMin: 5, ProfileDigest: "0000"}},
				BreakGlassAccounts: []string{"paddock-admin"}})
		})
	}
	for _, build := range builders {
		r, err := build()
		if err != nil {
			return b, err
		}
		b.Resources = append(b.Resources, r)
	}
	if schema >= bundle.SchemaVersion2 {
		updates := bundle.UpdatesSpec{SecurityDailyAt: "03:00", RegularSchedule: "Sun 04:00", RegularUpdatesEnabled: true,
			MaxRandomDelayMin: 30, Holds: []bundle.Hold{}}
		hostname := bundle.HostnameSpec{Name: "fixture-laptop"}
		watch := bundle.WatchSpec{Units: []string{"edr.service"}}
		entry := "0190f000-0000-7000-8000-00000000e001"
		software := bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{}, Packages: []bundle.SoftwarePackage{
			{Package: "htop", Intent: bundle.SoftwareRequired, CatalogEntryID: entry}}}
		if err := bundle.ValidateSoftware(software); err != nil {
			return b, fmt.Errorf("compat: sample software section: %w", err)
		}
		b.Updates, b.Hostname, b.Watch, b.Software = &updates, &hostname, &watch, &software
		b.Disk = &bundle.DiskSpec{UnlockMode: bundle.UnlockModeTPMPIN, BootPINMinLength: 6}
		b.DMS = &bundle.DMS{Enabled: true, PeriodDays: 30, WarnDays: []int{7, 1}}
		pub := base64.StdEncoding.EncodeToString(commandKey.Public().(ed25519.PublicKey))
		b.Keys = &bundle.Keys{CommandSigning: []bundle.SigningKey{{KeyID: "command-signing:fixture", PublicKey: pub}},
			TimeTicket: []bundle.SigningKey{{KeyID: "time-ticket:fixture", PublicKey: pub}}}
		b.Revocation = &bundle.Revocation{Enabled: false, Keys: []bundle.SigningKey{{KeyID: "revocation:fixture", PublicKey: pub}}}
		b.Inventory = &bundle.Inventory{FleetURL: "https://fleet.example.org", EnrollSecret: "fixture-not-a-secret", //nolint:gosec // G101: a literal placeholder in a fixture, not a credential
			Package: bundle.InventoryPackage{Version: "1.48.0", URLPath: "packages/1.48.0/fleet-osquery_1.48.0_amd64.deb",
				SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}
	}
	bundle.SortResources(b.Resources)
	return b, nil
}
