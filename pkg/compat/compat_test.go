package compat

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// verifyRelease is what the current tree must still accept of a release's wire format: every bundle, check-in,
// events body and command (ADR 0047 decision 2). Unknown fields are ignored on purpose: a newer release adds fields
// and an older reader skips them.
func verifyRelease(t *testing.T, dir string) {
	t.Helper()
	var meta Meta
	readJSON(t, filepath.Join(dir, MetaFile), &meta)

	bundleTrust, err := bundle.TrustFromKeys(meta.BundleKeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.SchemaVersions) == 0 {
		t.Fatal("meta.json lists no schema versions")
	}
	for _, schema := range meta.SchemaVersions {
		raw, err := os.ReadFile(filepath.Join(dir, BundleFile(schema)))
		if err != nil {
			t.Fatal(err)
		}
		b, err := bundle.VerifyVersions(raw, bundleTrust, meta.DeviceID, meta.OrganizationID, 0, meta.SchemaVersions)
		if err != nil {
			t.Fatalf("bundle schema %d of %s: %v", schema, meta.Release, err)
		}
		if b.SchemaVersion != schema || len(b.Resources) == 0 {
			t.Fatalf("bundle schema %d decoded as schema %d with %d resources", schema, b.SchemaVersion, len(b.Resources))
		}
	}

	var checkin protocol.CheckinRequest
	readJSON(t, filepath.Join(dir, CheckinFile), &checkin)
	if checkin.AgentVersion == "" || len(checkin.SchemaVersions) == 0 {
		t.Fatalf("check-in does not decode: %+v", checkin)
	}

	var events protocol.EventsRequest
	readJSON(t, filepath.Join(dir, EventsFile), &events)
	if len(events.Events) == 0 {
		t.Fatal("events fixture is empty")
	}
	for _, ev := range events.Events {
		if !slices.Contains(protocol.EventTypes, ev.Type) {
			t.Errorf("event type %q of %s is no longer in the closed set; a device of that release would be refused", ev.Type, meta.Release)
		}
	}

	var commands []CommandFixture
	readJSON(t, filepath.Join(dir, CommandsFile), &commands)
	commandTrust, err := command.TrustFromKeys(meta.CommandKeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) == 0 {
		t.Fatal("commands fixture is empty")
	}
	for _, c := range commands {
		got, err := command.Verify(c.Envelope, commandTrust, meta.DeviceID, meta.OrganizationID, meta.CommandVerifyAt)
		if err != nil {
			t.Errorf("command %s of %s: %v", c.Type, meta.Release, err)
			continue
		}
		if got.Type != c.Type {
			t.Errorf("command fixture %s decoded as %s", c.Type, got.Type)
		}
		if _, ok := command.Lifetime(c.Type); !ok {
			t.Errorf("command type %q of %s is no longer registered", c.Type, meta.Release)
		}
	}

	if sql, err := os.ReadFile(filepath.Join(dir, AuditInsertFile)); err != nil || !strings.Contains(string(sql), "INSERT INTO audit_event") {
		t.Fatalf("audit insert fixture: %v", err)
	}
}

// TestPreviousReleaseFixtures verifies every release directory of testdata/. The audit insert of the same
// directories runs against the current audit schema in server/internal/auditwriter (pkg must not import the server).
func TestPreviousReleaseFixtures(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("testdata", "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("no release fixtures in testdata/; make compat-fixtures RELEASE=<version> creates them")
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) { verifyRelease(t, dir) })
	}
}

// TestGenerateIsDeterministicAndVerifies: the generator's output for the current tree passes the same checks as a
// stored release, and a second run writes the same bytes, so a regeneration changes a file only with the wire format.
func TestGenerateIsDeterministicAndVerifies(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, dir := range []string{a, b} {
		if err := Generate(dir, "0.1.0-test", "INSERT INTO audit_event\n"); err != nil {
			t.Fatal(err)
		}
	}
	verifyRelease(t, a)
	entries, err := os.ReadDir(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		x, _ := os.ReadFile(filepath.Join(a, e.Name()))
		y, _ := os.ReadFile(filepath.Join(b, e.Name()))
		if !bytes.Equal(x, y) {
			t.Errorf("%s differs between two generations", e.Name())
		}
	}
}

// TestFixturesAreTamperEvident: the verification of the fixtures is not vacuous.
func TestFixturesAreTamperEvident(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir, "0.1.0-test", "INSERT INTO audit_event\n"); err != nil {
		t.Fatal(err)
	}
	var meta Meta
	readJSON(t, filepath.Join(dir, MetaFile), &meta)
	trust, err := bundle.TrustFromKeys(meta.BundleKeys)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, BundleFile(2)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.VerifyVersions(raw, trust, meta.DeviceID, meta.OrganizationID, 0, []int{bundle.SchemaVersion}); !errors.Is(err, bundle.ErrSchema) {
		t.Fatalf("schema 2 bundle accepted by a schema 1 reader: %v", err)
	}
	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || !bytes.Contains(payload, []byte(`"bundle_version":1`)) {
		t.Fatalf("payload: %v", err)
	}
	env.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte(`"bundle_version":1`), []byte(`"bundle_version":2`), 1))
	tampered, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.VerifyVersions(tampered, trust, meta.DeviceID, meta.OrganizationID, 0, SchemaVersions); !errors.Is(err, bundle.ErrSignature) {
		t.Fatalf("a tampered envelope: %v", err)
	}
}
