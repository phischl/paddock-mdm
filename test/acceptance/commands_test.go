package acceptance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// deviceCommand is the part of the admin API's device command the gates read.
type deviceCommand struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Status    string         `json:"status"`
	ExpiresAt time.Time      `json:"expires_at"`
	Result    map[string]any `json:"result"`
}

// rotate issues rotate_admin_password through the admin API and returns the command.
func rotate(t *testing.T, p *env.Portal, deviceID string) (deviceCommand, env.Response) {
	t.Helper()
	res := call(t, p, http.MethodPost, "/api/v1/devices/"+deviceID+"/local-admin/rotate", nil)
	expectStatus(t, res, http.StatusAccepted, "")
	var c deviceCommand
	if err := res.JSON(&c); err != nil {
		t.Fatal(err)
	}
	return c, res
}

// waitCommand polls the device's command list until the command has status.
func waitCommand(t *testing.T, p *env.Portal, deviceID, id, status string, timeout time.Duration) deviceCommand {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		res := call(t, p, http.MethodGet, "/api/v1/devices/"+deviceID+"/commands?page_size=100", nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []deviceCommand `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		for _, c := range page.Items {
			if c.ID == id && c.Status == status {
				return c
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("command %s: status %s not reached within %s: %+v", id, status, timeout, page.Items)
		}
		time.Sleep(time.Second)
	}
}

// commandEnvelope checks in until the response carries the command and returns its envelope.
func commandEnvelope(t *testing.T, d *devicesim.Device, id string, trust command.Trust) json.RawMessage {
	t.Helper()
	var found json.RawMessage
	checkinUntil(t, d, 30*time.Second, func(out protocol.CheckinResponse) bool {
		for _, env := range out.Commands {
			c, err := command.Verify(env, trust, d.DeviceID, d.Config.OrganizationID, time.Now())
			if err != nil {
				t.Fatalf("delivered command does not verify with the bundle keys: %v", err)
			}
			if c.CommandID == id {
				found = env
			}
		}
		return found != nil
	})
	return found
}

// carries reports whether the next check-in response carries the command.
func carries(t *testing.T, d *devicesim.Device, id string) bool {
	t.Helper()
	out, res, err := d.Checkin(testContext(t, time.Minute))
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("checkin: %v HTTP %d %s", err, res.Status, res.Body)
	}
	for _, env := range out.Commands {
		if commandID(env) == id {
			return true
		}
	}
	return false
}

func commandID(env json.RawMessage) string {
	_, payload, err := dsse.Decode(env)
	if err != nil {
		return ""
	}
	var c command.Command
	_ = json.Unmarshal(payload, &c)
	return c.CommandID
}

// paddockSQL runs a statement in Paddock's database as the superuser (test-only access, like the system tests).
func paddockSQL(t *testing.T, query string) string {
	t.Helper()
	out, err := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "paddock", "-tAc", query)
	if err != nil {
		t.Fatalf("psql %q: %v: %s", query, err, out)
	}
	return strings.TrimSpace(out)
}

// TestCommands is gate C1 of plan M4a: an issued command appears in the next check-in and verifies with the keys of
// the device's bundle; its result is recorded idempotently; an expired command is never delivered; a forged or
// foreign envelope fails pkg/command.Verify; another organization cannot issue to the device.
func TestCommands(t *testing.T) {
	alice := login(t, "alice@acme.test")
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil })
	trust, err := command.TrustFromKeys(b.Keys.CommandSigning)
	if err != nil {
		t.Fatal(err)
	}

	issued, res := rotate(t, alice, d.DeviceID)
	expectOneEvent(t, alice, res.RequestID, "local_admin.rotation_requested", "success")
	if issued.Type != command.TypeRotateAdminPassword || issued.Status != "pending" ||
		time.Until(issued.ExpiresAt) < 7*24*time.Hour-time.Hour {
		t.Fatalf("issued command %+v", issued)
	}
	env := commandEnvelope(t, d, issued.ID, trust)
	waitCommand(t, alice, d.DeviceID, issued.ID, "delivered", 30*time.Second)

	t.Run("forged and foreign envelopes", func(t *testing.T) {
		other := activeDevice(t, alice, "", "c1-other-"+uniqueSuffix())
		if _, err := command.Verify(env, trust, other.DeviceID, d.Config.OrganizationID, time.Now()); !errors.Is(err, command.ErrWrongDevice) {
			t.Fatalf("envelope of another device: %v", err)
		}
		_, payload, err := dsse.Decode(env)
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		forged, _ := dsse.New(command.PayloadType, payload, dsse.SignEd25519(key, "command-signing:v1", command.PayloadType, payload)).Encode()
		if _, err := command.Verify(forged, trust, d.DeviceID, d.Config.OrganizationID, time.Now()); !errors.Is(err, command.ErrSignature) {
			t.Fatalf("forged envelope: %v", err)
		}
		// The other device cannot report a result for the command either.
		res, err := other.CommandResult(testContext(t, time.Minute), issued.ID, protocol.CommandSucceeded, nil)
		if err != nil || res.Status != http.StatusNotFound {
			t.Fatalf("result of another device: %v HTTP %d %s", err, res.Status, res.Body)
		}
	})

	t.Run("result is idempotent", func(t *testing.T) {
		ctx := testContext(t, time.Minute)
		result := json.RawMessage(`{"generation":1}`)
		for i := range 2 {
			res, err := d.CommandResult(ctx, issued.ID, protocol.CommandSucceeded, result)
			if err != nil || res.Status != http.StatusAccepted {
				t.Fatalf("result %d: %v HTTP %d %s", i+1, err, res.Status, res.Body)
			}
		}
		res, err := d.CommandResult(ctx, issued.ID, protocol.CommandFailed, nil)
		if err != nil || res.Status != http.StatusConflict || res.Problem().Code != protocol.CodeConflict {
			t.Fatalf("conflicting result: %v HTTP %d %s", err, res.Status, res.Body)
		}
		done := waitCommand(t, alice, d.DeviceID, issued.ID, "succeeded", 30*time.Second)
		if done.Result["generation"] != float64(1) {
			t.Fatalf("recorded result %+v", done.Result)
		}
		if carries(t, d, issued.ID) {
			t.Fatal("a finished command is delivered again")
		}
	})

	t.Run("expired command is never delivered", func(t *testing.T) {
		c, _ := rotate(t, alice, d.DeviceID)
		paddockSQL(t, "UPDATE device_command SET issued_at = now() - interval '8 days', expires_at = now() - interval '1 second' WHERE id = '"+c.ID+"'")
		waitCommand(t, alice, d.DeviceID, c.ID, "expired", 2*time.Minute)
		if carries(t, d, c.ID) {
			t.Fatal("an expired command was delivered")
		}
		res, err := d.CommandResult(testContext(t, time.Minute), c.ID, protocol.CommandSucceeded, nil)
		if err != nil || res.Status != http.StatusNotFound {
			t.Fatalf("result of an expired command: %v HTTP %d %s", err, res.Status, res.Body)
		}
	})

	t.Run("organization isolation", func(t *testing.T) {
		carol := login(t, "carol@globex.test")
		res := call(t, carol, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/local-admin/rotate", nil)
		expectStatus(t, res, http.StatusNotFound, "not_found")
		expectOneEvent(t, carol, res.RequestID, "local_admin.rotation_requested", "failure")
		expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/commands", nil), http.StatusNotFound, "not_found")
	})
}

// m3bCommit is the last commit of M3.1 (agent of bundle schema 2 without the keys object).
const m3bCommit = "99937ad"

// TestM3bAgentAcceptsBundleKeys (plan M4a decision 5): the bundle verification of an M3b-built agent — pkg/bundle at
// m3bCommit — accepts a v2 bundle of this release, which carries the top-level keys object.
func TestM3bAgentAcceptsBundleKeys(t *testing.T) {
	alice := login(t, "alice@acme.test")
	d := v2Device(t, alice, "", 1, 2)
	ctx := testContext(t, 5*time.Minute)
	var envelope []byte
	checkinUntil(t, d, time.Minute, func(out protocol.CheckinResponse) bool {
		if out.Bundle == nil {
			return false
		}
		env, status, err := d.Download(ctx, out.Bundle.URL)
		if err != nil || status != http.StatusOK {
			t.Fatalf("download: %v HTTP %d", err, status)
		}
		envelope = env
		return true
	})
	if b, err := bundle.VerifyVersions(envelope, d.Trust, d.DeviceID, d.Config.OrganizationID, 0, []int{1, 2}); err != nil || b.Keys == nil {
		t.Fatalf("current verification: %+v %v", b, err)
	}

	root, err := stack.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archive := exec.CommandContext(ctx, "sh", "-c", "git -C '"+root+"' archive "+m3bCommit+" pkg | tar -x -C '"+dir+"'")
	if out, err := archive.CombinedOutput(); err != nil {
		t.Fatalf("extract pkg at %s: %v: %s", m3bCommit, err, out)
	}
	// The verifier imports pkg under the module path of the extracted commit.
	gomod, err := os.ReadFile(filepath.Join(dir, "pkg", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(gomod), "\n")
	module, ok := strings.CutPrefix(first, "module ")
	if !ok {
		t.Fatalf("pkg/go.mod at %s starts with %q", m3bCommit, first)
	}
	verify := strings.ReplaceAll(m3bVerify, "{{module}}", module)
	trust, _ := json.Marshal(d.Config.BundleKeys)
	for name, data := range map[string][]byte{"envelope.json": envelope, "trust.json": trust, "pkg/cmd/m3bverify/main.go": []byte(verify)} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := exec.CommandContext(ctx, "go", "run", "./cmd/m3bverify", filepath.Join(dir, "envelope.json"), filepath.Join(dir, "trust.json"),
		d.DeviceID, d.Config.OrganizationID)
	run.Dir = filepath.Join(dir, "pkg")
	run.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := run.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "accepted schema 2") {
		t.Fatalf("M3b verification: %v\n%s", err, out)
	}
}

// m3bVerify verifies a bundle with the pkg/bundle of the extracted commit, as the M3b agent does; {{module}} is the
// module path of pkg at that commit.
const m3bVerify = `package main

import (
	"encoding/json"
	"fmt"
	"os"

	"{{module}}/bundle"
	"{{module}}/protocol"
)

func main() {
	env, _ := os.ReadFile(os.Args[1])
	raw, _ := os.ReadFile(os.Args[2])
	var keys []protocol.BundleKey
	_ = json.Unmarshal(raw, &keys)
	trust, err := bundle.TrustFromKeys(keys)
	if err == nil {
		var b *bundle.Bundle
		if b, err = bundle.VerifyVersions(env, trust, os.Args[3], os.Args[4], 0, []int{1, 2}); err == nil {
			fmt.Printf("accepted schema %d with %d resources\n", b.SchemaVersion, len(b.Resources))
			return
		}
	}
	fmt.Println(err)
	os.Exit(1)
}
`
