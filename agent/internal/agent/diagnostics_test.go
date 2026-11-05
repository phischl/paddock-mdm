package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const diagID = "0190f000-0000-7000-8000-0000000000c1"

// diagnosticsAgent is an agent with a bundle that carries an escrow key (returned for unwrapping), a German system
// locale and one active wayland session.
func diagnosticsAgent(t *testing.T) (*Agent, *testgw.Gateway, *fakesys.System, *rsa.PrivateKey) {
	t.Helper()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keys := testgw.CommandKeys()
	keys.EscrowWrap = &bundle.EncryptionKey{KeyID: "escrow-wrap:v1", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	a.current = &bundle.Bundle{SchemaVersion: 2, Keys: keys}
	sys.Files["/etc/default/locale"] = &fakesys.File{Data: []byte("LANG=de_DE.UTF-8\n"), Mode: 0o644}
	sys.Files["/etc/sudoers"] = &fakesys.File{Data: []byte("Defaults env_reset\n"), Mode: 0o440}
	sys.Sessions = []fakesys.Session{
		{ID: "2", UID: 811622788, User: "dave@acme.test", Class: "user", Type: "wayland", State: "active"},
		{ID: "3", UID: 1001, User: "erin", Class: "user", Type: "tty", State: "active"},
	}
	sys.Outputs = map[string]fakesys.OutputReply{}
	return a, g, sys, key
}

func collectCommand(id, requestID, reason string) *command.Command {
	params, _ := json.Marshal(command.CollectStatusParams{RequestID: requestID, Reason: reason})
	return &command.Command{CommandID: id, DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID, Type: command.TypeCollectStatus,
		Params: params}
}

func notifyCall(sys *fakesys.System) {
	sys.Outputs["systemd-run --machine=811622788@.host --user --quiet --collect --wait notify-send --app-name=Paddock "+
		"--urgency=normal -- Paddock: Diagnosedaten erfasst Paddock hat für Ihre Administration Diagnosedaten von diesem Gerät "+
		"erfasst. Grund: VPN fails since Monday. Erfasst wurden: die eigenen Protokolle und die Konfiguration von Paddock, keine "+
		"persönlichen Dateien."] = fakesys.OutputReply{}
}

// collect runs c through the handler and, once accepted, through the diagnostics worker's job, as the worker would.
func collect(t *testing.T, a *Agent, c *command.Command) (string, map[string]any) {
	t.Helper()
	status, result := a.collectStatusCommand(context.Background(), c)
	if status != commands.Deferred {
		return status, result
	}
	select {
	case job := <-a.diagnosticsJobs:
		return a.collectStatus(context.Background(), job)
	default:
		t.Fatal("accepted but not queued")
		return "", nil
	}
}

func diagnosticsDirEmpty(t *testing.T, a *Agent) {
	t.Helper()
	entries, err := os.ReadDir(a.d.Layout.Diagnostics())
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

// TestCollectStatusUploads: the user is notified in German before anything is collected, the sealed archive is
// announced and uploaded, it opens with the escrow key and the command ID only, the result carries the facts of the
// bundle, and no temporary file is left.
func TestCollectStatusUploads(t *testing.T) {
	a, g, sys, key := diagnosticsAgent(t)
	notifyCall(sys)
	status, result := collect(t, a, collectCommand(diagID, diagID, " VPN fails since Monday "))
	if status != protocol.CommandSucceeded || result["uploaded"] != true || result["notified_sessions"] != float64(1) ||
		result["files"].(float64) < 1 || result["bytes"].(float64) < 1 || result["reason"] != nil {
		t.Fatalf("%s %v", status, result)
	}
	if len(sys.OutputCalls) < 2 || !strings.HasPrefix(sys.OutputCalls[0], "systemd-run ") ||
		strings.HasPrefix(sys.OutputCalls[1], "systemd-run ") {
		t.Fatalf("the notice is not the first call: %v", sys.OutputCalls[:2])
	}
	if len(g.Diagnostics) != 1 || len(g.Uploads) != 1 {
		t.Fatalf("announcements %v, uploads %d", g.Diagnostics, len(g.Uploads))
	}
	req, sealed := g.Diagnostics[0], g.Uploads[diagID]
	sum := sha256.Sum256(sealed)
	if req.CommandID != diagID || req.Size != int64(len(sealed)) || req.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("announcement %+v for %d bytes", req, len(sealed))
	}
	wrapped, _ := base64.StdEncoding.DecodeString(req.WrappedDEK)
	dek, err := rsa.DecryptOAEP(sha256.New(), nil, key, wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(req.Nonce)
	if _, err := escrow.OpenObject(dek, nonce, "0190f000-0000-7000-8000-0000000000c2", sealed); err == nil {
		t.Fatal("opened under another ID")
	}
	archive, err := escrow.OpenObject(dek, nonce, diagID, sealed)
	if err != nil || int64(len(archive)) != int64(result["bytes"].(float64)) {
		t.Fatalf("open: %v (%d bytes)", err, len(archive))
	}
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	h, err := tar.NewReader(zr).Next()
	if err != nil || h.Name != "manifest.json" {
		t.Fatalf("first file %v %v", h, err)
	}
	diagnosticsDirEmpty(t, a)
}

// TestCollectStatusRefusals: invalid params are refused before anything runs; a refused announcement, an unreachable
// server, a failed PUT and a bundle without an escrow key each fail with their reason and leave no temporary file.
func TestCollectStatusRefusals(t *testing.T) {
	for name, tt := range map[string]struct {
		cmd     *command.Command
		prepare func(a *Agent, g *testgw.Gateway)
		reason  string
	}{
		"another request ID":    {cmd: collectCommand(diagID, "0190f000-0000-7000-8000-0000000000c2", "VPN fails"), reason: "invalid_params"},
		"request ID not a UUID": {cmd: collectCommand("../../etc/x", "../../etc/x", "VPN fails"), reason: "invalid_params"},
		"reason too short":      {cmd: collectCommand(diagID, diagID, " x "), reason: "invalid_params"},
		"reason too long":       {cmd: collectCommand(diagID, diagID, strings.Repeat("ä", 501)), reason: "invalid_params"},
		"announcement refused": {cmd: collectCommand(diagID, diagID, "VPN fails"), reason: "upload_refused",
			prepare: func(_ *Agent, g *testgw.Gateway) { g.DiagnosticsFail = http.StatusNotFound }},
		"server unavailable": {cmd: collectCommand(diagID, diagID, "VPN fails"), reason: "upload_failed",
			prepare: func(_ *Agent, g *testgw.Gateway) { g.DiagnosticsFail = http.StatusServiceUnavailable }},
		"PUT fails": {cmd: collectCommand(diagID, diagID, "VPN fails"), reason: "upload_failed",
			prepare: func(_ *Agent, g *testgw.Gateway) { g.UploadFail = http.StatusForbidden }},
		"no escrow key": {cmd: collectCommand(diagID, diagID, "VPN fails"), reason: "collect_failed",
			prepare: func(a *Agent, _ *testgw.Gateway) {
				a.current = &bundle.Bundle{SchemaVersion: 2, Keys: testgw.CommandKeys()}
			}},
	} {
		t.Run(name, func(t *testing.T) {
			a, g, sys, _ := diagnosticsAgent(t)
			if tt.prepare != nil {
				tt.prepare(a, g)
			}
			status, result := collect(t, a, tt.cmd)
			if status != protocol.CommandFailed || result["reason"] != tt.reason || result["uploaded"] != false {
				t.Fatalf("%s %v", status, result)
			}
			if tt.reason == "invalid_params" && len(sys.OutputCalls) != 0 {
				t.Fatalf("ran %v", sys.OutputCalls)
			}
			if len(g.Uploads) != 0 {
				t.Fatal("uploaded")
			}
			diagnosticsDirEmpty(t, a)
		})
	}
}

// TestCollectStatusLeftovers: a file an interrupted collection left is removed by the next one.
func TestCollectStatusLeftovers(t *testing.T) {
	a, _, _, _ := diagnosticsAgent(t)
	dir := a.d.Layout.Diagnostics()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/0190f000-0000-7000-8000-0000000000c0.tar.gz", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, result := collect(t, a, collectCommand(diagID, diagID, "VPN fails")); status != protocol.CommandSucceeded {
		t.Fatalf("%s %v", status, result)
	}
	diagnosticsDirEmpty(t, a)
}

// TestCollectStatusDeferred: the handler only queues the collection: it returns at once without a notice, a command
// or a request, and refuses when too many collections wait.
func TestCollectStatusDeferred(t *testing.T) {
	a, g, sys, _ := diagnosticsAgent(t)
	for i := range diagnosticsQueue {
		id := fmt.Sprintf("0190f000-0000-7000-8000-0000000000d%d", i)
		if status, result := a.collectStatusCommand(context.Background(), collectCommand(id, id, "VPN fails")); status != commands.Deferred {
			t.Fatalf("%d: %s %v", i, status, result)
		}
	}
	status, result := a.collectStatusCommand(context.Background(), collectCommand(diagID, diagID, "VPN fails"))
	if status != protocol.CommandFailed || result["reason"] != "collect_failed" {
		t.Fatalf("queue full: %s %v", status, result)
	}
	if len(sys.OutputCalls) != 0 || len(g.Diagnostics) != 0 || len(g.Uploads) != 0 {
		t.Fatalf("ran in the handler: %v, %d announcements", sys.OutputCalls, len(g.Diagnostics))
	}
}

// TestCollectStatusWorker: the worker runs the queued collections one after another, returns each result to the loop
// in order and stops with its context.
func TestCollectStatusWorker(t *testing.T) {
	a, g, _, _ := diagnosticsAgent(t)
	second := "0190f000-0000-7000-8000-0000000000c2"
	for _, id := range []string{diagID, second} {
		if status, _ := a.collectStatusCommand(context.Background(), collectCommand(id, id, "VPN fails")); status != commands.Deferred {
			t.Fatal(status)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		a.runDiagnostics(ctx)
		close(stopped)
	}()
	for _, id := range []string{diagID, second} {
		select {
		case d := <-a.diagnosticsDone:
			if d.commandID != id || d.status != protocol.CommandSucceeded || d.result["uploaded"] != true {
				t.Fatalf("%+v, want %s", d, id)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no result")
		}
	}
	cancel()
	<-stopped
	if len(g.Uploads) != 2 {
		t.Fatalf("uploads %d", len(g.Uploads))
	}
	diagnosticsDirEmpty(t, a)
}

// TestSweepDiagnostics: the plaintext archive of a collection the agent was killed during is removed at start.
func TestSweepDiagnostics(t *testing.T) {
	a, _, _, _ := diagnosticsAgent(t)
	dir := a.d.Layout.Diagnostics()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/"+diagID+".tar.gz", []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.sweepDiagnostics()
	diagnosticsDirEmpty(t, a)
}

// TestCollectStatusRegistered: the check-in that carries collect_status returns before the collection ran; the
// worker's result is reported at the next check-in.
func TestCollectStatusRegistered(t *testing.T) {
	a, g, _, _ := diagnosticsAgent(t)
	now := time.Now().UTC()
	c := collectCommand(diagID, diagID, "VPN fails")
	c.IssuedAt, c.ExpiresAt = now, now.Add(time.Hour)
	g.Mu.Lock()
	g.Checkin.Commands = []json.RawMessage{testgw.SignedCommand(t, *c)}
	g.Mu.Unlock()
	a.Cycle(context.Background())
	g.Mu.Lock()
	g.Checkin.Commands = nil
	_, reported := g.Results[diagID]
	g.Mu.Unlock()
	if reported || len(g.Uploads) != 0 {
		t.Fatal("the check-in waited for the collection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.runDiagnostics(ctx)
	a.finishDiagnostics(<-a.diagnosticsDone)
	a.Cycle(context.Background())
	if r := g.Results[diagID]; r.Status != protocol.CommandSucceeded || !strings.Contains(string(r.Result), `"uploaded":true`) {
		t.Fatalf("result %+v", g.Results)
	}
}

// TestRunCollectsStatus drives the real run loop: Run removes the plaintext archive an earlier run left, the
// collect_status of a check-in is handed to the worker Run started, and the loop reports the worker's result at a
// later check-in.
func TestRunCollectsStatus(t *testing.T) {
	a, g, _, _ := diagnosticsAgent(t)
	dir := a.d.Layout.Diagnostics()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	leftover := dir + "/" + diagID + ".tar.gz"
	if err := os.WriteFile(leftover, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.Mu.Lock()
	g.Checkin.NextCheckinS = 1
	g.Mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, func() bool { return checkins(g) >= 1 })
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("leftover archive not removed at start: %v", err)
	}
	now := time.Now().UTC()
	c := collectCommand(diagID, diagID, "VPN fails")
	c.IssuedAt, c.ExpiresAt = now, now.Add(time.Hour)
	g.Mu.Lock()
	g.Checkin.Commands = []json.RawMessage{testgw.SignedCommand(t, *c)}
	g.Mu.Unlock()
	waitFor(t, func() bool {
		g.Mu.Lock()
		defer g.Mu.Unlock()
		r, ok := g.Results[diagID]
		return ok && r.Status == protocol.CommandSucceeded && strings.Contains(string(r.Result), `"uploaded":true`)
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	g.Mu.Lock()
	defer g.Mu.Unlock()
	if len(g.Uploads) != 1 {
		t.Fatalf("uploads %d", len(g.Uploads))
	}
}

// TestRunKeepsDiagnosticsResultAtShutdown: a result the worker returned when the loop already stopped is kept in the
// state, so that it reaches the server after the restart.
func TestRunKeepsDiagnosticsResultAtShutdown(t *testing.T) {
	a, _, _, _ := diagnosticsAgent(t)
	a.st.Status, a.st.EnrollmentID = state.StatusPending, ""
	a.diagnosticsDone <- diagnosticsDone{commandID: diagID, status: protocol.CommandSucceeded, result: map[string]any{"uploaded": true}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Run(ctx); err == nil {
		t.Fatal("run of an inactive agent ended without the context error")
	}
	st, err := state.Load(a.d.Layout.State())
	if err != nil || len(st.CommandResults) != 1 || st.CommandResults[0].CommandID != diagID {
		t.Fatalf("state results %+v, %v", st.CommandResults, err)
	}
}
