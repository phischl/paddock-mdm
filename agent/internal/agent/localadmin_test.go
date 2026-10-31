package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/localadmin"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// localAdminBundle is an applied bundle with a login resource that manages paddock-admin and the escrow and command
// keys.
func localAdminBundle(t *testing.T) *bundle.Bundle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	login, err := bundle.LoginResource(bundle.LoginSpec{Provider: bundle.ProviderHimmelblau, SessionAction: bundle.SessionActionLockScreen,
		BreakGlassAccounts: []string{"paddock-admin"}, LocalAdmin: &bundle.LocalAdminSpec{Username: "paddock-admin", RotationDays: 30}})
	if err != nil {
		t.Fatal(err)
	}
	keys := testgw.CommandKeys()
	keys.EscrowWrap = &bundle.EncryptionKey{KeyID: "escrow-wrap:v1", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	return &bundle.Bundle{SchemaVersion: 2, Resources: []bundle.Resource{login}, Keys: keys}
}

// TestLocalAdminWiring: the agent creates and rotates the local administrator through the device API, answers
// rotate_admin_password after the rotation it triggered, and reports only the local administrator's logins.
func TestLocalAdminWiring(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	sys.Files["/etc/passwd"] = &fakesys.File{Data: []byte("root:x:0:0:root:/root:/bin/bash\n"), Mode: 0o644}
	sys.Files["/etc/group"] = &fakesys.File{Data: []byte("sudo:x:27:\n"), Mode: 0o644}
	a.d.Accounts, a.localAdmin.Sys = sys, sys
	now := time.Now().UTC()
	a.localAdmin.Now = func() time.Time { return now }
	a.current = localAdminBundle(t)
	ctx := context.Background()

	a.tickLocalAdmin(ctx) // creates the account, uploads generation 1
	now = now.Add(localadmin.PollInterval)
	a.tickLocalAdmin(ctx) // stored: sets the password
	if len(g.Escrows) != 1 || g.Escrows[0].Generation != 1 || a.st.LocalAdmin.Generation != 1 {
		t.Fatalf("escrows %+v, state %+v", g.Escrows, a.st.LocalAdmin)
	}

	g.Mu.Lock()
	g.Checkin.Commands = []json.RawMessage{testgw.SignedCommand(t, command.Command{CommandID: "0190f000-0000-7000-8000-0000000000c9",
		DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID, Type: command.TypeRotateAdminPassword, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})}
	g.Mu.Unlock()
	a.Cycle(ctx)          // executes the command (deferred)
	a.tickLocalAdmin(ctx) // the run loop ticks after every check-in: the rotation starts
	g.Mu.Lock()
	g.Checkin.Commands = nil
	g.Mu.Unlock()
	if len(g.Results) != 0 || len(g.Escrows) != 2 {
		t.Fatalf("results %v before the rotation, escrows %d", g.Results, len(g.Escrows))
	}
	now = now.Add(localadmin.PollInterval)
	a.tickLocalAdmin(ctx)
	a.Cycle(ctx)
	if r := g.Results["0190f000-0000-7000-8000-0000000000c9"]; r.Status != "succeeded" || string(r.Result) != `{"generation":2}` {
		t.Fatalf("command result %+v", g.Results)
	}

	a.localAdminLogin(localadmin.Login{Service: "sshd", User: "dave", At: now})
	a.localAdminLogin(localadmin.Login{Service: "sshd", User: "paddock-admin", At: now})
	a.flush(ctx)
	logins := eventsOf(g, protocol.EventLocalAdminLogin)
	if len(logins) != 1 || string(logins[0].Data) != `{"service":"sshd","at":"`+now.Format(time.RFC3339Nano)+`"}` {
		t.Fatalf("login events %+v", logins)
	}
	if rotated := eventsOf(g, protocol.EventLocalAdminRotated); len(rotated) != 2 {
		t.Fatalf("rotated events %+v", rotated)
	}
}

// TestLocalAdminWaitsForEnforcement (plan M11 decision 9): while the current bundle is report-only the local
// administrator is neither created nor rotated and rotate_admin_password fails with reason report_only; the first
// enforced bundle creates it.
func TestLocalAdminWaitsForEnforcement(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	sys.Files["/etc/passwd"] = &fakesys.File{Data: []byte("root:x:0:0:root:/root:/bin/bash\n"), Mode: 0o644}
	sys.Files["/etc/group"] = &fakesys.File{Data: []byte("sudo:x:27:\n"), Mode: 0o644}
	a.d.Accounts, a.localAdmin.Sys = sys, sys
	now := time.Now().UTC()
	a.localAdmin.Now = func() time.Time { return now }
	a.current = localAdminBundle(t)
	a.current.Mode = bundle.ModeReportOnly
	ctx := context.Background()

	for range 2 {
		a.tickLocalAdmin(ctx)
		now = now.Add(localadmin.PollInterval)
	}
	if calls := sys.TakeCalls(); len(calls) != 0 || len(g.Escrows) != 0 || a.st.LocalAdmin.Generation != 0 {
		t.Fatalf("report-only: calls %v, escrows %d, state %+v", calls, len(g.Escrows), a.st.LocalAdmin)
	}
	// rotate_admin_password gets a final answer instead of a deferral the manager would never resolve (R6.7).
	const commandID = "0190f000-0000-7000-8000-0000000000ca"
	g.Mu.Lock()
	g.Checkin.Commands = []json.RawMessage{testgw.SignedCommand(t, command.Command{CommandID: commandID,
		DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID, Type: command.TypeRotateAdminPassword, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})}
	g.Mu.Unlock()
	a.Cycle(ctx)
	a.Cycle(ctx)
	g.Mu.Lock()
	g.Checkin.Commands = nil
	r := g.Results[commandID]
	g.Mu.Unlock()
	if r.Status != protocol.CommandFailed || string(r.Result) != `{"reason":"report_only"}` {
		t.Fatalf("command result %+v", r)
	}
	if calls := sys.TakeCalls(); len(calls) != 0 || len(g.Escrows) != 0 {
		t.Fatalf("report-only rotation: calls %v, escrows %d", calls, len(g.Escrows))
	}

	a.current.Mode = bundle.ModeEnforce
	a.tickLocalAdmin(ctx)
	if len(sys.TakeCalls()) == 0 || len(g.Escrows) != 1 {
		t.Fatalf("enforced: escrows %d", len(g.Escrows))
	}
}
