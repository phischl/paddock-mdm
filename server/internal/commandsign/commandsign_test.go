package commandsign_test

import (
	"context"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/command"
	"github.com/paddock-mdm/paddock/server/internal/commandsign"
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/baotest"
)

// TestSignVerifies: an envelope signed through OpenBao with the worker's AppRole verifies with the public keys the
// compiler's AppRole reads (plan M4a decisions 2 and 5).
func TestSignVerifies(t *testing.T) {
	b := baotest.Start(t)
	ctx := context.Background()
	worker := b.AppRole(t, "paddock-worker")
	signer, err := bao.New(b.Addr, worker.RoleID, worker.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	compiler := b.AppRole(t, "paddock-compiler")
	reader, err := bao.New(b.Addr, compiler.RoleID, compiler.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := commandsign.PublicKeys(ctx, reader)
	if err != nil || len(keys) != 1 || keys[0].KeyID != "command-signing:v1" {
		t.Fatalf("public keys %+v %v", keys, err)
	}
	if _, err := commandsign.PublicKeys(ctx, signer); err == nil {
		t.Fatal("the worker may read the public keys")
	}
	now := time.Now().UTC().Truncate(time.Second)
	c := command.Command{CommandID: "0190f000-0000-7000-8000-0000000000c1", DeviceID: "0190f000-0000-7000-8000-000000000001",
		OrganizationID: "0190f000-0000-7000-8000-0000000000aa", Type: command.TypeRotateAdminPassword, IssuedAt: now,
		ExpiresAt: now.Add(time.Hour)}
	env, err := commandsign.Sign(ctx, signer, c)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := command.TrustFromKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := command.Verify(env, trust, c.DeviceID, c.OrganizationID, now); err != nil || got.CommandID != c.CommandID {
		t.Fatalf("verify: %+v %v", got, err)
	}
}
