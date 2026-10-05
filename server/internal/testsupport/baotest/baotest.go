// Package baotest starts OpenBao in dev mode with the transit keys audit-chain, bundle-signing, command-signing and
// escrow-wrap, the session KV secret and AppRoles equivalent to deploy/compose/scripts/openbao-bootstrap.sh.
package baotest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
)

// Bao is a running dev-mode OpenBao.
type Bao struct {
	Addr string
	Root *api.Client
}

// AppRole holds AppRole credentials.
type AppRole struct{ RoleID, SecretID string }

// Start starts OpenBao and creates transit/keys/audit-chain, transit/keys/bundle-signing and
// transit/keys/command-signing (ed25519, non-exportable) and secret/paddock/session.
func Start(t testing.TB) *Bao {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        pgtest.Image(t, "OPENBAO_IMAGE"),
			ExposedPorts: []string{"8200/tcp"},
			Cmd:          []string{"server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=0.0.0.0:8200"},
			WaitingFor:   wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("baotest: start: %v", err)
	}
	host, _ := c.Host(ctx)
	port, err := c.MappedPort(ctx, "8200/tcp")
	if err != nil {
		t.Fatal(err)
	}
	b := &Bao{Addr: fmt.Sprintf("http://%s:%s", host, port.Port())}
	cfg := api.DefaultConfig()
	cfg.Address = b.Addr
	b.Root, err = api.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b.Root.SetToken("root")
	must(t, b.Root.Sys().Mount("transit", &api.MountInput{Type: "transit"}))
	_, err = b.Root.Logical().Write("transit/keys/audit-chain", map[string]any{
		"type": "ed25519", "exportable": false, "allow_plaintext_backup": false,
	})
	must(t, err)
	for _, key := range []string{"bundle-signing", "command-signing"} {
		_, err = b.Root.Logical().Write("transit/keys/"+key, map[string]any{
			"type": "ed25519", "exportable": false, "allow_plaintext_backup": false,
		})
		must(t, err)
	}
	_, err = b.Root.Logical().Write("transit/keys/escrow-wrap", map[string]any{
		"type": "rsa-4096", "exportable": false, "allow_plaintext_backup": false,
	})
	must(t, err)
	_, err = b.Root.Logical().Write("secret/data/paddock/session", map[string]any{
		"data": map[string]any{"current": "Y3VycmVudC1rZXktMzItYnl0ZXMtbG9uZy0tLS0tLS0=", "previous": "cHJldmlvdXMta2V5LTMyLWJ5dGVzLWxvbmctLS0tLS0="},
	})
	must(t, err)
	must(t, b.Root.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}))
	must(t, b.Root.Sys().PutPolicy("paddock-audit-writer", `
path "transit/sign/audit-chain" { capabilities = ["update"] }
path "transit/keys/audit-chain" { capabilities = ["read"] }`))
	must(t, b.Root.Sys().PutPolicy("paddock-api", `
path "secret/data/paddock/session" { capabilities = ["read"] }
path "transit/keys/bundle-signing" { capabilities = ["read"] }`))
	must(t, b.Root.Sys().PutPolicy("paddock-compiler", `
path "transit/sign/bundle-signing" { capabilities = ["update"] }
path "transit/keys/bundle-signing" { capabilities = ["read"] }
path "transit/keys/command-signing" { capabilities = ["read"] }
path "transit/keys/escrow-wrap" { capabilities = ["read"] }`))
	must(t, b.Root.Sys().PutPolicy("paddock-escrow-reader", `
path "transit/decrypt/escrow-wrap" { capabilities = ["update"] }`))
	must(t, b.Root.Sys().PutPolicy("paddock-worker", `
path "transit/sign/command-signing" { capabilities = ["update"] }`))
	return b
}

// AppRole creates an AppRole with the named policy and returns its credentials.
func (b *Bao) AppRole(t testing.TB, name string) AppRole {
	t.Helper()
	_, err := b.Root.Logical().Write("auth/approle/role/"+name, map[string]any{
		"token_policies": name, "token_ttl": "1h", "token_max_ttl": "4h",
	})
	must(t, err)
	s, err := b.Root.Logical().Read("auth/approle/role/" + name + "/role-id")
	must(t, err)
	sid, err := b.Root.Logical().Write("auth/approle/role/"+name+"/secret-id", nil)
	must(t, err)
	return AppRole{RoleID: s.Data["role_id"].(string), SecretID: sid.Data["secret_id"].(string)}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("baotest: %v", err)
	}
}
