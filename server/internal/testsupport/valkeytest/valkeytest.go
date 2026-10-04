// Package valkeytest starts a Valkey test container (image pinned in versions.env) with a password.
package valkeytest

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	vk "github.com/valkey-io/valkey-go"

	"github.com/paddock-mdm/paddock/server/internal/platform/valkey"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
)

// Password is the password of the test server.
const Password = "test-valkey"

// Server is a running Valkey.
type Server struct {
	Config    valkey.Config
	container testcontainers.Container
}

// Start starts Valkey.
func Start(t testing.TB) *Server {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        pgtest.Image(t, "VALKEY_IMAGE"),
			Cmd:          []string{"valkey-server", "--requirepass", Password, "--appendonly", "yes"},
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("valkeytest: start: %v", err)
	}
	endpoint, err := c.PortEndpoint(ctx, "6379/tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Config: valkey.Config{Addr: endpoint, Password: Password}, container: c}
}

// Client returns a client that is closed when the test ends.
func (s *Server) Client(t testing.TB) vk.Client {
	t.Helper()
	c, err := valkey.New(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}
