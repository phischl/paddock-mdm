// Package valkeytest starts a Valkey test container (image pinned in versions.env): Start with one password for the
// default user, StartACL with the control plane's real ACL entrypoint, template and configuration.
package valkeytest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	vk "github.com/valkey-io/valkey-go"

	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
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

// ACLUsers returns the users StartACL creates: the users of deploy/compose/valkey/users.acl.tmpl and the development
// user acceptance of users.acl.dev.tmpl (plan M12h §14.3).
func ACLUsers() []string {
	return []string{"api", "gateway", "worker", "compiler", "escrow_reader", "revocation_issuer", "healthcheck", "acceptance"}
}

// ACLServer is a running Valkey with one ACL user per role.
type ACLServer struct {
	Addr      string
	Passwords map[string]string // by user
}

// StartACL starts Valkey the way compose.yaml and compose.dev.yaml do (plan M12h §14.10.1): the repository's
// entrypoint.sh, valkey.conf, users.acl.tmpl and users.acl.dev.tmpl at their container paths, one random password file
// per user under /run/secrets and a tmpfs at /run/valkey. A rendering bug of the entrypoint fails here. The files are
// copied rather than bind-mounted (testcontainers' portable way); the container sees the same content.
func StartACL(t testing.TB) *ACLServer {
	t.Helper()
	ctx := context.Background()
	root, err := pgtest.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "deploy", "compose", "valkey")
	files := []testcontainers.ContainerFile{
		{HostFilePath: filepath.Join(conf, "entrypoint.sh"), ContainerFilePath: "/usr/local/bin/paddock-entrypoint.sh", FileMode: 0o755},
		{HostFilePath: filepath.Join(conf, "valkey.conf"), ContainerFilePath: "/etc/valkey/valkey.conf", FileMode: 0o644},
		{HostFilePath: filepath.Join(conf, "users.acl.tmpl"), ContainerFilePath: "/etc/valkey/users.acl.tmpl", FileMode: 0o644},
		{HostFilePath: filepath.Join(conf, "users.acl.dev.tmpl"), ContainerFilePath: "/etc/valkey/users.acl.dev.tmpl", FileMode: 0o644},
	}
	s := &ACLServer{Passwords: map[string]string{}}
	for _, u := range ACLUsers() {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		s.Passwords[u] = hex.EncodeToString(b)
		// A trailing newline as an editor leaves it: the entrypoint and the loader both strip it.
		files = append(files, testcontainers.ContainerFile{Reader: strings.NewReader(s.Passwords[u] + "\n"),
			ContainerFilePath: "/run/secrets/valkey_" + u + "_password", FileMode: 0o644})
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        pgtest.Image(t, "VALKEY_IMAGE"),
			Entrypoint:   []string{"/usr/local/bin/paddock-entrypoint.sh"},
			Cmd:          []string{"valkey-server", "/etc/valkey/valkey.conf"},
			Tmpfs:        map[string]string{"/run/valkey": "rw"},
			Files:        files,
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("valkeytest: start with ACL: %v", err)
	}
	if s.Addr, err = c.PortEndpoint(ctx, "6379/tcp", ""); err != nil {
		t.Fatal(err)
	}
	return s
}

// Config returns the client configuration of user.
func (s *ACLServer) Config(user string) valkey.Config {
	return valkey.Config{Addr: s.Addr, Username: user, Password: s.Passwords[user]}
}

// Client returns a client authenticated as user that is closed when the test ends.
func (s *ACLServer) Client(t testing.TB, user string) vk.Client {
	t.Helper()
	c, err := valkey.New(s.Config(user))
	if err != nil {
		t.Fatalf("valkeytest: connect as %s: %v", user, err)
	}
	t.Cleanup(c.Close)
	return c
}
