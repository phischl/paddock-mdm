// Package pgtest starts PostgreSQL test containers with the production role scripts and migrations applied.
package pgtest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/paddock-mdm/paddock/server/internal/platform/migrate"
)

const superPassword = "test-superuser"

// Paddock holds the DSNs of every role of database paddock.
type Paddock struct {
	Super, Owner, API, Platform, Relay string
}

// Audit holds the DSNs of every role of database paddock_audit.
type Audit struct {
	Super, Owner, Writer, Reader string
}

// RepoRoot returns the repository root (directory containing go.work).
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("pgtest: go.work not found")
		}
		dir = parent
	}
}

// Image returns a pinned image reference from deploy/compose/versions.env.
func Image(t testing.TB, name string) string {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(root, "deploy", "compose", "versions.env")) //nolint:gosec // fixed path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), name+"="); ok {
			return v
		}
	}
	t.Fatalf("pgtest: %s not found in versions.env", name)
	return ""
}

// StartPaddock starts PostgreSQL with deploy/compose/postgres/init/10-roles.sh and migrates database paddock.
func StartPaddock(t testing.TB) Paddock {
	t.Helper()
	pw := map[string]string{
		"PADDOCK_OWNER_PASSWORD":    "owner-pw",
		"PADDOCK_API_PASSWORD":      "api-pw",
		"PADDOCK_PLATFORM_PASSWORD": "platform-pw",
		"PADDOCK_RELAY_PASSWORD":    "relay-pw",
	}
	host := start(t, "paddock", filepath.Join("deploy", "compose", "postgres", "init", "10-roles.sh"), pw)
	p := Paddock{
		Super:    dsn(host, "postgres", superPassword, "paddock"),
		Owner:    dsn(host, "paddock_owner", pw["PADDOCK_OWNER_PASSWORD"], "paddock"),
		API:      dsn(host, "paddock_api", pw["PADDOCK_API_PASSWORD"], "paddock"),
		Platform: dsn(host, "paddock_platform", pw["PADDOCK_PLATFORM_PASSWORD"], "paddock"),
		Relay:    dsn(host, "paddock_relay", pw["PADDOCK_RELAY_PASSWORD"], "paddock"),
	}
	if err := migrate.Paddock(context.Background(), p.Owner); err != nil {
		t.Fatalf("pgtest: migrate paddock: %v", err)
	}
	return p
}

// StartAudit starts PostgreSQL with deploy/compose/audit-postgres/init/10-roles.sh and migrates paddock_audit.
func StartAudit(t testing.TB) Audit {
	t.Helper()
	pw := map[string]string{
		"AUDIT_OWNER_PASSWORD":  "owner-pw",
		"AUDIT_WRITER_PASSWORD": "writer-pw",
		"AUDIT_READER_PASSWORD": "reader-pw",
	}
	host := start(t, "paddock_audit", filepath.Join("deploy", "compose", "audit-postgres", "init", "10-roles.sh"), pw)
	a := Audit{
		Super:  dsn(host, "postgres", superPassword, "paddock_audit"),
		Owner:  dsn(host, "audit_owner", pw["AUDIT_OWNER_PASSWORD"], "paddock_audit"),
		Writer: dsn(host, "paddock_audit_writer", pw["AUDIT_WRITER_PASSWORD"], "paddock_audit"),
		Reader: dsn(host, "paddock_audit_reader", pw["AUDIT_READER_PASSWORD"], "paddock_audit"),
	}
	if err := migrate.Audit(context.Background(), a.Owner); err != nil {
		t.Fatalf("pgtest: migrate audit: %v", err)
	}
	return a
}

func start(t testing.TB, database, initScript string, env map[string]string) string {
	t.Helper()
	ctx := context.Background()
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	c, err := postgres.Run(ctx, Image(t, "POSTGRES_IMAGE"),
		postgres.WithDatabase(database),
		postgres.WithUsername("postgres"),
		postgres.WithPassword(superPassword),
		postgres.WithInitScripts(filepath.Join(root, initScript)),
		testcontainers.WithEnv(env),
		postgres.BasicWaitStrategies(),
	)
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("pgtest: start postgres: %v", err)
	}
	h, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s:%s", h, port.Port())
}

func dsn(hostPort, user, password, database string) string {
	u := url.URL{Scheme: "postgres", User: url.UserPassword(user, password), Host: hostPort, Path: "/" + database,
		RawQuery: "sslmode=disable"}
	return u.String()
}
