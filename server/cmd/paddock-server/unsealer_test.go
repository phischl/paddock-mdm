package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestServeUnsealerConfiguration: the unsealer refuses to start without its three variables and names each.
func TestServeUnsealerConfiguration(t *testing.T) {
	err := serveUnsealer(context.Background(), config.NewLoaderFrom(map[string]string{}), config.Common{})
	var missing *config.MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want a MissingError", err)
	}
	for _, name := range []string{"PADDOCK_DB_UNSEALER_URL_FILE", "PADDOCK_OPENBAO_ADDR", "PADDOCK_OPENBAO_UNSEAL_SHARES_FILE"} {
		if !slices.Contains(missing.Names, name) {
			t.Errorf("missing %v does not name %s", missing.Names, name)
		}
	}
}

// TestServeUnsealerReadsNoOtherCredential: the unsealer's wiring names no AppRole, Valkey, AMQP or other database
// variable (plan M8u decision 9).
func TestServeUnsealerReadsNoOtherCredential(t *testing.T) {
	src, err := os.ReadFile("unsealer.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ROLE_ID", "SECRET_ID", "VALKEY", "AMQP", "LoadOpenBao(", "PADDOCK_DB_PLATFORM",
		"PADDOCK_DB_API", "PADDOCK_DB_WORKER", "PADDOCK_DB_URL"} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("unsealer.go mentions %s", forbidden)
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// startUnsealer runs serve unsealer with the given database URL against an OpenBao that does not answer and returns
// the status of /readyz once the ops server answers.
func startUnsealer(t *testing.T, dsn string) int {
	t.Helper()
	dir := t.TempDir()
	urlFile := filepath.Join(dir, "db_url")
	if err := os.WriteFile(urlFile, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := freeAddr(t)
	l := config.NewLoaderFrom(map[string]string{
		"PADDOCK_DB_UNSEALER_URL_FILE":       urlFile,
		"PADDOCK_OPENBAO_ADDR":               "http://127.0.0.1:1",
		"PADDOCK_OPENBAO_UNSEAL_SHARES_FILE": filepath.Join(dir, "absent"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveUnsealer(ctx, l, config.Common{OpsAddr: ops}) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + ops + "/readyz") //nolint:noctx // test
		if err == nil {
			_ = resp.Body.Close()
			return resp.StatusCode
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the ops server did not answer")
	return 0
}

// TestServeUnsealerReadiness: /readyz follows the database only, never OpenBao (plan M8u decision 12).
func TestServeUnsealerReadiness(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	if _, err := super.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_unsealer') THEN
			CREATE ROLE paddock_unsealer LOGIN PASSWORD 'unsealer-pw';
		END IF; END $$;
		GRANT CONNECT ON DATABASE paddock TO paddock_unsealer;`); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(env.Super)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("paddock_unsealer", "unsealer-pw")
	if got := startUnsealer(t, u.String()); got != http.StatusOK {
		t.Fatalf("/readyz with the database up and OpenBao down = %d, want 200", got)
	}
	u.Host = "127.0.0.1:1"
	if got := startUnsealer(t, u.String()); got != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with the database down = %d, want 503", got)
	}
}
