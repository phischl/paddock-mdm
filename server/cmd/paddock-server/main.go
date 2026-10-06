// Command paddock-server is the single Paddock server binary. Roles are selected by subcommand.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/migrate"
)

const usage = `usage: paddock-server <command> [arguments] [+ <command> [arguments] ...]

commands:
  serve api|gateway|worker|compiler|outbox-relay|audit-writer|escrow-reader
  migrate paddock|audit
  provision rabbitmq
  audit seal [--day YYYY-MM-DD]
  audit verify --org <id> --from YYYY-MM-DD --to YYYY-MM-DD
  healthcheck

Commands separated by a lone "+" run one after another; the first failure stops the chain.
`

// errUsage marks invalid command lines (exit code 2).
var errUsage = errors.New("usage")

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for _, cmd := range splitChain(args) {
		if code := runOne(ctx, cmd); code != 0 {
			return code
		}
	}
	return 0
}

func splitChain(args []string) [][]string {
	var cmds [][]string
	cur := []string{}
	for _, a := range args {
		if a == "+" {
			cmds = append(cmds, cur)
			cur = []string{}
			continue
		}
		cur = append(cur, a)
	}
	return append(cmds, cur)
}

func runOne(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	l := config.NewLoader()
	common := config.LoadCommon(l)
	setupLogging(common.LogLevel)

	var err error
	switch args[0] {
	case "migrate":
		err = runMigrate(ctx, l, args[1:])
	case "healthcheck":
		err = runHealthcheck(ctx, common)
	case "serve":
		err = runServe(ctx, l, common, args[1:])
	case "audit":
		err = runAudit(ctx, l, common, args[1:])
	case "provision":
		if len(args) != 2 || args[1] != "rabbitmq" {
			err = errUsage
			break
		}
		err = provisionRabbitMQ(ctx, l)
	default:
		err = errUsage
	}
	return exitCode(err)
}

func runServe(ctx context.Context, l *config.Loader, common config.Common, args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	switch args[0] {
	case "outbox-relay":
		return serveOutboxRelay(ctx, l, common)
	case "audit-writer":
		return serveAuditWriter(ctx, l, common)
	case "api":
		return serveAPI(ctx, l, common)
	case "worker":
		return serveWorker(ctx, l, common)
	case "gateway":
		return serveGateway(ctx, l, common)
	case "compiler":
		return serveCompiler(ctx, l, common)
	case "escrow-reader":
		return serveEscrowReader(ctx, l, common)
	default:
		return errUsage
	}
}

func exitCode(err error) int {
	var missing *config.MissingError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprint(os.Stderr, usage)
		return 2
	case errors.As(err, &missing):
		slog.Error("configuration incomplete", "missing", missing.Names)
		return 2
	default:
		slog.Error("command failed", "error", err)
		return 1
	}
}

func setupLogging(level string) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

func runMigrate(ctx context.Context, l *config.Loader, args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	switch args[0] {
	case "paddock":
		dsn := l.SecretFile("PADDOCK_DB_OWNER_URL_FILE")
		if err := l.Err(); err != nil {
			return err
		}
		return migrate.Paddock(ctx, dsn)
	case "audit":
		dsn := l.SecretFile("PADDOCK_AUDIT_DB_OWNER_URL_FILE")
		if err := l.Err(); err != nil {
			return err
		}
		return migrate.Audit(ctx, dsn)
	default:
		return errUsage
	}
}

// runHealthcheck is the container health check: GET /readyz on the ops listener.
func runHealthcheck(ctx context.Context, common config.Common) error {
	addr := common.OpsAddr
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/readyz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz: %s", resp.Status)
	}
	return nil
}
