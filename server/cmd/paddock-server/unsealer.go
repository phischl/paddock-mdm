package main

import (
	"context"
	"log/slog"

	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
	"github.com/phischl/paddock-mdm/server/internal/unsealer"
)

// serveUnsealer runs the unsealer (ADR 0035, plan M8u decision 9). It reads its own database credential, the
// OpenBao address and the path of the shares file, and nothing else: no AppRole, no cache, no message broker, no
// other database.
func serveUnsealer(ctx context.Context, l *config.Loader, common config.Common) error {
	dsn := l.SecretFile("PADDOCK_DB_UNSEALER_URL_FILE")
	addr := config.LoadOpenBaoAddr(l)
	sharesPath := l.Required("PADDOCK_OPENBAO_UNSEAL_SHARES_FILE")
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewUnsealerPool(ctx, dsn, db.Options{ApplicationName: "paddock-unsealer", MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	seal, err := bao.New(addr, "", "")
	if err != nil {
		return err
	}
	u := unsealer.New(seal, unsealer.NewPGStore(pool), sharesPath)
	slog.InfoContext(ctx, "unsealer starting", "interval", unsealer.Interval)

	return runAll(ctx,
		// Readiness is the database only: a sealed or unreachable OpenBao is exactly what the unsealer waits for.
		func(ctx context.Context) error { return ops.Serve(ctx, common.OpsAddr, pool.Ping) },
		u.Run,
	)
}
