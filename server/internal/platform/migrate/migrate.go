// Package migrate applies the embedded forward-only migrations with goose.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/phischl/paddock-mdm/server/migrations"
)

// Paddock migrates database paddock. dsn must belong to paddock_owner.
func Paddock(ctx context.Context, dsn string) error {
	return run(ctx, dsn, migrations.Paddock, "paddock")
}

// Audit migrates database paddock_audit. dsn must belong to audit_owner.
func Audit(ctx context.Context, dsn string) error {
	return run(ctx, dsn, migrations.Audit, "audit")
}

func run(ctx context.Context, dsn string, fsys fs.FS, dir string) error {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return err
	}
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("migrate: parse dsn: %w", err)
	}
	db := stdlib.OpenDB(*connConfig)
	defer func() { _ = db.Close() }()

	if err := waitForDB(ctx, db); err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, sub)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("migrate %s: %w", dir, err)
	}
	for _, r := range results {
		slog.InfoContext(ctx, "migration applied", "database", dir, "version", r.Source.Version, "duration", r.Duration)
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "database migrated", "database", dir, "version", version)
	return nil
}

// waitForDB retries for up to 60 s; the database may still be starting.
func waitForDB(ctx context.Context, db *sql.DB) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := db.PingContext(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("migrate: database not reachable: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
