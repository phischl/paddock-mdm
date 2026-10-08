package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/osv"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// runOSV imports Ubuntu's OSV bulk zip from a file (plan M5c decision 3): the path of installations without access to
// the OSV bucket. The worker enriches the findings with it in its next osv round.
func runOSV(ctx context.Context, l *config.Loader, args []string) error {
	if len(args) != 2 || args[0] != "import" {
		return errUsage
	}
	dsn := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	if err := l.Err(); err != nil {
		return err
	}
	f, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	pool, err := db.NewPlatformPool(ctx, dsn, db.Options{ApplicationName: "paddock-osv-import", MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "osv-import"})
	st, err := app.NewOSV(nil, nil, pool).Import(sys, "", func(fn func(osv.Entry) error) (osv.Stats, error) { return osv.Read(f, fn) })
	if err != nil {
		return fmt.Errorf("import %s: %w", args[1], err)
	}
	slog.InfoContext(ctx, "Ubuntu's vulnerability data imported", "file", args[1], "records", st.Records, "entries", st.Entries,
		"skipped", st.Skipped)
	return nil
}
