package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/worker"
)

// adminCommand is a parsed paddock-server admin command line (plan M6c decision 20).
type adminCommand struct {
	name string // bump-bundle-seq | recompile | rebuild-cache
	by   int64  // bump-bundle-seq only
}

// parseAdmin parses the arguments after "admin"; every error is a usage error.
func parseAdmin(args []string) (adminCommand, error) {
	if len(args) == 0 {
		return adminCommand{}, errUsage
	}
	cmd := adminCommand{name: args[0]}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	switch cmd.name {
	case "bump-bundle-seq":
		by := fs.String("by", "", "")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *by == "" {
			return adminCommand{}, errUsage
		}
		n, err := strconv.ParseInt(*by, 10, 64)
		if err != nil || n < app.MinBundleSeqBump || n > app.MaxBundleSeqBump {
			return adminCommand{}, errUsage
		}
		cmd.by = n
	case "recompile":
		all := fs.Bool("all", false, "")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || !*all {
			return adminCommand{}, errUsage
		}
	case "rebuild-cache":
		if len(args) != 1 {
			return adminCommand{}, errUsage
		}
	default:
		return adminCommand{}, errUsage
	}
	return cmd, nil
}

// runAdmin runs a restore command with the worker's configuration (plan M6c decisions 20–22): in the Compose stack as
// docker compose … run --rm --no-deps paddock-worker admin <command>. It prints one line on stdout.
func runAdmin(ctx context.Context, l *config.Loader, args []string) error {
	cmd, err := parseAdmin(args)
	if err != nil {
		return err
	}
	dsn := l.SecretFile("PADDOCK_DB_WORKER_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	var vkCfg config.Valkey
	if cmd.name == "rebuild-cache" {
		vkCfg = config.LoadValkey(l)
	}
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-admin", MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-admin-platform", MaxConns: 2})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	correlation := "admin-" + uuid.NewString()
	admin := app.NewAdmin(app.NewActionRunner(pool, platformPool, func(context.Context) string { return correlation }), pool)

	switch cmd.name {
	case "bump-bundle-seq":
		n, err := admin.BumpBundleSeq(ctx, cmd.by)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "bumped bundle_seq of %d devices by %d\n", n, cmd.by)
	case "recompile":
		n, err := admin.RecompileAll(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "recompile requested for %d organizations\n", n)
	case "rebuild-cache":
		vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
		if err != nil {
			return err
		}
		defer vk.Close()
		sync := worker.NewCacheSync(pool, devicecache.New(vk))
		n, err := admin.RebuildCache(ctx, sync.ReconcileAll)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "cache rebuilt for %d organizations\n", n)
	}
	return nil
}
