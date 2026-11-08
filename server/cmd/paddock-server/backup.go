package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/backuprole"
	"github.com/phischl/paddock-mdm/server/internal/buildinfo"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// loadBackupRole reads the role's directories and timing (plan M15 decision 15). PADDOCK_BACKUP_FULL_INTERVAL_S
// shortens the full backup interval on the development stack only.
func loadBackupRole(l *config.Loader, common config.Common) backuprole.Config {
	cfg := backuprole.Config{
		RepoDir:       l.String("PADDOCK_BACKUP_REPO_DIR", "/backup-repo"),
		RuntimeDir:    l.String("PADDOCK_BACKUP_RUNTIME_DIR", "/run/paddock-backup"),
		TargetsDir:    l.String("PADDOCK_BACKUP_TARGETS_DIR", "/backup-targets"),
		FleetDumpsDir: l.String("PADDOCK_FLEET_DUMPS_DIR", "/fleet-dumps"),
		StateDir:      l.String("PADDOCK_BACKUP_STATE_DIR", "/pgbackrest-state"),
		RoundInterval: l.Duration("PADDOCK_BACKUP_ROUND_INTERVAL", time.Minute),
		ServerVersion: buildinfo.Version,
		HighWaterFile: l.String("PADDOCK_BACKUP_HIGH_WATER_FILE", ""),
	}
	if s := l.Int("PADDOCK_BACKUP_FULL_INTERVAL_S", 0); s != 0 {
		switch {
		case !common.Development():
			l.Invalid("PADDOCK_BACKUP_FULL_INTERVAL_S", "is a development setting; set PADDOCK_ENV=development or remove it")
		case s < 60:
			l.Invalid("PADDOCK_BACKUP_FULL_INTERVAL_S", "must be at least 60")
		default:
			cfg.FullInterval = time.Duration(s) * time.Second
		}
	}
	if cfg.RoundInterval < 10*time.Second {
		l.Invalid("PADDOCK_BACKUP_ROUND_INTERVAL", "must be at least 10s")
	}
	return cfg
}

// serveBackup runs the backup role (plan M15 decisions 15–19): the only holder of the AppRole paddock-backup, which
// may decrypt the backup key and the target credentials and take OpenBao's snapshot, writing through the database
// role paddock_backup.
func serveBackup(ctx context.Context, l *config.Loader, common config.Common) error {
	dsn := l.SecretFile("PADDOCK_DB_BACKUP_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	baoCfg := config.LoadOpenBao(l)
	escrow := objectstore.New(l.Required("PADDOCK_ESCROW_S3_ENDPOINT"), l.SecretFile("PADDOCK_ESCROW_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ESCROW_S3_SECRET_KEY_FILE"), l.String("PADDOCK_ESCROW_S3_BUCKET", "paddock-escrow"))
	cfg := loadBackupRole(l, common)
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewBackupPool(ctx, dsn, db.Options{ApplicationName: "paddock-backup", MaxConns: 4})
	if err != nil {
		return err
	}
	defer pool.Close()
	// The platform pool holds the round's leader lock and reads the schema version; every write goes through
	// paddock_backup.
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-backup-lock", MaxConns: 2})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	keys, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}
	runner := app.NewActionRunner(nil, platformPool, httpx.RequestID, app.WithPlatformScope(pool.InBackup))
	engine := backuprole.NewEngine(cfg, platformPool, backuprole.NewPGStore(pool, platformPool, runner), keys, keys,
		escrow, backuprole.NewTargetFactory(keys, cfg.TargetsDir), backuprole.NewMetrics(prometheus.DefaultRegisterer),
		time.Now)
	slog.InfoContext(ctx, "backup role starting", "repo", cfg.RepoDir, "round_interval", cfg.RoundInterval,
		"full_interval_override", cfg.FullInterval)
	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				return errors.Join(pool.Ping(ctx), platformPool.Ping(ctx), keys.Ping(ctx), writable(cfg.RepoDir))
			})
		},
		engine.Run,
	)
}

// writable reports whether the repository accepts a new file.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".paddock-ready-")
	if err != nil {
		return fmt.Errorf("backup repository not writable: %w", err)
	}
	_ = f.Close()
	return os.Remove(f.Name())
}

// runBackup implements `paddock-server backup now|status` (the host's emergency path, plan M15 decision 21; run in a
// one-off paddock-backup container), the restore's commands (restore.go), `backup plan|restore-report` (the restore
// plan's host side, restoreplan.go), `backup mark-mount|resolve-local` (backup-target apply, backuptargets.go) and
// `paddock-server backup decrypt <in> <out|->` (restore,
// docs/operations/restore.md; "-" writes to stdout).
func runBackup(ctx context.Context, l *config.Loader, args []string) error {
	switch {
	case len(args) >= 1 && args[0] == "now":
		return backupNow(ctx, l, args[1:], os.Stdout)
	case len(args) == 1 && args[0] == "status":
		return backupStatus(ctx, l, os.Stdout)
	case len(args) >= 1 && args[0] == "manifest":
		return backupManifest(args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "fetch-set":
		return backupFetchSet(ctx, l, args[1:], os.Stdin, os.Stdout)
	case len(args) >= 1 && args[0] == "restore-repo":
		return backupRestoreRepo(ctx, l, args[1:], os.Stdin, os.Stdout)
	case len(args) >= 1 && args[0] == "restore-escrow":
		return backupRestoreEscrow(ctx, l, args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "target-export":
		return backupTargetExport(ctx, l, args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "plan":
		return backupPlan(ctx, l, args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "restore-report":
		return backupRestoreReport(ctx, l, args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "mark-mount":
		return backupMarkMount(l, args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "resolve-local":
		return backupResolveLocal(args[1:], os.Stdout)
	case len(args) == 3 && args[0] == "decrypt":
		raw := l.SecretFile("PADDOCK_BACKUP_ENCRYPTION_KEY_FILE")
		if err := l.Err(); err != nil {
			return err
		}
		key, err := backup.ParseKey(raw)
		if err != nil {
			return err
		}
		sealed, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		plain, err := backup.Open(key, sealed)
		if err != nil {
			return err
		}
		if args[2] == "-" {
			_, err = os.Stdout.Write(plain)
			return err
		}
		return os.WriteFile(args[2], plain, 0o600) //nolint:gosec // the operator names the output file on the command line
	default:
		return errUsage
	}
}

// hostOperator is the actor of the host's backup commands.
var hostOperator = principal.Principal{Kind: principal.KindSystem, Display: "operator (host)"}

type kindFlags []string

func (k *kindFlags) String() string     { return strings.Join(*k, ",") }
func (k *kindFlags) Set(v string) error { *k = append(*k, v); return nil }

// backupNow requests a run of the given kinds (all without --kind) like the portal's "backup now"; with --wait it
// follows the runs until each is finished and fails when one failed.
func backupNow(ctx context.Context, l *config.Loader, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("backup now", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var kinds kindFlags
	fs.Var(&kinds, "kind", "")
	label := fs.String("label", "", "")
	wait := fs.Bool("wait", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	dsn := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewPlatformPool(ctx, dsn, db.Options{ApplicationName: "paddock-backup-now", MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	ctx = principal.With(ctx, hostOperator)
	correlation := uuid.NewString()
	runs, err := app.NewBackupRuns(app.NewActionRunner(nil, pool, func(context.Context) string { return correlation }), pool).
		Request(ctx, kinds, *label)
	if err != nil {
		return err
	}
	for _, r := range runs {
		_, _ = fmt.Fprintf(out, "requested %s %s\n", r.Kind, r.ID)
	}
	if !*wait {
		return nil
	}
	return waitRuns(ctx, pool, runs, out)
}

// waitRuns polls the requested runs until each finished (at most 30 minutes: a full backup of a large database).
func waitRuns(ctx context.Context, pool *db.PlatformPool, runs []app.Run, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	pending := map[uuid.UUID]string{}
	for _, r := range runs {
		pending[r.ID] = r.Kind
	}
	failed := 0
	for len(pending) > 0 {
		for id, kind := range pending {
			var row pgstore.BackupRun
			if err := pool.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
				var err error
				row, err = q.GetBackupRun(ctx, id)
				return err
			}); err != nil {
				return err
			}
			if row.State != "finished" || row.Outcome == nil {
				continue
			}
			delete(pending, id)
			class := ""
			if row.ErrorClass != nil {
				class = " (" + *row.ErrorClass + ")"
			}
			if *row.Outcome != "succeeded" {
				failed++
			}
			_, _ = fmt.Fprintf(out, "%s %s%s\n", kind, *row.Outcome, class)
		}
		if len(pending) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("backup now: %d runs still pending: %w", len(pending), ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
	if failed > 0 {
		return fmt.Errorf("backup now: %d runs failed", failed)
	}
	return nil
}

// backupStatus prints the key, the newest run of every kind and the targets with their status per kind.
func backupStatus(ctx context.Context, l *config.Loader, out io.Writer) error {
	dsn := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewPlatformPool(ctx, dsn, db.Options{ApplicationName: "paddock-backup-status", MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	var keys []pgstore.ListBackupKeyStatesRow
	var runs []pgstore.BackupRun
	var targets []pgstore.AllBackupTargetsRow
	var status []pgstore.BackupTargetStatus
	err = pool.InPlatform(principal.With(ctx, hostOperator), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if keys, err = q.ListBackupKeyStates(ctx); err != nil {
			return err
		}
		if runs, err = q.LatestBackupRuns(ctx); err != nil {
			return err
		}
		if targets, err = q.AllBackupTargets(ctx); err != nil {
			return err
		}
		ids := make([]uuid.UUID, 0, len(targets))
		for _, t := range targets {
			ids = append(ids, t.ID)
		}
		status, err = q.ListBackupTargetStatus(ctx, ids)
		return err
	})
	if err != nil {
		return err
	}
	return printBackupStatus(out, keys, runs, targets, status)
}

func printBackupStatus(out io.Writer, keys []pgstore.ListBackupKeyStatesRow, runs []pgstore.BackupRun,
	targets []pgstore.AllBackupTargetsRow, status []pgstore.BackupTargetStatus) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	active := "none: no backup runs until a platform administrator confirms a key"
	for _, k := range keys {
		if k.State == "confirmed" {
			active = k.KeyID + " (fingerprint " + k.Fingerprint + ")"
		}
	}
	_, _ = fmt.Fprintf(w, "key\t%s\n\nKIND\tSTATE\tOUTCOME\tFINISHED\tERROR\n", active)
	for _, r := range runs {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Kind, r.State, deref(r.Outcome), timeOrDash(r.FinishedAt),
			deref(r.ErrorClass))
	}
	byTarget := map[uuid.UUID][]pgstore.BackupTargetStatus{}
	for _, s := range status {
		byTarget[s.TargetID] = append(byTarget[s.TargetID], s)
	}
	_, _ = fmt.Fprint(w, "\nTARGET\tTYPE\tENABLED\tHOST STATE\tKIND\tLAST SUCCESS\tERROR\n")
	for _, t := range targets {
		rows := byTarget[t.ID]
		if len(rows) == 0 {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%t\t%s\t-\t-\t-\n", t.Name, t.Type, t.Enabled, t.HostState)
		}
		for _, s := range rows {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%t\t%s\t%s\t%s\t%s\n", t.Name, t.Type, t.Enabled, t.HostState, s.Kind,
				timeOrDash(s.LastSuccessAt), deref(s.LastError))
		}
	}
	return w.Flush()
}

func deref(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}

func timeOrDash(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
