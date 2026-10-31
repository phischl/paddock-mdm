package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/buildinfo"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
)

// auditDeps are the dependencies shared by serve audit-writer, audit seal, audit verify and audit purge.
type auditDeps struct {
	pool           *db.AuditWriterPool
	store          *objectstore.Store
	bao            *bao.Client
	writer         *auditwriter.Writer
	indexRetention int
}

func loadAuditDeps(ctx context.Context, l *config.Loader) (*auditDeps, error) {
	dsn := l.SecretFile("PADDOCK_AUDIT_DB_WRITER_URL_FILE")
	baoCfg := config.LoadOpenBao(l)
	endpoint := l.Required("PADDOCK_AUDIT_S3_ENDPOINT")
	accessKey := l.SecretFile("PADDOCK_AUDIT_S3_ACCESS_KEY_FILE")
	secretKey := l.SecretFile("PADDOCK_AUDIT_S3_SECRET_KEY_FILE")
	bucket := l.String("PADDOCK_AUDIT_S3_BUCKET", "paddock-audit")
	retention, indexRetention := auditRetention(l)
	if err := l.Err(); err != nil {
		return nil, err
	}
	pool, err := db.NewAuditWriterPool(ctx, dsn, db.Options{ApplicationName: "paddock-audit-writer", MaxConns: 8})
	if err != nil {
		return nil, err
	}
	store := objectstore.New(endpoint, accessKey, secretKey, bucket)
	baoClient, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		pool.Close()
		return nil, err
	}
	writer, err := auditwriter.NewWriter(pool, store, retention)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &auditDeps{pool: pool, store: store, bao: baoClient, writer: writer, indexRetention: indexRetention}, nil
}

// auditRetention reads the audit writer's WORM retention and audit index retention in days.
func auditRetention(l *config.Loader) (retention, index int) {
	retention = wormRetention(l)
	// The index is purged after, never ahead of, the WORM retention (ADR 0032, plan M10 decision 23).
	index = l.Int("PADDOCK_AUDIT_INDEX_RETENTION_DAYS", retention)
	if index < retention {
		l.Invalid("PADDOCK_AUDIT_INDEX_RETENTION_DAYS", fmt.Sprintf("must be at least PADDOCK_AUDIT_RETENTION_DAYS (%d days)", retention))
	}
	return retention, index
}

// wormRetention reads the audit writer's WORM retention in days, at least the bucket default.
func wormRetention(l *config.Loader) int {
	retention := l.Int("PADDOCK_AUDIT_RETENTION_DAYS", auditwriter.MinRetentionDays)
	if retention < auditwriter.MinRetentionDays {
		l.Invalid("PADDOCK_AUDIT_RETENTION_DAYS", fmt.Sprintf("must be at least the bucket default of %d days, got %d", auditwriter.MinRetentionDays, retention))
	}
	return retention
}

// workerIndexRetention reads the audit index retention in days for the worker, whose retention round keeps the rows
// that explain audit events as long as the index shows them (ADR 0032 amendments 2026-10-18 and 2026-10-31, PDK-180).
// The worker reads the audit writer's variables but has no default for the index retention: a worker that guessed a
// value other than the writer's would purge ahead of the index. Missing or empty, not an integer, below the bucket
// default or below PADDOCK_AUDIT_RETENTION_DAYS (the writer's own limits), the worker does not start.
func workerIndexRetention(l *config.Loader) int {
	retention := wormRetention(l)
	if l.Required("PADDOCK_AUDIT_INDEX_RETENTION_DAYS") == "" {
		return 0
	}
	index := l.Int("PADDOCK_AUDIT_INDEX_RETENTION_DAYS", 0)
	switch {
	case index < auditwriter.MinRetentionDays:
		l.Invalid("PADDOCK_AUDIT_INDEX_RETENTION_DAYS", fmt.Sprintf("must be at least the bucket default of %d days, got %d", auditwriter.MinRetentionDays, index))
	case index < retention:
		l.Invalid("PADDOCK_AUDIT_INDEX_RETENTION_DAYS", fmt.Sprintf("must be at least PADDOCK_AUDIT_RETENTION_DAYS (%d days), got %d", retention, index))
	}
	return index
}

// verifier checks the hash chain with the audit-chain public keys from OpenBao.
func (d *auditDeps) verifier() *auditwriter.Verifier {
	return auditwriter.NewVerifier(d.pool, d.store, d.publicKeys)
}

// publicKeys reads the audit-chain public keys from OpenBao.
func (d *auditDeps) publicKeys(ctx context.Context) (map[int][]byte, error) {
	return d.bao.PublicKeys(ctx, auditwriter.SigningKey)
}

func serveAuditWriter(ctx context.Context, l *config.Loader, common config.Common) error {
	amqpCfg := config.LoadAMQP(l)
	poll := l.Duration("PADDOCK_AUDIT_EXPORT_POLL_INTERVAL", 30*time.Second)
	if poll <= 0 {
		l.Invalid("PADDOCK_AUDIT_EXPORT_POLL_INTERVAL", "must be positive")
	}
	deps, err := loadAuditDeps(ctx, l)
	if err != nil {
		return err
	}
	defer deps.pool.Close()
	consumer := mq.NewConsumer(mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password},
		mq.QueueAudit, auditwriter.Prefetch)
	sealer := auditwriter.NewSealer(deps.pool, deps.writer, deps.bao, auditwriter.NewKeyPublisher(deps.publicKeys))
	recorder := auditwriter.NewRecorder(deps.pool, deps.writer, time.Now)
	if err := prometheus.Register(recorder.Collector()); err != nil {
		return err
	}
	nightly := auditwriter.NewNightly(deps.pool, deps.verifier(), recorder, time.Now)
	purger := auditwriter.NewPurger(deps.pool, deps.writer, deps.indexRetention)
	exporter := auditwriter.NewExporter(deps.pool, deps.writer, deps.store, deps.bao, deps.publicKeys, deps.verifier(),
		buildinfo.Version, poll)
	slog.InfoContext(ctx, "audit-writer starting", "bucket", deps.store.Bucket())

	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				var notConnected error
				if !consumer.Connected() {
					notConnected = errors.New("rabbitmq consumer not connected")
				}
				return errors.Join(deps.pool.Ping(ctx), deps.store.Ping(ctx), deps.bao.Ping(ctx), notConnected)
			})
		},
		func(ctx context.Context) error { return consumer.Run(ctx, deps.writer.Handle) },
		func(ctx context.Context) error { sealer.RunDaily(ctx); return nil },
		func(ctx context.Context) error { nightly.RunNightly(ctx); return nil },
		func(ctx context.Context) error { purger.RunDaily(ctx); return nil },
		exporter.Run,
	)
}

// runAudit implements `audit seal [--day YYYY-MM-DD]`, `audit verify --org <id> --from <day> --to <day>` and
// `audit keys` and `audit purge [--dry-run]`.
func runAudit(ctx context.Context, l *config.Loader, common config.Common, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "seal":
		fs := flag.NewFlagSet("audit seal", flag.ContinueOnError)
		dayFlag := fs.String("day", "", "seal every unsealed day up to and including this day (development only)")
		orgFlag := fs.String("org", "", "seal only this organization (development only)")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		var only uuid.UUID
		if *orgFlag != "" {
			if !common.Development() {
				return errors.New("audit seal --org is only allowed with PADDOCK_ENV=development")
			}
			var err error
			if only, err = uuid.Parse(*orgFlag); err != nil {
				return errUsage
			}
		}
		last := time.Now().UTC().AddDate(0, 0, -1)
		if *dayFlag != "" {
			if !common.Development() {
				return errors.New("audit seal --day is only allowed with PADDOCK_ENV=development")
			}
			d, err := time.Parse(time.DateOnly, *dayFlag)
			if err != nil {
				return errUsage
			}
			last = d
		}
		deps, err := loadAuditDeps(ctx, l)
		if err != nil {
			return err
		}
		defer deps.pool.Close()
		sealer := auditwriter.NewSealer(deps.pool, deps.writer, deps.bao, auditwriter.NewKeyPublisher(deps.publicKeys))
		var n int
		if only != uuid.Nil {
			n, err = sealer.SealOrganizationThrough(ctx, only, last)
		} else {
			n, err = sealer.SealThrough(ctx, last)
		}
		if err != nil {
			return err
		}
		slog.InfoContext(ctx, "sealed", "manifests", n, "through", last.Format(time.DateOnly))
		return nil
	case "verify":
		fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
		orgFlag := fs.String("org", "", "organization ID")
		fromFlag := fs.String("from", "", "first day YYYY-MM-DD")
		toFlag := fs.String("to", "", "last day YYYY-MM-DD")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		org, err1 := uuid.Parse(*orgFlag)
		from, err2 := time.Parse(time.DateOnly, *fromFlag)
		to, err3 := time.Parse(time.DateOnly, *toFlag)
		if err := errors.Join(err1, err2, err3); err != nil {
			return errUsage
		}
		deps, err := loadAuditDeps(ctx, l)
		if err != nil {
			return err
		}
		defer deps.pool.Close()
		started := time.Now()
		report, err := deps.verifier().Verify(ctx, org, from, to)
		if err != nil {
			return err
		}
		// The run is recorded (plan M8b decision 28) before the result is printed, so its ID can be shown with it.
		runID, recordErr := auditwriter.NewRecorder(deps.pool, deps.writer, time.Now).
			Record(ctx, org, auditwriter.TriggerCLI, from, to, started, report)
		if report.OK() {
			fmt.Fprintf(os.Stdout, "OK %s %s..%s: %d days, %d objects verified\n", org, *fromFlag, *toFlag, report.Days, report.Objects)
		}
		if runID != uuid.Nil {
			fmt.Fprintln(os.Stdout, "run", runID)
		}
		for _, p := range report.Problems {
			fmt.Fprintln(os.Stdout, "FAIL", p)
		}
		if !report.OK() {
			return errors.Join(fmt.Errorf("audit chain verification failed: %d problems", len(report.Problems)), recordErr)
		}
		if recordErr != nil {
			return fmt.Errorf("audit chain verified, but the run was not recorded: %w", recordErr)
		}
		return nil
	case "keys":
		if len(args) != 1 {
			return errUsage
		}
		baoCfg := config.LoadOpenBao(l)
		if err := l.Err(); err != nil {
			return err
		}
		baoClient, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
		if err != nil {
			return err
		}
		keys, err := baoClient.PublicKeys(ctx, auditwriter.SigningKey)
		if err != nil {
			return err
		}
		printAuditKeys(os.Stdout, keys)
		return nil
	case "purge":
		fs := flag.NewFlagSet("audit purge", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "only report which partitions would be dropped")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errUsage
		}
		deps, err := loadAuditDeps(ctx, l)
		if err != nil {
			return err
		}
		defer deps.pool.Close()
		report, err := auditwriter.NewPurger(deps.pool, deps.writer, deps.indexRetention).Run(ctx, *dryRun)
		if err == nil || len(report.Partitions) > 0 {
			printPurgeReport(os.Stdout, report)
		}
		return err
	default:
		return errUsage
	}
}

// printAuditKeys prints one line per audit-chain key version, the ISB's out-of-band copy of the fingerprints that the
// auditor compares with the ones in an evidence package (plan M10 decision 36).
func printAuditKeys(w io.Writer, keys map[int][]byte) {
	versions := make([]int, 0, len(keys))
	for v := range keys {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	for _, v := range versions {
		fmt.Fprintf(w, "%s v%d %s\n", auditwriter.SigningKey, v, auditevidence.Fingerprint(keys[v]))
	}
}

// printPurgeReport prints one line per partition that was due or unexpected (DROP, KEEP or FAIL), or
// "nothing to purge" when there is none (plan M10 decision 23).
func printPurgeReport(w io.Writer, report auditwriter.PurgeReport) {
	printed := false
	for _, p := range report.Partitions {
		if !p.Due && p.Reason != auditwriter.PurgeReasonUnknownName {
			continue
		}
		printed = true
		switch {
		case p.Failed:
			fmt.Fprintf(w, "FAIL %s: %s\n", p.Name, p.Reason)
		case p.Dropped:
			fmt.Fprintf(w, "DROP %s: %d events\n", p.Name, p.Events)
		default:
			fmt.Fprintf(w, "KEEP %s: %s\n", p.Name, p.Reason)
		}
	}
	if !printed {
		fmt.Fprintln(w, "nothing to purge")
	}
}
