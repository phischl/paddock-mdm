package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/auditwriter"
	"github.com/paddock-mdm/paddock/server/internal/config"
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/mq"
	"github.com/paddock-mdm/paddock/server/internal/platform/objectstore"
	"github.com/paddock-mdm/paddock/server/internal/platform/ops"
)

// auditDeps are the dependencies shared by serve audit-writer, audit seal and audit verify.
type auditDeps struct {
	pool   *db.AuditWriterPool
	store  *objectstore.Store
	bao    *bao.Client
	writer *auditwriter.Writer
}

func loadAuditDeps(ctx context.Context, l *config.Loader) (*auditDeps, error) {
	dsn := l.SecretFile("PADDOCK_AUDIT_DB_WRITER_URL_FILE")
	baoCfg := config.LoadOpenBao(l)
	endpoint := l.Required("PADDOCK_AUDIT_S3_ENDPOINT")
	accessKey := l.SecretFile("PADDOCK_AUDIT_S3_ACCESS_KEY_FILE")
	secretKey := l.SecretFile("PADDOCK_AUDIT_S3_SECRET_KEY_FILE")
	bucket := l.String("PADDOCK_AUDIT_S3_BUCKET", "paddock-audit")
	retention := l.Int("PADDOCK_AUDIT_RETENTION_DAYS", auditwriter.MinRetentionDays)
	if retention < auditwriter.MinRetentionDays {
		l.Invalid("PADDOCK_AUDIT_RETENTION_DAYS", fmt.Sprintf("must be at least the bucket default of %d days", auditwriter.MinRetentionDays))
	}
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
	return &auditDeps{pool: pool, store: store, bao: baoClient, writer: writer}, nil
}

func serveAuditWriter(ctx context.Context, l *config.Loader, common config.Common) error {
	amqpCfg := config.LoadAMQP(l)
	deps, err := loadAuditDeps(ctx, l)
	if err != nil {
		return err
	}
	defer deps.pool.Close()
	consumer := mq.NewConsumer(mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password},
		mq.QueueAudit, auditwriter.Prefetch)
	sealer := auditwriter.NewSealer(deps.pool, deps.writer, deps.bao)
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
	)
}

// runAudit implements `audit seal [--day YYYY-MM-DD]` and `audit verify --org <id> --from <day> --to <day>`.
func runAudit(ctx context.Context, l *config.Loader, common config.Common, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "seal":
		fs := flag.NewFlagSet("audit seal", flag.ContinueOnError)
		dayFlag := fs.String("day", "", "seal every unsealed day up to and including this day (development only)")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
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
		n, err := auditwriter.NewSealer(deps.pool, deps.writer, deps.bao).SealThrough(ctx, last)
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
		keys := func(ctx context.Context) (map[int][]byte, error) {
			return deps.bao.PublicKeys(ctx, auditwriter.SigningKey)
		}
		report, err := auditwriter.NewVerifier(deps.pool, deps.store, keys).Verify(ctx, org, from, to)
		if err != nil {
			return err
		}
		for _, p := range report.Problems {
			fmt.Fprintln(os.Stdout, "FAIL", p)
		}
		if !report.OK() {
			return fmt.Errorf("audit chain verification failed: %d problems", len(report.Problems))
		}
		fmt.Fprintf(os.Stdout, "OK %s %s..%s: %d days, %d objects verified\n", org, *fromFlag, *toFlag, report.Days, report.Objects)
		return nil
	default:
		return errUsage
	}
}
