package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/buildinfo"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/notifier"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
)

// notifierSettings are the engine settings of plan M9 §6.7.
type notifierSettings struct {
	engine       notifier.Config
	allowPrivate bool
	// smtp is the relay of plan M9 decision 27, nil without PADDOCK_SMTP_HOST (e-mail destinations are not served).
	smtp *notifier.EmailConfig
}

// loadNotifierSettings reads and checks the engine settings; PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE is refused outside
// development (plan M9 decision 20).
func loadNotifierSettings(l *config.Loader, common config.Common) notifierSettings {
	s := notifierSettings{engine: notifier.Config{
		PollInterval:   l.Duration("PADDOCK_NOTIFY_POLL_INTERVAL", notifier.DefaultPollInterval),
		StallAfter:     l.Duration("PADDOCK_NOTIFY_STALL_AFTER", notifier.DefaultStallAfter),
		Batch:          l.Int("PADDOCK_NOTIFY_BATCH", notifier.DefaultBatch),
		PublicAdminURL: strings.TrimRight(l.Required("PADDOCK_PUBLIC_ADMIN_URL"), "/"),
	}}
	if s.engine.PollInterval < notifier.MinPollInterval {
		l.Invalid("PADDOCK_NOTIFY_POLL_INTERVAL", "must be at least 5s")
	}
	if s.engine.StallAfter < notifier.MinStallAfter {
		l.Invalid("PADDOCK_NOTIFY_STALL_AFTER", "must be at least 1m")
	}
	if s.engine.Batch < 1 || s.engine.Batch > notifier.MaxBatch {
		l.Invalid("PADDOCK_NOTIFY_BATCH", "must be 1 to 100")
	}
	s.allowPrivate = l.Bool("PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE", false)
	if s.allowPrivate && !common.Development() {
		l.Invalid("PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE", "only allowed with PADDOCK_ENV=development")
	}
	s.smtp = loadSMTPSettings(l, common)
	return s
}

// loadSMTPSettings reads the relay (plan M9 decision 27, amendment B6.2). TLS is mandatory: PADDOCK_SMTP_TLS=none is
// refused outside development, and credentials are refused with it everywhere, so they never travel in plain text.
func loadSMTPSettings(l *config.Loader, common config.Common) *notifier.EmailConfig {
	mode := l.String("PADDOCK_SMTP_TLS", notifier.SMTPStartTLS)
	switch mode {
	case notifier.SMTPStartTLS, notifier.SMTPImplicit:
	case notifier.SMTPNone:
		if !common.Development() {
			l.Invalid("PADDOCK_SMTP_TLS", "none is only allowed with PADDOCK_ENV=development")
		}
	default:
		l.Invalid("PADDOCK_SMTP_TLS", "must be starttls, implicit or none")
	}
	host := l.String("PADDOCK_SMTP_HOST", "")
	if host == "" {
		return nil
	}
	defaultPort := 587
	if mode == notifier.SMTPImplicit {
		defaultPort = 465
	}
	cfg := &notifier.EmailConfig{Host: host, Port: l.Int("PADDOCK_SMTP_PORT", defaultPort), TLS: mode,
		Username: l.String("PADDOCK_SMTP_USERNAME", ""), Timeout: l.Duration("PADDOCK_SMTP_TIMEOUT", 30*time.Second)}
	if cfg.Port < 1 || cfg.Port > 65535 {
		l.Invalid("PADDOCK_SMTP_PORT", "must be 1 to 65535")
	}
	if cfg.Timeout <= 0 {
		l.Invalid("PADDOCK_SMTP_TIMEOUT", "must be positive")
	}
	if cfg.Username != "" {
		cfg.Password = l.SecretFile("PADDOCK_SMTP_PASSWORD_FILE")
		if mode == notifier.SMTPNone {
			l.Invalid("PADDOCK_SMTP_USERNAME", "credentials need TLS; not allowed with PADDOCK_SMTP_TLS=none")
		}
	}
	if from := l.Required("PADDOCK_SMTP_FROM"); from != "" {
		addr, err := mail.ParseAddress(from)
		if err != nil {
			l.Invalid("PADDOCK_SMTP_FROM", "not a valid e-mail address")
		} else {
			cfg.From = *addr
		}
	}
	if path := l.String("PADDOCK_SMTP_CA_FILE", ""); path != "" {
		cfg.RootCAs = smtpRootCAs(l, path)
	}
	return cfg
}

// smtpRootCAs adds the PEM certificates of path to the system roots, for a relay with a certificate of an internal CA.
// Verification itself is never switched off.
func smtpRootCAs(l *config.Loader, path string) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		l.Invalid("PADDOCK_SMTP_CA_FILE", "unreadable: "+err.Error())
		return nil
	}
	if !pool.AppendCertsFromPEM(pem) {
		l.Invalid("PADDOCK_SMTP_CA_FILE", "holds no PEM certificate")
		return nil
	}
	return pool
}

// serveNotifier runs the notifier role (plan M9 decisions 20–26): the only holder of the AppRole paddock-notifier,
// which may decrypt the notification secrets and nothing else, delivering through the database role paddock_notifier.
func serveNotifier(ctx context.Context, l *config.Loader, common config.Common) error {
	dsn := l.SecretFile("PADDOCK_DB_NOTIFIER_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	auditDSN := l.SecretFile("PADDOCK_AUDIT_DB_READER_URL_FILE")
	baoCfg := config.LoadOpenBao(l)
	settings := loadNotifierSettings(l, common)
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewNotifierPool(ctx, dsn, db.Options{ApplicationName: "paddock-notifier", MaxConns: 8})
	if err != nil {
		return err
	}
	defer pool.Close()
	// The platform pool only holds the round's leader lock; platform destinations are served under paddock_notifier.
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-notifier-lock", MaxConns: 2})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	reader, err := db.NewAuditReader(ctx, auditDSN, db.Options{ApplicationName: "paddock-notifier-audit", MaxConns: 2})
	if err != nil {
		return err
	}
	defer reader.Close()
	keys, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}
	runner := app.NewActionRunner(&pool.OrgPool, platformPool, httpx.RequestID, app.WithPlatformScope(pool.InPlatformScope))
	store := notifier.NewPGStore(pool, reader, runner)
	transports := map[outbound.Type]notifier.Transport{
		outbound.TypeWebhook: notifier.NewWebhook(settings.allowPrivate, buildinfo.Version),
	}
	if settings.smtp != nil {
		transports[outbound.TypeEmail] = notifier.NewEmail(*settings.smtp)
	}
	engine := notifier.NewEngine(settings.engine, platformPool, store, store, keys, transports,
		notifier.NewMetrics(prometheus.DefaultRegisterer))
	slog.InfoContext(ctx, "notifier starting", "poll_interval", settings.engine.PollInterval,
		"stall_after", settings.engine.StallAfter, "batch", settings.engine.Batch, "allow_private", settings.allowPrivate,
		"smtp", settings.smtp != nil)
	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				return errors.Join(pool.Ping(ctx), platformPool.Ping(ctx), reader.Ping(ctx), keys.Ping(ctx))
			})
		},
		engine.Run,
	)
}
