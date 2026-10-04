package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/server/internal/adapters/authentik"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/bundlesign"
	"github.com/paddock-mdm/paddock/server/internal/config"
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/platform/ops"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin"
	"github.com/paddock-mdm/paddock/server/web"
)

// sessionKeyPath is the KV v2 secret holding the session cookie keys (fields current and previous).
const sessionKeyPath = "secret/data/paddock/session"

func serveAPI(ctx context.Context, l *config.Loader, common config.Common) error {
	httpAddr := l.String("PADDOCK_HTTP_ADDR", ":8080")
	publicURL := strings.TrimRight(l.Required("PADDOCK_PUBLIC_ADMIN_URL"), "/")
	deviceURL := strings.TrimRight(l.Required("PADDOCK_PUBLIC_DEVICE_URL"), "/")
	orgDSN := l.SecretFile("PADDOCK_DB_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	auditDSN := l.SecretFile("PADDOCK_AUDIT_DB_READER_URL_FILE")
	baoCfg := config.LoadOpenBao(l)
	oidcCfg := admin.OIDCConfig{
		Issuer:       l.Required("PADDOCK_OIDC_ISSUER"),
		ClientID:     l.Required("PADDOCK_OIDC_CLIENT_ID"),
		ClientSecret: l.SecretFile("PADDOCK_OIDC_CLIENT_SECRET_FILE"),
		PublicURL:    publicURL,
	}
	authentikURL := l.Required("PADDOCK_AUTHENTIK_URL")
	authentikToken := l.SecretFile("PADDOCK_AUTHENTIK_TOKEN_FILE")
	var runnerOpts []app.RunnerOption
	if common.Development() {
		// Development-only test hook for the reaper acceptance test (plan M0 §8, A3).
		if d := l.Duration("PADDOCK_TEST_EXTERNAL_DELAY", 0); d > 0 {
			runnerOpts = append(runnerOpts, app.WithExternalDelay(d))
		}
	}
	if err := l.Err(); err != nil {
		return err
	}

	orgPool, err := db.NewOrgPool(ctx, orgDSN, db.Options{ApplicationName: "paddock-api"})
	if err != nil {
		return err
	}
	defer orgPool.Close()
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-api-platform", MaxConns: 4})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	auditReader, err := db.NewAuditReader(ctx, auditDSN, db.Options{ApplicationName: "paddock-api-audit"})
	if err != nil {
		return err
	}
	defer auditReader.Close()
	baoClient, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}

	static, err := admin.NewStaticHandler(web.Dist())
	if err != nil {
		return err
	}
	runner := app.NewActionRunner(orgPool, platformPool, httpx.RequestID, runnerOpts...)
	keys := &admin.Keyring{}
	oidc := admin.NewOIDC(oidcCfg)
	bundleKeys := func(ctx context.Context) ([]protocol.BundleKey, error) { return bundlesign.PublicKeys(ctx, baoClient) }
	handler := admin.NewHandler(admin.Deps{
		DeviceGroups:  app.NewDeviceGroups(runner, orgPool),
		Tokens:        app.NewEnrollmentTokens(runner, orgPool, bundleKeys, deviceURL),
		Devices:       app.NewDevices(runner, orgPool),
		Managed:       app.NewManagedConfig(runner, orgPool),
		Organizations: app.NewOrganizations(runner, platformPool, authentik.New(authentikURL, authentikToken)),
		Accounts:      app.NewAccounts(runner, orgPool, platformPool),
		AuditLog:      app.NewAuditLog(auditReader),
		Runner:        runner,
		Keys:          keys,
		OIDC:          oidc,
		PublicURL:     publicURL,
		Static:        static,
	})
	srv := &http.Server{Addr: httpAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	slog.InfoContext(ctx, "api starting", "addr", httpAddr, "public_url", publicURL)

	keySource := func(ctx context.Context) (string, string, error) {
		kv, err := baoClient.KV(ctx, sessionKeyPath)
		if err != nil {
			return "", "", err
		}
		return kv["current"], kv["previous"], nil
	}
	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				var notReady error
				if !keys.Ready() {
					notReady = errors.New("session keys not loaded")
				}
				if !oidc.Ready() {
					notReady = errors.Join(notReady, errors.New("oidc provider not discovered"))
				}
				return errors.Join(orgPool.Ping(ctx), platformPool.Ping(ctx), auditReader.Ping(ctx), notReady)
			})
		},
		func(ctx context.Context) error {
			keys.Reload(ctx, keySource, 10*time.Minute, func(err error) {
				slog.WarnContext(ctx, "loading session keys from OpenBao failed", "error", err)
			})
			return nil
		},
		func(ctx context.Context) error { oidc.Discover(ctx); <-ctx.Done(); return nil },
		func(ctx context.Context) error { return listenAndServe(ctx, srv) },
	)
}
