package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/bundlesign"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/escrowreader"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/web"
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
	// New and revoked enrollment tokens are published to the gateway's cache at once (the worker's cache sync stays
	// the authority).
	vkCfg := config.LoadValkey(l)
	// The reveal's own AppRole paddock-escrow-reader (plan M4a decision 9).
	escrowRoleID := l.SecretFile("PADDOCK_OPENBAO_ESCROW_ROLE_ID_FILE")
	escrowSecretID := l.SecretFile("PADDOCK_OPENBAO_ESCROW_SECRET_ID_FILE")
	oidcCfg := admin.OIDCConfig{
		Issuer:       l.Required("PADDOCK_OIDC_ISSUER"),
		ClientID:     l.Required("PADDOCK_OIDC_CLIENT_ID"),
		ClientSecret: l.SecretFile("PADDOCK_OIDC_CLIENT_SECRET_FILE"),
		PublicURL:    publicURL,
	}
	// Step-up (plan M4a decision 6): the provider paddock-portal-stepup shares the portal's client secret.
	stepUpCfg := oidcCfg
	stepUpCfg.Issuer = l.Required("PADDOCK_OIDC_STEPUP_ISSUER")
	stepUpCfg.ClientID = l.String("PADDOCK_OIDC_STEPUP_CLIENT_ID", "paddock-portal-stepup")
	stepUpCfg.RedirectPath = "/api/auth/stepup/callback"
	authentikURL := l.Required("PADDOCK_AUTHENTIK_URL")
	authentikToken := l.SecretFile("PADDOCK_AUTHENTIK_TOKEN_FILE")
	releaseKey := l.SecretFile("PADDOCK_RELEASE_PUBLIC_KEY_FILE")
	artifacts := objectstore.New(l.Required("PADDOCK_ARTIFACTS_S3_ENDPOINT"), l.SecretFile("PADDOCK_ARTIFACTS_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ARTIFACTS_S3_SECRET_KEY_FILE"), l.String("PADDOCK_ARTIFACTS_S3_BUCKET", "paddock-agent-artifacts"))
	var runnerOpts []app.RunnerOption
	if common.Development() {
		// Development-only test hook for the reaper acceptance test (plan M0 §8, A3).
		if d := l.Duration("PADDOCK_TEST_EXTERNAL_DELAY", 0); d > 0 {
			runnerOpts = append(runnerOpts, app.WithExternalDelay(d))
		}
	}
	devStepUp := config.LoadDevStepUp(l, common)
	if devStepUp.Window > 0 {
		runnerOpts = append(runnerOpts, app.WithStepUpWindow(devStepUp.Window))
	}
	if err := l.Err(); err != nil {
		return err
	}
	var releasePub minisign.PublicKey
	if err := releasePub.UnmarshalText([]byte(releaseKey)); err != nil {
		return fmt.Errorf("PADDOCK_RELEASE_PUBLIC_KEY_FILE: %w", err)
	}
	verifyRelease := func(binary, sig []byte) bool { return minisign.Verify(releasePub, binary, sig) }

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
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()

	static, err := admin.NewStaticHandler(web.Dist())
	if err != nil {
		return err
	}
	runner := app.NewActionRunner(orgPool, platformPool, httpx.RequestID, runnerOpts...)
	escrowReader, err := escrowreader.New(baoCfg.Addr, escrowRoleID, escrowSecretID)
	if err != nil {
		return err
	}
	keys := &admin.Keyring{}
	oidc := admin.NewOIDC(oidcCfg)
	stepUp := admin.NewOIDC(stepUpCfg)
	bundleKeys := func(ctx context.Context) ([]protocol.BundleKey, error) { return bundlesign.PublicKeys(ctx, baoClient) }
	ak := authentik.New(authentikURL, authentikToken)
	handler := admin.NewHandler(admin.Deps{
		DeviceGroups:  app.NewDeviceGroups(runner, orgPool),
		Tokens:        app.NewEnrollmentTokens(runner, orgPool, bundleKeys, devicecache.New(vk), deviceURL),
		Devices:       app.NewDevices(runner, orgPool),
		Managed:       app.NewManagedConfig(runner, orgPool),
		Organizations: app.NewOrganizations(runner, platformPool, ak),
		Users:         app.NewUsers(runner, orgPool, ak),
		UserGroups:    app.NewUserGroups(runner, orgPool, ak),
		Logins:        app.NewLogins(runner, orgPool, ak),
		LoginSettings: app.NewLoginSettings(runner, orgPool),
		Privileges:    app.NewPrivileges(runner, orgPool),
		Commands:      app.NewDeviceCommands(orgPool),
		LocalAdmin:    app.NewLocalAdmin(runner, orgPool, escrowReader),
		Accounts:      app.NewAccounts(runner, orgPool, platformPool),
		Releases:      app.NewAgentReleases(runner, platformPool, artifacts, verifyRelease, common.Development()),
		AuditLog:      app.NewAuditLog(auditReader),
		Runner:        runner,
		Keys:          keys,
		OIDC:          oidc,
		StepUp:        stepUp,
		PublicURL:     publicURL,
		Static:        static,
		// Development only: LoadDevStepUp refuses the variables in production.
		StepUpMaxAuthAge: devStepUp.MaxAuthAge,
		ExposeStepUp:     common.Development(),
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
				if !oidc.Ready() || !stepUp.Ready() {
					notReady = errors.Join(notReady, errors.New("oidc providers not discovered"))
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
		func(ctx context.Context) error { stepUp.Discover(ctx); <-ctx.Done(); return nil },
		func(ctx context.Context) error { return listenAndServe(ctx, srv) },
	)
}
