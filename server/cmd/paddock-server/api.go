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
	"github.com/phischl/paddock-mdm/server/internal/revocationsign"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/web"
)

// sessionKeyPath is the KV v2 secret holding the session cookie keys (fields current and previous).
const sessionKeyPath = "secret/data/paddock/session"

func serveAPI(ctx context.Context, l *config.Loader, common config.Common) error {
	httpAddr := l.String("PADDOCK_HTTP_ADDR", ":8080")
	publicURL := strings.TrimRight(l.Required("PADDOCK_PUBLIC_ADMIN_URL"), "/")
	deviceURL := strings.TrimRight(l.Required("PADDOCK_PUBLIC_DEVICE_URL"), "/")
	// The Paddock autoinstall downloads the agent packages from the public bundles host (plan M4b decision 1).
	bundlesURL := strings.TrimRight(l.Required("PADDOCK_BUNDLES_PUBLIC_URL"), "/")
	orgDSN := l.SecretFile("PADDOCK_DB_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	auditDSN := l.SecretFile("PADDOCK_AUDIT_DB_READER_URL_FILE")
	baoCfg := config.LoadOpenBao(l)
	// New and revoked enrollment tokens are published to the gateway's cache at once (the worker's cache sync stays
	// the authority).
	vkCfg := config.LoadValkey(l)
	// Escrowed secrets are decrypted by the escrow-reader role only (plan M4b.1 decision 5).
	escrowReaderURL := l.Required("PADDOCK_ESCROW_READER_URL")
	escrowReaderToken := l.SecretFile("PADDOCK_ESCROW_READER_TOKEN_FILE")
	revocationEnabled := config.RevocationEnabled(l)
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
	// The paddock-revoke package is signed with a key of its own (architecture §12.3, plan M4c decision 4).
	revokeReleaseKey := l.SecretFile("PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE")
	artifacts := objectstore.New(l.Required("PADDOCK_ARTIFACTS_S3_ENDPOINT"), l.SecretFile("PADDOCK_ARTIFACTS_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ARTIFACTS_S3_SECRET_KEY_FILE"), l.String("PADDOCK_ARTIFACTS_S3_BUCKET", "paddock-agent-artifacts"))
	// Escrowed LUKS headers, read for a recovery only (plan M4b decision 14).
	escrowObjects := objectstore.New(l.Required("PADDOCK_ESCROW_S3_ENDPOINT"), l.SecretFile("PADDOCK_ESCROW_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ESCROW_S3_SECRET_KEY_FILE"), l.String("PADDOCK_ESCROW_S3_BUCKET", "paddock-escrow"))
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
	verifyRelease := app.NewReleaseVerifier(releasePub)
	var revokeReleasePub minisign.PublicKey
	if err := revokeReleasePub.UnmarshalText([]byte(revokeReleaseKey)); err != nil {
		return fmt.Errorf("PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE: %w", err)
	}
	verifyRevokeRelease := app.NewReleaseVerifier(revokeReleasePub)

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
	stepUpTokens := stepupproof.NewStore(vk)
	escrowAccess := app.NewEscrowAccess(escrowreader.NewClient(escrowReaderURL, escrowReaderToken), stepUpTokens)
	keys := &admin.Keyring{}
	oidc := admin.NewOIDC(oidcCfg)
	stepUp := admin.NewOIDC(stepUpCfg)
	bundleKeys := func(ctx context.Context) ([]protocol.BundleKey, error) { return bundlesign.PublicKeys(ctx, baoClient) }
	revocationKeys := func(ctx context.Context) ([]protocol.BundleKey, error) {
		keys, err := revocationsign.PublicKeys(ctx, baoClient)
		out := make([]protocol.BundleKey, len(keys))
		for i, k := range keys {
			out[i] = protocol.BundleKey{KeyID: k.KeyID, PublicKey: k.PublicKey}
		}
		return out, err
	}
	ak := authentik.New(authentikURL, authentikToken)
	handler := admin.NewHandler(admin.Deps{
		DeviceGroups:  app.NewDeviceGroups(runner, orgPool),
		Tokens:        app.NewEnrollmentTokens(runner, orgPool, bundleKeys, revocationKeys, devicecache.New(vk), deviceURL),
		Devices:       app.NewDevices(runner, orgPool),
		Managed:       app.NewManagedConfig(runner, orgPool),
		Organizations: app.NewOrganizations(runner, platformPool, ak),
		Users:         app.NewUsers(runner, orgPool, ak),
		UserGroups:    app.NewUserGroups(runner, orgPool, ak),
		Logins:        app.NewLogins(runner, orgPool, ak),
		LoginSettings: app.NewLoginSettings(runner, orgPool),
		Privileges:    app.NewPrivileges(runner, orgPool),
		Commands:      app.NewDeviceCommands(orgPool),
		LocalAdmin:    app.NewLocalAdmin(runner, orgPool, escrowAccess),
		Autoinstall:   app.NewAutoinstall(runner, orgPool, bundlesURL),
		Disk:          app.NewDisk(runner, orgPool, escrowAccess, escrowObjects),
		Revocations:   app.NewRevocations(runner, orgPool, stepUpTokens, revocationEnabled),
		DMS:           app.NewDMS(runner, orgPool, devicecache.New(vk), revocationEnabled, common.Development()),
		Updates:       app.NewUpdates(runner, orgPool),
		Attention:     app.NewAttention(orgPool),
		Inventory:     app.NewInventory(orgPool),
		Accounts:      app.NewAccounts(runner, orgPool, platformPool),
		Releases:      app.NewAgentReleases(runner, platformPool, artifacts, verifyRelease, verifyRevokeRelease, common.Development()),
		AuditLog:      app.NewAuditLog(auditReader),
		Runner:        runner,
		Keys:          keys,
		OIDC:          oidc,
		StepUp:        stepUp,
		StepUpTokens:  stepUpTokens,
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
