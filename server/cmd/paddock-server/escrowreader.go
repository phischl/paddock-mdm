package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/escrowreader"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
)

// serveEscrowReader runs the escrow-reader role (plan M4b.1 decision 5): the only holder of the AppRole
// paddock-escrow-reader, reachable by the api alone, decrypting escrows after it verified the step-up proof itself.
func serveEscrowReader(ctx context.Context, l *config.Loader, common config.Common) error {
	httpAddr := l.Required("PADDOCK_HTTP_ADDR")
	secret := l.SecretFile("PADDOCK_ESCROW_READER_TOKEN_FILE")
	dsn := l.SecretFile("PADDOCK_DB_URL_FILE")
	// The AppRole paddock-escrow-reader, which may decrypt with escrow-wrap and nothing else.
	baoCfg := config.LoadOpenBao(l)
	vkCfg := config.LoadValkey(l)
	issuer := l.Required("PADDOCK_OIDC_STEPUP_ISSUER")
	clientID := l.String("PADDOCK_OIDC_STEPUP_CLIENT_ID", "paddock-portal-stepup")
	// The api's step-up window, including its development override.
	window := app.StepUpValidity
	if dev := config.LoadDevStepUp(l, common); dev.Window > 0 {
		window = dev.Window
	}
	if err := l.Err(); err != nil {
		return err
	}

	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-escrow-reader", MaxConns: 4})
	if err != nil {
		return err
	}
	defer pool.Close()
	reader, err := escrowreader.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()
	verifier := stepupproof.NewVerifier(issuer, clientID, window, time.Now)
	svc := escrowreader.NewService(secret, pool, verifier, stepupproof.NewStore(vk), reader)
	srv := &http.Server{Addr: httpAddr, Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	slog.InfoContext(ctx, "escrow-reader starting", "addr", httpAddr, "stepup_window", window)
	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				var notReady error
				if !verifier.Ready() {
					notReady = errors.New("step-up issuer not discovered")
				}
				return errors.Join(pool.Ping(ctx), valkey.Ping(ctx, vk), reader.Ping(ctx), notReady)
			})
		},
		func(ctx context.Context) error { verifier.Discover(ctx); <-ctx.Done(); return nil },
		func(ctx context.Context) error { return listenAndServe(ctx, srv) },
	)
}
