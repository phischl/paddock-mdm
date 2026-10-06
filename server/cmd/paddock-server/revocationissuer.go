package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/revocationissuer"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
)

// serveRevocationIssuer runs the revocation-issuer role (plan M4c decision 8): the single active consumer of
// revocation.approved and the only holder of the AppRole paddock-revocation-issuer, which alone can sign with
// revocation-signing. Its database role paddock_revocation reaches the revocation tables, devices and
// administrators (read) and the escrow (delete for Destroy); its escrow bucket credential may only list and delete
// header versions.
func serveRevocationIssuer(ctx context.Context, l *config.Loader, common config.Common) error {
	dsn := l.SecretFile("PADDOCK_DB_URL_FILE")
	amqpCfg := config.LoadAMQP(l)
	baoCfg := config.LoadOpenBao(l)
	vkCfg := config.LoadValkey(l)
	issuer := l.Required("PADDOCK_OIDC_STEPUP_ISSUER")
	clientID := l.String("PADDOCK_OIDC_STEPUP_CLIENT_ID", "paddock-portal-stepup")
	escrowEndpoint := l.Required("PADDOCK_ESCROW_S3_ENDPOINT")
	escrowBucket := l.String("PADDOCK_ESCROW_S3_BUCKET", "paddock-escrow")
	escrowAccess := l.SecretFile("PADDOCK_ESCROW_S3_ACCESS_KEY_FILE")
	escrowSecret := l.SecretFile("PADDOCK_ESCROW_S3_SECRET_KEY_FILE")
	enabled := config.RevocationEnabled(l)
	// The api's step-up window, including its development override: auth_time at most this long before the approval.
	window := app.StepUpValidity
	if dev := config.LoadDevStepUp(l, common); dev.Window > 0 {
		window = dev.Window
	}
	if err := l.Err(); err != nil {
		return err
	}

	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-revocation-issuer", MaxConns: 4})
	if err != nil {
		return err
	}
	defer pool.Close()
	signer, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()
	escrow := objectstore.New(escrowEndpoint, escrowAccess, escrowSecret, escrowBucket)
	verifier := stepupproof.NewVerifier(issuer, clientID, window, time.Now)
	// The issuer records only organization events: no platform pool.
	runner := app.NewActionRunner(pool, nil, httpx.RequestID)
	iss := revocationissuer.New(pool, runner, verifier, revocationissuer.NewJTIClaims(vk), signer, devicecache.New(vk), escrow, enabled)
	consumer := mq.NewConsumer(mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password},
		mq.QueueRevocationApproved, 1)
	slog.InfoContext(ctx, "revocation-issuer starting", "revocation_enabled", enabled, "stepup_window", window)
	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				var notReady error
				if !verifier.Ready() {
					notReady = errors.New("step-up issuer not discovered")
				}
				if !consumer.Connected() {
					notReady = errors.Join(notReady, errors.New("rabbitmq consumer not connected"))
				}
				return errors.Join(pool.Ping(ctx), valkey.Ping(ctx, vk), signer.Ping(ctx), escrow.Ping(ctx), notReady)
			})
		},
		func(ctx context.Context) error { verifier.Discover(ctx); <-ctx.Done(); return nil },
		func(ctx context.Context) error { return consumer.Run(ctx, iss.Handle) },
		iss.Run,
	)
}
