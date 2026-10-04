package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/compiler"
	"github.com/paddock-mdm/paddock/server/internal/config"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/platform/mq"
	"github.com/paddock-mdm/paddock/server/internal/platform/objectstore"
	"github.com/paddock-mdm/paddock/server/internal/platform/ops"
	"github.com/paddock-mdm/paddock/server/internal/platform/valkey"
)

func serveCompiler(ctx context.Context, l *config.Loader, common config.Common) error {
	dsn := l.SecretFile("PADDOCK_DB_COMPILER_URL_FILE")
	amqpCfg := config.LoadAMQP(l)
	vkCfg := config.LoadValkey(l)
	baoCfg := config.LoadOpenBao(l)
	endpoint := l.Required("PADDOCK_BUNDLES_S3_ENDPOINT")
	bucket := l.String("PADDOCK_BUNDLES_S3_BUCKET", "paddock-bundles")
	accessKey := l.SecretFile("PADDOCK_BUNDLES_S3_ACCESS_KEY_FILE")
	secretKey := l.SecretFile("PADDOCK_BUNDLES_S3_SECRET_KEY_FILE")
	authentikURL := l.Required("PADDOCK_AUTHENTIK_URL")
	visudo := l.String("PADDOCK_VISUDO", "/usr/sbin/visudo")
	himmelblau := l.String("PADDOCK_HIMMELBLAU_VERSION", "4.0.4")
	if err := l.Err(); err != nil {
		return err
	}
	if !bundle.ValidHimmelblauVersion(himmelblau) {
		return fmt.Errorf("PADDOCK_HIMMELBLAU_VERSION %q is not a release number such as 4.0.4", himmelblau)
	}
	// Every sudo entry is checked with visudo before signing (plan M3a decision 16); without it the compiler must
	// not run.
	if _, err := os.Stat(visudo); err != nil {
		return fmt.Errorf("PADDOCK_VISUDO: %w", err)
	}
	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-compiler", MaxConns: 8})
	if err != nil {
		return err
	}
	defer pool.Close()
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()
	signer, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}
	store := objectstore.New(endpoint, accessKey, secretKey, bucket)
	comp := compiler.New(pool, signer, store, devicecache.New(vk), compiler.Config{
		AuthentikURL: authentikURL, HimmelblauVersion: himmelblau, Sudoers: compiler.Visudo{Path: visudo},
		// The compiler records only organization events (device.bundle_render_failed): no platform pool.
		Runner: app.NewActionRunner(pool, nil, httpx.RequestID),
	})

	mqCfg := mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password}
	var consumers []*mq.Consumer
	fns := []func(context.Context) error{
		func(ctx context.Context) error { comp.RunReconcile(ctx); return nil },
	}
	for _, key := range mq.StateRoutingKeys() {
		consumer := mq.NewConsumer(mqCfg, mq.StateQueue(key), compiler.Prefetch)
		consumers = append(consumers, consumer)
		handle := comp.Handle
		if key == mq.StatePriority {
			handle = comp.HandlePriority
		}
		fns = append(fns, func(ctx context.Context) error { return consumer.Run(ctx, handle) })
	}
	fns = append(fns, func(ctx context.Context) error {
		return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
			var notConnected error
			for _, c := range consumers {
				if !c.Connected() {
					notConnected = errors.New("rabbitmq consumers not connected")
				}
			}
			return errors.Join(pool.Ping(ctx), valkey.Ping(ctx, vk), signer.Ping(ctx), store.Ping(ctx), notConnected)
		})
	})
	slog.InfoContext(ctx, "compiler starting", "bucket", bucket, "partitions", len(consumers))
	return runAll(ctx, fns...)
}
