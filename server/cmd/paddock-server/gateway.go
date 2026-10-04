package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/config"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/platform/mq"
	"github.com/paddock-mdm/paddock/server/internal/platform/objectstore"
	"github.com/paddock-mdm/paddock/server/internal/platform/ops"
	"github.com/paddock-mdm/paddock/server/internal/platform/valkey"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/device"
)

// serveGateway runs the device API. The gateway has no database credentials (plan M2a decision 1).
func serveGateway(ctx context.Context, l *config.Loader, common config.Common) error {
	httpAddr := l.String("PADDOCK_HTTP_ADDR", ":8081")
	amqpCfg := config.LoadAMQP(l)
	vkCfg := config.LoadValkey(l)
	bundlesURL := strings.TrimRight(l.Required("PADDOCK_BUNDLES_PUBLIC_URL"), "/")
	bucket := l.String("PADDOCK_BUNDLES_S3_BUCKET", "paddock-bundles")
	artifactsBucket := l.String("PADDOCK_ARTIFACTS_S3_BUCKET", "paddock-agent-artifacts")
	accessKey := l.SecretFile("PADDOCK_BUNDLES_S3_ACCESS_KEY_FILE")
	secretKey := l.SecretFile("PADDOCK_BUNDLES_S3_SECRET_KEY_FILE")
	if err := l.Err(); err != nil {
		return err
	}
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()
	pub := mq.NewPublisher(mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password})
	defer pub.Close()
	handler := device.NewHandler(device.Deps{
		Cache:     devicecache.New(vk),
		Publisher: pub,
		Presigner: objectstore.NewPresigner(bundlesURL, accessKey, secretKey, bucket),
		// Agent artifacts are served through the same public host with the gateway's read-only credential.
		Artifacts: objectstore.NewPresigner(bundlesURL, accessKey, secretKey, artifactsBucket),
	})
	srv := &http.Server{Addr: httpAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	slog.InfoContext(ctx, "gateway starting", "addr", httpAddr, "bundles_url", bundlesURL)

	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				return errors.Join(valkey.Ping(ctx, vk), pub.Ping())
			})
		},
		func(ctx context.Context) error { return listenAndServe(ctx, srv) },
	)
}

// listenAndServe runs srv until ctx ends, then shuts it down gracefully.
func listenAndServe(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errCh:
		return err
	}
}
