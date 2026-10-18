package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// AutoUnsealInterval is the period of the observation of the unsealer's report (plan M8u decision 13).
const AutoUnsealInterval = 30 * time.Second

// autoUnsealLockKey is the advisory lock of the observation ("padd aus").
const autoUnsealLockKey = 0x7061646420617573

var (
	metricAutoUnsealEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_auto_unseal_enabled",
		Help: "1 while the platform setting of the automatic unseal of OpenBao is enabled, else 0.",
	})
	metricAutoUnsealSharesPresent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_auto_unseal_shares_present",
		Help: "1 when a running unsealer reports three shares on the host, else 0.",
	})
	metricAutoUnsealUnsealerUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_auto_unseal_unsealer_up",
		Help: "1 when the unsealer reported within the last 60 s, else 0.",
	})
)

// AutoUnsealObserver exports the setting and the unsealer's report and records one platform.openbao_auto_unsealed
// event per observed change of the unsealer's counters (ADR 0035 option C2): the unsealer itself has no right to
// write audit events.
type AutoUnsealObserver struct {
	platform *db.PlatformPool
	runner   *app.ActionRunner
	now      func() time.Time
}

// NewAutoUnsealObserver creates the observation.
func NewAutoUnsealObserver(platform *db.PlatformPool, runner *app.ActionRunner) *AutoUnsealObserver {
	return &AutoUnsealObserver{platform: platform, runner: runner, now: time.Now}
}

// Run observes at start and then every AutoUnsealInterval until ctx ends; only the replica holding the lock acts.
func (o *AutoUnsealObserver) Run(ctx context.Context) error {
	tick := time.NewTicker(AutoUnsealInterval)
	defer tick.Stop()
	for {
		if err := o.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "automatic unseal observation failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round reads the row, exports the metrics and records the unseals and failures since the last round.
func (o *AutoUnsealObserver) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := o.platform.WithLeaderLock(sys, autoUnsealLockKey, func(ctx context.Context) error {
		var row pgstore.OpenbaoAutoUnseal
		if err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			row, err = q.GetAutoUnseal(ctx)
			return err
		}); err != nil {
			return fmt.Errorf("read automatic unseal: %w", err)
		}
		s := app.AutoUnsealSetting(row)
		metricAutoUnsealEnabled.Set(gauge(s.State == autounseal.StateEnabled))
		metricAutoUnsealSharesPresent.Set(gauge(s.Report.SharesOnHost(o.now())))
		metricAutoUnsealUnsealerUp.Set(gauge(s.Report.UnsealerRunning(o.now())))

		if row.UnsealCount > row.AuditedUnsealCount {
			if err := o.recordUnseals(ctx); err != nil {
				return err
			}
		}
		if row.FailureCount > row.AuditedFailureCount {
			if err := o.recordFailures(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// observedContext gives every recorded event its own correlation ID.
func observedContext(ctx context.Context) context.Context {
	return httpx.WithRequestID(ctx, "auto-unseal-"+uuid.Must(uuid.NewV7()).String())
}

func (o *AutoUnsealObserver) recordUnseals(ctx context.Context) error {
	return o.runner.RunTx(observedContext(ctx), app.ScopePlatform, app.SpecAutoUnsealObserved,
		func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
			row, err := q.GetAutoUnsealForUpdate(ctx)
			if err != nil {
				return fmt.Errorf("read automatic unseal: %w", err)
			}
			rec.SetParam("unseals", row.UnsealCount-row.AuditedUnsealCount)
			rec.SetParam("failures", 0)
			rec.SetParam("last_unseal_at", timeParam(row.LastUnsealAt))
			return q.MarkAutoUnsealAudited(ctx, pgstore.MarkAutoUnsealAuditedParams{
				AuditedUnsealCount: row.UnsealCount, AuditedFailureCount: row.AuditedFailureCount,
			})
		})
}

func (o *AutoUnsealObserver) recordFailures(ctx context.Context) error {
	err := o.runner.RunTxRefusal(observedContext(ctx), app.ScopePlatform, app.SpecAutoUnsealObserved, app.ErrAutoUnsealFailed,
		func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
			row, err := q.GetAutoUnsealForUpdate(ctx)
			if err != nil {
				return fmt.Errorf("read automatic unseal: %w", err)
			}
			rec.SetParam("failures", row.FailureCount-row.AuditedFailureCount)
			rec.SetParam("last_failure_at", timeParam(row.LastFailureAt))
			reason := ""
			if row.LastFailureReason != nil {
				reason = *row.LastFailureReason
			}
			rec.SetParam("last_failure_reason", reason)
			return q.MarkAutoUnsealAudited(ctx, pgstore.MarkAutoUnsealAuditedParams{
				AuditedUnsealCount: row.AuditedUnsealCount, AuditedFailureCount: row.FailureCount,
			})
		})
	if errors.Is(err, app.ErrAutoUnsealFailed) {
		return nil
	}
	return err
}

func timeParam(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func gauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
