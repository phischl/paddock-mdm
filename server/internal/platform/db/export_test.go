package db

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// NewOrgPoolWithClock is NewOrgPool with the status cache's monotonic clock injected.
func NewOrgPoolWithClock(ctx context.Context, dsn string, o Options, since func() time.Duration) (*OrgPool, error) {
	return newOrgPool(ctx, dsn, o, since, slog.Default())
}

// NewOrgPoolWithLogger is NewOrgPool with the status cache's logger injected.
func NewOrgPoolWithLogger(ctx context.Context, dsn string, o Options, log *slog.Logger) (*OrgPool, error) {
	return newOrgPool(ctx, dsn, o, monotonicSince(), log)
}

// GateRefreshFailures is the value of paddock_org_gate_refresh_failures_total.
func GateRefreshFailures() float64 { return testutil.ToFloat64(metricGateRefreshFailures) }

// StopStatusPoller stops p's status cache poller, so only RefreshOrganizationStatus changes the cache.
func StopStatusPoller(p *OrgPool) { p.gate.close() }

// SetBeforeGate makes fn run at the start of every gate pass of p, before the status cache is consulted. Set it
// before p is used concurrently.
func SetBeforeGate(p *OrgPool, fn func(org uuid.UUID)) { p.beforeGate = fn }

// TransactionTimeouts is the value of paddock_db_transaction_timeout_total{op}.
func TransactionTimeouts(op string) float64 {
	return testutil.ToFloat64(metricTransactionTimeouts.WithLabelValues(op))
}

// InOrgTx is InOrg with fn on the raw transaction, so a test can run a statement pgstore has no query for.
func InOrgTx(p *OrgPool, ctx context.Context, fn func(tx pgx.Tx) error) error {
	org, err := orgFromContext(ctx)
	if err != nil {
		return err
	}
	return inTx(ctx, p.p, func(tx pgx.Tx) error { return p.enterOrg(ctx, tx, org) }, fn)
}

// QueryExecModes returns the default query execution mode of the query pool behind p, keyed "query", and of its health
// ("health") and lock ("locks") pools where it has them. p is one of the pool types of this package.
func QueryExecModes(p any) map[string]pgx.QueryExecMode {
	var base pool
	var locks *pgxpool.Pool
	switch v := p.(type) {
	case *OrgPool:
		base = v.pool
	case *NotifierPool:
		base = v.pool
	case *PlatformPool:
		base, locks = v.pool, v.locks
	case *RelayPool:
		base = v.pool
	case *UnsealerPool:
		base = v.pool
	case *BackupPool:
		base = v.pool
	case *AuditReader:
		base = v.pool
	case *AuditWriterPool:
		base = v.pool
	default:
		panic("db: QueryExecModes: unknown pool type")
	}
	modes := map[string]pgx.QueryExecMode{"query": base.p.Config().ConnConfig.DefaultQueryExecMode}
	if base.health != nil {
		modes["health"] = base.health.Config().ConnConfig.DefaultQueryExecMode
	}
	if locks != nil {
		modes["locks"] = locks.Config().ConnConfig.DefaultQueryExecMode
	}
	return modes
}
