package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/platform/op"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// OrgTransactionTimeout is the transaction_timeout of every connection of an organization pool (plan M17 amendment r
// point 2). An organization deletion waits for every open organization-role transaction, so this bounds that wait. The
// processes pass it as Options.TransactionTimeout; the exceptions (platform, owner, backup, audit and relay pools)
// pass nothing.
const OrgTransactionTimeout = 45 * time.Second

// ErrTransactionTimeout is the error of a transaction that PostgreSQL ended because it exceeded transaction_timeout
// (SQLSTATE 25P04, or the loss of the connection that follows). The transaction was rolled back completely. It is
// problem.TransactionTimeout: the api answers 503 with Retry-After, the ActionRunner records the attempt as failure,
// and a worker consumer requeues the message (plan M17 amendment r point 5).
var ErrTransactionTimeout error = problem.TransactionTimeout

// sqlstateTransactionTimeout is the SQLSTATE of a session ended by transaction_timeout (PostgreSQL 17 and later).
const sqlstateTransactionTimeout = "25P04"

// runtimeTransactionTimeout is the connection runtime parameter Options.TransactionTimeout sets.
const runtimeTransactionTimeout = "transaction_timeout"

// metricTransactionTimeouts is paddock_db_transaction_timeout_total{role, op} (plan M17 amendment r point 5). The
// process exports op only: role is the label of its scrape target (deploy/compose/prometheus/scrape), which a label
// of the same name here would push aside as exported_role.
var metricTransactionTimeouts = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_db_transaction_timeout_total",
	Help: "Database transactions that PostgreSQL ended because they exceeded transaction_timeout, by operation.",
}, []string{"op"})

// transactionTimeoutParam formats d for the runtime parameter: whole milliseconds, PostgreSQL's unit for it.
func transactionTimeoutParam(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10)
}

// timedOut maps err of a transaction begun at start on conn to ErrTransactionTimeout when PostgreSQL ended the
// transaction for exceeding transaction_timeout, counts and logs it; any other error is returned unchanged. A session
// that was idle in the transaction when the timeout struck is gone without an error of its own, so a closed
// connection counts as well once the transaction is older than the connection's timeout and ctx is still live.
func timedOut(ctx context.Context, conn *pgx.Conn, start time.Time, err error) error {
	if err == nil || errors.Is(err, ErrTransactionTimeout) {
		return err
	}
	var pgErr *pgconn.PgError
	hit := errors.As(err, &pgErr) && pgErr.Code == sqlstateTransactionTimeout
	app := ""
	if conn != nil {
		params := conn.Config().RuntimeParams
		app = params["application_name"]
		if !hit && ctx.Err() == nil && conn.IsClosed() {
			ms, perr := strconv.ParseInt(params[runtimeTransactionTimeout], 10, 64)
			hit = perr == nil && ms > 0 && time.Since(start) >= time.Duration(ms)*time.Millisecond
		}
	}
	if !hit {
		return err
	}
	name := op.From(ctx)
	metricTransactionTimeouts.WithLabelValues(name).Inc()
	slog.ErrorContext(ctx, "database transaction exceeded transaction_timeout and was rolled back", "pool", app,
		"op", name, "duration", time.Since(start).Round(time.Millisecond), "error", err)
	return fmt.Errorf("%w: %w", ErrTransactionTimeout, err)
}
