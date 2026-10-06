// Package db is the only place that opens database connections. Organization data is reachable only through
// OrgPool.InOrg, which sets paddock.org_id from the authenticated principal (architecture §5, plan M0 §6.3).
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

var (
	// ErrNoOrganization is returned by InOrg when ctx carries no principal with an organization.
	ErrNoOrganization = errors.New("db: no organization in context")
	// ErrForbiddenScope is returned by InPlatform for principals other than platform admins and system.
	ErrForbiddenScope = errors.New("db: principal may not use the platform scope")
)

// Options tunes a pool.
type Options struct {
	MaxConns        int32
	ApplicationName string
}

func newPool(ctx context.Context, dsn string, o Options) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse dsn: %w", err)
	}
	if o.MaxConns > 0 {
		cfg.MaxConns = o.MaxConns
	}
	if o.ApplicationName != "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = o.ApplicationName
	}
	cfg.MaxConnIdleTime = 5 * time.Minute
	return pgxpool.NewWithConfig(ctx, cfg)
}

// pool is the common part of all pools.
type pool struct{ p *pgxpool.Pool }

// Ping checks connectivity (readiness).
func (p pool) Ping(ctx context.Context) error { return p.p.Ping(ctx) }

// Close closes all connections.
func (p pool) Close() { p.p.Close() }

// inTx runs setup and fn in one transaction. fn's error is returned unchanged; the transaction is rolled back.
func inTx(ctx context.Context, p *pgxpool.Pool, setup func(pgx.Tx) error, fn func(pgx.Tx) error) error {
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if setup != nil {
		if err := setup(tx); err != nil {
			return err
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func setOrg(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	_, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String())
	return err
}

func orgFromContext(ctx context.Context) (uuid.UUID, error) {
	p, ok := principal.From(ctx)
	if !ok || p.OrganizationID == uuid.Nil {
		return uuid.Nil, ErrNoOrganization
	}
	return p.OrganizationID, nil
}

// OrgPool is the pool of role paddock_api (organization data, RLS enforced).
type OrgPool struct{ pool }

// NewOrgPool opens the paddock_api pool.
func NewOrgPool(ctx context.Context, dsn string, o Options) (*OrgPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &OrgPool{pool{p}}, nil
}

// InOrg opens a transaction, executes SELECT set_config('paddock.org_id', <principal.OrganizationID>, true) and
// calls fn. It returns ErrNoOrganization if the principal is missing or has no organization. It commits if fn
// returns nil, otherwise it rolls back and returns fn's error unchanged.
func (p *OrgPool) InOrg(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	org, err := orgFromContext(ctx)
	if err != nil {
		return err
	}
	return inTx(ctx, p.p,
		func(tx pgx.Tx) error { return setOrg(ctx, tx, org) },
		func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// ResolveSlug maps an organization slug to its ID before an organization context exists (login). It runs only the
// SECURITY DEFINER function paddock_org_id_by_slug, which reveals nothing but the ID of an active organization, and
// returns uuid.Nil when there is none.
func (p *OrgPool) ResolveSlug(ctx context.Context, slug string) (uuid.UUID, error) {
	var id uuid.UUID
	err := inTx(ctx, p.p, nil, func(tx pgx.Tx) error {
		var err error
		id, err = pgstore.New(tx).OrganizationIDBySlug(ctx, slug)
		return err
	})
	return id, err
}

// OrganizationIDs lists every organization ID before an organization context exists, for the cache loops of worker
// and compiler. It runs only the SECURITY DEFINER function paddock_organization_ids; all organization data is
// then read with InOrg.
func (p *OrgPool) OrganizationIDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := inTx(ctx, p.p, nil, func(tx pgx.Tx) error {
		var err error
		ids, err = pgstore.New(tx).ListOrganizationIDs(ctx)
		return err
	})
	return ids, err
}

// Listen holds a dedicated connection with LISTEN channel and calls fn with the payload of every notification. It
// returns when ctx ends or the connection fails; notifications sent meanwhile are lost, so callers reconcile.
func (p *OrgPool) Listen(ctx context.Context, channel string, fn func(payload string)) error {
	return listen(ctx, p.p, channel, fn)
}

func listen(ctx context.Context, p *pgxpool.Pool, channel string, fn func(payload string)) error {
	conn, err := p.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			// The connection state is unknown after an interrupted wait; do not return it to the pool.
			_ = conn.Conn().Close(context.WithoutCancel(ctx))
			return err
		}
		fn(n.Payload)
	}
}

// PlatformPool is the pool of role paddock_platform (platform endpoints only).
type PlatformPool struct{ pool }

// NewPlatformPool opens the paddock_platform pool.
func NewPlatformPool(ctx context.Context, dsn string, o Options) (*PlatformPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &PlatformPool{pool{p}}, nil
}

// InPlatform requires principal.Kind == KindPlatformAdmin or KindSystem; otherwise it returns ErrForbiddenScope.
func (p *PlatformPool) InPlatform(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	pr, ok := principal.From(ctx)
	if !ok || (pr.Kind != principal.KindPlatformAdmin && pr.Kind != principal.KindSystem) {
		return ErrForbiddenScope
	}
	return inTx(ctx, p.p, nil, func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// WithLeaderLock runs fn while holding the session advisory lock key on a dedicated connection, so that only one
// replica of a role runs a periodic job at a time. It reports false (and does not call fn) when another session
// holds the lock.
func (p *PlatformPool) WithLeaderLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error) {
	conn, err := p.p.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil || !locked {
		return false, err
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", key); err != nil {
			_ = conn.Conn().Close(context.WithoutCancel(ctx)) // closing the session releases the lock
		}
	}()
	return true, fn(ctx)
}

// RelayPool is the pool of role paddock_relay (outbox relay and reaper).
type RelayPool struct{ pool }

// NewRelayPool opens the paddock_relay pool.
func NewRelayPool(ctx context.Context, dsn string, o Options) (*RelayPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &RelayPool{pool{p}}, nil
}

// InRelay runs fn in a transaction of role paddock_relay.
func (p *RelayPool) InRelay(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	return inTx(ctx, p.p, nil, func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// Listen holds a dedicated connection with LISTEN channel and sends to notify on every notification (non-blocking).
// It returns when ctx ends or the connection fails.
func (p *RelayPool) Listen(ctx context.Context, channel string, notify chan<- struct{}) error {
	return listen(ctx, p.p, channel, func(string) {
		select {
		case notify <- struct{}{}:
		default:
		}
	})
}

// AuditReader is the read-only pool of role paddock_audit_reader, with the same InOrg semantics as OrgPool.
type AuditReader struct{ pool }

// NewAuditReader opens the paddock_audit_reader pool.
func NewAuditReader(ctx context.Context, dsn string, o Options) (*AuditReader, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &AuditReader{pool{p}}, nil
}

// InOrg runs fn in a read-only transaction scoped to the principal's organization.
func (r *AuditReader) InOrg(ctx context.Context, fn func(ctx context.Context, q *auditstore.Queries) error) error {
	org, err := orgFromContext(ctx)
	if err != nil {
		return err
	}
	return inTx(ctx, r.p,
		func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
				return err
			}
			return setOrg(ctx, tx, org)
		},
		func(tx pgx.Tx) error { return fn(ctx, auditstore.New(tx)) })
}

// AuditWriterPool is the pool of role paddock_audit_writer (cross-organization writer).
type AuditWriterPool struct{ pool }

// NewAuditWriterPool opens the paddock_audit_writer pool.
func NewAuditWriterPool(ctx context.Context, dsn string, o Options) (*AuditWriterPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &AuditWriterPool{pool{p}}, nil
}

// WriterTransactionTimeout bounds every paddock_audit_writer transaction. Objects are dated by the transaction's
// start, and day D is sealed at D+1 00:15 UTC; the timeout guarantees that no transaction started on D commits after
// that (architecture §14.4).
const WriterTransactionTimeout = 5 * time.Minute

// InWriter runs fn in a transaction of role paddock_audit_writer limited to WriterTransactionTimeout.
func (p *AuditWriterPool) InWriter(ctx context.Context, fn func(ctx context.Context, q *auditstore.Queries) error) error {
	return p.InWriterWithTimeout(ctx, WriterTransactionTimeout, fn)
}

// InWriterWithTimeout runs fn in a transaction of role paddock_audit_writer whose first statement is
// SET LOCAL transaction_timeout. PostgreSQL terminates the session when the transaction exceeds it, which rolls the
// transaction back. Timeouts that are not positive or exceed WriterTransactionTimeout are rejected.
func (p *AuditWriterPool) InWriterWithTimeout(ctx context.Context, timeout time.Duration,
	fn func(ctx context.Context, q *auditstore.Queries) error) error {
	if timeout < time.Millisecond || timeout > WriterTransactionTimeout {
		return fmt.Errorf("db: writer transaction timeout %s outside (0, %s]", timeout, WriterTransactionTimeout)
	}
	return inTx(ctx, p.p,
		func(tx pgx.Tx) error {
			// SET takes no parameters; the value is an integer number of milliseconds.
			_, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL transaction_timeout = %d", timeout.Milliseconds()))
			return err
		},
		func(tx pgx.Tx) error { return fn(ctx, auditstore.New(tx)) })
}

// WithSession runs fn on one dedicated connection outside a transaction (session-level advisory locks).
func (p *AuditWriterPool) WithSession(ctx context.Context, fn func(ctx context.Context, q *auditstore.Queries) error) error {
	conn, err := p.p.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return fn(ctx, auditstore.New(conn))
}

// IsNoRows reports whether err means "no row" (missing or hidden by RLS).
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// IsUniqueViolation reports whether err is a unique violation, optionally of the named constraint.
func IsUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}

// IsForeignKeyViolation reports whether err is a foreign key violation (a referenced row is missing or still
// referenced).
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// IsCheckViolation reports whether err is a check constraint violation.
func IsCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514"
}
