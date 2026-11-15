// Package db is the only place that opens database connections. Organization data is reachable only through
// OrgPool.InOrg, which sets paddock.org_id from the authenticated principal (architecture §5, plan M0 §6.3).
package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

var (
	// ErrNoOrganization is returned by InOrg when ctx carries no principal with an organization.
	ErrNoOrganization = errors.New("db: no organization in context")
	// ErrForbiddenScope is returned by InPlatform for principals other than platform admins and system.
	ErrForbiddenScope = errors.New("db: principal may not use the platform scope")
	// ErrNotPendingDeletion is returned by InPendingDeletionOrg when the organization is unknown, or no deletion of it
	// is pending and it is neither deleting nor deleted (those get OrganizationUnavailable).
	ErrNotPendingDeletion = errors.New("db: no deletion of the organization is pending")
)

// Options tunes a pool.
type Options struct {
	MaxConns        int32
	ApplicationName string
	// HealthConn gives Ping a connection of its own, so readiness does not wait for a pool that busy rounds have
	// taken (PDK-1010).
	HealthConn bool
	// LockConns, for a PlatformPool only, gives the leader locks a pool of their own with this many connections, so
	// rounds that hold a lock connection for their whole duration cannot take the connections their own queries need
	// (PDK-1010). Zero keeps the locks in the query pool.
	LockConns int32
}

// newPool opens the query pool and, with o.HealthConn, the health pool of one connection.
func newPool(ctx context.Context, dsn string, o Options) (pool, error) {
	p, err := openPool(ctx, dsn, o)
	if err != nil {
		return pool{}, err
	}
	if !o.HealthConn {
		return pool{p: p}, nil
	}
	health, err := openPool(ctx, dsn, Options{MaxConns: 1, ApplicationName: suffixed(o.ApplicationName, "health")})
	if err != nil {
		p.Close()
		return pool{}, err
	}
	return pool{p: p, health: health}, nil
}

func suffixed(name, suffix string) string {
	if name == "" {
		return ""
	}
	return name + "-" + suffix
}

func openPool(ctx context.Context, dsn string, o Options) (*pgxpool.Pool, error) {
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

// pool is the common part of all pools; health is nil without Options.HealthConn.
type pool struct{ p, health *pgxpool.Pool }

// Ping checks connectivity (readiness), on the health connection if the pool has one.
func (p pool) Ping(ctx context.Context) error {
	if p.health != nil {
		return p.health.Ping(ctx)
	}
	return p.p.Ping(ctx)
}

// Close closes all connections.
func (p pool) Close() {
	p.p.Close()
	if p.health != nil {
		p.health.Close()
	}
}

// inTx runs setup and fn in one transaction. fn's error is returned unchanged; the transaction is rolled back.
func inTx(ctx context.Context, p *pgxpool.Pool, setup func(pgx.Tx) error, fn func(pgx.Tx) error) error {
	return inTxWith(ctx, p, pgx.TxOptions{}, setup, fn)
}

// inTxWith is inTx with transaction options.
func inTxWith(ctx context.Context, p *pgxpool.Pool, opts pgx.TxOptions, setup func(pgx.Tx) error, fn func(pgx.Tx) error) error {
	tx, err := p.BeginTx(ctx, opts)
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

// enterOrg sets the organization context and passes the offboarding gate (plan M17 amendment 2026-11-15 j points 2
// and 3): an organization that is deleting or deleted is refused with OrganizationUnavailable before fn runs. With a
// fresh status cache the gate is a map lookup and the transaction runs no SQL beyond set_config. A cache older than
// gateMaxAge fails closed: the status is read in the transaction, in the same batch as set_config, so the fallback
// costs no extra round trip. No row (the organization does not exist) passes: RLS still applies, and there is
// nothing to protect.
func (p *OrgPool) enterOrg(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	if p.beforeGate != nil {
		p.beforeGate(org)
	}
	status, fresh := p.gate.lookup(org)
	if fresh {
		if status != "" {
			return OrganizationUnavailable(org, status)
		}
		return setOrg(ctx, tx, org)
	}
	b := &pgx.Batch{}
	b.Queue("SELECT set_config('paddock.org_id', $1, true)", org.String())
	b.Queue("SELECT status FROM organization WHERE id = $1::uuid", org)
	br := tx.SendBatch(ctx, b)
	if _, err := br.Exec(); err != nil {
		_ = br.Close()
		return err
	}
	err := br.QueryRow().Scan(&status)
	if cerr := br.Close(); err == nil || errors.Is(err, pgx.ErrNoRows) {
		err = cerr
	}
	if err != nil {
		return err
	}
	if status == "deleting" || status == "deleted" {
		return OrganizationUnavailable(org, status)
	}
	return nil
}

// OrganizationUnavailableError is the gate's refusal of an organization that is deleting or deleted. It matches
// problem.OrganizationInactive (api and MCP 403, worker drop, audit organization.inactive_denied).
type OrganizationUnavailableError struct {
	Organization uuid.UUID
	Status       string
}

// OrganizationUnavailable returns the gate's refusal of org in status.
func OrganizationUnavailable(org uuid.UUID, status string) error {
	return &OrganizationUnavailableError{Organization: org, Status: status}
}

func (e *OrganizationUnavailableError) Error() string {
	return fmt.Sprintf("db: organization %s is %s", e.Organization, e.Status)
}

// Unwrap makes the refusal match problem.OrganizationInactive.
func (e *OrganizationUnavailableError) Unwrap() error { return problem.OrganizationInactive }

func orgFromContext(ctx context.Context) (uuid.UUID, error) {
	p, ok := principal.From(ctx)
	if !ok || p.OrganizationID == uuid.Nil {
		return uuid.Nil, ErrNoOrganization
	}
	return p.OrganizationID, nil
}

// OrgPool is the pool of role paddock_api (organization data, RLS enforced). It keeps the offboarding gate's status
// cache, polled every second on the pool itself until Close.
type OrgPool struct {
	pool
	gate *orgGate
	// beforeGate, set only by tests (export_test.go), runs at the start of every gate pass, so a test can commit a
	// status change between a caller's earlier check and the gate.
	beforeGate func(org uuid.UUID)
}

// NewOrgPool opens the paddock_api pool.
func NewOrgPool(ctx context.Context, dsn string, o Options) (*OrgPool, error) {
	return newOrgPool(ctx, dsn, o, monotonicSince(), slog.Default())
}

func newOrgPool(ctx context.Context, dsn string, o Options, since func() time.Duration, log *slog.Logger) (*OrgPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &OrgPool{pool: p, gate: newOrgGate(ctx, p.p, since, log)}, nil
}

// Close stops the status cache's poller and closes all connections.
func (p *OrgPool) Close() {
	p.gate.close()
	p.pool.Close()
}

// RefreshOrganizationStatus re-reads the offboarding gate's status cache now instead of at the next poll, for a
// caller that has just changed an organization's status and must see the gate apply it at once (tests).
func (p *OrgPool) RefreshOrganizationStatus(ctx context.Context) error {
	return p.gate.refresh(ctx)
}

// InOrg opens a transaction, executes SELECT set_config('paddock.org_id', <principal.OrganizationID>, true) and
// calls fn. It returns ErrNoOrganization if the principal is missing or has no organization, and an error matching
// problem.OrganizationInactive (IsOrganizationUnavailable) if the organization is deleting or deleted (the offboarding
// gate, plan M17 amendments 2026-11-14 d and 2026-11-15 j). It commits if fn returns nil, otherwise it rolls back and
// returns fn's error unchanged.
func (p *OrgPool) InOrg(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	org, err := orgFromContext(ctx)
	if err != nil {
		return err
	}
	return inTx(ctx, p.p,
		func(tx pgx.Tx) error { return p.enterOrg(ctx, tx, org) },
		func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// InOrgOffboarding is InOrg without the gate, for the offboarding job only (app.Offboarding; enforced by
// TestInOrgOffboardingCallers): it reaches an organization that is deleting, to delete its rows and finalize it. The
// organization comes from the principal, as for InOrg.
func (p *OrgPool) InOrgOffboarding(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	org, err := orgFromContext(ctx)
	if err != nil {
		return err
	}
	return inTx(ctx, p.p,
		func(tx pgx.Tx) error { return setOrg(ctx, tx, org) },
		func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// InOrgSnapshot is InOrg in a REPEATABLE READ transaction: every query of fn sees the snapshot taken at its first
// query, so data read by several queries is consistent with itself (the compiler's definitions and its rollout
// overlay, plan M11 decision 30). The transaction is read-only: a write fails.
func (p *OrgPool) InOrgSnapshot(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	org, err := orgFromContext(ctx)
	if err != nil {
		return err
	}
	return inTxWith(ctx, p.p, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error { return p.enterOrg(ctx, tx, org) },
		func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// InPendingDeletionOrg is InOrg for an organization named by its argument instead of the principal: the second narrow
// exception to architecture §5 rule 4 (ADR 0052 amendment b decision 8), used only by the platform administrator's
// encrypted recovery export (app.RecoveryExports). It returns ErrForbiddenScope unless the principal is a platform
// administrator, OrganizationUnavailable when platform finds the organization deleting or deleted (plan M17 amendment
// h point 2), and ErrNotPendingDeletion unless platform confirms that the organization's deletion is pending (status
// active or provisioning_failed with delete_after set); otherwise it runs fn in the organization's context
// exactly like InOrg, through enterOrg and never its bypass (plan M17 amendments g point 6, i point 3): a deleting
// committed after the platform check refuses with OrganizationUnavailable before fn runs.
func (p *OrgPool) InPendingDeletionOrg(ctx context.Context, platform *PlatformPool, org uuid.UUID,
	fn func(ctx context.Context, q *pgstore.Queries) error) error {
	pr, ok := principal.From(ctx)
	if !ok || pr.Kind != principal.KindPlatformAdmin || org == uuid.Nil {
		return ErrForbiddenScope
	}
	var o pgstore.Organization
	err := platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		o, err = q.GetOrganization(ctx, org)
		return err
	})
	switch {
	case IsNoRows(err):
		return ErrNotPendingDeletion
	case err != nil:
		return fmt.Errorf("db: check the pending deletion: %w", err)
	case o.Status == "deleting" || o.Status == "deleted":
		// Never ErrNotPendingDeletion: its caller would fall back to the ungated platform pool (amendment h point 2).
		return OrganizationUnavailable(org, o.Status)
	case (o.Status != "active" && o.Status != "provisioning_failed") || o.DeleteAfter == nil:
		return ErrNotPendingDeletion
	}
	return inTx(ctx, p.p,
		func(tx pgx.Tx) error { return p.enterOrg(ctx, tx, org) },
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

// LookupAPIToken finds the API token with the SHA-256 hash of its secret before an organization context exists
// (bearer authentication, plan M6c decision 9). It runs only the SECURITY DEFINER function paddock_api_token_lookup,
// which reveals nothing but the token's own row of an active organization; ok is false when there is none.
func (p *OrgPool) LookupAPIToken(ctx context.Context, hash []byte) (row pgstore.LookupApiTokenRow, ok bool, err error) {
	err = inTx(ctx, p.p, nil, func(tx pgx.Tx) error {
		var err error
		row, err = pgstore.New(tx).LookupApiToken(ctx, hash)
		return err
	})
	if IsNoRows(err) {
		return row, false, nil
	}
	return row, err == nil, err
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
// calls listening (if not nil) once LISTEN is established: notifications sent before that, and after Listen returns
// when ctx ends or the connection fails, are lost, so callers reconcile after listening.
func (p *OrgPool) Listen(ctx context.Context, channel string, listening func(), fn func(payload string)) error {
	return listen(ctx, p.p, channel, listening, fn)
}

func listen(ctx context.Context, p *pgxpool.Pool, channel string, listening func(), fn func(payload string)) error {
	conn, err := p.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	if listening != nil {
		listening()
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
type PlatformPool struct {
	pool
	locks *pgxpool.Pool // nil without Options.LockConns: the locks share the query pool
}

// NewPlatformPool opens the paddock_platform pool.
func NewPlatformPool(ctx context.Context, dsn string, o Options) (*PlatformPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	if o.LockConns <= 0 {
		return &PlatformPool{pool: p}, nil
	}
	locks, err := openPool(ctx, dsn, Options{MaxConns: o.LockConns, ApplicationName: suffixed(o.ApplicationName, "locks")})
	if err != nil {
		p.Close()
		return nil, err
	}
	return &PlatformPool{pool: p, locks: locks}, nil
}

// Close closes all connections, the lock connections included.
func (p *PlatformPool) Close() {
	p.pool.Close()
	if p.locks != nil {
		p.locks.Close()
	}
}

func (p *PlatformPool) lockPool() *pgxpool.Pool {
	if p.locks != nil {
		return p.locks
	}
	return p.p
}

// InPlatform requires principal.Kind == KindPlatformAdmin or KindSystem; otherwise it returns ErrForbiddenScope.
func (p *PlatformPool) InPlatform(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	pr, ok := principal.From(ctx)
	if !ok || (pr.Kind != principal.KindPlatformAdmin && pr.Kind != principal.KindSystem) {
		return ErrForbiddenScope
	}
	return inTx(ctx, p.p, nil, func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// The answers of PlatformPool.FleetHostInUse (plan M10 amendments 2026-10-30).
const (
	// FleetHostUsedByRef: another device's inventory reference names the host.
	FleetHostUsedByRef = "ref"
	// FleetHostUsedByHardware: an active, quarantined or pending device with the retired device's hardware has no
	// inventory reference yet, so the host may become its own.
	FleetHostUsedByHardware = "hardware"
	// FleetHostUnused: neither.
	FleetHostUnused = "none"
)

// FleetHostInUse reports whether a device of any organization other than retiredDevice still uses the Fleet host or
// may use it through retiredDevice's hardware (plan M10 amendments 2026-10-30): one Fleet serves every organization,
// and the retention round's organization scope cannot see another organization's re-enrolment. A read-only existence
// check that answers only FleetHostUsedByRef, FleetHostUsedByHardware or FleetHostUnused (InPlatform's principals); any
// other answer is an error.
func (p *PlatformPool) FleetHostInUse(ctx context.Context, retiredDevice uuid.UUID, host string) (string, error) {
	var use string
	err := p.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		use, err = q.FleetHostInUse(ctx, pgstore.FleetHostInUseParams{RetiredDevice: retiredDevice, Host: host})
		return err
	})
	if err != nil {
		return "", fmt.Errorf("check the Fleet host's other devices: %w", err)
	}
	switch use {
	case FleetHostUsedByRef, FleetHostUsedByHardware, FleetHostUnused:
		return use, nil
	}
	return "", fmt.Errorf("check the Fleet host's other devices: unexpected answer %q", use)
}

// WithLeaderLock runs fn while holding the session advisory lock key on a dedicated connection (from the lock pool if
// the pool has one, Options.LockConns), so that only one replica of a role runs a periodic job at a time. It reports
// false (and does not call fn) when another session holds the lock.
func (p *PlatformPool) WithLeaderLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error) {
	return p.WithLeaderLocks(ctx, []int64{key}, fn)
}

// WithLeaderLocks is WithLeaderLock for several keys, all taken on the same connection, so the job never needs a
// second pool connection while it holds the first lock. It reports false (and does not call fn) when another session
// holds any of the keys; the keys it got are released again.
func (p *PlatformPool) WithLeaderLocks(ctx context.Context, keys []int64, fn func(ctx context.Context) error) (bool, error) {
	conn, err := p.lockPool().Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var held []int64
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			if _, err := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", held[i]); err != nil {
				_ = conn.Conn().Close(context.WithoutCancel(ctx)) // closing the session releases the locks
				return
			}
		}
	}()
	for _, key := range keys {
		var locked bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil || !locked {
			return false, err
		}
		held = append(held, key)
	}
	return true, fn(ctx)
}

// ErrLeadershipLost is the cause with which Lead ends fn's context: the connection holding the lock stopped answering,
// and with its session PostgreSQL released the lock, so another process may lead from then on.
var ErrLeadershipLost = errors.New("db: leader lock lost with its connection")

// Lead holds the advisory lock key on one dedicated connection for as long as fn runs, for a role that leads for its
// whole process life rather than per round (the backup role, decisions-alpha10 §50). Every check it asks that
// connection whether it still answers; when it does not, fn's context ends with the cause ErrLeadershipLost, Lead
// waits for fn, discards the connection and returns ErrLeadershipLost. It reports false without calling fn when
// another session holds the key.
func (p *PlatformPool) Lead(ctx context.Context, key int64, check time.Duration, fn func(ctx context.Context) error) (bool, error) {
	conn, err := p.lockPool().Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil || !locked {
		return false, err
	}
	leadCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		tick := time.NewTicker(check)
		defer tick.Stop()
		for {
			select {
			case <-leadCtx.Done():
				return
			case <-tick.C:
			}
			pingCtx, done := context.WithTimeout(leadCtx, check)
			err := conn.Ping(pingCtx)
			done()
			if err != nil && leadCtx.Err() == nil {
				cancel(ErrLeadershipLost)
				return
			}
		}
	}()
	err = fn(leadCtx)
	lost := errors.Is(context.Cause(leadCtx), ErrLeadershipLost)
	cancel(nil)
	<-watching
	// A dead network path would hold an unlock or a close without a deadline for the TCP timeout.
	endCtx, end := context.WithTimeout(context.WithoutCancel(ctx), check)
	defer end()
	if lost {
		// The session may still be alive behind a broken network path; closing it is the only way to be sure the
		// lock is not held on by a connection nobody watches.
		_ = conn.Conn().Close(endCtx)
		return true, errors.Join(ErrLeadershipLost, err)
	}
	if _, uerr := conn.Exec(endCtx, "SELECT pg_advisory_unlock($1)", key); uerr != nil {
		closeCtx, done := context.WithTimeout(context.WithoutCancel(ctx), check)
		_ = conn.Conn().Close(closeCtx) // closing the session releases the lock
		done()
	}
	return true, err
}

// NotifierPool is the pool of role paddock_notifier (plan M9 decisions 21–23): InOrg for the organizations and
// InPlatformScope for the platform destinations, which the notifier serves under its own role because
// paddock_platform has no right on their delivery state (plan M9 amendment section E).
type NotifierPool struct{ OrgPool }

// NewNotifierPool opens the paddock_notifier pool.
func NewNotifierPool(ctx context.Context, dsn string, o Options) (*NotifierPool, error) {
	p, err := newOrgPool(ctx, dsn, o, monotonicSince(), slog.Default())
	if err != nil {
		return nil, err
	}
	return &NotifierPool{*p}, nil
}

// InPlatformScope runs fn in a transaction scoped to the platform pseudo-organization (audit.PlatformOrganizationID),
// independent of any principal in ctx. Its only caller is the notifier's platform round (plan M9 amendment section E);
// like AuditReader.InPlatformScope it MUST NOT be reachable from an HTTP handler (platformscope_lint_test.go).
func (p *NotifierPool) InPlatformScope(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	return inTx(ctx, p.p,
		func(tx pgx.Tx) error { return setOrg(ctx, tx, audit.PlatformOrganizationID) },
		func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// RelayPool is the pool of role paddock_relay (outbox relay and reaper).
type RelayPool struct{ pool }

// NewRelayPool opens the paddock_relay pool.
func NewRelayPool(ctx context.Context, dsn string, o Options) (*RelayPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &RelayPool{p}, nil
}

// InRelay runs fn in a transaction of role paddock_relay.
func (p *RelayPool) InRelay(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	return inTx(ctx, p.p, nil, func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// UnsealerPool is the pool of role paddock_unsealer (plan M8u decision 10): SELECT on openbao_auto_unseal and UPDATE
// of its report columns, nothing else.
type UnsealerPool struct{ pool }

// NewUnsealerPool opens the paddock_unsealer pool.
func NewUnsealerPool(ctx context.Context, dsn string, o Options) (*UnsealerPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &UnsealerPool{p}, nil
}

// InUnsealer runs fn in a transaction of role paddock_unsealer. There is no principal check: the unsealer is a
// background role with one credential, and the role's grants are the boundary.
func (p *UnsealerPool) InUnsealer(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	return inTx(ctx, p.p, nil, func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// BackupPool is the pool of role paddock_backup (plan M15 decision 15): it reads the backup key, targets and schedule,
// writes runs, target status and the targets' host and test columns, and records audit actions in the platform
// pseudo-organization only (migration 00100).
type BackupPool struct{ pool }

// NewBackupPool opens the paddock_backup pool.
func NewBackupPool(ctx context.Context, dsn string, o Options) (*BackupPool, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &BackupPool{p}, nil
}

// InBackup runs fn in a transaction of role paddock_backup scoped to the platform pseudo-organization
// (audit.PlatformOrganizationID): the role's audit policies accept no other organization, and without the setting the
// policy fails closed.
// Under a context from TakeLeaderEpoch, the transaction first checks the leader epoch and fails with ErrFenced once
// another process took a newer one.
func (p *BackupPool) InBackup(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	return inTx(ctx, p.p,
		func(tx pgx.Tx) error {
			if err := checkLeaderEpoch(ctx, tx); err != nil {
				return err
			}
			return setOrg(ctx, tx, audit.PlatformOrganizationID)
		},
		func(tx pgx.Tx) error { return fn(ctx, pgstore.New(tx)) })
}

// ErrFenced is the error of an InBackup transaction whose leader epoch is no longer the newest (plan M19 D5, RR-134):
// another process took the backup leadership after this one, so this one must write nothing further. The transaction
// also ends the leadership's context with this cause.
var ErrFenced = errors.New("db: backup leader epoch moved on; another process leads")

// leaderFence is the epoch a leadership took and the cancel that ends its context once a transaction finds the epoch
// moved on.
type leaderFence struct {
	epoch  int64
	cancel context.CancelCauseFunc
}

type leaderFenceKey struct{}

// TakeLeaderEpoch increments the backup leader epoch for holder and returns a context that carries it (plan M19 D5):
// every InBackup transaction under that context first reads the epoch under FOR SHARE and, once another process took
// a newer one, fails with ErrFenced and ends the context with that cause. The caller MUST hold the backup leader lock
// (PlatformPool.Lead) and call stop when its leadership ends.
func (p *BackupPool) TakeLeaderEpoch(ctx context.Context, holder string) (fenced context.Context, stop context.CancelFunc, err error) {
	var epoch int64
	if err := p.p.QueryRow(ctx,
		"UPDATE backup_leader SET epoch = epoch + 1, holder = $1, acquired_at = now() RETURNING epoch",
		holder).Scan(&epoch); err != nil {
		return nil, nil, fmt.Errorf("take the backup leader epoch: %w", err)
	}
	fenced, cancel := context.WithCancelCause(ctx)
	return context.WithValue(fenced, leaderFenceKey{}, leaderFence{epoch: epoch, cancel: cancel}),
		func() { cancel(nil) }, nil
}

// LeaderEpoch returns the backup leader epoch ctx carries (TakeLeaderEpoch).
func LeaderEpoch(ctx context.Context) (int64, bool) {
	f, ok := ctx.Value(leaderFenceKey{}).(leaderFence)
	return f.epoch, ok
}

// checkLeaderEpoch fails with ErrFenced when ctx carries a leader epoch that is no longer the stored one. FOR SHARE
// holds the next leader's increment until this transaction ended, so a write that passed the check commits before
// the next leader's first write.
func checkLeaderEpoch(ctx context.Context, tx pgx.Tx) error {
	f, ok := ctx.Value(leaderFenceKey{}).(leaderFence)
	if !ok {
		return nil
	}
	var epoch int64
	if err := tx.QueryRow(ctx, "SELECT epoch FROM backup_leader FOR SHARE").Scan(&epoch); err != nil {
		return fmt.Errorf("check the backup leader epoch: %w", err)
	}
	if epoch != f.epoch {
		f.cancel(ErrFenced)
		return ErrFenced
	}
	return nil
}

// SystemIdentifier returns the PostgreSQL cluster's system identifier: it is fixed at initdb and kept by a physical
// restore, so it identifies the installation a backup set belongs to.
func (p *BackupPool) SystemIdentifier(ctx context.Context) (int64, error) {
	var id int64
	err := p.p.QueryRow(ctx, "SELECT system_identifier FROM pg_control_system()").Scan(&id)
	return id, err
}

// BundleSeqHighWater returns the highest device.bundle_seq of every organization (0 without devices) through the
// SECURITY DEFINER function paddock_backup_bundle_seq_high_water: the role reads no device row itself.
func (p *BackupPool) BundleSeqHighWater(ctx context.Context) (int64, error) {
	var v int64
	err := p.p.QueryRow(ctx, "SELECT paddock_backup_bundle_seq_high_water()").Scan(&v)
	return v, err
}

// Listen holds a dedicated connection with LISTEN channel and sends to notify on every notification (non-blocking).
// It returns when ctx ends or the connection fails.
func (p *RelayPool) Listen(ctx context.Context, channel string, notify chan<- struct{}) error {
	return listen(ctx, p.p, channel, nil, func(string) {
		select {
		case notify <- struct{}{}:
		default:
		}
	})
}

// AuditReader is the pool of role paddock_audit_reader, with the same InOrg semantics as OrgPool. It reads the
// organization's audit data; its only write is InOrgWrite's insert of an evidence export request.
type AuditReader struct{ pool }

// NewAuditReader opens the paddock_audit_reader pool.
func NewAuditReader(ctx context.Context, dsn string, o Options) (*AuditReader, error) {
	p, err := newPool(ctx, dsn, o)
	if err != nil {
		return nil, err
	}
	return &AuditReader{p}, nil
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

// InPlatformScope runs fn in a read-only transaction scoped to the platform pseudo-organization
// (audit.PlatformOrganizationID), independent of any principal in ctx. Its only callers are the notifier's platform
// round and test fixtures (plan M9 decision 5); it MUST NOT be reachable from an HTTP handler, which
// platformscope_lint_test.go asserts for server/internal/transport/.
func (r *AuditReader) InPlatformScope(ctx context.Context, fn func(ctx context.Context, q *auditstore.Queries) error) error {
	return inTx(ctx, r.p,
		func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
				return err
			}
			return setOrg(ctx, tx, audit.PlatformOrganizationID)
		},
		func(tx pgx.Tx) error { return fn(ctx, auditstore.New(tx)) })
}

// InOrgWrite is InOrg in a read-write transaction. The reader role's only write is the insert of an evidence export
// request (plan M10 decision 29); its grants and RLS policies, not this transaction mode, keep it from anything else.
func (r *AuditReader) InOrgWrite(ctx context.Context, fn func(ctx context.Context, q *auditstore.Queries) error) error {
	org, err := orgFromContext(ctx)
	if err != nil {
		return err
	}
	return inTx(ctx, r.p,
		func(tx pgx.Tx) error { return setOrg(ctx, tx, org) },
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
	return &AuditWriterPool{p}, nil
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

// IsAuditDaySealed reports whether err is the audit_object trigger's refusal of an object for an already sealed day
// (SQLSTATE PA422, audit migration 00005).
func IsAuditDaySealed(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "PA422"
}

// IsLockTimeout reports whether err is a lock wait that exceeded lock_timeout (SQLSTATE 55P03).
func IsLockTimeout(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03"
}

// IsSerializationFailure reports whether err is SQLSTATE 40001, e.g. paddock_offboard_finalize finding rows of the
// organization that a straggling transaction wrote after the delete loop.
func IsSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

// IsNotInPrerequisiteState reports whether err is SQLSTATE 55000, e.g. paddock_offboard_finalize called while
// paddock_offboard_quiesce still waits.
func IsNotInPrerequisiteState(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55000"
}

// IsNoPartition reports whether err is an insert into a partitioned table without a partition for the row (SQLSTATE
// 23514 without a constraint name), e.g. an audit_event month the index purge dropped concurrently.
func IsNoPartition(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514" && pgErr.ConstraintName == ""
}

// IsOrganizationUnavailable reports whether err is the gate's refusal: the organization is deleting or deleted.
func IsOrganizationUnavailable(err error) bool {
	var u *OrganizationUnavailableError
	return errors.As(err, &u)
}

// OrganizationUnavailableStatus is the status (deleting or deleted) of the organization the gate refused in err, and ""
// when err is no such refusal.
func OrganizationUnavailableStatus(err error) string {
	var u *OrganizationUnavailableError
	if !errors.As(err, &u) {
		return ""
	}
	return u.Status
}

// IsCheckViolation reports whether err is a check constraint violation.
func IsCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514"
}
