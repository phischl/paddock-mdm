package db

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// WithStatementCache returns a view of p for the worker's heartbeat and event consumers (ADR 0055 amendment 2
// decisions 8 and 9): it shares p's connections, role, offboarding gate and jit = off, and runs the pgstore statements
// that ingestStatementCached lists as named, cached statements (pgx.QueryExecModeCacheStatement), so their plans are
// not rebuilt for every execution. Every other statement still runs in p's mode, planned per execution. Close of the
// view does nothing; only p closes the connections.
func (p *OrgPool) WithStatementCache() *OrgPool {
	return &OrgPool{pool: p.pool, gate: p.gate, beforeGate: p.beforeGate, statementCache: true}
}

// cachedTx is the pgstore.DBTX of a statement-cache view: it runs a listed statement in
// pgx.QueryExecModeCacheStatement and passes every other call through unchanged.
type cachedTx struct{ tx pgx.Tx }

func (c cachedTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return c.tx.Exec(ctx, sql, cachedArgs(sql, args)...)
}

func (c cachedTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return c.tx.Query(ctx, sql, cachedArgs(sql, args)...)
}

func (c cachedTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return c.tx.QueryRow(ctx, sql, cachedArgs(sql, args)...)
}

// cachedArgs prepends pgx.QueryExecModeCacheStatement to args if the statement sql is on the allow list; pgx reads a
// QueryExecMode in the first argument as the mode of that one call.
func cachedArgs(sql string, args []any) []any {
	if !ingestStatementCached(statementName(sql)) {
		return args
	}
	return append([]any{pgx.QueryExecModeCacheStatement}, args...)
}

// statementName returns the sqlc name of a pgstore statement, taken from the "-- name: <Name> :<kind>" line that
// starts its SQL text, or "" if sql does not start with one.
func statementName(sql string) string {
	line, _, _ := strings.Cut(sql, "\n")
	rest, ok := strings.CutPrefix(line, "-- name: ")
	if !ok {
		return ""
	}
	name, _, ok := strings.Cut(rest, " ")
	if !ok {
		return ""
	}
	return name
}

// ingestStatementCached is the closed allow list of the statement-cache view (ADR 0055 amendment 2026-11-16 (3),
// decision 11): a name may be listed only if it is (a) an INSERT … VALUES without SELECT whose ON CONFLICT, if any,
// names a unique index, or (b) compares device_id with a parameter and every table of its plan has no index led by
// organization_id without device_id in second place. Access by primary key alone admits nothing: when ANALYZE misses a
// small organization, a generic plan built there takes an index led by organization_id and reads the whole large
// organization. TestIngestViewAdmissionRule checks the rule, TestIngestViewGenericPlans the plans under that worst case;
// an unlisted statement runs per execution, which is safe and costs only planning.
func ingestStatementCached(name string) bool {
	switch name {
	case
		// Rule (b): device_event_seen and device_event_dropped by device_id, which their organization indexes contain
		// since migration 00158.
		"MaxDeviceEventSeenBefore", "DeleteDeviceEventSeenBefore", "DeleteDeviceEventDropped",
		// Rule (a): UpsertDeviceStatus and SetDeviceLoginState conflict on device_status's primary key,
		// UpsertDeviceUserSeen on (device_id, username).
		"UpsertDeviceStatus", "SetDeviceLoginState", "UpsertDeviceUserSeen", "InsertDeviceEventSeen",
		"InsertDeviceEventDropped", "InsertAction", "InsertOutbox", "InsertDeviceLoginEvent", "InsertAgentUpdateReport":
		return true
	}
	return false
}
