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

// ingestStatementCached is the closed allow list of the statement-cache view (ADR 0055 amendment 2, clarification of
// decisions 8 and 11): a name may be listed only if every table it touches is reached by its primary key or by a
// device key that every index led by organization_id on that table contains, or if it is a plain INSERT … VALUES
// without a subquery. TestIngestViewGenericPlans proves the plans of the listed reads and writes; an unlisted
// statement runs per execution, which is safe and costs only planning.
func ingestStatementCached(name string) bool {
	switch name {
	case
		// device by its primary key id.
		"GetDevice", "LockDevice", "ClearAgentUpdateRequest", "UpdateDeviceOSRelease", "UpdateReportedHostname",
		"SetDeviceRetiredReason", "EndFailedUninstall",
		// device_status by its primary key device_id.
		"GetDeviceStatus", "GetDeviceClockState", "LockDeviceEventSeq", "ClearClockDrift", "SetClockDrift",
		"ResetEventSeq", "UpsertDeviceStatus", "SetDeviceLoginState",
		// device_event_seen, device_event_gap, device_event_dropped by device_id, which their organization indexes
		// contain since migration 00158.
		"MaxDeviceEventSeenBefore", "DeleteDeviceEventSeenBefore", "CloseOpenDeviceEventGaps", "DeleteDeviceEventDropped",
		// action by its primary key id.
		"FinishAction",
		// Plain INSERT … VALUES without a subquery; UpsertDeviceUserSeen conflicts on (device_id, username).
		"InsertDeviceEventSeen", "InsertDeviceEventDropped", "InsertAction", "InsertOutbox", "InsertDeviceLoginEvent",
		"InsertAgentUpdateReport", "UpsertDeviceUserSeen":
		return true
	}
	return false
}
