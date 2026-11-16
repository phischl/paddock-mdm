package app

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// recordedLogs collects the records of slog's default logger.
type recordedLogs struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *recordedLogs) Enabled(context.Context, slog.Level) bool { return true }
func (r *recordedLogs) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	return nil
}
func (r *recordedLogs) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recordedLogs) WithGroup(string) slog.Handler      { return r }

func (r *recordedLogs) count(level slog.Level, msg string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.records {
		if rec.Level == level && rec.Message == msg {
			n++
		}
	}
	return n
}

// TestMaterializeStopsAtADeletingOrganization (plan M17 amendment s point 6.1, PDK-1088 AC5): an organization that
// starts deleting after the round listed its 1 000 open conditions ends the round at the first refused write, with
// one error and no WARN per finding.
func TestMaterializeStopsAtADeletingOrganization(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	pool, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	org := uuid.Must(uuid.NewV7())
	exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'F', 'active')", org, "u"+org.String()[24:])
	exec(`WITH d AS (INSERT INTO device (id, organization_id, hostname, state)
			SELECT gen_random_uuid(), $1, 'ws-' || i, 'active' FROM generate_series(1, 1000) i RETURNING id)
		INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at)
		SELECT gen_random_uuid(), $1, id, 'stale_critical', now() - interval '3 hours' FROM d`, org)
	t.Cleanup(func() {
		for _, table := range []string{"finding", "device_alert", "device"} {
			_, _ = super.Exec(ctx, "DELETE FROM "+table+" WHERE organization_id = $1", org)
		}
	})

	f := NewFindings(NewActionRunner(pool, platform, httpx.RequestID), pool)
	f.beforeWrites = func() {
		exec(`UPDATE organization SET status = 'deleting', deletion_requested_at = now(),
			deletion_requested_by = 'platform admin', deletion_reason = 'contract ended', delete_after = now() WHERE id = $1`, org)
		if err := pool.RefreshOrganizationStatus(ctx); err != nil {
			t.Fatal(err)
		}
	}
	logs := &recordedLogs{}
	previous := slog.Default()
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() { slog.SetDefault(previous) })

	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
	err = f.Materialize(sys, time.Now())
	if !db.IsOrganizationUnavailable(err) {
		t.Fatalf("Materialize = %v, want the organization's refusal", err)
	}
	// errors.Join puts one error per line.
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("Materialize returned %v, want exactly one error", err)
	}
	if n := logs.count(slog.LevelWarn, "attention finding not materialized; retried next round"); n != 0 {
		t.Fatalf("%d WARN lines per finding, want 0", n)
	}
	var findings int
	if err := super.QueryRow(ctx, "SELECT count(*) FROM finding WHERE organization_id = $1", org).Scan(&findings); err != nil || findings != 0 {
		t.Fatalf("%d findings written (%v), want 0", findings, err)
	}
}
