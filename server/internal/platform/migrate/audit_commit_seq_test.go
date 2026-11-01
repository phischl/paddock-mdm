package migrate_test

import (
	"context"
	"io/fs"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/migrations"
)

const commitSeqVersion = 10

// TestCommitSeqBackfill: audit migration 00010 numbers an already filled index per organization from 1 in
// (recorded_at, event_id) order, independent of occurred_at, and seeds audit_org_seq with the maximum (plan M9
// decision 1).
func TestCommitSeqBackfill(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedAudit(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	name := "audit_backfill_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := super.Exec(ctx, "CREATE DATABASE "+name+" OWNER audit_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = super.Close(context.Background())
	})

	provider := auditProvider(t, withDatabase(t, env.Owner, name))
	if _, err := provider.UpTo(ctx, commitSeqVersion-1); err != nil {
		t.Fatal(err)
	}

	db, err := pgx.Connect(ctx, withDatabase(t, env.Super, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	orgA, orgB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	tie1, tie2 := sortedPair()
	rows := []struct {
		id         uuid.UUID
		org        uuid.UUID
		occurred   time.Time
		recorded   time.Time
		wantCommit int64
	}{
		{uuid.Must(uuid.NewV7()), orgA, base.Add(time.Hour), base.Add(time.Hour), 1},
		{tie2, orgA, base.Add(2 * time.Hour), base.Add(3 * time.Hour), 3},
		{tie1, orgA, base.Add(-40 * 24 * time.Hour), base.Add(3 * time.Hour), 2}, // late event of an earlier month
		{uuid.Must(uuid.NewV7()), orgA, base, base.Add(4 * time.Hour), 4},
		{uuid.Must(uuid.NewV7()), orgB, base, base.Add(2 * time.Hour), 1},
	}
	for _, r := range rows {
		if _, err := db.Exec(ctx, "SELECT audit_ensure_partition($1::date)", r.occurred); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO audit_event (event_id, organization_id, occurred_at, recorded_at, code,
			outcome, source, actor, params, correlation_id, object_key)
			VALUES ($1, $2, $3, $4, 'device_group.created', 'success', 'portal', '{}', '{}', 'test', 'k')`,
			r.id, r.org, r.occurred, r.recorded); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := provider.UpTo(ctx, commitSeqVersion); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		var got int64
		if err := db.QueryRow(ctx, "SELECT commit_seq FROM audit_event WHERE event_id = $1", r.id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != r.wantCommit {
			t.Errorf("event recorded %s: commit_seq %d, want %d", r.recorded.Format(time.TimeOnly), got, r.wantCommit)
		}
	}
	var forced bool
	if err := db.QueryRow(ctx, "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'audit_event'").Scan(&forced); err != nil {
		t.Fatal(err)
	}
	if !forced {
		t.Error("audit_event lost FORCE ROW LEVEL SECURITY after the backfill")
	}
	for org, want := range map[uuid.UUID]int64{orgA: 4, orgB: 1} {
		var last int64
		if err := db.QueryRow(ctx, "SELECT last_seq FROM audit_org_seq WHERE organization_id = $1", org).Scan(&last); err != nil {
			t.Fatal(err)
		}
		if last != want {
			t.Errorf("audit_org_seq.last_seq of %s = %d, want %d", org, last, want)
		}
	}
}

func sortedPair() (uuid.UUID, uuid.UUID) {
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if a.String() > b.String() {
		return b, a
	}
	return a, b
}

func auditProvider(t *testing.T, dsn string) *goose.Provider {
	t.Helper()
	sub, err := fs.Sub(migrations.Audit, "audit")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sub)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func withDatabase(t *testing.T, dsn, database string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + database
	return u.String()
}
