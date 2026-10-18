package worker

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type observedEvent struct {
	Event  string
	Params map[string]any
	Actor  string
}

// TestAutoUnsealObserver covers plan M8u decision 13: one success event per grown unseal count, one failure event
// per grown failure count, none without a change, the audited counters move in the same transaction, and the
// metrics follow the row.
func TestAutoUnsealObserver(t *testing.T) {
	env := pgtest.StartPaddock(t)
	ctx := context.Background()
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	exec := func(sql string) {
		t.Helper()
		if _, err := super.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	events := func() []observedEvent {
		t.Helper()
		rows, err := super.Query(ctx, `SELECT code || ':' || outcome || ':' || coalesce(error_code, ''), params,
			actor->>'display' FROM action WHERE code = 'platform.openbao_auto_unsealed' ORDER BY started_at`)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[observedEvent])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	audited := func() (int64, int64) {
		t.Helper()
		var u, f int64
		if err := super.QueryRow(ctx, "SELECT audited_unseal_count, audited_failure_count FROM openbao_auto_unseal").Scan(&u, &f); err != nil {
			t.Fatal(err)
		}
		return u, f
	}

	o := NewAutoUnsealObserver(platform, app.NewActionRunner(orgPool, platform, httpx.RequestID))
	now := time.Now()
	o.now = func() time.Time { return now }

	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if got := events(); len(got) != 0 {
		t.Fatalf("events without a change: %v", got)
	}
	if testutil.ToFloat64(metricAutoUnsealEnabled) != 0 || testutil.ToFloat64(metricAutoUnsealUnsealerUp) != 0 ||
		testutil.ToFloat64(metricAutoUnsealSharesPresent) != 0 {
		t.Fatal("metrics of the initial row are not 0")
	}

	exec(`UPDATE openbao_auto_unseal SET state = 'enabled', disclaimer_version = '2026-10-17',
		acknowledgement = 'I understand and accept the risk', acknowledged_by = 'Root', acknowledged_at = now(),
		unsealer_seen_at = now(), unsealer_shares_present = true, unseal_count = 5, audited_unseal_count = 3,
		last_unseal_at = '2026-10-17T10:00:00Z'`)
	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	got := events()
	if len(got) != 1 || got[0].Event != "platform.openbao_auto_unsealed:success:" || got[0].Params["unseals"] != float64(2) ||
		got[0].Params["last_unseal_at"] != "2026-10-17T10:00:00Z" || got[0].Params["failures"] != float64(0) ||
		got[0].Actor != "paddock-unsealer" {
		t.Fatalf("events after two unseals: %+v", got)
	}
	if u, f := audited(); u != 5 || f != 0 {
		t.Fatalf("audited %d/%d, want 5/0", u, f)
	}
	if testutil.ToFloat64(metricAutoUnsealEnabled) != 1 || testutil.ToFloat64(metricAutoUnsealUnsealerUp) != 1 ||
		testutil.ToFloat64(metricAutoUnsealSharesPresent) != 1 {
		t.Fatal("metrics of the enabled row are not 1")
	}

	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if got := events(); len(got) != 1 {
		t.Fatalf("a round without a change recorded: %+v", got)
	}

	exec(`UPDATE openbao_auto_unseal SET failure_count = failure_count + 1, last_failure_at = '2026-10-17T11:00:00Z',
		last_failure_reason = 'invalid_share'`)
	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	got = events()
	if len(got) != 2 || got[1].Event != "platform.openbao_auto_unsealed:failure:auto_unseal_failed" ||
		got[1].Params["failures"] != float64(1) || got[1].Params["last_failure_reason"] != "invalid_share" ||
		got[1].Params["last_failure_at"] != "2026-10-17T11:00:00Z" {
		t.Fatalf("events after a failure: %+v", got)
	}
	if u, f := audited(); u != 5 || f != 1 {
		t.Fatalf("audited %d/%d, want 5/1", u, f)
	}

	now = now.Add(2 * time.Minute)
	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(metricAutoUnsealUnsealerUp) != 0 {
		t.Fatal("an unsealer silent for two minutes counts as up")
	}
	if got := events(); len(got) != 2 {
		t.Fatalf("a round without a change recorded: %+v", got)
	}
}
