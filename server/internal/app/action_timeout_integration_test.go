package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestRunTxTransactionTimeout: an action whose transaction PostgreSQL ends for exceeding transaction_timeout returns
// ErrTransactionTimeout, records its one event as failure with error code transaction_timeout in a new transaction,
// and leaves none of its changes (plan M17 amendment r point 5).
func TestRunTxTransactionTimeout(t *testing.T) {
	h := newHarness(t)
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	capped, err := db.NewOrgPool(ctx, env.API, db.Options{MaxConns: 2, TransactionTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(capped.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(capped, platform, func(context.Context) string { return "corr-" + t.Name() })

	err = runner.RunTx(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, createSpec,
		func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
			if err := createGroup("timed-out")(ctx, q, rec); err != nil {
				return err
			}
			time.Sleep(time.Second)
			_, err := q.ListAllDeviceGroups(ctx)
			return err
		})
	if !errors.Is(err, db.ErrTransactionTimeout) {
		t.Fatalf("RunTx = %v, want ErrTransactionTimeout", err)
	}
	expectOne(t, h, audit.OutcomeFailure, "transaction_timeout")
	var n int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM device_group WHERE name = 'timed-out' AND organization_id = $1",
		h.org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the timed-out action's change was committed (%d rows, %v)", n, err)
	}
}
