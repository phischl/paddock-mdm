package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/op"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// timeoutPool opens an organization pool whose connections carry transaction_timeout = timeout.
func timeoutPool(t *testing.T, app string, timeout time.Duration) *db.OrgPool {
	t.Helper()
	p, err := db.NewOrgPool(context.Background(), sharedPaddock(t).API,
		db.Options{ApplicationName: app, MaxConns: 2, TransactionTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func groupExists(t *testing.T, f fixture, org, id uuid.UUID) bool {
	t.Helper()
	var found bool
	err := f.org.InOrg(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.GetDeviceGroup(ctx, id)
		found = err == nil
		if db.IsNoRows(err) {
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestTransactionTimeoutParameter: Options.TransactionTimeout reaches every connection as transaction_timeout, and a
// pool without it keeps the server's default (none), plan M17 amendment r point 2.
func TestTransactionTimeoutParameter(t *testing.T) {
	f := newFixture(t)
	capped := timeoutPool(t, "paddock-test-capped", db.OrgTransactionTimeout)
	for name, p := range map[string]*db.OrgPool{"capped": capped, "uncapped": f.org} {
		var got string
		err := db.InOrgTx(p, orgCtx(f.orgA), func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SHOW transaction_timeout").Scan(&got)
		})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"capped": "45s", "uncapped": "0"}[name]
		if got != want {
			t.Errorf("%s pool: transaction_timeout = %q, want %q", name, got, want)
		}
	}
}

// TestTransactionTimeoutEndsLongTransaction: a transaction longer than the pool's transaction_timeout ends with
// ErrTransactionTimeout (problem transaction_timeout, 503), whether a statement was running or the session sat idle in
// the transaction, nothing it wrote remains, and the metric counts it by role and op (plan M17 amendment r points 5
// and 9).
func TestTransactionTimeoutEndsLongTransaction(t *testing.T) {
	f := newFixture(t)
	const app = "paddock-test-timeout"
	p := timeoutPool(t, app, 300*time.Millisecond)
	for name, wait := range map[string]func(tx pgx.Tx) error{
		"running statement": func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), "SELECT pg_sleep(2)")
			return err
		},
		"idle in transaction": func(tx pgx.Tx) error {
			time.Sleep(time.Second)
			_, err := tx.Exec(context.Background(), "SELECT 1")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := op.With(orgCtx(f.orgA), "test."+name)
			before := db.TransactionTimeouts("test." + name)
			id := uuid.Must(uuid.NewV7())
			err := db.InOrgTx(p, ctx, func(tx pgx.Tx) error {
				if _, err := pgstore.New(tx).InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{
					ID: id, OrganizationID: f.orgA, Name: "timeout-" + id.String()}); err != nil {
					return err
				}
				return wait(tx)
			})
			if !errors.Is(err, db.ErrTransactionTimeout) {
				t.Fatalf("err = %v, want ErrTransactionTimeout", err)
			}
			if p := problem.From(err); p.Code != "transaction_timeout" || p.Status != 503 {
				t.Errorf("problem = %+v, want 503 transaction_timeout", p)
			}
			if groupExists(t, f, f.orgA, id) {
				t.Error("the timed-out transaction's insert was committed")
			}
			if got := db.TransactionTimeouts("test."+name) - before; got != 1 {
				t.Errorf("paddock_db_transaction_timeout_total{op=%q} grew by %v, want 1", "test."+name, got)
			}
		})
	}
	// The pool replaced the ended sessions: the next transaction works.
	if id := insertGroup(t, p, f.orgA, "after-timeout"); !groupExists(t, f, f.orgA, id) {
		t.Fatal("the pool does not work after a timeout")
	}
}

// TestTransactionTimeoutLeavesOtherErrors: an error that is no timeout is returned unchanged, also on a pool with the
// cap, and is not counted.
func TestTransactionTimeoutLeavesOtherErrors(t *testing.T) {
	f := newFixture(t)
	const app = "paddock-test-other"
	p := timeoutPool(t, app, db.OrgTransactionTimeout)
	ctx := op.With(orgCtx(f.orgA), "test.other")
	err := p.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: f.groupA, OrganizationID: f.orgA, Name: "dup"})
		return err
	})
	if err == nil || errors.Is(err, db.ErrTransactionTimeout) || !db.IsUniqueViolation(err, "") {
		t.Fatalf("err = %v, want the unique violation unchanged", err)
	}
	if got := db.TransactionTimeouts("test.other"); got != 0 {
		t.Errorf("counted %v timeouts for a unique violation", got)
	}
}
