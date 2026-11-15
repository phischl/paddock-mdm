package worker

import (
	"context"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestConsumerRequeuesOnTransactionTimeout: a message whose transaction PostgreSQL ends for exceeding
// transaction_timeout is not acknowledged but requeued, nothing of it is written, and its redelivery is processed
// (plan M17 amendment r point 5: at-least-once, idempotent consumers).
func TestConsumerRequeuesOnTransactionTimeout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// 1 ms: every transaction of the enrollment takes longer, so the first delivery times out for certain.
	capped, err := db.NewOrgPool(ctx, pgtest.SharedPaddock(t).Worker,
		db.Options{MaxConns: 2, TransactionTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(capped.Close)
	secret, _ := f.token(t, true)
	req, body := f.message(t, secret)

	timedOut := NewEnrollment(app.NewEnrollments(app.NewActionRunner(capped, nil, httpx.RequestID), capped), f.cache)
	if o := timedOut.process(ctx, req.EnrollmentID.String(), body); o != retry {
		t.Fatalf("outcome of the timed-out delivery %v, want retry", o)
	}
	if n := f.count(t, "SELECT count(*) FROM device WHERE id = $1", req.EnrollmentID); n != 0 {
		t.Fatalf("the timed-out delivery created %d devices", n)
	}

	redelivered := NewEnrollment(app.NewEnrollments(app.NewActionRunner(f.pool, nil, httpx.RequestID), f.pool), f.cache)
	if o := redelivered.process(ctx, req.EnrollmentID.String(), body); o != ack {
		t.Fatalf("outcome of the redelivery %v, want ack", o)
	}
	if n := f.count(t, "SELECT count(*) FROM device WHERE id = $1", req.EnrollmentID); n != 1 {
		t.Fatalf("the redelivery created %d devices, want 1", n)
	}
}
