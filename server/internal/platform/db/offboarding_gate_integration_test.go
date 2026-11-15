package db_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// gateEnv holds a superuser connection and one OrgPool per application role that enters organizations.
type gateEnv struct {
	super  *pgx.Conn
	worker *db.OrgPool
	pools  map[string]*db.OrgPool
}

func newGateEnv(ctx context.Context, t *testing.T) gateEnv {
	t.Helper()
	env := sharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	g := gateEnv{super: super, pools: map[string]*db.OrgPool{}}
	for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_worker": env.Worker,
		"paddock_compiler": env.Compiler, "paddock_escrow_reader": env.EscrowReader, "paddock_revocation": env.Revocation,
		"paddock_notifier": env.Notifier} {
		p, err := db.NewOrgPool(ctx, dsn, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		g.pools[name] = p
	}
	g.worker = g.pools["paddock_worker"]
	return g
}

func noop(context.Context, *pgstore.Queries) error { return nil }

// refresh makes every pool's gate see the statuses committed so far at once instead of at its next poll.
func (g gateEnv) refresh(ctx context.Context, t *testing.T) {
	t.Helper()
	for name, p := range g.pools {
		if err := p.RefreshOrganizationStatus(ctx); err != nil {
			t.Fatalf("%s: refresh the status cache: %v", name, err)
		}
	}
}

// wantUnavailable checks that err is the gate's refusal in every form a caller matches it.
func wantUnavailable(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, problem.OrganizationInactive) || !db.IsOrganizationUnavailable(err) {
		t.Errorf("%s: %v, want organization_inactive", what, err)
	}
	if p := problem.From(err); p.Status != 403 || p.Code != "organization_inactive" {
		t.Errorf("%s: problem %d %s, want 403 organization_inactive", what, p.Status, p.Code)
	}
}

// deleteAll runs the delete batch through the offboarding bypass until it reports 0.
func deleteAll(t *testing.T, worker *db.OrgPool, org uuid.UUID) {
	t.Helper()
	if err := tryDeleteAll(worker, org); err != nil {
		t.Fatal(err)
	}
}

// tryDeleteAll is deleteAll returning the first error of a batch.
func tryDeleteAll(worker *db.OrgPool, org uuid.UUID) error {
	for calls := 0; ; calls++ {
		var n int64
		err := worker.InOrgOffboarding(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			n, err = q.OffboardDeleteBatch(ctx, 10000)
			return err
		})
		if err != nil {
			return fmt.Errorf("delete batch %d: %w", calls+1, err)
		}
		if n == 0 {
			return nil
		}
		if calls > 100 {
			return errors.New("the deletion does not end")
		}
	}
}

// deleteAllRetrying is deleteAll that retries a batch's serialization failure up to tries times: a writer that read
// active just before the status change may still commit while the delete loop runs.
func deleteAllRetrying(t *testing.T, worker *db.OrgPool, org uuid.UUID, tries int) {
	t.Helper()
	for i := 1; ; i++ {
		err := tryDeleteAll(worker, org)
		var pgErr *pgconn.PgError
		if err == nil {
			return
		}
		if !errors.As(err, &pgErr) || pgErr.Code != "40001" || i >= tries {
			t.Fatalf("delete loop, try %d: %v", i, err)
		}
	}
}

// quiesce calls paddock_offboard_quiesce through the offboarding bypass.
func quiesce(worker *db.OrgPool, org uuid.UUID) (bool, error) {
	var ready bool
	err := worker.InOrgOffboarding(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		ready, err = q.OffboardQuiesce(ctx)
		return err
	})
	return ready, err
}

// pastCutoff moves the organization's deleting_committed_at 7 s back, so the quiescence cutoff has passed, for tests
// that are not about the cutoff itself.
func pastCutoff(ctx context.Context, t *testing.T, super *pgx.Conn, org uuid.UUID) {
	t.Helper()
	if _, err := super.Exec(ctx, `UPDATE organization SET deleting_committed_at = now() - interval '7 seconds'
		WHERE id = $1`, org); err != nil {
		t.Fatal(err)
	}
}

// quiesced moves the cutoff into the past and calls quiesce until it is true.
func quiesced(ctx context.Context, t *testing.T, g gateEnv, org uuid.UUID) {
	t.Helper()
	pastCutoff(ctx, t, g.super, org)
	deadline := time.Now().Add(15 * time.Second)
	for {
		ready, err := quiesce(g.worker, org)
		if err != nil {
			t.Fatalf("quiesce: %v", err)
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("quiesce did not become ready within 15 s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitState is the organization's stored quiescence state.
type waitState struct {
	committedAt *time.Time
	vxids       []string
	takenAt     *time.Time
}

func orgWait(ctx context.Context, t *testing.T, super *pgx.Conn, org uuid.UUID) waitState {
	t.Helper()
	var w waitState
	if err := super.QueryRow(ctx, `SELECT deleting_committed_at, offboarding_wait_vxids, offboarding_wait_taken_at
		FROM organization WHERE id = $1`, org).Scan(&w.committedAt, &w.vxids, &w.takenAt); err != nil {
		t.Fatal(err)
	}
	return w
}

func finalize(worker *db.OrgPool, org uuid.UUID) error {
	return worker.InOrgOffboarding(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
		return q.OffboardFinalize(ctx)
	})
}

func orgStatus(ctx context.Context, t *testing.T, super *pgx.Conn, org uuid.UUID) (status string, deletedAt *time.Time) {
	t.Helper()
	if err := super.QueryRow(ctx, "SELECT status, deleted_at FROM organization WHERE id = $1", org).
		Scan(&status, &deletedAt); err != nil {
		t.Fatal(err)
	}
	return status, deletedAt
}

func TestOrganizationUnavailableStatusOfOtherErrors(t *testing.T) {
	for _, err := range []error{nil, errors.New("boom"), problem.OrganizationInactive} {
		if got := db.OrganizationUnavailableStatus(err); got != "" {
			t.Errorf("OrganizationUnavailableStatus(%v) = %q, want empty", err, got)
		}
	}
}

// TestOrgEnterGate: every role that enters organizations passes the gate of an active organization; once deleting
// or deleted is committed and the status cache has read it, InOrg and InOrgSnapshot of every role are refused with
// the status before fn runs, other organizations are unaffected, and only the offboarding bypass still enters (plan
// M17 amendment 2026-11-14 d points 1, 2 and 7, amendment 2026-11-15 j points 1 to 3). The cache's fail-closed
// fallback is TestOrgGateStatusCache.
func TestOrgEnterGate(t *testing.T) {
	ctx := context.Background()
	g := newGateEnv(ctx, t)
	gone := offboardingFixture(ctx, t, g.super, 0)
	kept := offboardingFixture(ctx, t, g.super, 0)

	t.Run("finalize, quiesce and the cache's read are definer functions owned by paddock_owner with a pinned search path", func(t *testing.T) {
		for _, fn := range []string{"paddock_offboard_finalize", "paddock_offboard_quiesce", "paddock_inactive_organizations"} {
			var owner string
			var definer bool
			var config []string
			if err := g.super.QueryRow(ctx, `SELECT pg_get_userbyid(proowner), prosecdef, coalesce(proconfig, '{}')
				FROM pg_proc WHERE proname = $1`, fn).Scan(&owner, &definer, &config); err != nil {
				t.Fatal(err)
			}
			if owner != "paddock_owner" || !definer || len(config) != 1 ||
				config[0] != "search_path=pg_catalog, public, pg_temp" {
				t.Errorf("%s: owner %q, security definer %v, config %v", fn, owner, definer, config)
			}
		}
	})

	t.Run("an active organization is entered by every role", func(t *testing.T) {
		for name, p := range g.pools {
			if err := p.InOrg(orgCtx(gone), noop); err != nil {
				t.Errorf("%s InOrg: %v", name, err)
			}
			if err := p.InOrgSnapshot(orgCtx(gone), noop); err != nil {
				t.Errorf("%s InOrgSnapshot: %v", name, err)
			}
		}
	})

	t.Run("the gate has no per-transaction function and no lock key", func(t *testing.T) {
		var n int
		if err := g.super.QueryRow(ctx, `SELECT count(*) FROM pg_proc
			WHERE proname IN ('paddock_org_enter', 'paddock_offboarding_lock_key')`).Scan(&n); err != nil || n != 0 {
			t.Errorf("paddock_org_enter or paddock_offboarding_lock_key exists: %d, %v", n, err)
		}
	})

	t.Run("the cache's read reveals only ID and status of inactive organizations, to organization roles", func(t *testing.T) {
		var cols string
		if err := g.super.QueryRow(ctx, `SELECT pg_get_function_result(oid) FROM pg_proc
			WHERE proname = 'paddock_inactive_organizations'`).Scan(&cols); err != nil {
			t.Fatal(err)
		}
		if cols != "TABLE(id uuid, status text, checked_at timestamp with time zone)" {
			t.Errorf("paddock_inactive_organizations returns %s", cols)
		}
		for name, p := range g.pools {
			if err := p.RefreshOrganizationStatus(ctx); err != nil {
				t.Errorf("%s may not read the inactive organizations: %v", name, err)
			}
		}
		env := sharedPaddock(t)
		conn, err := pgx.Connect(ctx, env.Platform)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		_, err = conn.Exec(ctx, "SELECT * FROM paddock_inactive_organizations()")
		wantDenied(t, "paddock_platform reads the inactive organizations", err)
	})

	t.Run("escrow reader and revocation issuer read only their own organization's id and status", func(t *testing.T) {
		env := sharedPaddock(t)
		for name, dsn := range map[string]string{"paddock_escrow_reader": env.EscrowReader, "paddock_revocation": env.Revocation} {
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", gone.String()); err != nil {
				t.Fatal(err)
			}
			var status string
			if err := tx.QueryRow(ctx, "SELECT status FROM organization WHERE id = $1", gone).Scan(&status); err != nil ||
				status != "active" {
				t.Errorf("%s: own status %q, %v", name, status, err)
			}
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM organization WHERE id <> $1", gone).Scan(&n); err != nil || n != 0 {
				t.Errorf("%s: %d other organizations visible, %v", name, n, err)
			}
			_, err = tx.Exec(ctx, "SELECT slug FROM organization WHERE id = $1", gone)
			wantDenied(t, name+" SELECT slug", err)
			_ = tx.Rollback(ctx)
			_ = conn.Close(ctx)
		}
	})

	setDeleting(ctx, t, g.super, gone)
	g.refresh(ctx, t)

	t.Run("a deleting organization is refused for every role", func(t *testing.T) {
		for name, p := range g.pools {
			called := false
			fn := func(context.Context, *pgstore.Queries) error { called = true; return nil }
			err := p.InOrg(orgCtx(gone), fn)
			wantUnavailable(t, name+" InOrg", err)
			if got := db.OrganizationUnavailableStatus(err); got != "deleting" {
				t.Errorf("%s: refused status %q, want deleting", name, got)
			}
			err = p.InOrgSnapshot(orgCtx(gone), fn)
			wantUnavailable(t, name+" InOrgSnapshot", err)
			if got := db.OrganizationUnavailableStatus(err); got != "deleting" {
				t.Errorf("%s InOrgSnapshot: refused status %q, want deleting", name, got)
			}
			if called {
				t.Errorf("%s: fn ran in a deleting organization", name)
			}
		}
	})

	t.Run("other organizations are unaffected", func(t *testing.T) {
		for name, p := range g.pools {
			if err := p.InOrg(orgCtx(kept), noop); err != nil {
				t.Errorf("%s InOrg of an active organization: %v", name, err)
			}
		}
	})

	t.Run("the offboarding bypass enters the deleting organization", func(t *testing.T) {
		var n int64
		err := g.worker.InOrgOffboarding(orgCtx(gone), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			n, err = q.OffboardDeleteBatch(ctx, 1)
			return err
		})
		if err != nil || n != 1 {
			t.Errorf("delete batch through InOrgOffboarding: %d, %v, want 1", n, err)
		}
		if err := g.worker.InOrgOffboarding(context.Background(), noop); !errors.Is(err, db.ErrNoOrganization) {
			t.Errorf("InOrgOffboarding without principal: %v, want ErrNoOrganization", err)
		}
	})

	t.Run("rounds no longer list the organization", func(t *testing.T) {
		ids, err := g.worker.OrganizationIDs(principal.With(ctx, principal.Principal{Kind: principal.KindSystem}))
		if err != nil {
			t.Fatal(err)
		}
		listed := map[uuid.UUID]bool{}
		for _, id := range ids {
			listed[id] = true
		}
		if listed[gone] || !listed[kept] {
			t.Errorf("OrganizationIDs lists the deleting organization: %v, the active one: %v", listed[gone], listed[kept])
		}
	})

	deleteAll(t, g.worker, gone)
	quiesced(ctx, t, g, gone)
	if err := finalize(g.worker, gone); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	g.refresh(ctx, t)

	t.Run("a deleted organization is refused for every role", func(t *testing.T) {
		for name, p := range g.pools {
			for path, enter := range map[string]func(context.Context, func(context.Context, *pgstore.Queries) error) error{
				"InOrg": p.InOrg, "InOrgSnapshot": p.InOrgSnapshot} {
				err := enter(orgCtx(gone), noop)
				wantUnavailable(t, name+" "+path, err)
				if got := db.OrganizationUnavailableStatus(err); got != "deleted" {
					t.Errorf("%s %s: refused status %q, want deleted", name, path, got)
				}
			}
		}
	})
}

// TestOffboardFinalize: quiesce and finalize refuse an organization that is not deleting and every role but the
// worker. quiesce stores the cutoff after the status change, takes nothing before deleting_committed_at + 6 s, then
// takes the wait set once and is true only when every transaction in it has ended: a writer that read before the
// change and writes after the delete loop holds it off, as does a read-only transaction; sessions of other roles do
// not. finalize refuses until quiesce is true (55000), raises 40001 while rows remain, keeps the wait set on failure
// and writes the tombstone; writers that keep entering the organization, and writers of another organization, do not
// starve it (plan M17 amendment 2026-11-14 d points 3 and 7, amendment 2026-11-15 j point 4 and its addendum).
func TestOffboardFinalize(t *testing.T) {
	ctx := context.Background()
	g := newGateEnv(ctx, t)

	t.Run("refuses an active organization", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		wantSQLState(t, "finalize of an active organization", finalize(g.worker, org), "42501")
		_, err := quiesce(g.worker, org)
		wantSQLState(t, "quiesce of an active organization", err, "42501")
		if status, _ := orgStatus(ctx, t, g.super, org); status != "active" {
			t.Errorf("status %q, want active", status)
		}
	})

	t.Run("no other role may execute it", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		setDeleting(ctx, t, g.super, org)
		deleteAll(t, g.worker, org)
		for name, p := range g.pools {
			if name == "paddock_worker" {
				continue
			}
			wantDenied(t, name, finalize(p, org))
			_, err := quiesce(p, org)
			wantDenied(t, name+" quiesce", err)
		}
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleting" {
			t.Errorf("status %q, want deleting", status)
		}
	})

	t.Run("raises while rows remain", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 3)
		setDeleting(ctx, t, g.super, org)
		wantSQLState(t, "finalize before quiesce", finalize(g.worker, org), "55000")
		quiesced(ctx, t, g, org)
		wantSQLState(t, "finalize with rows left", finalize(g.worker, org), "40001")
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleting" {
			t.Errorf("status %q, want deleting", status)
		}
		deleteAll(t, g.worker, org)
		if err := finalize(g.worker, org); err != nil {
			t.Fatalf("finalize after the deletion: %v", err)
		}
		status, deletedAt := orgStatus(ctx, t, g.super, org)
		if status != "deleted" || deletedAt == nil {
			t.Errorf("tombstone: status %q, deleted_at %v", status, deletedAt)
		}
		if w := orgWait(ctx, t, g.super, org); w.vxids != nil || w.takenAt != nil {
			t.Errorf("the tombstone keeps the wait set %v taken at %v", w.vxids, w.takenAt)
		}
		wantSQLState(t, "second finalize", finalize(g.worker, org), "42501")
	})

	t.Run("a writer that read before deleting and writes after the delete loop holds quiesce off", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		read, insert := make(chan struct{}), make(chan struct{})
		writerDone := make(chan error, 1)
		go func() {
			writerDone <- g.pools["paddock_api"].InOrg(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
				if _, err := q.GetOrganization(ctx, org); err != nil {
					return err
				}
				close(read)
				<-insert
				_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.New(), OrganizationID: org,
					Name: "late"})
				return err
			})
		}()
		<-read
		setDeleting(ctx, t, g.super, org)
		g.refresh(ctx, t)
		deleteAll(t, g.worker, org)
		if got := offboardingRows(ctx, t, g.super, org); got != 0 {
			t.Fatalf("%d rows left after the delete loop", got)
		}
		// A new transaction of the organization is refused at once, and other organizations are entered as usual.
		wantUnavailable(t, "InOrg while a writer is open", g.pools["paddock_api"].InOrg(orgCtx(org), noop))
		other := offboardingFixture(ctx, t, g.super, 0)
		if err := g.pools["paddock_api"].InOrg(orgCtx(other), noop); err != nil {
			t.Errorf("InOrg of another organization: %v", err)
		}

		// Before the cutoff, quiesce stores only the moment after the change and takes no wait set.
		start := time.Now()
		if ready, err := quiesce(g.worker, org); err != nil || ready {
			t.Fatalf("first quiesce: %v, %v; want false", ready, err)
		}
		w := orgWait(ctx, t, g.super, org)
		if w.committedAt == nil || w.vxids != nil || w.takenAt != nil {
			t.Fatalf("after the first quiesce: committed %v, wait set %v taken at %v; want only the commit moment",
				w.committedAt, w.vxids, w.takenAt)
		}
		for time.Since(start) < 5*time.Second {
			if ready, err := quiesce(g.worker, org); err != nil || ready {
				t.Fatalf("quiesce before the cutoff: %v, %v; want false", ready, err)
			}
			if w := orgWait(ctx, t, g.super, org); w.vxids != nil {
				t.Fatalf("quiesce took the wait set %v %v after the change, before the cutoff", w.vxids, time.Since(start))
			}
			time.Sleep(250 * time.Millisecond)
		}
		// After the cutoff, the writer is in the wait set, and quiesce stays false while it is open.
		deadline := time.Now().Add(10 * time.Second)
		for orgWait(ctx, t, g.super, org).vxids == nil {
			if ready, err := quiesce(g.worker, org); err != nil || ready {
				t.Fatalf("quiesce with the writer open: %v, %v; want false", ready, err)
			}
			if time.Now().After(deadline) {
				t.Fatal("quiesce took no wait set after the cutoff")
			}
			time.Sleep(100 * time.Millisecond)
		}
		taken := orgWait(ctx, t, g.super, org)
		if len(taken.vxids) == 0 {
			t.Fatal("the wait set is empty although the writer is open")
		}
		if ready, err := quiesce(g.worker, org); err != nil || ready {
			t.Fatalf("quiesce with the writer open: %v, %v; want false", ready, err)
		}
		wantSQLState(t, "finalize with the writer open", finalize(g.worker, org), "55000")

		close(insert)
		if err := <-writerDone; err != nil {
			t.Fatalf("writer that read before deleting: %v", err)
		}
		if ready, err := quiesce(g.worker, org); err != nil || !ready {
			t.Fatalf("quiesce after the writer ended: %v, %v; want true", ready, err)
		}
		wantSQLState(t, "finalize after the late insert", finalize(g.worker, org), "40001")
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleting" {
			t.Fatalf("status %q after the refused finalize, want deleting", status)
		}
		if got := offboardingRows(ctx, t, g.super, org); got != 1 {
			t.Fatalf("%d rows after the late insert, want 1", got)
		}

		// The wait set survives the failed finalize and is not taken again, although organization-role transactions
		// open now would be in a new one.
		hold := make(chan struct{})
		holding := make(chan struct{})
		otherDone := make(chan error, 1)
		go func() {
			otherDone <- g.pools["paddock_api"].InOrg(orgCtx(other), func(context.Context, *pgstore.Queries) error {
				close(holding)
				<-hold
				return nil
			})
		}()
		<-holding
		if ready, err := quiesce(g.worker, org); err != nil || !ready {
			t.Errorf("quiesce after the failed finalize, another transaction open: %v, %v; want true", ready, err)
		}
		if w := orgWait(ctx, t, g.super, org); !slices.Equal(w.vxids, taken.vxids) || w.takenAt == nil ||
			!w.takenAt.Equal(*taken.takenAt) {
			t.Errorf("wait set %v taken at %v, want %v taken at %v", w.vxids, w.takenAt, taken.vxids, taken.takenAt)
		}
		deleteAll(t, g.worker, org)
		if err := finalize(g.worker, org); err != nil {
			t.Fatalf("finalize in the next round: %v", err)
		}
		close(hold)
		if err := <-otherDone; err != nil {
			t.Fatal(err)
		}
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleted" {
			t.Errorf("status %q, want deleted", status)
		}
		if got := offboardingRows(ctx, t, g.super, org); got != 0 {
			t.Errorf("%d rows of the tombstone", got)
		}
	})

	t.Run("the stored cutoff base is not before the deleting commit, even when quiesce's transaction began earlier", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		var commit time.Time
		err := g.worker.InOrgOffboarding(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
			// The transaction has begun (set_config ran); deleting commits only now, from another session.
			time.Sleep(200 * time.Millisecond)
			setDeleting(ctx, t, g.super, org)
			if err := g.super.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&commit); err != nil {
				return err
			}
			ready, err := q.OffboardQuiesce(ctx)
			if err == nil && ready {
				t.Error("the first quiesce returned true")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		w := orgWait(ctx, t, g.super, org)
		if w.committedAt == nil || w.committedAt.Before(commit) {
			t.Errorf("deleting_committed_at %v lies before the deleting commit %v", w.committedAt, commit)
		}
	})

	t.Run("quiesce takes the wait set only at or after the cutoff on the database's clock", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		setDeleting(ctx, t, g.super, org)
		// Just below: the cutoff lies 0.5 s after the database's now() of the call; nothing is stored.
		if _, err := g.super.Exec(ctx, `UPDATE organization SET deleting_committed_at = now() - interval '5.5 seconds'
			WHERE id = $1`, org); err != nil {
			t.Fatal(err)
		}
		if ready, err := quiesce(g.worker, org); err != nil || ready {
			t.Fatalf("quiesce just below the cutoff: %v, %v; want false", ready, err)
		}
		if w := orgWait(ctx, t, g.super, org); w.vxids != nil || w.takenAt != nil {
			t.Fatalf("quiesce just below the cutoff stored the wait set %v taken at %v", w.vxids, w.takenAt)
		}
		// At: the cutoff is the database's now() of the update, at or before that of the call.
		if _, err := g.super.Exec(ctx, `UPDATE organization SET deleting_committed_at = now() - interval '6 seconds'
			WHERE id = $1`, org); err != nil {
			t.Fatal(err)
		}
		if _, err := quiesce(g.worker, org); err != nil {
			t.Fatal(err)
		}
		w := orgWait(ctx, t, g.super, org)
		if w.vxids == nil || w.takenAt == nil || w.takenAt.Before(w.committedAt.Add(6*time.Second)) {
			t.Errorf("quiesce at the cutoff: wait set %v taken at %v, committed at %v", w.vxids, w.takenAt, w.committedAt)
		}
	})

	t.Run("a read-only transaction open at the cutoff holds quiesce off", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		other := offboardingFixture(ctx, t, g.super, 0)
		hold, holding := make(chan struct{}), make(chan struct{})
		readerDone := make(chan error, 1)
		go func() {
			readerDone <- g.pools["paddock_compiler"].InOrgSnapshot(orgCtx(other), func(context.Context, *pgstore.Queries) error {
				close(holding)
				<-hold
				return nil
			})
		}()
		<-holding
		setDeleting(ctx, t, g.super, org)
		if ready, err := quiesce(g.worker, org); err != nil || ready {
			t.Fatalf("first quiesce: %v, %v", ready, err)
		}
		pastCutoff(ctx, t, g.super, org)
		for range 3 {
			if ready, err := quiesce(g.worker, org); err != nil || ready {
				t.Fatalf("quiesce with a read-only transaction open: %v, %v; want false", ready, err)
			}
		}
		close(hold)
		if err := <-readerDone; err != nil {
			t.Fatal(err)
		}
		if ready, err := quiesce(g.worker, org); err != nil || !ready {
			t.Errorf("quiesce after the read-only transaction ended: %v, %v; want true", ready, err)
		}
	})

	t.Run("transactions of other roles do not hold quiesce off", func(t *testing.T) {
		env := sharedPaddock(t)
		org := offboardingFixture(ctx, t, g.super, 0)
		var open []pgx.Tx
		var theirs []string
		for _, dsn := range []string{env.Super, env.Platform} {
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close(ctx) }()
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var vxid string
			if err := tx.QueryRow(ctx, `SELECT virtualxid FROM pg_locks
				WHERE pid = pg_backend_pid() AND locktype = 'virtualxid'`).Scan(&vxid); err != nil {
				t.Fatal(err)
			}
			open = append(open, tx)
			theirs = append(theirs, vxid)
		}
		setDeleting(ctx, t, g.super, org)
		quiesced(ctx, t, g, org)
		// The pools' status polls are organization-role transactions too and may be in the set; the open superuser and
		// platform transactions must not.
		if w := orgWait(ctx, t, g.super, org); w.takenAt == nil || slices.ContainsFunc(w.vxids, func(v string) bool {
			return slices.Contains(theirs, v)
		}) {
			t.Errorf("wait set %v taken at %v holds a transaction of another role %v", w.vxids, w.takenAt, theirs)
		}
		for _, tx := range open {
			_ = tx.Rollback(ctx)
		}
	})

	t.Run("application roles still cannot read other sessions' query text", func(t *testing.T) {
		env := sharedPaddock(t)
		for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_worker": env.Worker} {
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			var hidden, visible int
			if err := conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE query = '<insufficient privilege>'),
				count(*) FILTER (WHERE query IS NOT NULL AND query <> '<insufficient privilege>')
				FROM pg_stat_activity WHERE usename IS NOT NULL AND usename <> current_user`).Scan(&hidden, &visible); err != nil {
				t.Fatal(err)
			}
			if hidden == 0 || visible != 0 {
				t.Errorf("%s: %d other sessions' query text hidden, %d visible; want all hidden", name, hidden, visible)
			}
			var stats bool
			if err := conn.QueryRow(ctx, "SELECT pg_has_role(current_user, 'pg_read_all_stats', 'USAGE')").Scan(&stats); err != nil ||
				stats {
				t.Errorf("%s holds pg_read_all_stats: %v, %v", name, stats, err)
			}
			_ = conn.Close(ctx)
		}
	})

	t.Run("continuous writers do not starve finalize", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		other := offboardingFixture(ctx, t, g.super, 0)
		wctx, stop := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var refused, written, otherWritten atomic.Int64
		for range continuousWriters {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for wctx.Err() == nil {
					err := g.pools["paddock_api"].InOrg(orgCtx(other), func(ctx context.Context, q *pgstore.Queries) error {
						_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.New(), OrganizationID: other,
							Name: uuid.NewString()})
						return err
					})
					if err != nil {
						t.Errorf("writer of another organization: %v", err)
						return
					}
					otherWritten.Add(1)
				}
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				for wctx.Err() == nil {
					err := g.pools["paddock_api"].InOrg(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
						_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.New(), OrganizationID: org,
							Name: uuid.NewString()})
						return err
					})
					switch {
					case err == nil:
						written.Add(1)
					case errors.Is(err, problem.OrganizationInactive):
						refused.Add(1)
					default:
						t.Errorf("writer: %v", err)
						return
					}
				}
			}()
		}
		defer func() { stop(); wg.Wait() }()
		time.Sleep(200 * time.Millisecond)
		setDeleting(ctx, t, g.super, org)
		g.refresh(ctx, t)
		before := otherWritten.Load()
		quiesced(ctx, t, g, org)

		attempts := 0
		for {
			attempts++
			deleteAllRetrying(t, g.worker, org, 5)
			err := finalize(g.worker, org)
			if err == nil {
				break
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
				t.Fatalf("finalize attempt %d: %v", attempts, err)
			}
			if attempts >= finalizeAttempts {
				t.Fatalf("finalize did not succeed in %d attempts against %d continuous writers (%d refused)",
					attempts, continuousWriters, refused.Load())
			}
			time.Sleep(finalizePause)
		}
		t.Logf("finalize succeeded at attempt %d against %d continuous writers: %d written, %d refused",
			attempts, continuousWriters, written.Load(), refused.Load())
		if otherWritten.Load() == before {
			t.Error("the other organization's writers made no progress during the deletion")
		}
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleted" {
			t.Errorf("status %q, want deleted", status)
		}
		if got := offboardingRows(ctx, t, g.super, org); got != 0 {
			t.Errorf("%d rows of the tombstone", got)
		}
		if refused.Load() == 0 {
			t.Error("no writer was refused: the writers stopped before the deletion")
		}
	})

	t.Run("no deadlock with leader locks and concurrent entries", func(t *testing.T) {
		env := sharedPaddock(t)
		platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{LockConns: 2})
		if err != nil {
			t.Fatal(err)
		}
		defer platform.Close()
		org := offboardingFixture(ctx, t, g.super, 50)
		other := offboardingFixture(ctx, t, g.super, 0)
		sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem})
		const leaderKey = 0x7061646420746573 // "padd tes"
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		// A round holds its leader lock while it enters organizations, one of which turns deleting meanwhile; the
		// offboarding job deletes and finalizes it under the same leader lock's lifetime.
		locked, err := platform.WithLeaderLock(sys, leaderKey, func(context.Context) error {
			errs := make(chan error, 40)
			for i := range 40 {
				go func() {
					target := org
					if i%2 == 1 {
						target = other
					}
					err := g.pools["paddock_api"].InOrg(principal.With(tctx, principal.Principal{Kind: principal.KindAdmin,
						OrganizationID: target, Role: principal.RoleOrgAdmin}), func(ctx context.Context, q *pgstore.Queries) error {
						_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.New(), OrganizationID: target,
							Name: "c" + uuid.NewString()})
						return err
					})
					if target == org && errors.Is(err, problem.OrganizationInactive) {
						err = nil
					}
					errs <- err
				}()
				if i == 20 {
					setDeleting(ctx, t, g.super, org)
				}
			}
			for range 40 {
				if err := <-errs; err != nil {
					return err
				}
			}
			quiesced(ctx, t, g, org)
			for round := 0; ; round++ {
				deleteAll(t, g.worker, org)
				err := finalize(g.worker, org)
				if err == nil {
					return nil
				}
				if !strings.Contains(err.Error(), "40001") || round > 20 {
					return err
				}
			}
		})
		if err != nil || !locked {
			t.Fatalf("round under the leader lock: locked %v, %v", locked, err)
		}
		if tctx.Err() != nil {
			t.Fatal("the round ran into the deadline")
		}
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleted" {
			t.Errorf("status %q, want deleted", status)
		}
		if got := offboardingRows(ctx, t, g.super, org); got != 0 {
			t.Errorf("%d rows of the tombstone", got)
		}
	})
}

// The continuous-writers test: continuousWriters goroutines enter the organization in a tight loop, more than the
// consumer concurrency of two ingest workers, and as many enter another organization. quiesce waits only for the
// transactions open when it took its wait set, so new writers cannot starve it; finalizeAttempts is 3: the first
// finalize may still meet a straggler's row (40001) if the delete loop ran before it committed; after the next delete
// loop nothing is left, and the third is margin.
const (
	continuousWriters = 16
	finalizeAttempts  = 3
	finalizePause     = 20 * time.Millisecond
)

// identRefs lists the positions of the identifier name in the Go files under root, skipping the directories skip.
func identRefs(t *testing.T, root, name string, skip ...string) []string {
	t.Helper()
	var refs []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			for _, s := range skip {
				if d.Name() == s {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == name {
				refs = append(refs, fset.Position(id.Pos()).Filename)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

// offboardingBypassAllowed: only the db package (definition and tests) and the files of app.Offboarding may name
// InOrgOffboarding.
func offboardingBypassAllowed(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	dir, base := filepath.Dir(filepath.FromSlash(rel)), filepath.Base(rel)
	return strings.HasPrefix(rel, "internal/platform/db/") ||
		(filepath.ToSlash(dir) == "internal/app" && strings.HasPrefix(base, "offboarding"))
}

// TestInOrgOffboardingCallers: the bypass of the gate is used only by app.Offboarding (plan M17 amendment
// 2026-11-14 d point 2).
func TestInOrgOffboardingCallers(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "internal", "platform", "db", "db.go")); err != nil {
		t.Fatalf("server tree: %v", err)
	}
	refs := identRefs(t, root, "InOrgOffboarding", "web", "node_modules")
	if len(refs) == 0 {
		t.Fatal("the scan found not even the definition")
	}
	for _, f := range refs {
		if !offboardingBypassAllowed(root, f) {
			t.Errorf("InOrgOffboarding used outside app.Offboarding: %s", f)
		}
	}
}

func TestInOrgOffboardingCallersDetectsUse(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"internal/worker/round.go", "internal/app/offboarding.go", "internal/app/devices.go"} {
		path := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		src := "package p\n\nfunc f(r interface{ InOrgOffboarding() }) { r.InOrgOffboarding() }\n"
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var denied []string
	for _, f := range identRefs(t, root, "InOrgOffboarding") {
		if !offboardingBypassAllowed(root, f) {
			rel, _ := filepath.Rel(root, f)
			denied = append(denied, filepath.ToSlash(rel))
		}
	}
	if len(denied) != 4 || denied[0] != "internal/app/devices.go" || denied[2] != "internal/worker/round.go" {
		t.Errorf("denied references %v, want two each in internal/app/devices.go and internal/worker/round.go", denied)
	}
}

// BenchmarkInOrgGate measures the gate (plan M17 amendment 2026-11-14 d point 5, amendment 2026-11-15 j point 7): InOrg
// on the status cache against InOrgOffboarding, which is the transaction without the gate, empty, with one read and
// with one committed insert, serially and in parallel on one organization.
func BenchmarkInOrgGate(b *testing.B) {
	ctx := context.Background()
	env := pgtest.StartPaddock(b)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	pool, err := db.NewOrgPool(ctx, env.API, db.Options{MaxConns: 8})
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Bench', 'active')",
		org, "bn"+org.String()[24:]); err != nil {
		b.Fatal(err)
	}
	read := func(ctx context.Context, q *pgstore.Queries) error { _, err := q.GetOrganization(ctx, org); return err }
	write := func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.New(), OrganizationID: org,
			Name: uuid.NewString()})
		return err
	}
	paths := map[string]func(context.Context, func(context.Context, *pgstore.Queries) error) error{
		"gated": pool.InOrg, "ungated": pool.InOrgOffboarding}
	for _, fn := range []struct {
		name string
		fn   func(context.Context, *pgstore.Queries) error
	}{{"empty", noop}, {"read", read}, {"write", write}} {
		for _, path := range []string{"ungated", "gated"} {
			run := paths[path]
			b.Run(fn.name+"/"+path+"/serial", func(b *testing.B) {
				for b.Loop() {
					if err := run(orgCtx(org), fn.fn); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(fn.name+"/"+path+"/parallel", func(b *testing.B) {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if err := run(orgCtx(org), fn.fn); err != nil {
							b.Error(err)
							return
						}
					}
				})
			})
		}
	}
}
