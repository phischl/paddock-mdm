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

	t.Run("finalize and the cache's read are definer functions owned by paddock_owner with a pinned search path", func(t *testing.T) {
		for _, fn := range []string{"paddock_offboard_finalize", "paddock_inactive_organizations"} {
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

// TestOffboardFinalize: finalize refuses an organization that is not deleting and every role but the worker; it
// raises 40001 while rows remain; a writer that entered before deleting and inserts after the delete loop makes the
// next finalize raise 40001, and the round after it deletes the row and finalizes; writers that keep entering the
// organization, and writers of another organization, do not stop finalize (plan M17 amendment 2026-11-14 d points 3
// and 7, amendment 2026-11-15 j point 4). The wait for writers that passed the gate on a stale cache (amendment j's
// addendum, PR #663) is not in this commit yet; its tests come with it.
func TestOffboardFinalize(t *testing.T) {
	ctx := context.Background()
	g := newGateEnv(ctx, t)

	t.Run("refuses an active organization", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		wantSQLState(t, "finalize of an active organization", finalize(g.worker, org), "42501")
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
		}
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleting" {
			t.Errorf("status %q, want deleting", status)
		}
	})

	t.Run("raises while rows remain", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 3)
		setDeleting(ctx, t, g.super, org)
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
		wantSQLState(t, "second finalize", finalize(g.worker, org), "42501")
	})

	t.Run("a straggler that entered before deleting is caught by the count", func(t *testing.T) {
		org := offboardingFixture(ctx, t, g.super, 0)
		entered, insert := make(chan struct{}), make(chan struct{})
		writerDone := make(chan error, 1)
		go func() {
			writerDone <- g.pools["paddock_api"].InOrg(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
				close(entered)
				<-insert
				_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.New(), OrganizationID: org,
					Name: "late"})
				return err
			})
		}()
		<-entered
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

		close(insert)
		if err := <-writerDone; err != nil {
			t.Fatalf("writer that entered before deleting: %v", err)
		}
		wantSQLState(t, "finalize after the late insert", finalize(g.worker, org), "40001")
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleting" {
			t.Fatalf("status %q after the refused finalize, want deleting", status)
		}
		if got := offboardingRows(ctx, t, g.super, org); got != 1 {
			t.Fatalf("%d rows after the late insert, want 1", got)
		}

		deleteAll(t, g.worker, org)
		if err := finalize(g.worker, org); err != nil {
			t.Fatalf("finalize in the next round: %v", err)
		}
		if status, _ := orgStatus(ctx, t, g.super, org); status != "deleted" {
			t.Errorf("status %q, want deleted", status)
		}
		if got := offboardingRows(ctx, t, g.super, org); got != 0 {
			t.Errorf("%d rows of the tombstone", got)
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
		// Stand-in for the quiescence wait of amendment j's addendum, which replaces it: writers that passed the gate
		// before the refresh end within one transaction's time.
		time.Sleep(stragglerPause)
		before := otherWritten.Load()

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
// consumer concurrency of two ingest workers, and as many enter another organization. finalizeAttempts is 3: the
// first finalize may meet a straggler's row (40001); after the next delete loop nothing is left, and the third is
// margin. Nothing in finalize waits on new writers, so they cannot starve it.
const (
	continuousWriters = 16
	finalizeAttempts  = 3
	finalizePause     = 20 * time.Millisecond
	stragglerPause    = 500 * time.Millisecond
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
