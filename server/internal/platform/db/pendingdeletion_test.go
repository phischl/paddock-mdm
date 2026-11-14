package db_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestInPendingDeletionOrg (ADR 0052 amendment b decision 8): the organization of the argument is entered only by a
// platform administrator and only while its deletion is pending; inside, RLS limits every query to that organization,
// and the api role may change nothing of the organization but the export count.
func TestInPendingDeletionOrg(t *testing.T) {
	f := newFixture(t)
	root := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin, Role: principal.RolePlatform})
	enter := func(ctx context.Context, org uuid.UUID) ([]uuid.UUID, error) {
		var seen []uuid.UUID
		err := f.org.InPendingDeletionOrg(ctx, f.platform, org, func(ctx context.Context, q *pgstore.Queries) error {
			for _, id := range []uuid.UUID{f.orgA, f.orgB} {
				if o, err := q.GetOrganization(ctx, id); err == nil {
					seen = append(seen, o.ID)
				} else if !db.IsNoRows(err) {
					return err
				}
			}
			return nil
		})
		return seen, err
	}

	if _, err := enter(root, f.orgA); !errors.Is(err, db.ErrNotPendingDeletion) {
		t.Fatalf("no pending deletion: %v", err)
	}
	if _, err := enter(root, uuid.New()); !errors.Is(err, db.ErrNotPendingDeletion) {
		t.Fatalf("unknown organization: %v", err)
	}
	err := f.platform.InPlatform(root, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.RequestOrganizationDeletion(ctx, pgstore.RequestOrganizationDeletionParams{ID: f.orgA, GraceDays: 30})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	seen, err := enter(root, f.orgA)
	if err != nil || !slices.Equal(seen, []uuid.UUID{f.orgA}) {
		t.Fatalf("pending: %v %v", seen, err)
	}
	for name, ctx := range map[string]context.Context{
		"organization administrator": orgCtx(f.orgA),
		"system":                     principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem}),
		"no principal":               context.Background(),
	} {
		if _, err := enter(ctx, f.orgA); !errors.Is(err, db.ErrForbiddenScope) {
			t.Errorf("%s: %v", name, err)
		}
	}

	err = f.org.InPendingDeletionOrg(root, f.platform, f.orgA, func(ctx context.Context, q *pgstore.Queries) error {
		res, err := q.ReserveRecoveryExport(ctx, pgstore.ReserveRecoveryExportParams{ID: f.orgA, MaxExports: 5})
		if err != nil || res.RecoveryExports != 1 {
			t.Errorf("reserve: %+v %v", res, err)
		}
		// Another organization's row is invisible, so its count cannot change.
		if _, err := q.ReserveRecoveryExport(ctx, pgstore.ReserveRecoveryExportParams{ID: f.orgB, MaxExports: 5}); !db.IsNoRows(err) {
			t.Errorf("reserve another organization: %v", err)
		}
		_, err = q.CancelOrganizationDeletion(ctx, f.orgA)
		return err
	})
	expectPermissionDenied(t, "paddock_api cancels a deletion", err)
}

// TestInPendingDeletionOrgRacesDeleting (plan M17 amendment g point 6): when the worker commits deleting after the
// platform check but before the transaction passes the gate, InPendingDeletionOrg fails closed with
// problem.OrganizationInactive (PD001) and fn never runs.
func TestInPendingDeletionOrgRacesDeleting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	root := principal.With(ctx, principal.Principal{Kind: principal.KindPlatformAdmin, Role: principal.RolePlatform})
	err := f.platform.InPlatform(root, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.RequestOrganizationDeletion(ctx, pgstore.RequestOrganizationDeletionParams{ID: f.orgA, GraceDays: 30})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// The worker's side: hold the offboarding lock exclusively, as paddock_offboard_finalize does, so the export's
	// transaction waits in paddock_org_enter after the platform check passed.
	worker, err := pgx.Connect(ctx, sharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close(ctx) }()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", db.OffboardingLockKey(f.orgA)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ran := false
	go func() {
		done <- f.org.InPendingDeletionOrg(root, f.platform, f.orgA, func(context.Context, *pgstore.Queries) error {
			ran = true
			return nil
		})
	}()
	for waited := 0; ; waited++ {
		var waiting bool
		if err := worker.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted)`).
			Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if waited > 200 {
			t.Fatal("the export's transaction never waited for the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := tx.Exec(ctx, "UPDATE organization SET status = 'deleting' WHERE id = $1", f.orgA); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	if !errors.Is(err, problem.OrganizationInactive) || db.OrganizationUnavailableStatus(err) != "deleting" || ran {
		t.Fatalf("race with deleting: %v (ran %v)", err, ran)
	}
	// Once deleting is committed, the platform check itself refuses with the gate's error, never
	// ErrNotPendingDeletion, whose caller would fall back to the ungated platform pool (amendment h point 2).
	err = f.org.InPendingDeletionOrg(root, f.platform, f.orgA, func(context.Context, *pgstore.Queries) error {
		t.Error("fn ran for a deleting organization")
		return nil
	})
	if !errors.Is(err, problem.OrganizationInactive) || errors.Is(err, db.ErrNotPendingDeletion) ||
		db.OrganizationUnavailableStatus(err) != "deleting" {
		t.Fatalf("deleting: %v", err)
	}
}

// TestInPendingDeletionOrgCallers: the exception is reached only through ActionRunner.RunExternalInPendingDeletion
// (ADR 0052 amendment b decision 8).
func TestInPendingDeletionOrgCallers(t *testing.T) {
	var callers []string
	for _, ref := range identRefs(t, filepath.Join("..", ".."), "InPendingDeletionOrg", "web", "node_modules") {
		if !strings.HasSuffix(ref, "_test.go") {
			callers = append(callers, filepath.ToSlash(ref))
		}
	}
	for _, c := range callers {
		if !strings.HasSuffix(c, "platform/db/db.go") && !strings.HasSuffix(c, "app/action.go") {
			t.Errorf("InPendingDeletionOrg is used in %s", c)
		}
	}
	if len(callers) < 2 {
		t.Fatalf("the scan found no use: %v", callers)
	}
}
