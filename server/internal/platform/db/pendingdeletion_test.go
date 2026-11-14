package db_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
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

// TestInPendingDeletionOrgCallers: the exception is reached only through ActionRunner.RunExternalInPendingDeletion
// (ADR 0052 amendment b decision 8).
func TestInPendingDeletionOrgCallers(t *testing.T) {
	var callers []string
	for _, ref := range identRefs(t, filepath.Join("..", ".."), "InPendingDeletionOrg") {
		if strings.Contains(ref, "_test.go") {
			continue
		}
		callers = append(callers, filepath.ToSlash(ref[:strings.Index(ref, ".go:")+3]))
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

// identRefs lists the positions of the identifier name in the Go files under root.
func identRefs(t *testing.T, root, name string) []string {
	t.Helper()
	var refs []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == name {
				refs = append(refs, fset.Position(id.Pos()).String())
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
