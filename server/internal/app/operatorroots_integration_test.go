package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestOperatorRoots: only an organization administrator with a step-up changes the operator roots; a root outside
// the rules is refused; a file below a root is ordinary for operators, the same file without the root is sensitive,
// and the security review lists a file whose tier rose when its root was removed (plan M8s decisions 7a–7d).
func TestOperatorRoots(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	files := app.NewManagedConfig(h.runner, pool)
	review := app.NewSecurityReview(pool)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	roots := []string{"/etc/vendor/", "/etc/myapp/"}

	got := h.during(t, func() {
		if _, err := files.SetOperatorRoots(ctx(operator), roots); !errors.Is(err, problem.Forbidden) {
			t.Errorf("operator = %v", err)
		}
		if _, err := files.SetOperatorRoots(ctx(admin), roots); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("admin without step-up = %v", err)
		}
		if _, err := files.SetOperatorRoots(ctx(tp), roots); !errors.Is(err, problem.StepUpRequired) ||
			!strings.Contains(problem.From(err).Detail, "API tokens") {
			t.Errorf("token = %v", err)
		}
		if _, err := files.SetOperatorRoots(ctx(steppedUp), []string{"/etc/apt/"}); !errors.Is(err, problem.PathNotAllowed) ||
			!strings.HasPrefix(problem.From(err).Detail, "/etc/apt/: ") {
			t.Errorf("never-operator root = %v", err)
		}
	})
	want := "settings.managed_files_changed:denied:forbidden,settings.managed_files_changed:denied:step_up_required," +
		"settings.managed_files_changed:denied:step_up_required,settings.managed_files_changed:failure:path_not_allowed"
	if strings.Join(got, ",") != want {
		t.Fatalf("actions %v", got)
	}

	path, mode, content := "/etc/vendor/app.conf", "0644", "x"
	in := app.FileInput{Path: &path, Mode: &mode, Content: &content}
	if _, err := files.CreateFile(ctx(operator), in); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator outside every root = %v", err)
	}
	s, err := files.SetOperatorRoots(ctx(steppedUp), append(roots, " /etc/vendor/"))
	if err != nil || !slices.Equal(s.OperatorRoots, []string{"/etc/myapp/", "/etc/vendor/"}) {
		t.Fatalf("set roots = %+v, %v", s, err)
	}
	if ev := h.lastEvent(t); !ev.Actor.StepUp || ev.Params["operator_roots"] == nil || ev.Params["old_operator_roots"] == nil {
		t.Fatalf("event %+v", ev)
	}
	f, err := files.CreateFile(ctx(operator), in)
	if err != nil {
		t.Fatalf("operator below a root = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["tier"] != "ordinary" {
		t.Fatalf("file event %+v", ev)
	}

	// Removing the root never changes the definition; its tier rises and the review lists it.
	if _, err := files.SetOperatorRoots(ctx(steppedUp), []string{"/etc/myapp/"}); err != nil {
		t.Fatal(err)
	}
	r, err := review.Get(ctx(admin))
	if err != nil || !slices.ContainsFunc(r.Sensitive, func(x pgstore.ManagedFile) bool { return x.ID == f.ID }) {
		t.Fatalf("review after removing the root: %+v, %v", r.Sensitive, err)
	}
	newContent := "y"
	if _, err := files.UpdateFile(ctx(operator), f.ID, app.FileInput{Content: &newContent}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator changing a file whose root was removed = %v", err)
	}
}

// TestOperatorRootsDeclarative: the settings section of the document follows the same rule.
func TestOperatorRootsDeclarative(t *testing.T) {
	h := newConfigHarness(t)
	operator := h.account(t, principal.RoleOrgOperator, true)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	doc := h.export(t, steppedUp)
	doc.Settings.ManagedFiles = &declarative.ManagedFileSettings{OperatorRoots: []string{"/opt/vendor/"}}
	if _, _, err := h.config.Apply(principal.With(context.Background(), operator), raw(t, doc), ""); !errors.Is(err, problem.Forbidden) ||
		!strings.HasPrefix(problem.From(err).Detail, "/settings/managed_files: ") {
		t.Fatalf("operator changing the roots = %v", err)
	}
	if _, _, err := h.config.Apply(principal.With(context.Background(), steppedUp), raw(t, doc), ""); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
	if got := h.export(t, steppedUp).Settings.ManagedFiles.OperatorRoots; !slices.Equal(got, []string{"/opt/vendor/"}) {
		t.Fatalf("exported roots %v", got)
	}
}
