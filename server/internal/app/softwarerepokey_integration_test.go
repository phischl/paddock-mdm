package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestSoftwareRepositoryRotateKey (ADR 0050 decision 3, plan M13c decision 12): only an organization administrator with
// a fresh step-up rotates the signing key, not before the first key exists; the api only queues the rotation for the
// worker, which holds software-repo-wrap, and every attempt is recorded once with the fingerprint being replaced.
func TestSoftwareRepositoryRotateKey(t *testing.T) {
	h := newPrivilegesHarness(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	pkgs := app.NewSoftwarePackages(h.runner, pool, fakeRepoKeys{}, &fakePackageStore{objects: map[string][]byte{}},
		fakePresigner{}, "https://bundles.example.com/")
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(ctx, token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	as := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }

	got := h.during(t, func() {
		if _, err := pkgs.RotateKey(as(steppedUp)); !errors.Is(err, problem.RepositoryNotReady) {
			t.Errorf("rotation before the first key = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_repository.key_rotated:denied:repository_not_ready"}) {
		t.Fatalf("actions %v", got)
	}
	fingerprint := strings.Repeat("CD", 20)
	if _, err := h.super.Exec(ctx, `UPDATE software_repository SET signing_public_key = 'key', signing_fingerprint = $2,
		signing_private_ciphertext = 'vault:v1:x', rebuild_requested_at = NULL WHERE organization_id = $1`, h.org, fingerprint); err != nil {
		t.Fatal(err)
	}

	got = h.during(t, func() {
		for name, c := range map[string]struct {
			p    principal.Principal
			want *problem.Error
		}{
			"operator":           {operator, problem.Forbidden},
			"admin without step": {admin, problem.StepUpRequired},
			"api token":          {tp, problem.StepUpRequired},
		} {
			if _, err := pkgs.RotateKey(as(c.p)); !errors.Is(err, c.want) {
				t.Errorf("%s = %v, want %s", name, err, c.want.Code)
			}
		}
	})
	if len(got) != 3 || slices.ContainsFunc(got, func(a string) bool { return !strings.HasPrefix(a, "software_repository.key_rotated:denied:") }) {
		t.Fatalf("actions %v", got)
	}
	var queued int
	if err := h.super.QueryRow(ctx, `SELECT count(*) FROM software_repository WHERE organization_id = $1
		AND key_rotation_requested_at IS NOT NULL`, h.org).Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("a refused rotation was queued (%d, %v)", queued, err)
	}

	got = h.during(t, func() {
		v, err := pkgs.RotateKey(as(steppedUp))
		if err != nil {
			t.Fatal(err)
		}
		if v.Repository.KeyRotationRequestedAt == nil || v.Repository.RebuildRequestedAt == nil || v.State != app.RepositoryPending ||
			v.Repository.SigningFingerprint == nil || *v.Repository.SigningFingerprint != fingerprint {
			t.Fatalf("after the request %+v", v.Repository)
		}
	})
	if !slices.Equal(got, []string{"software_repository.key_rotated:success:"}) {
		t.Fatalf("actions %v", got)
	}
	if ev := h.lastEvent(t); ev.Params["previous_fingerprint"] != fingerprint {
		t.Fatalf("key_rotated params %v", ev.Params)
	}
}
