package app_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/debtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// fakeRepoKeys plays Transit for the credential: the ciphertext names the organization and field it is bound to.
type fakeRepoKeys struct{}

func (fakeRepoKeys) Encrypt(_ context.Context, key string, org uuid.UUID, field bao.ContextField, plaintext []byte) (string, error) {
	return "vault:v1:" + key + ":" + org.String() + ":" + string(field) + ":" + base64.StdEncoding.EncodeToString(plaintext), nil
}

// fakePackageStore is the bundles bucket; failDelete makes Delete fail.
type fakePackageStore struct {
	mu         sync.Mutex
	objects    map[string][]byte
	failDelete bool
}

func (s *fakePackageStore) PutReader(_ context.Context, key string, body io.ReadSeeker, _ int64) error {
	data, err := io.ReadAll(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = data
	return err
}

func (s *fakePackageStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failDelete {
		return errors.New("bucket unavailable")
	}
	delete(s.objects, key)
	return nil
}

func (s *fakePackageStore) Size(_ context.Context, key string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[key]
	return int64(len(data)), ok, nil
}

// sealedRepoKeys is Transit while OpenBao is sealed.
type sealedRepoKeys struct{}

func (sealedRepoKeys) Encrypt(context.Context, string, uuid.UUID, bao.ContextField, []byte) (string, error) {
	return "", errors.New("openbao sealed")
}

type fakePresigner struct{}

func (fakePresigner) PresignGet(_ context.Context, key string, ttl time.Duration) (string, error) {
	return fmt.Sprintf("https://bundles.example.com/paddock-bundles/%s?ttl=%s", key, ttl), nil
}

// TestSoftwarePackages (plan M13c decisions 11, 12 and 14, §3.8 L6, L7 and L9; ADR 0050; architect decision A10-21):
// the repository is created with its credential on the first visit, uploads wait for the signing key, only an
// organization administrator with a fresh step-up uploads, the .deb is checked, stored and audited with its hash,
// duplicates and assigned packages are refused, the credential rotates with a 24-hour overlap, and apt's requests are
// answered by the organization's credential only.
func TestSoftwarePackages(t *testing.T) {
	h := newPrivilegesHarness(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := &fakePackageStore{objects: map[string][]byte{}}
	pkgs := app.NewSoftwarePackages(h.runner, pool, fakeRepoKeys{}, store, fakePresigner{}, "https://bundles.example.com/")
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(ctx, token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	as := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	var slug string
	if err := h.super.QueryRow(ctx, "SELECT slug FROM organization WHERE id = $1", h.org).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	deb := debtest.Deb(debtest.Control("acme-tool", "1.0-1", "amd64"))

	// The first visit creates the repository without a key: disabled, no source, and uploads wait (A10-21).
	repo, err := pkgs.Repository(as(auditor))
	if err != nil {
		t.Fatal(err)
	}
	if repo.State != app.RepositoryDisabled || repo.Source != nil || repo.Repository.SigningFingerprint != nil ||
		repo.URL != "https://bundles.example.com/apt/"+slug+"/" || repo.Repository.RebuildRequestedAt == nil {
		t.Fatalf("new repository %+v", repo)
	}
	if !strings.HasPrefix(repo.Repository.CredentialCiphertext, "vault:v1:"+app.SoftwareRepoCredentialKey+":"+h.org.String()+":") ||
		len(repo.Repository.CredentialSha256) != 32 {
		t.Fatalf("credential %q", repo.Repository.CredentialCiphertext)
	}
	got := h.during(t, func() {
		if _, err := pkgs.Upload(as(steppedUp), app.PackageUpload{File: deb}); !errors.Is(err, problem.RepositoryNotReady) {
			t.Errorf("upload before the key = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_package.uploaded:denied:repository_not_ready"}) {
		t.Fatalf("actions %v", got)
	}
	// Until the key exists the repository publishes nothing, even for the right credential.
	rotated, err := pkgs.RotateCredential(as(steppedUp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkgs.Locate(ctx, slug, "paddock", rotated.Secret, "dists/paddock/InRelease"); !errors.Is(err, app.ErrRepositoryNotFound) {
		t.Fatalf("repository without a key = %v", err)
	}

	// The worker's key generation (PDK-813).
	if _, err := h.super.Exec(ctx, `UPDATE software_repository SET signing_public_key = 'key', signing_fingerprint = $2,
		signing_private_ciphertext = 'vault:v1:x' WHERE organization_id = $1`, h.org, strings.Repeat("AB", 20)); err != nil {
		t.Fatal(err)
	}

	got = h.during(t, func() {
		for name, c := range map[string]struct {
			p    principal.Principal
			in   app.PackageUpload
			want *problem.Error
		}{
			"operator":           {operator, app.PackageUpload{File: deb}, problem.Forbidden},
			"admin without step": {admin, app.PackageUpload{File: deb}, problem.StepUpRequired},
			"api token":          {tp, app.PackageUpload{File: deb}, problem.StepUpRequired},
			"not a package":      {steppedUp, app.PackageUpload{File: []byte("MZ\x90\x00")}, problem.InvalidRequest},
			"package differs":    {steppedUp, app.PackageUpload{File: deb, Package: "other"}, problem.InvalidRequest},
			"version differs":    {steppedUp, app.PackageUpload{File: deb, Version: "2.0"}, problem.InvalidRequest},
			"xz control":         {steppedUp, app.PackageUpload{File: readFixture(t, "hello-xz.deb")}, problem.UnsupportedCompression},
		} {
			if _, err := pkgs.Upload(as(c.p), c.in); !errors.Is(err, c.want) {
				t.Errorf("%s = %v, want %s", name, err, c.want.Code)
			}
		}
	})
	if len(got) != 7 {
		t.Fatalf("actions %v", got)
	}

	before := repositoryRow(t, h)
	up, err := pkgs.Upload(as(steppedUp), app.PackageUpload{File: deb, Package: "acme-tool", Version: "1.0-1", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	key := "apt/" + h.org.String() + "/pool/main/a/acme-tool/acme-tool_1.0-1_amd64.deb"
	if up.ObjectKey != key || up.Filename != "pool/main/a/acme-tool/acme-tool_1.0-1_amd64.deb" || up.Size != int64(len(deb)) ||
		up.Fields["Maintainer"] != "Paddock Test <test@example.invalid>" || string(store.objects[key]) != string(deb) {
		t.Fatalf("uploaded %+v", up)
	}
	ev := h.lastEvent(t)
	if ev.Code != "software_package.uploaded" || ev.Params["sha256"] != up.Sha256 || ev.Params["package"] != "acme-tool" ||
		ev.Params["version"] != "1.0-1" || ev.Params["architecture"] != "amd64" || !ev.Actor.StepUp {
		t.Fatalf("uploaded event %+v", ev)
	}
	if after := repositoryRow(t, h); !after.After(before) {
		t.Fatalf("rebuild not requested: %v, before %v", after, before)
	}
	if _, err := pkgs.Upload(as(steppedUp), app.PackageUpload{File: deb}); !errors.Is(err, problem.AlreadyExists) {
		t.Fatalf("duplicate = %v", err)
	}
	hello, err := pkgs.Upload(as(steppedUp), app.PackageUpload{File: readFixture(t, "hello-zstd.deb")})
	if err != nil {
		t.Fatalf("zstd control = %v", err)
	}
	second, err := pkgs.Upload(as(steppedUp), app.PackageUpload{File: debtest.Deb(debtest.Control("acme-tool", "2.0", "all"))})
	if err != nil {
		t.Fatal(err)
	}

	amd64 := "amd64"
	list, err := pkgs.List(as(auditor), app.ListPage{Sort: "package", Limit: 10}, &amd64)
	if err != nil || list.Count != 1 || list.Items[0].ID != up.ID {
		t.Fatalf("list amd64 = %+v, %v", list, err)
	}
	q := "%hello%"
	if list, err := pkgs.List(as(auditor), app.ListPage{Sort: "-uploaded_at", QPattern: &q, Limit: 10}, nil); err != nil || list.Count != 1 {
		t.Fatalf("search = %+v, %v", list, err)
	}

	// A package no entry names is deleted with its object.
	if err := pkgs.Delete(as(steppedUp), hello.ID); err != nil {
		t.Fatalf("delete = %v", err)
	}
	if _, ok := store.objects[hello.ObjectKey]; ok {
		t.Fatal("object not deleted")
	}
	if ev := h.lastEvent(t); ev.Code != "software_package.deleted" || ev.Params["sha256"] != hello.Sha256 {
		t.Fatalf("deleted event %+v", ev)
	}
	// The object goes after the commit: a bucket that fails then leaves only an object no row names, and the next
	// upload of the same file replaces it.
	store.failDelete = true
	if err := pkgs.Delete(as(steppedUp), up.ID); err != nil {
		t.Fatalf("delete while the bucket fails = %v", err)
	}
	store.failDelete = false
	if list, err := pkgs.List(as(auditor), app.ListPage{Sort: "package", Limit: 10}, &amd64); err != nil || list.Count != 0 {
		t.Fatalf("row after the delete = %+v, %v", list, err)
	}
	if up, err = pkgs.Upload(as(steppedUp), app.PackageUpload{File: deb}); err != nil {
		t.Fatalf("upload over a left-behind object = %v", err)
	}

	// A catalog entry of the Paddock source names acme-tool on every architecture, and an assignment pins 1.0-1
	// (§3.8 L9, plan M13c decision 12): no stored version of acme-tool may go, not even one that 2.0 (all) supersedes.
	source := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, `INSERT INTO software_source (id, organization_id, kind, slug, name, uris, suites, components,
		signing_key, fingerprint) VALUES ($1, $2, 'paddock', 'paddock', 'Paddock', $3, '{paddock}', '{main}', 'key', $4)`,
		source, h.org, []string{"https://bundles.example.com/apt/" + slug + "/"}, strings.Repeat("AB", 20)); err != nil {
		t.Fatal(err)
	}
	entry := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, `INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages)
		VALUES ($1, $2, 'Acme', $3, '[{"distribution":"ubuntu","release":"*","architecture":"*","package":"acme-tool"}]')`,
		entry, h.org, source); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(ctx, `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, intent, update_rule, version)
		VALUES ($1, $2, $3, 'required', 'pinned', '1.0-1')`, uuid.Must(uuid.NewV7()), h.org, entry); err != nil {
		t.Fatal(err)
	}
	got = h.during(t, func() {
		if err := pkgs.Delete(as(steppedUp), up.ID); !errors.Is(err, problem.InUse) {
			t.Errorf("delete of the pinned version = %v", err)
		}
		if err := pkgs.Delete(as(steppedUp), second.ID); !errors.Is(err, problem.InUse) {
			t.Errorf("delete of the assigned package = %v", err)
		}
		if err := pkgs.Delete(as(admin), second.ID); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("delete without step-up = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_package.deleted:failure:in_use", "software_package.deleted:failure:in_use",
		"software_package.deleted:denied:step_up_required"}) {
		t.Fatalf("actions %v", got)
	}
	if _, ok := store.objects[up.ObjectKey]; !ok {
		t.Fatal("object of a refused delete removed")
	}

	// The system source is the worker's: the API never changes or deletes it.
	sources := app.NewSoftwareSources(h.runner, pool)
	if err := sources.Delete(as(steppedUp), source); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("delete of the paddock source = %v", err)
	}
	if _, err := sources.Update(as(steppedUp), source, app.SourceUpdate{Name: new("X")}); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("update of the paddock source = %v", err)
	}
	repo, err = pkgs.Repository(as(auditor))
	if err != nil || repo.Source == nil || repo.Source.ID != source || repo.Source.EntryCount != 1 || repo.State != app.RepositoryPending ||
		repo.PackageCount != 2 {
		t.Fatalf("repository with key = %+v, %v", repo, err)
	}

	// Another organization's package is not found.
	other := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')",
		other, "o"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	foreign := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, `INSERT INTO software_package (id, organization_id, package, version, architecture, size, sha256,
		object_key, control, uploaded_by) VALUES ($1, $2, 'x1', '1', 'amd64', 1, $3, 'k', '{}', 'x')`,
		foreign, other, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := pkgs.Delete(as(steppedUp), foreign); !errors.Is(err, problem.NotFound) {
		t.Fatalf("delete of another organization's package = %v", err)
	}

	// The credential (§3.8 L6): the new one and, for 24 hours, the previous one; nothing else.
	first, err := pkgs.RotateCredential(as(steppedUp))
	if err != nil {
		t.Fatal(err)
	}
	second2, err := pkgs.RotateCredential(as(steppedUp))
	if err != nil {
		t.Fatal(err)
	}
	if ev := h.lastEvent(t); ev.Code != "software_repository.credential_rotated" || strings.Contains(fmt.Sprint(ev.Params), second2.Secret) ||
		ev.Params["previous_valid_until"] == nil {
		t.Fatalf("rotated event %+v", ev)
	}
	if d := time.Until(second2.PreviousValidUntil); d < 23*time.Hour || d > 25*time.Hour || len(second2.Secret) < 40 {
		t.Fatalf("rotated %+v", second2)
	}
	if _, err := pkgs.RotateCredential(as(operator)); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("rotate by an operator = %v", err)
	}
	path := strings.TrimPrefix(second.ObjectKey, "apt/"+h.org.String()+"/")
	for name, c := range map[string]struct {
		slug, user, secret, path string
		want                     error
	}{
		"current":           {slug, "paddock", second2.Secret, path, nil},
		"previous":          {slug, "paddock", first.Secret, path, nil},
		"older":             {slug, "paddock", rotated.Secret, path, app.ErrRepositoryUnauthorized},
		"no credential":     {slug, "", "", path, app.ErrRepositoryUnauthorized},
		"wrong user":        {slug, "admin", second2.Secret, path, app.ErrRepositoryUnauthorized},
		"other org":         {"o" + other.String()[24:], "paddock", second2.Secret, path, app.ErrRepositoryUnauthorized},
		"unknown org":       {"nobody", "paddock", second2.Secret, path, app.ErrRepositoryUnauthorized},
		"bad slug":          {"../x", "paddock", second2.Secret, path, app.ErrRepositoryUnauthorized},
		"missing object":    {slug, "paddock", second2.Secret, "dists/paddock/InRelease", app.ErrRepositoryNotFound},
		"traversal":         {slug, "paddock", second2.Secret, "pool/../../" + other.String() + "/x", app.ErrRepositoryNotFound},
		"outside the pool":  {slug, "paddock", second2.Secret, "secrets/x", app.ErrRepositoryNotFound},
		"empty path":        {slug, "paddock", second2.Secret, "", app.ErrRepositoryNotFound},
		"double slash path": {slug, "paddock", second2.Secret, "pool//x", app.ErrRepositoryNotFound},
	} {
		url, err := pkgs.Locate(ctx, c.slug, c.user, c.secret, c.path)
		if !errors.Is(err, c.want) || (c.want == nil && !strings.Contains(url, second.ObjectKey)) {
			t.Errorf("%s: %q, %v, want %v", name, url, err, c.want)
		}
	}
	if _, err := h.super.Exec(ctx, `UPDATE software_repository SET previous_credential_expires_at = now() - interval '1 second'
		WHERE organization_id = $1`, h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := pkgs.Locate(ctx, slug, "paddock", first.Secret, path); !errors.Is(err, app.ErrRepositoryUnauthorized) {
		t.Fatalf("previous credential after its overlap = %v", err)
	}

	// Without a repository row (its creation failed, OpenBao sealed) a rotation is not ready rather than an error.
	if _, err := h.super.Exec(ctx, "DELETE FROM software_repository WHERE organization_id = $1", h.org); err != nil {
		t.Fatal(err)
	}
	sealed := app.NewSoftwarePackages(h.runner, pool, sealedRepoKeys{}, store, fakePresigner{}, "https://bundles.example.com/")
	got = h.during(t, func() {
		if _, err := sealed.RotateCredential(as(steppedUp)); !errors.Is(err, problem.RepositoryNotReady) {
			t.Errorf("rotate without a repository = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_repository.credential_rotated:denied:repository_not_ready"}) {
		t.Fatalf("actions %v", got)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "domain", "software", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// repositoryRow returns rebuild_requested_at of the harness' organization.
func repositoryRow(t *testing.T, h privilegesHarness) time.Time {
	t.Helper()
	var at time.Time
	if err := h.super.QueryRow(context.Background(), "SELECT rebuild_requested_at FROM software_repository WHERE organization_id = $1",
		h.org).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}
