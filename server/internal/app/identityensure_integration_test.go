package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// ensureMark returns the organization's ensure mark: whether idp_ensured_at is set, and idp_ensure_revision.
func (s syncHarness) ensureMark(t *testing.T) (bool, string) {
	t.Helper()
	var (
		ensured  bool
		revision *string
	)
	if err := s.super.QueryRow(context.Background(),
		"SELECT idp_ensured_at IS NOT NULL, idp_ensure_revision FROM organization WHERE id = $1", s.org).Scan(&ensured, &revision); err != nil {
		t.Fatal(err)
	}
	if revision == nil {
		return ensured, ""
	}
	return ensured, *revision
}

// reconcile runs one reconcile round and returns the EnsureOrganization calls it made.
func (s syncHarness) reconcile(t *testing.T) (int, error) {
	t.Helper()
	before := s.dir.ensures
	err := s.sync.Reconcile(s.system())
	return s.dir.ensures - before, err
}

// platformScope returns a platform pool and a platform principal's context, for the platform use cases' queries.
func platformScope(t *testing.T) (*db.PlatformPool, context.Context) {
	t.Helper()
	pool, err := db.NewPlatformPool(context.Background(), pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin,
		ID: uuid.Must(uuid.NewV7()), Role: principal.RolePlatform})
}

// TestReconcileEnsureCache (PDK-1021, plan M17 decision 20): the reconcile round ensures the organization's Authentik
// objects only when the mark is missing, of another revision or older than 6 h plus the organization's jitter; a
// domain change, a (re)creation and a failed round clear the mark, a failed ensure never sets it.
func TestReconcileEnsureCache(t *testing.T) {
	s := newSyncHarness(t)
	s.sync.WithEnsureRevision("rev-a")
	ctx := context.Background()
	round := func(step string, want int) {
		t.Helper()
		n, err := s.reconcile(t)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if n != want {
			t.Fatalf("%s: %d ensures, want %d", step, n, want)
		}
	}
	marked := func(step, revision string) {
		t.Helper()
		if ensured, rev := s.ensureMark(t); !ensured || rev != revision {
			t.Fatalf("%s: mark %v %q, want set with %q", step, ensured, rev, revision)
		}
	}
	cleared := func(step string) {
		t.Helper()
		if ensured, _ := s.ensureMark(t); ensured {
			t.Fatalf("%s: the mark is still set", step)
		}
	}

	cleared("a new organization")
	round("first round", 1)
	marked("first round", "rev-a")
	round("second round", 0)
	round("third round", 0)

	s.sync.WithEnsureRevision("rev-b")
	round("revision bump", 1)
	marked("revision bump", "rev-b")
	round("after the revision bump", 0)

	full := app.IdentityFullEnsureInterval + app.IdentityEnsureJitter(s.org)
	age := func(d time.Duration) {
		if _, err := s.super.Exec(ctx, "UPDATE organization SET idp_ensured_at = now() - make_interval(secs => $2) WHERE id = $1",
			s.org, d.Seconds()); err != nil {
			t.Fatal(err)
		}
	}
	age(full - time.Minute)
	round("a minute before the full interval", 0)
	age(full + time.Second)
	round("after the full interval", 1)
	round("after the full re-ensure", 0)

	platform, pctx := platformScope(t)
	if err := platform.InPlatform(pctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.UpdateOrganizationDomains(ctx, pgstore.UpdateOrganizationDomainsParams{ID: s.org, Domains: []string{"d" + s.slug + ".test"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cleared("domain change")
	round("after a domain change", 1)
	round("after the domain change re-ensure", 0)

	if err := platform.InPlatform(pctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.UpdateOrganizationStatus(ctx, pgstore.UpdateOrganizationStatusParams{ID: s.org, Name: "Test", Status: "active"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cleared("re-creation")
	round("after a re-creation", 1)

	// A failed ensure clears the mark and does not set it; the round after it ensures again.
	s.dir.fail = errors.New("authentik: HTTP 503")
	age(full + time.Second)
	if n, err := s.reconcile(t); err == nil || n != 1 {
		t.Fatalf("a failing ensure: %d ensures, %v", n, err)
	}
	cleared("a failed ensure")
	if n, err := s.reconcile(t); err == nil || n != 1 {
		t.Fatalf("a failing ensure again: %d ensures, %v", n, err)
	}
	cleared("a second failed ensure")
	s.dir.fail = nil
	round("after the failures", 1)
	marked("after the failures", "rev-b")

	// A failed synchronization of the organization's users clears the mark as well.
	s.dir.fail = errors.New("authentik: HTTP 503")
	if _, err := s.sync.SyncUsers(s.system(), func(string) bool { return false }); err == nil {
		t.Fatal("a failing user listing did not fail the sync round")
	}
	s.dir.fail = nil
	cleared("a failed user sync")
	round("after a failed user sync", 1)
}

// TestReconcileEnsureCacheLaterFailure (PDK-1021): a round that skipped the ensure but failed afterwards (a device
// group listing) clears the mark, as does a round that set the mark and then failed.
func TestReconcileEnsureCacheLaterFailure(t *testing.T) {
	s := newSyncHarness(t)
	s.sync.WithEnsureRevision("rev-a")
	ctx := context.Background()
	suffix := s.org.String()[24:]
	s.dir.users = append(s.dir.users, ports.IdentityUser{PK: "e" + suffix, Username: "erin@r-" + suffix + ".test", Name: "Erin"})
	if _, err := s.sync.SyncUsers(s.system(), func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	device := uuid.Must(uuid.NewV7())
	if _, err := s.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')",
		device, s.org); err != nil {
		t.Fatal(err)
	}
	if _, err := s.super.Exec(ctx, `INSERT INTO device_login_assignment (organization_id, device_id, subject_type, subject_id)
		SELECT $1, $2, 'user', id FROM app_user WHERE authentik_pk = $3`, s.org, device, "e"+suffix); err != nil {
		t.Fatal(err)
	}

	s.dir.deviceListFail = errors.New("authentik: HTTP 503")
	if n, err := s.reconcile(t); err == nil || n != 1 {
		t.Fatalf("a round failing after its ensure: %d ensures, %v", n, err)
	}
	if ensured, _ := s.ensureMark(t); ensured {
		t.Fatal("a round failing after its ensure left the mark set")
	}
	s.dir.deviceListFail = nil
	if n, err := s.reconcile(t); err != nil || n != 1 {
		t.Fatalf("the round after: %d ensures, %v", n, err)
	}
	if n, err := s.reconcile(t); err != nil || n != 0 {
		t.Fatalf("a settled round: %d ensures, %v", n, err)
	}
	s.dir.deviceListFail = errors.New("authentik: HTTP 503")
	if n, err := s.reconcile(t); err == nil || n != 0 {
		t.Fatalf("a round failing without an ensure: %d ensures, %v", n, err)
	}
	if ensured, _ := s.ensureMark(t); ensured {
		t.Fatal("a round failing without an ensure left the mark set")
	}
	s.dir.deviceListFail = nil
	if n, err := s.reconcile(t); err != nil || n != 1 {
		t.Fatalf("the round after the failure: %d ensures, %v", n, err)
	}
}

// TestReconcileWithoutEnsureCache: without an ensure revision every round ensures and no mark is written.
func TestReconcileWithoutEnsureCache(t *testing.T) {
	s := newSyncHarness(t)
	for range 3 {
		if n, err := s.reconcile(t); err != nil || n != 1 {
			t.Fatalf("%d ensures, %v", n, err)
		}
	}
	if ensured, rev := s.ensureMark(t); ensured || rev != "" {
		t.Fatalf("mark %v %q without a revision", ensured, rev)
	}
}

// TestMarkOrganizationIdentityEnsuredStale (PDK-1021): the mark applies only to the row as the round read it; a domain
// change during the ensure keeps the mark cleared.
func TestMarkOrganizationIdentityEnsuredStale(t *testing.T) {
	s := newSyncHarness(t)
	ctx := context.Background()
	worker, err := db.NewOrgPool(ctx, pgtest.SharedPaddock(t).Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	var seen time.Time
	if err := s.super.QueryRow(ctx, "SELECT updated_at FROM organization WHERE id = $1", s.org).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	platform, pctx := platformScope(t)
	if err := platform.InPlatform(pctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.UpdateOrganizationDomains(ctx, pgstore.UpdateOrganizationDomainsParams{ID: s.org, Domains: []string{"s" + s.slug + ".test"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	mark := func(at time.Time) {
		t.Helper()
		if err := worker.InOrg(s.system(), func(ctx context.Context, q *pgstore.Queries) error {
			return q.MarkOrganizationIdentityEnsured(ctx, pgstore.MarkOrganizationIdentityEnsuredParams{
				ID: s.org, Revision: new("rev-a"), SeenUpdatedAt: at})
		}); err != nil {
			t.Fatal(err)
		}
	}
	mark(seen)
	if ensured, _ := s.ensureMark(t); ensured {
		t.Fatal("a mark read before the domain change was applied")
	}
	if err := s.super.QueryRow(ctx, "SELECT updated_at FROM organization WHERE id = $1", s.org).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	mark(seen)
	if ensured, rev := s.ensureMark(t); !ensured || rev != "rev-a" {
		t.Fatalf("a current mark: %v %q", ensured, rev)
	}
	if err := worker.InOrg(s.system(), func(ctx context.Context, q *pgstore.Queries) error {
		return q.ClearOrganizationIdentityEnsured(ctx, s.org)
	}); err != nil {
		t.Fatal(err)
	}
	if ensured, rev := s.ensureMark(t); ensured || rev != "rev-a" {
		t.Fatalf("a cleared mark: %v %q (the revision stays for the record)", ensured, rev)
	}
}
