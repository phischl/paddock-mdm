package app_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// offboardingStatusSQL moves an organization into status $2 the way the offboarding leaves it, with the deletion
// columns its consistency constraint requires.
const offboardingStatusSQL = `UPDATE organization SET status = $2, deleted_at = CASE WHEN $2 = 'deleted' THEN now() END,
	domains = CASE WHEN $2 = 'deleted' THEN '{}'::text[] ELSE domains END,
	deletion_requested_at = now(), delete_after = now(), deletion_uninstalls_issued = 0, deletion_uninstalls_skipped = 0
	WHERE id = $1`

// rowsOf counts the action and outbox rows of org.
func (d deletionWorld) rowsOf(t *testing.T, org uuid.UUID) (actions, outbox int) {
	t.Helper()
	return d.count(t, "SELECT count(*) FROM action WHERE organization_id = $1", org),
		d.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1", org)
}

func (d deletionWorld) domainsOf(t *testing.T, org uuid.UUID) []string {
	t.Helper()
	var domains []string
	if err := d.super.QueryRow(context.Background(), "SELECT domains FROM organization WHERE id = $1", org).Scan(&domains); err != nil {
		t.Fatal(err)
	}
	return domains
}

// holdStatusChange begins a transaction on its own connection that moves org into status and keeps it uncommitted,
// holding the organization row; commit commits it.
func holdStatusChange(t *testing.T, org uuid.UUID, status string) (pid uint32, commit func()) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, offboardingStatusSQL, org, status); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid, func() {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// awaitBlockedBy waits until a session waits for a lock that the session pid holds.
func (d deletionWorld) awaitBlockedBy(t *testing.T, pid uint32) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for d.count(t, "SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", int32(pid)) == 0 { //nolint:gosec // a backend PID
		if time.Now().After(deadline) {
			t.Fatal("no session waited for the held organization row")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestOrganizationSetDomainsOffboarding (PDK-1053): a platform domain change on an organization that is deleting or
// deleted is refused with 409 invalid_state and recorded once in the platform pseudo-organization; it writes no action
// or outbox row of the organization and leaves its domains as they are. An active organization's change still works
// and is recorded in the organization.
func TestOrganizationSetDomainsOffboarding(t *testing.T) {
	d := newDeletionWorld(t)
	for _, status := range []string{organization.StatusDeleting, organization.StatusDeleted} {
		org := d.otherOrg(t)
		d.exec(t, "UPDATE organization SET domains = $2 WHERE id = $1", org, []string{"keep-" + org.String()[24:] + ".example"})
		d.exec(t, offboardingStatusSQL, org, status)
		domains := d.domainsOf(t, org)
		actions, outbox := d.rowsOf(t, org)

		ctx := d.root(false)
		_, err := d.orgs.SetDomains(ctx, org, []string{"new-" + org.String()[24:] + ".example"})
		expectUninstallProblem(t, err, "invalid_state", 409, "the organization is "+status+": its domains cannot be changed")
		ev := d.attempt(t, ctx)
		expectAttempt(t, ev, audit.CodeOrganizationDomainsChanged, audit.OutcomeFailure, "invalid_state", audit.PlatformOrganizationID)
		if ev.Target == nil || ev.Target.ID != org.String() {
			t.Fatalf("%s: target %+v", status, ev.Target)
		}
		if a, o := d.rowsOf(t, org); a != actions || o != outbox {
			t.Fatalf("%s: the refusal wrote rows of the organization: action %d→%d, outbox %d→%d", status, actions, a, outbox, o)
		}
		if got := d.domainsOf(t, org); !slices.Equal(got, domains) {
			t.Fatalf("%s: domains %v, want %v", status, got, domains)
		}
	}

	active := d.otherOrg(t)
	want := "active-" + active.String()[24:] + ".example"
	ctx := d.root(false)
	out, err := d.orgs.SetDomains(ctx, active, []string{want})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Domains) != 1 || out.Domains[0] != want {
		t.Fatalf("domains %v", out.Domains)
	}
	expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationDomainsChanged, audit.OutcomeSuccess, "", active)
	if n := d.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND NOT payload ? 'code'", active); n == 0 {
		t.Fatal("the change queued no state change of the organization")
	}
}

// TestOrganizationSetDomainsRacesDeletionStart (PDK-1053): a domain change that reads the organization while the
// worker's start of the deletion is uncommitted waits for it and is refused once it commits; it writes no row of the
// organization.
func TestOrganizationSetDomainsRacesDeletionStart(t *testing.T) {
	d := newDeletionWorld(t)
	org := d.otherOrg(t)
	actions, outbox := d.rowsOf(t, org)
	pid, commit := holdStatusChange(t, org, organization.StatusDeleting)

	ctx := d.root(false)
	errs := make(chan error, 1)
	go func() {
		_, err := d.orgs.SetDomains(ctx, org, []string{"race-" + org.String()[24:] + ".example"})
		errs <- err
	}()
	d.awaitBlockedBy(t, pid)
	commit()

	expectUninstallProblem(t, <-errs, "invalid_state", 409, "the organization is deleting: its domains cannot be changed")
	expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationDomainsChanged, audit.OutcomeFailure, "invalid_state",
		audit.PlatformOrganizationID)
	if a, o := d.rowsOf(t, org); a != actions || o != outbox {
		t.Fatalf("the refused change wrote rows of the organization: action %d→%d, outbox %d→%d", actions, a, outbox, o)
	}
	if got := d.domainsOf(t, org); len(got) != 0 {
		t.Fatalf("domains %v", got)
	}
}

// TestOrganizationReprovisionRacesDeletionStart (PDK-1053): re-creating a provisioning_failed organization whose
// deletion the worker is starting waits for the start and then finds the slug taken; the organization stays deleting
// and gets no row.
func TestOrganizationReprovisionRacesDeletionStart(t *testing.T) {
	d := newDeletionWorld(t)
	org := d.otherOrg(t)
	d.exec(t, "UPDATE organization SET status = 'provisioning_failed' WHERE id = $1", org)
	var slug string
	if err := d.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", org).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	actions, outbox := d.rowsOf(t, org)
	pid, commit := holdStatusChange(t, org, organization.StatusDeleting)

	runner := app.NewActionRunner(d.api, d.platform, httpx.RequestID)
	orgs := app.NewOrganizations(runner, d.platform, newDirectory(), app.NewUninstalls(runner, d.api, d.cache), false)
	ctx := d.root(false)
	errs := make(chan error, 1)
	go func() {
		_, _, err := orgs.Create(ctx, slug, "Other")
		errs <- err
	}()
	d.awaitBlockedBy(t, pid)
	commit()

	expectUninstallProblem(t, <-errs, "slug_taken", 409, "")
	expectAttempt(t, d.attempt(t, ctx), audit.CodeOrganizationCreated, audit.OutcomeFailure, "slug_taken", audit.PlatformOrganizationID)
	var status string
	if err := d.super.QueryRow(context.Background(), "SELECT status FROM organization WHERE id = $1", org).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != organization.StatusDeleting {
		t.Fatalf("status %s after the refused reprovisioning, want deleting", status)
	}
	if a, o := d.rowsOf(t, org); a != actions || o != outbox {
		t.Fatalf("the refused reprovisioning wrote rows of the organization: action %d→%d, outbox %d→%d", actions, a, outbox, o)
	}
}
