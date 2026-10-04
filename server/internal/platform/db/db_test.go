package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paddock-mdm/paddock/server/internal/adapters/auditpg/auditstore"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

type fixture struct {
	org      *db.OrgPool
	platform *db.PlatformPool
	orgA     uuid.UUID
	orgB     uuid.UUID
	groupA   uuid.UUID
	groupB   uuid.UUID
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	env := sharedPaddock(t)
	ctx := context.Background()
	org, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(org.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)

	f := fixture{org: org, platform: platform, orgA: uuid.Must(uuid.NewV7()), orgB: uuid.Must(uuid.NewV7())}
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem})
	err = platform.InPlatform(sys, func(ctx context.Context, q *pgstore.Queries) error {
		for i, id := range []uuid.UUID{f.orgA, f.orgB} {
			slug := "org" + id.String()[24:] + string(rune('a'+i))
			if _, err := q.InsertOrganization(ctx, pgstore.InsertOrganizationParams{ID: id, Slug: slug, Name: slug, Status: "active"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed organizations: %v", err)
	}
	f.groupA = insertGroup(t, org, f.orgA, "group-a")
	f.groupB = insertGroup(t, org, f.orgB, "group-b")
	return f
}

func orgCtx(org uuid.UUID) context.Context {
	return principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, OrganizationID: org, Role: principal.RoleOrgAdmin})
}

func insertGroup(t *testing.T, pool *db.OrgPool, org uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	err := pool.InOrg(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: id, OrganizationID: org, Name: name})
		return err
	})
	if err != nil {
		t.Fatalf("insert device group: %v", err)
	}
	return id
}

func TestInOrgWithoutPrincipal(t *testing.T) {
	f := newFixture(t)
	called := false
	fn := func(context.Context, *pgstore.Queries) error { called = true; return nil }

	if err := f.org.InOrg(context.Background(), fn); !errors.Is(err, db.ErrNoOrganization) {
		t.Fatalf("InOrg without principal: got %v, want ErrNoOrganization", err)
	}
	platformAdmin := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin})
	if err := f.org.InOrg(platformAdmin, fn); !errors.Is(err, db.ErrNoOrganization) {
		t.Fatalf("InOrg with uuid.Nil organization: got %v, want ErrNoOrganization", err)
	}
	if called {
		t.Fatal("fn was called without an organization")
	}
}

func TestInPlatformRequiresPlatformPrincipal(t *testing.T) {
	f := newFixture(t)
	err := f.platform.InPlatform(orgCtx(f.orgA), func(context.Context, *pgstore.Queries) error { return nil })
	if !errors.Is(err, db.ErrForbiddenScope) {
		t.Fatalf("InPlatform as org admin: got %v, want ErrForbiddenScope", err)
	}
	if err := f.platform.InPlatform(context.Background(), func(context.Context, *pgstore.Queries) error { return nil }); !errors.Is(err, db.ErrForbiddenScope) {
		t.Fatalf("InPlatform without principal: got %v, want ErrForbiddenScope", err)
	}
}

// TestFailClosedWithoutOrgSetting: a raw query as paddock_api without set_config fails instead of returning rows.
func TestFailClosedWithoutOrgSetting(t *testing.T) {
	newFixture(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, sharedPaddock(t).API)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	for _, table := range []string{"device_group", "admin_account", "organization", "action"} {
		rows, err := conn.Query(ctx, "SELECT * FROM "+table)
		if err == nil {
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
		}
		if err == nil {
			t.Errorf("SELECT from %s without paddock.org_id succeeded; RLS does not fail closed", table)
		}
	}
}

func TestCrossOrganizationAccess(t *testing.T) {
	f := newFixture(t)

	err := f.org.InOrg(orgCtx(f.orgA), func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDeviceGroup(ctx, f.groupB); !db.IsNoRows(err) {
			t.Errorf("read of org B group from org A: got %v, want no rows", err)
		}
		if _, err := q.UpdateDeviceGroup(ctx, pgstore.UpdateDeviceGroupParams{ID: f.groupB, Name: "stolen"}); !db.IsNoRows(err) {
			t.Errorf("update of org B group from org A: got %v, want no rows", err)
		}
		n, err := q.DeleteDeviceGroup(ctx, f.groupB)
		if err != nil || n != 0 {
			t.Errorf("delete of org B group from org A: %d rows, err %v; want 0 rows", n, err)
		}
		groups, err := q.ListDeviceGroups(ctx, pgstore.ListDeviceGroupsParams{MaxRows: 1000})
		if err != nil {
			return err
		}
		for _, g := range groups {
			if g.OrganizationID != f.orgA {
				t.Errorf("list in org A returned a group of organization %s", g.OrganizationID)
			}
		}
		if _, err := q.GetOrganization(ctx, f.orgB); !db.IsNoRows(err) {
			t.Errorf("read of organization B from org A: got %v, want no rows", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Writing a row for another organization violates the WITH CHECK clause.
	err = f.org.InOrg(orgCtx(f.orgA), func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.InsertDeviceGroup(ctx, pgstore.InsertDeviceGroupParams{ID: uuid.Must(uuid.NewV7()), OrganizationID: f.orgB, Name: "planted"})
		return err
	})
	if err == nil {
		t.Fatal("insert of an org B row from org A succeeded")
	}

	// Org B's row is untouched.
	err = f.org.InOrg(orgCtx(f.orgB), func(ctx context.Context, q *pgstore.Queries) error {
		g, err := q.GetDeviceGroup(ctx, f.groupB)
		if err != nil {
			return err
		}
		if g.Name != "group-b" {
			t.Errorf("org B group was modified: %q", g.Name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRawCrossOrganizationStatements checks RLS with hand-written SQL, independent of the generated queries.
func TestRawCrossOrganizationStatements(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, sharedPaddock(t).API)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", f.orgA.String()); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE device_group SET name = 'x' WHERE id = $1",
		"DELETE FROM device_group WHERE id = $1",
	} {
		tag, err := tx.Exec(ctx, stmt, f.groupB)
		if err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("%s affected %d rows of organization B", stmt, tag.RowsAffected())
		}
	}
}

func TestAPIRoleGrants(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, sharedPaddock(t).API)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", f.orgA.String()); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, "SELECT * FROM outbox")
	expectPermissionDenied(t, "paddock_api SELECT outbox", err)
}

func TestOrganizationIDBySlug(t *testing.T) {
	f := newFixture(t)
	var slug string
	sys := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem})
	if err := f.platform.InPlatform(sys, func(ctx context.Context, q *pgstore.Queries) error {
		o, err := q.GetOrganization(ctx, f.orgB)
		slug = o.Slug
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The SECURITY DEFINER function resolves slugs for paddock_api although organization is FORCE RLS.
	err := f.org.InOrg(orgCtx(f.orgA), func(ctx context.Context, q *pgstore.Queries) error {
		id, err := q.OrganizationIDBySlug(ctx, slug)
		if err != nil {
			return err
		}
		if id != f.orgB {
			t.Errorf("OrganizationIDBySlug(%q) = %s, want %s", slug, id, f.orgB)
		}
		missing, err := q.OrganizationIDBySlug(ctx, "does-not-exist")
		if err != nil {
			return err
		}
		if missing != uuid.Nil {
			t.Errorf("unknown slug resolved to %s", missing)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuditWriterTransactionTimeoutBounds(t *testing.T) {
	writer, err := db.NewAuditWriterPool(context.Background(), sharedAudit(t).Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, timeout := range []time.Duration{0, -time.Second, db.WriterTransactionTimeout + time.Second} {
		called := false
		err := writer.InWriterWithTimeout(context.Background(), timeout, func(context.Context, *auditstore.Queries) error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Errorf("InWriterWithTimeout(%s) = %v, called %v; want an error before the transaction", timeout, err, called)
		}
	}
}

func TestAuditWriterCannotUpdateOrDelete(t *testing.T) {
	env := sharedAudit(t)
	ctx := context.Background()
	writer, err := db.NewAuditWriterPool(ctx, env.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	org := uuid.Must(uuid.NewV7())
	insertAuditEvent(t, writer, org)

	conn, err := pgx.Connect(ctx, env.Writer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, stmt := range []string{
		"UPDATE audit_event SET code = 'x'",
		"DELETE FROM audit_event",
		"UPDATE audit_object SET event_count = 0",
		"DELETE FROM audit_manifest",
	} {
		_, err := conn.Exec(ctx, stmt)
		expectPermissionDenied(t, "paddock_audit_writer: "+stmt, err)
	}
}

// TestAuditReaderIsolation: RLS policies on the partitioned audit_event apply through the parent (stop condition S5).
func TestAuditReaderIsolation(t *testing.T) {
	env := sharedAudit(t)
	ctx := context.Background()
	writer, err := db.NewAuditWriterPool(ctx, env.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := db.NewAuditReader(ctx, env.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	orgA, orgB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	insertAuditEvent(t, writer, orgA)
	insertAuditEvent(t, writer, orgB)

	err = reader.InOrg(orgCtx(orgA), func(ctx context.Context, q *auditstore.Queries) error {
		events, err := q.ListAuditEvents(ctx, auditstore.ListAuditEventsParams{
			FromTime: time.Now().Add(-time.Hour), ToTime: time.Now().Add(time.Hour), MaxRows: 1000,
		})
		if err != nil {
			return err
		}
		if len(events) == 0 {
			t.Error("reader of org A sees no events")
		}
		for _, e := range events {
			if e.OrganizationID != orgA {
				t.Errorf("reader of org A sees an event of %s", e.OrganizationID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := pgx.Connect(ctx, env.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, "SELECT * FROM audit_object")
	expectPermissionDenied(t, "paddock_audit_reader SELECT audit_object", err)
	if err := reader.InOrg(context.Background(), func(context.Context, *auditstore.Queries) error { return nil }); !errors.Is(err, db.ErrNoOrganization) {
		t.Fatalf("AuditReader.InOrg without principal: got %v", err)
	}
}

func insertAuditEvent(t *testing.T, writer *db.AuditWriterPool, org uuid.UUID) {
	t.Helper()
	now := time.Now().UTC()
	err := writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.EnsureAuditPartition(ctx, now); err != nil {
			return err
		}
		_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
			EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: now, RecordedAt: now,
			Code: "device_group.created", Outcome: "success", Source: "portal",
			Actor: []byte(`{"type":"system","step_up":false}`), Params: []byte(`{}`), CorrelationID: "test",
			ObjectKey: "org/" + org.String() + "/test",
		})
		return err
	})
	if err != nil {
		t.Fatalf("insert audit event: %v", err)
	}
}

func expectPermissionDenied(t *testing.T, what string, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("%s: got %v, want permission denied (42501)", what, err)
	}
}

// TestLoginSettingsPerOrganization: every new organization gets its login settings row with the defaults (trigger of
// migration 00007), and each organization sees only its own row.
func TestLoginSettingsPerOrganization(t *testing.T) {
	f := newFixture(t)
	for _, org := range []uuid.UUID{f.orgA, f.orgB} {
		err := f.org.InOrg(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
			s, err := q.GetLoginSettings(ctx)
			if err != nil {
				return err
			}
			if s.OrganizationID != org || !s.HelloEnabled || s.HelloPinMinLength != 6 || s.UserLockSessionAction != "lock_screen" ||
				len(s.BreakGlassAccounts) != 0 || len(s.SudoersDAllowlist) != 1 || s.SudoersDAllowlist[0] != "README" || s.SudoLectureText == "" {
				t.Errorf("settings of %s: %+v", org, s)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
