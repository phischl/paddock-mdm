package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// TestInDeletedOrg (plan M17 decision 18, §8 test 5): a platform administrator reads the events of a deleted
// organization and only of it; an active organization, an unknown one and the platform pseudo-organization are
// ErrNotDeleted; an organization administrator, also of the deleted organization, and the system are refused too; the
// read-only variant refuses writes.
func TestInDeletedOrg(t *testing.T) {
	ctx := context.Background()
	penv, aenv := sharedPaddock(t), sharedAudit(t)
	super, err := pgx.Connect(ctx, penv.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	deleted, active, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := super.Exec(ctx, `INSERT INTO organization (id, slug, name, status, deletion_requested_at, delete_after, deleted_at)
		VALUES ($1, $2, 'Gone', 'deleted', now(), now(), now())`, deleted, "gd"+deleted.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, `INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Live', 'active')`,
		active, "ga"+active.String()[24:]); err != nil {
		t.Fatal(err)
	}
	platform, err := db.NewPlatformPool(ctx, penv.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer platform.Close()
	writer, err := db.NewAuditWriterPool(ctx, aenv.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := db.NewAuditReader(ctx, aenv.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, org := range []uuid.UUID{deleted, active, other} {
		insertAuditEvent(t, writer, org)
	}

	admin := principal.With(ctx, principal.Principal{Kind: principal.KindPlatformAdmin, Role: principal.RolePlatform})
	list := func(ctx context.Context, q *auditstore.Queries) ([]auditstore.AuditEvent, error) {
		return q.ListAuditEvents(ctx, auditstore.ListAuditEventsParams{
			FromTime: time.Now().Add(-time.Hour), ToTime: time.Now().Add(time.Hour), MaxRows: 1000})
	}
	err = reader.InDeletedOrg(admin, platform, deleted, func(ctx context.Context, q *auditstore.Queries) error {
		events, err := list(ctx, q)
		if err != nil {
			return err
		}
		if len(events) != 1 || events[0].OrganizationID != deleted {
			t.Errorf("events of the deleted organization: %+v", events)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = reader.InDeletedOrg(admin, platform, deleted, func(ctx context.Context, q *auditstore.Queries) error {
		_, err := q.InsertAuditExport(ctx, auditstore.InsertAuditExportParams{ID: uuid.New(), OrganizationID: deleted,
			FromDay: time.Now(), ToDay: time.Now(), Purpose: "x", RequestedBy: []byte(`{}`), CorrelationID: "c"})
		return err
	})
	if err == nil {
		t.Error("the read-only variant inserted an export")
	}

	ran := false
	never := func(context.Context, *auditstore.Queries) error { ran = true; return nil }
	for name, c := range map[string]struct {
		ctx context.Context
		org uuid.UUID
	}{
		"active organization":      {admin, active},
		"unknown organization":     {admin, uuid.Must(uuid.NewV7())},
		"platform pseudo-org":      {admin, audit.PlatformOrganizationID},
		"organization admin":       {principal.With(ctx, principal.Principal{Kind: principal.KindAdmin, OrganizationID: deleted, Role: principal.RoleOrgAdmin}), deleted},
		"other organization admin": {orgCtx(other), deleted},
		"system":                   {principal.With(ctx, principal.Principal{Kind: principal.KindSystem}), deleted},
		"no principal":             {ctx, deleted},
	} {
		for _, run := range []func(context.Context, *db.PlatformPool, uuid.UUID, func(context.Context, *auditstore.Queries) error) error{
			reader.InDeletedOrg, reader.InDeletedOrgWrite} {
			if err := run(c.ctx, platform, c.org, never); !errors.Is(err, db.ErrNotDeleted) {
				t.Errorf("%s: %v, want ErrNotDeleted", name, err)
			}
		}
	}
	if ran {
		t.Fatal("a refused call ran its function")
	}
}
