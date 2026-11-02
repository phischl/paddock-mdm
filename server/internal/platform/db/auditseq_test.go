package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

func newAuditPools(t *testing.T) (*db.AuditWriterPool, *db.AuditReader) {
	t.Helper()
	env := sharedAudit(t)
	ctx := context.Background()
	writer, err := db.NewAuditWriterPool(ctx, env.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	reader, err := db.NewAuditReader(ctx, env.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	return writer, reader
}

func insertAuditEventSeq(t *testing.T, writer *db.AuditWriterPool, org uuid.UUID, seq int64) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()
	err := writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.EnsureAuditPartition(ctx, now); err != nil {
			return err
		}
		_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
			EventID: id, OrganizationID: org, OccurredAt: now, RecordedAt: now,
			Code: "device_group.created", Outcome: "success", Source: "portal",
			Actor: []byte(`{"type":"system","step_up":false}`), Params: []byte(`{}`), CorrelationID: "test",
			ObjectKey: "org/" + org.String() + "/test", CommitSeq: seq,
		})
		return err
	})
	if err != nil {
		t.Fatalf("insert audit event: %v", err)
	}
	return id
}

// TestListAuditEventsAfter: the commit-order read returns the organization's events after the cursor in ascending
// commit_seq, and LatestCommitSeq is the maximum (plan M9 decision 4).
func TestListAuditEventsAfter(t *testing.T) {
	writer, reader := newAuditPools(t)
	org, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, seq := range []int64{3, 1, 4, 2} {
		insertAuditEventSeq(t, writer, org, seq)
	}
	insertAuditEventSeq(t, writer, other, 9)

	err := reader.InOrg(orgCtx(org), func(ctx context.Context, q *auditstore.Queries) error {
		events, err := q.ListAuditEventsAfter(ctx, auditstore.ListAuditEventsAfterParams{After: 1, MaxRows: 2})
		if err != nil {
			return err
		}
		if len(events) != 2 || events[0].CommitSeq != 2 || events[1].CommitSeq != 3 {
			t.Errorf("ListAuditEventsAfter(after=1, limit=2) = %v, want commit_seq 2, 3", seqs(events))
		}
		all, err := q.ListAuditEventsAfter(ctx, auditstore.ListAuditEventsAfterParams{After: 0, MaxRows: 100})
		if err != nil {
			return err
		}
		if got := seqs(all); len(got) != 4 || got[0] != 1 || got[3] != 4 {
			t.Errorf("ListAuditEventsAfter(after=0) = %v, want 1..4", got)
		}
		for _, e := range all {
			if e.OrganizationID != org {
				t.Errorf("reader of org sees an event of %s", e.OrganizationID)
			}
		}
		latest, err := q.LatestCommitSeq(ctx)
		if err != nil {
			return err
		}
		if latest != 4 {
			t.Errorf("LatestCommitSeq = %d, want 4", latest)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	empty := uuid.Must(uuid.NewV7())
	err = reader.InOrg(orgCtx(empty), func(ctx context.Context, q *auditstore.Queries) error {
		latest, err := q.LatestCommitSeq(ctx)
		if err == nil && latest != 0 {
			t.Errorf("LatestCommitSeq of an organization without events = %d, want 0", latest)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func seqs(events []auditstore.AuditEvent) []int64 {
	out := make([]int64, 0, len(events))
	for _, e := range events {
		out = append(out, e.CommitSeq)
	}
	return out
}

// TestAuditReaderInPlatformScope: the platform scope reads only the platform pseudo-organization's events, without
// a principal in the context (plan M9 decision 5).
func TestAuditReaderInPlatformScope(t *testing.T) {
	writer, reader := newAuditPools(t)
	platformEvent := insertAuditEventSeq(t, writer, audit.PlatformOrganizationID, 1)
	insertAuditEventSeq(t, writer, uuid.Must(uuid.NewV7()), 1)

	err := reader.InPlatformScope(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		events, err := q.ListAuditEvents(ctx, auditstore.ListAuditEventsParams{
			FromTime: time.Now().Add(-time.Hour), ToTime: time.Now().Add(time.Hour), MaxRows: 10000,
		})
		if err != nil {
			return err
		}
		found := false
		for _, e := range events {
			if e.OrganizationID != audit.PlatformOrganizationID {
				t.Errorf("platform scope sees an event of %s", e.OrganizationID)
			}
			found = found || e.EventID == platformEvent
		}
		if !found {
			t.Error("platform scope does not see the platform event")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAuditReaderCannotReadOrgSeq: audit_org_seq belongs to the writer alone (plan M9 decision 1).
func TestAuditReaderCannotReadOrgSeq(t *testing.T) {
	env := sharedAudit(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, "SELECT * FROM audit_org_seq")
	expectPermissionDenied(t, "paddock_audit_reader SELECT audit_org_seq", err)
}
