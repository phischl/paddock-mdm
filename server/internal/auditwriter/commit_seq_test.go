package auditwriter_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

func (s stack) commitSeq(t *testing.T, eventID uuid.UUID) int64 {
	t.Helper()
	var seq int64
	if err := s.super.QueryRow(context.Background(), "SELECT commit_seq FROM audit_event WHERE event_id = $1", eventID).Scan(&seq); err != nil {
		t.Fatalf("commit_seq of %s: %v", eventID, err)
	}
	return seq
}

func (s stack) lastSeq(t *testing.T, org uuid.UUID) int64 {
	t.Helper()
	var last int64
	if err := s.super.QueryRow(context.Background(), "SELECT last_seq FROM audit_org_seq WHERE organization_id = $1", org).Scan(&last); err != nil {
		t.Fatalf("last_seq of %s: %v", org, err)
	}
	return last
}

// TestCommitSeqFollowsCommitOrder: two batches of one organization get contiguous numbers from 1, in sortEvents order
// within a batch, and a late event (older occurred_at) written later gets the higher commit_seq (plan M9 decision 2).
func TestCommitSeqFollowsCommitOrder(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	now := time.Now().UTC()

	early, later := event(org, now.Add(-time.Minute), "device_group.created"), event(org, now, "device_group.updated")
	if _, err := s.writer.WriteBatch(ctx, []audit.Event{later, early, event(other, now, "device_group.created")}); err != nil {
		t.Fatal(err)
	}
	late := event(org, now.Add(-48*time.Hour), "device_group.deleted")
	if _, err := s.writer.WriteBatch(ctx, []audit.Event{late}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		id   uuid.UUID
		want int64
	}{{"early", early.EventID, 1}, {"later", later.EventID, 2}, {"late", late.EventID, 3}} {
		if got := s.commitSeq(t, c.id); got != c.want {
			t.Errorf("%s event: commit_seq %d, want %d", c.name, got, c.want)
		}
	}
	if got := s.lastSeq(t, org); got != 3 {
		t.Errorf("audit_org_seq.last_seq = %d, want 3", got)
	}
	if got := s.lastSeq(t, other); got != 1 {
		t.Errorf("audit_org_seq.last_seq of the other organization = %d, want 1", got)
	}

	if n, err := s.writer.WriteBatch(ctx, []audit.Event{late}); err != nil || n != 0 {
		t.Fatalf("redelivery: wrote %d, err %v; want 0, nil", n, err)
	}
	if got := s.lastSeq(t, org); got != 3 {
		t.Errorf("redelivery moved audit_org_seq.last_seq to %d, want 3", got)
	}
}

// TestInsertWithoutRowIsAnError: an event a concurrent writer indexed after withoutExisting makes WriteBatch fail
// and roll back instead of skipping it, which would leave a gap in commit_seq (plan M9 decision 2).
func TestInsertWithoutRowIsAnError(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()
	if _, err := s.writer.WriteBatch(ctx, []audit.Event{event(org, now, "device_group.created")}); err != nil {
		t.Fatal(err)
	}

	raced, second := event(org, now, "device_group.updated"), event(org, now.Add(time.Second), "device_group.deleted")
	auditwriter.SetBeforeInsert(s.writer, func(ev audit.Event) {
		if ev.EventID != raced.EventID {
			return
		}
		if _, err := s.super.Exec(ctx, `INSERT INTO audit_event (event_id, organization_id, occurred_at, recorded_at, code,
			outcome, source, actor, params, correlation_id, object_key, commit_seq)
			VALUES ($1, $2, $3, now(), 'device_group.updated', 'success', 'portal', '{}', '{}', 'race', 'race', 0)`,
			ev.EventID, ev.OrganizationID, ev.OccurredAt); err != nil {
			t.Errorf("racing insert: %v", err)
		}
	})
	n, err := s.writer.WriteBatch(ctx, []audit.Event{raced, second})
	if err == nil || !strings.Contains(err.Error(), "already indexed by a concurrent writer") {
		t.Fatalf("WriteBatch = %d, %v; want the concurrent-writer error", n, err)
	}
	if got := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", second.EventID); got != 0 {
		t.Errorf("the batch's other event was indexed although the transaction failed")
	}
	if got := s.lastSeq(t, org); got != 1 {
		t.Errorf("audit_org_seq.last_seq = %d after the rollback, want 1", got)
	}
}

// TestObjectHasNoCommitSeq: commit_seq is index metadata and never enters a WORM object (amendment B1.4).
func TestObjectHasNoCommitSeq(t *testing.T) {
	body, err := auditwriter.EncodeObject([]audit.Event{event(uuid.Must(uuid.NewV7()), time.Now(), "device_group.created")})
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	raw, err := zr.DecodeAll(body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "device_group.created") {
		t.Fatalf("decoded object does not contain the event: %s", raw)
	}
	if strings.Contains(string(raw), "commit_seq") {
		t.Errorf("WORM object contains commit_seq: %s", raw)
	}
}
