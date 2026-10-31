package auditwriter_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// TestRecordSelf: RecordSelf fills the system fields of an audit-writer event and writes it to the index; an event
// that fails validation is not written.
func TestRecordSelf(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	ev := audit.Event{
		OrganizationID: org, Code: audit.CodeRetentionPurged, Outcome: audit.OutcomeSuccess,
		Params: map[string]any{"store": "audit_index"},
	}
	if err := auditwriter.RecordSelf(ctx, s.writer, ev); err != nil {
		t.Fatal(err)
	}
	var source, actor, correlation string
	if err := s.super.QueryRow(ctx,
		"SELECT source, actor->>'id', correlation_id FROM audit_event WHERE organization_id = $1 AND code = $2",
		org, string(audit.CodeRetentionPurged)).Scan(&source, &actor, &correlation); err != nil {
		t.Fatal(err)
	}
	if source != audit.SourceSystem || actor != "audit-writer" || correlation == "" {
		t.Errorf("recorded source %q, actor %q, correlation %q", source, actor, correlation)
	}

	bad := ev
	bad.Outcome = "maybe"
	if err := auditwriter.RecordSelf(ctx, s.writer, bad); err == nil {
		t.Error("an invalid outcome was recorded")
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE organization_id = $1", org); n != 1 {
		t.Errorf("%d events for the organization, want 1", n)
	}
}
