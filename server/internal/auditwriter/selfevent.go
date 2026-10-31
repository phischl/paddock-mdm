package auditwriter

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// selfActorID is the actor of every event the audit writer records about its own work.
const selfActorID = "audit-writer"

// RecordSelf records an event of the audit writer itself through w.WriteBatch, the path every event takes (index row,
// WORM object, partition ensured, sealed-day guard; plan M10 decision 24, amendment A1). It fills Schema, EventID,
// OccurredAt, Source and Actor when they are empty and validates the event. It opens its own writer transaction, so
// it MUST NOT be called inside an InWriter transaction.
func RecordSelf(ctx context.Context, w *Writer, ev audit.Event) error {
	if ev.Schema == "" {
		ev.Schema = audit.Schema
	}
	if ev.EventID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		ev.EventID = id
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = audit.Timestamp(time.Now())
	}
	if ev.Source == "" {
		ev.Source = audit.SourceSystem
	}
	if ev.Actor.Type == "" {
		ev.Actor = audit.Actor{Type: audit.ActorSystem, ID: selfActorID, Display: selfActorID}
	}
	if ev.CorrelationID == "" {
		ev.CorrelationID = selfActorID + "-" + ev.EventID.String()
	}
	if err := Validate(ev); err != nil {
		return fmt.Errorf("auditwriter: self event %s: %w", ev.Code, err)
	}
	if _, err := w.WriteBatch(ctx, []audit.Event{ev}); err != nil {
		return fmt.Errorf("auditwriter: write self event %s: %w", ev.Code, err)
	}
	return nil
}
