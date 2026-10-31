package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// PGStore is the Store and Index of the notifier role: the paddock database under paddock_notifier, the audit index
// under paddock_audit_reader, and audit events through the ActionRunner in the transaction of the state they describe.
type PGStore struct {
	pool   *db.NotifierPool
	reader *db.AuditReader
	runner *app.ActionRunner
}

// NewPGStore creates the store; runner MUST be built on pool, with app.WithPlatformScope(pool.InPlatformScope).
func NewPGStore(pool *db.NotifierPool, reader *db.AuditReader, runner *app.ActionRunner) *PGStore {
	return &PGStore{pool: pool, reader: reader, runner: runner}
}

// scopeContext carries the notifier's system principal of the scope (the nil organization for the platform).
func scopeContext(ctx context.Context, sc Scope) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "notifier", OrganizationID: sc.Org})
}

func (s *PGStore) tx(ctx context.Context, sc Scope, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	ctx = scopeContext(ctx, sc)
	if sc.Platform() {
		return s.pool.InPlatformScope(ctx, fn)
	}
	return s.pool.InOrg(ctx, fn)
}

// record runs fn and records rec in the same transaction; without rec it is a plain transaction.
func (s *PGStore) record(ctx context.Context, sc Scope, rec *Record, dest uuid.UUID, name string, correlation uuid.UUID,
	fn func(ctx context.Context, q *pgstore.Queries) error) error {
	if rec == nil {
		return s.tx(ctx, sc, fn)
	}
	scope := app.ScopeOrg
	if sc.Platform() {
		scope = app.ScopePlatform
	}
	spec := app.ActionSpec{
		Code: rec.Code, Params: rec.Params,
		Target: &audit.Target{Type: "notification_destination", ID: dest.String(), Display: name},
	}
	if correlation != uuid.Nil {
		spec.CorrelationID = correlation.String()
	}
	run := func(ctx context.Context, q *pgstore.Queries, _ app.Recorder) error { return fn(ctx, q) }
	if rec.Failure == nil {
		return s.runner.RunTx(scopeContext(ctx, sc), scope, spec, run)
	}
	err := s.runner.RunTxRefusal(scopeContext(ctx, sc), scope, spec, rec.Failure, run)
	if errors.Is(err, rec.Failure) {
		return nil
	}
	return err
}

// Organizations lists every organization.
func (s *PGStore) Organizations(ctx context.Context) ([]uuid.UUID, error) {
	return s.pool.OrganizationIDs(principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "notifier"}))
}

// Load reads the scope's slug, enabled destinations with their state and the pseudonym key ciphertext.
func (s *PGStore) Load(ctx context.Context, sc Scope) (ScopeData, error) {
	data := ScopeData{Slug: outbound.PlatformOrganization}
	err := s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		if !sc.Platform() {
			org, err := q.GetOrganization(ctx, sc.Org)
			if err != nil {
				return fmt.Errorf("organization: %w", err)
			}
			data.Slug = org.Slug
			key, err := q.GetNotifierPseudonymKey(ctx)
			switch {
			case err == nil:
				data.PseudonymKey = key
			case !db.IsNoRows(err):
				return fmt.Errorf("pseudonym key: %w", err)
			}
		}
		rows, err := q.ListNotifierDestinations(ctx)
		if err != nil {
			return fmt.Errorf("destinations: %w", err)
		}
		for _, r := range rows {
			data.Rows = append(data.Rows, toRow(r))
		}
		return nil
	})
	return data, err
}

func toRow(r pgstore.ListNotifierDestinationsRow) Row {
	codes := make([]audit.Code, len(r.Codes))
	for i, c := range r.Codes {
		codes[i] = audit.Code(c)
	}
	row := Row{
		Destination: Destination{
			ID: r.ID, Org: r.OrganizationID, Type: outbound.Type(r.Type), Name: r.Name,
			Filter: outbound.FilterMode(r.FilterMode), Codes: codes, Pseudonymize: r.PseudonymizeUsers,
			IncludeParams: r.IncludeParams, HeartbeatInterval: time.Duration(r.HeartbeatIntervalS) * time.Second,
			Recipients: r.Recipients, EmailMinInterval: time.Duration(r.EmailMinIntervalS) * time.Second,
		},
		State: State{
			Cursor: r.CursorCommitSeq, StartAtLatest: r.StartAtLatest, ForwardSeq: r.ForwardSeq, Status: r.Status,
			ConsecutiveFailures: int(r.ConsecutiveFailures), FirstFailureAt: r.FirstFailureAt,
			StalledSince: r.StalledSince, LastSuccessAt: r.LastSuccessAt, NextAttemptAt: r.NextAttemptAt,
			LastHeartbeatAt: r.LastHeartbeatAt,
		},
	}
	if r.PendingDeliveryID.Valid {
		row.State.Pending = r.PendingDeliveryID.UUID
	}
	if r.UrlCiphertext != nil {
		row.URLCiphertext = *r.UrlCiphertext
	}
	if r.SecretCiphertext != nil {
		row.SecretCiphertext = *r.SecretCiphertext
	}
	return row
}

// StartAtLatest resolves a skip request (Store).
func (s *PGStore) StartAtLatest(ctx context.Context, sc Scope, dest uuid.UUID, latest int64, dropped uuid.UUID) (
	int64, bool, error) {
	var cursor int64
	ok := false
	err := s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		cursor, err = q.StartNotifierCursorAtLatest(ctx, pgstore.StartNotifierCursorAtLatestParams{
			Latest: latest, DestinationID: dest,
		})
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		ok = true
		if dropped != uuid.Nil {
			return q.SkipNotifierDelivery(ctx, dropped)
		}
		return nil
	})
	return cursor, ok, err
}

// NextTest returns the oldest requested test delivery of the destination.
func (s *PGStore) NextTest(ctx context.Context, sc Scope, dest uuid.UUID) (TestDelivery, bool, error) {
	var t TestDelivery
	found := false
	err := s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.NextNotifierTestDelivery(ctx, dest)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		t, found = TestDelivery{ID: row.ID}, true
		if row.RequestedBy != nil {
			t.RequestedBy = *row.RequestedBy
		}
		return nil
	})
	return t, found, err
}

// FinishTest stores a test result and records notification.test_sent.
func (s *PGStore) FinishTest(ctx context.Context, sc Scope, r TestResult) error {
	rec := r.Record
	return s.record(ctx, sc, &rec, r.Destination, r.Name, r.Delivery, func(ctx context.Context, q *pgstore.Queries) error {
		at, ok := r.At, r.Class == ""
		p := pgstore.FinishNotifierTestDeliveryParams{ID: r.Delivery}
		var testError *string
		if ok {
			p.DeliveredAt = &at
		} else {
			p.LastError, testError = &r.Class, &r.Class
		}
		if err := q.FinishNotifierTestDelivery(ctx, p); err != nil {
			return err
		}
		return q.SetNotifierTestResult(ctx, pgstore.SetNotifierTestResultParams{
			At: &at, Ok: &ok, TestError: testError, DestinationID: r.Destination,
		})
	})
}

// Pending reads a pending batch.
func (s *PGStore) Pending(ctx context.Context, sc Scope, delivery uuid.UUID) (PendingBatch, error) {
	var p PendingBatch
	err := s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		d, err := q.GetNotifierDelivery(ctx, delivery)
		if err != nil {
			return err
		}
		refs, err := q.ListNotifierDeliveryEvents(ctx, delivery)
		if err != nil {
			return err
		}
		p = PendingBatch{ID: d.ID, Attempts: int(d.Attempts)}
		for _, r := range refs {
			p.Refs = append(p.Refs, EventRef{ForwardSeq: r.ForwardSeq, EventID: r.EventID, CommitSeq: r.CommitSeq})
		}
		return nil
	})
	return p, err
}

// CreateBatch inserts the delivery and its events and makes it the destination's pending batch.
func (s *PGStore) CreateBatch(ctx context.Context, sc Scope, dest uuid.UUID, b NewBatch) error {
	from, to := b.Refs[0].ForwardSeq, b.Refs[len(b.Refs)-1].ForwardSeq
	return s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		if err := q.InsertNotifierDelivery(ctx, pgstore.InsertNotifierDeliveryParams{
			ID: b.ID, DestinationID: dest, OrganizationID: sc.Org, Kind: outbound.KindEvents,
			ForwardFrom: &from, ForwardTo: &to, EventCount: int32(len(b.Refs)), //nolint:gosec // at most MaxBatch
		}); err != nil {
			return err
		}
		ev := pgstore.InsertNotifierDeliveryEventsParams{DestinationID: dest, OrganizationID: sc.Org, DeliveryID: b.ID}
		for _, r := range b.Refs {
			ev.ForwardSeqs = append(ev.ForwardSeqs, r.ForwardSeq)
			ev.EventIds = append(ev.EventIds, r.EventID)
			ev.CommitSeqs = append(ev.CommitSeqs, r.CommitSeq)
		}
		if err := q.InsertNotifierDeliveryEvents(ctx, ev); err != nil {
			return err
		}
		return q.SetNotifierPending(ctx, pgstore.SetNotifierPendingParams{
			ForwardSeq: to, DeliveryID: uuid.NullUUID{UUID: b.ID, Valid: true}, DestinationID: dest,
		})
	})
}

// CreateHeartbeat inserts a heartbeat delivery.
func (s *PGStore) CreateHeartbeat(ctx context.Context, sc Scope, dest, delivery uuid.UUID) error {
	return s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		return q.InsertNotifierDelivery(ctx, pgstore.InsertNotifierDeliveryParams{
			ID: delivery, DestinationID: dest, OrganizationID: sc.Org, Kind: outbound.KindHeartbeat,
		})
	})
}

// AdvanceCursor moves the cursor past events that matched nothing.
func (s *PGStore) AdvanceCursor(ctx context.Context, sc Scope, dest uuid.UUID, cursor int64) error {
	return s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		return q.AdvanceNotifierCursor(ctx, pgstore.AdvanceNotifierCursorParams{CursorCommitSeq: cursor, DestinationID: dest})
	})
}

// Succeeded stores a successful delivery and records its event (notification.delivered for event batches).
func (s *PGStore) Succeeded(ctx context.Context, sc Scope, r Success) error {
	return s.record(ctx, sc, r.Record, r.Destination, r.Name, r.Delivery, func(ctx context.Context, q *pgstore.Queries) error {
		if err := q.NotifierDeliverySucceeded(ctx, pgstore.NotifierDeliverySucceededParams{At: &r.At, ID: r.Delivery}); err != nil {
			return err
		}
		return q.NotifierDestinationSucceeded(ctx, pgstore.NotifierDestinationSucceededParams{
			CursorCommitSeq: r.Cursor, At: &r.At, DestinationID: r.Destination,
		})
	})
}

// Resumed ends a stall and records notification.destination_resumed.
func (s *PGStore) Resumed(ctx context.Context, sc Scope, r Resumption) error {
	rec := r.Record
	return s.record(ctx, sc, &rec, r.Destination, r.Name, uuid.Nil, func(ctx context.Context, q *pgstore.Queries) error {
		return q.NotifierDestinationResumed(ctx, r.Destination)
	})
}

// Failed stores a failed delivery and, at the stall, records notification.destination_stalled.
func (s *PGStore) Failed(ctx context.Context, sc Scope, f Failure) error {
	return s.record(ctx, sc, f.Record, f.Destination, f.Name, f.Delivery, func(ctx context.Context, q *pgstore.Queries) error {
		if err := q.NotifierDeliveryFailed(ctx, pgstore.NotifierDeliveryFailedParams{LastError: &f.Class, ID: f.Delivery}); err != nil {
			return err
		}
		return q.NotifierDestinationFailed(ctx, pgstore.NotifierDestinationFailedParams{
			ConsecutiveFailures: int32(f.ConsecutiveFailures), //nolint:gosec // a failure counter
			FirstFailureAt:      &f.FirstFailureAt, LastError: &f.Class, At: &f.At, NextAttemptAt: &f.NextAttemptAt,
			Status: f.Status, StalledSince: f.StalledSince, DestinationID: f.Destination,
		})
	})
}

// Lookups lists the unresolved pseudonym lookups.
func (s *PGStore) Lookups(ctx context.Context, sc Scope) ([]Lookup, error) {
	var out []Lookup
	err := s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.ListNotifierPseudonymLookups(ctx)
		for _, r := range rows {
			out = append(out, Lookup{ID: r.ID, Pseudonym: r.Pseudonym})
		}
		return err
	})
	return out, err
}

// Usernames lists the user and administrator names of the organization.
func (s *PGStore) Usernames(ctx context.Context, sc Scope) ([]string, error) {
	var out []string
	err := s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.ListNotifierUsernames(ctx)
		return err
	})
	return out, err
}

// ResolveLookup stores the answer of a lookup ("" when no name matched).
func (s *PGStore) ResolveLookup(ctx context.Context, sc Scope, id uuid.UUID, username string, at time.Time) error {
	return s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		return q.ResolveNotifierPseudonymLookup(ctx, pgstore.ResolveNotifierPseudonymLookupParams{
			ResolvedUsername: &username, At: &at, ID: id,
		})
	})
}

// PurgeLookups deletes the lookups created before before.
func (s *PGStore) PurgeLookups(ctx context.Context, sc Scope, before time.Time) error {
	return s.tx(ctx, sc, func(ctx context.Context, q *pgstore.Queries) error {
		return q.DeleteExpiredNotifierPseudonymLookups(ctx, before)
	})
}

func (s *PGStore) read(ctx context.Context, sc Scope, fn func(ctx context.Context, q *auditstore.Queries) error) error {
	ctx = scopeContext(ctx, sc)
	if sc.Platform() {
		return s.reader.InPlatformScope(ctx, fn)
	}
	return s.reader.InOrg(ctx, fn)
}

// Latest returns the scope's newest commit sequence (Index).
func (s *PGStore) Latest(ctx context.Context, sc Scope) (int64, error) {
	var latest int64
	err := s.read(ctx, sc, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		latest, err = q.LatestCommitSeq(ctx)
		return err
	})
	return latest, err
}

// After returns up to max events after the commit sequence after (Index).
func (s *PGStore) After(ctx context.Context, sc Scope, after int64, max int) ([]IndexedEvent, error) {
	var out []IndexedEvent
	err := s.read(ctx, sc, func(ctx context.Context, q *auditstore.Queries) error {
		rows, err := q.ListAuditEventsAfter(ctx, auditstore.ListAuditEventsAfterParams{
			After: after, MaxRows: int32(max), //nolint:gosec // at most ScanWindow
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			ev, err := toEvent(r)
			if err != nil {
				return fmt.Errorf("event %s: %w", r.EventID, err)
			}
			out = append(out, IndexedEvent{CommitSeq: r.CommitSeq, Event: ev})
		}
		return nil
	})
	return out, err
}

// toEvent maps an index row to the stored event (paddock.audit.v1); the writer keeps error_code in params.
func toEvent(r auditstore.AuditEvent) (audit.Event, error) {
	ev := audit.Event{
		Schema: audit.Schema, EventID: r.EventID, OrganizationID: r.OrganizationID, OccurredAt: r.OccurredAt.UTC(),
		RecordedAt: r.RecordedAt.UTC(), Code: audit.Code(r.Code), Outcome: audit.Outcome(r.Outcome), Source: r.Source,
		CorrelationID: r.CorrelationID, Params: map[string]any{},
	}
	if err := json.Unmarshal(r.Actor, &ev.Actor); err != nil {
		return ev, err
	}
	if len(r.Target) > 0 && string(r.Target) != "null" {
		ev.Target = &audit.Target{}
		if err := json.Unmarshal(r.Target, ev.Target); err != nil {
			return ev, err
		}
	}
	if len(r.Params) > 0 && string(r.Params) != "null" {
		if err := json.Unmarshal(r.Params, &ev.Params); err != nil {
			return ev, err
		}
	}
	if code, ok := ev.Params["error_code"].(string); ok {
		ev.ErrorCode = code
		delete(ev.Params, "error_code")
	}
	return ev, nil
}
