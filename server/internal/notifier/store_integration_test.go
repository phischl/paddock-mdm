package notifier

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// world is the notifier on real databases: paddock_notifier, the platform lock pool and the audit reader.
type world struct {
	t      *testing.T
	super  *pgx.Conn
	writer *db.AuditWriterPool
	e      *Engine
	tr     *fakeTransport
	now    time.Time
	org    uuid.UUID
	seq    map[uuid.UUID]int64
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	pg, ag := pgtest.SharedPaddock(t), pgtest.SharedAudit(t)
	pool, err := db.NewNotifierPool(ctx, pg.Notifier, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	platform, err := db.NewPlatformPool(ctx, pg.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	reader, err := db.NewAuditReader(ctx, ag.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	writer, err := db.NewAuditWriterPool(ctx, ag.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	super, err := pgx.Connect(ctx, pg.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	w := &world{t: t, super: super, writer: writer, tr: &fakeTransport{}, now: time.Now().UTC().Truncate(time.Second),
		org: uuid.Must(uuid.NewV7()), seq: map[uuid.UUID]int64{}}
	w.exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'N', 'active')", w.org, "n"+w.org.String()[24:])
	// Each test starts with the platform scope empty, as it shares the database with the other tests of the package.
	w.exec("DELETE FROM notification_destination WHERE organization_id = $1", audit.PlatformOrganizationID)
	runner := app.NewActionRunner(&pool.OrgPool, platform, func(context.Context) string { return "" },
		app.WithPlatformScope(pool.InPlatformScope))
	store := NewPGStore(pool, reader, runner)
	w.e = NewEngine(Config{PollInterval: 5 * time.Second, StallAfter: time.Minute, Batch: 100,
		PublicAdminURL: "https://admin.example"}, platform, store, store, fakeKeys{},
		map[outbound.Type]Transport{outbound.TypeWebhook: w.tr}, NewMetrics(prometheus.NewRegistry()))
	w.e.now = func() time.Time { return w.now }
	if err := writer.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		return q.EnsureAuditPartition(ctx, w.now)
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.super.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) destination(org uuid.UUID, startAtLatest bool) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO notification_destination (id, organization_id, type, name, filter_mode, url_ciphertext, url_display,
		secret_ciphertext, created_by) VALUES ($1, $2, 'webhook', $3, 'security', $4, 'https://sink.example', $5, 'alice')`,
		id, org, "d"+id.String()[24:], "url:"+id.String(), "secret:"+id.String())
	w.exec(`INSERT INTO notification_destination_state (destination_id, organization_id, start_at_latest) VALUES ($1, $2, $3)`,
		id, org, startAtLatest)
	return id
}

// events indexes n events of org with the next commit sequence numbers, as the audit writer does.
func (w *world) events(org uuid.UUID, code audit.Code, n int) {
	w.t.Helper()
	err := w.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		for range n {
			w.seq[org]++
			if _, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
				EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: w.now, RecordedAt: w.now,
				Code: string(code), Outcome: "success", Source: "device",
				Actor: []byte(`{"type":"device","id":"x"}`), Target: []byte(`{"type":"device","id":"d1","display":"lt-01"}`),
				Params: []byte(`{"file":"/etc/sudoers.d/x"}`), CorrelationID: "c", ObjectKey: "k", CommitSeq: w.seq[org],
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) round() {
	w.t.Helper()
	if err := w.e.Round(context.Background()); err != nil {
		w.t.Fatalf("round: %v", err)
	}
}

type stateRow struct {
	cursor, forward int64
	status          string
	pending         *uuid.UUID
	failures        int
	startAtLatest   bool
}

func (w *world) state(dest uuid.UUID) stateRow {
	w.t.Helper()
	var s stateRow
	if err := w.super.QueryRow(context.Background(), `SELECT cursor_commit_seq, forward_seq, status, pending_delivery_id,
		consecutive_failures, start_at_latest FROM notification_destination_state WHERE destination_id = $1`, dest).
		Scan(&s.cursor, &s.forward, &s.status, &s.pending, &s.failures, &s.startAtLatest); err != nil {
		w.t.Fatal(err)
	}
	return s
}

// actions returns the outcome and params of the actions of code about dest, in order.
func (w *world) actions(org uuid.UUID, code audit.Code, dest uuid.UUID) []map[string]any {
	w.t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT outcome, params FROM action WHERE organization_id = $1
		AND code = $2 AND target->>'id' = $3 ORDER BY started_at, id`, org, string(code), dest.String())
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var outcome string
		var raw []byte
		if err := rows.Scan(&outcome, &raw); err != nil {
			w.t.Fatal(err)
		}
		p := map[string]any{}
		if err := json.Unmarshal(raw, &p); err != nil {
			w.t.Fatal(err)
		}
		p["_outcome"] = outcome
		out = append(out, p)
	}
	return out
}

// TestPGStoreDelivery: on the real roles the notifier skips history for a new destination, delivers, numbers and
// audits batches of an organization and of the platform (nil organization under paddock_notifier), and keeps the
// cursor, the failures and the stall in the database.
func TestPGStoreDelivery(t *testing.T) {
	w := newWorld(t)
	old := w.destination(w.org, true)
	w.events(w.org, tamper, 3)
	w.round()
	if s := w.state(old); s.cursor != 3 || s.startAtLatest || len(w.tr.sent) != 0 {
		t.Fatalf("start at latest: %+v, %d messages", s, len(w.tr.sent))
	}

	w.events(w.org, tamper, 2)
	platformDest := w.destination(audit.PlatformOrganizationID, false)
	w.events(audit.PlatformOrganizationID, audit.CodeAgentRolloutHalted, 1)
	w.round()
	byDest := map[uuid.UUID][]outbound.Message{}
	for _, s := range w.tr.sent {
		byDest[s.dest.ID] = append(byDest[s.dest.ID], s.msg)
	}
	if m := byDest[old]; len(m) != 1 || m[0].ForwardSeq.From != 1 || m[0].ForwardSeq.To != 2 ||
		m[0].Events[0].CommitSeq != 4 || m[0].Organization != "n"+w.org.String()[24:] ||
		m[0].Events[0].Event.Params["file"] != "/etc/sudoers.d/x" || m[0].Events[0].Links == nil {
		t.Fatalf("organization delivery %+v", m)
	}
	if m := byDest[platformDest]; len(m) != 1 || m[0].Organization != outbound.PlatformOrganization ||
		len(m[0].Events) != 1 || m[0].Events[0].Event.Code != audit.CodeAgentRolloutHalted {
		t.Fatalf("platform delivery %+v", m)
	}
	if s := w.state(old); s.cursor != 5 || s.forward != 2 || s.pending != nil {
		t.Errorf("state %+v", s)
	}
	var stored int
	if err := w.super.QueryRow(context.Background(), `SELECT count(*) FROM notification_delivery_event
		WHERE destination_id = $1`, old).Scan(&stored); err != nil || stored != 2 {
		t.Errorf("%d delivery events (%v)", stored, err)
	}
	if a := w.actions(w.org, audit.CodeNotificationDelivered, old); len(a) != 1 || a[0]["_outcome"] != "success" ||
		a[0]["forward_from"] != float64(1) || a[0]["count"] != float64(2) {
		t.Errorf("organization delivered actions %+v", a)
	}
	if a := w.actions(audit.PlatformOrganizationID, audit.CodeNotificationDelivered, platformDest); len(a) != 1 {
		t.Errorf("platform delivered actions %+v", a)
	}
	var outbox int
	if err := w.super.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE organization_id = $1`,
		audit.PlatformOrganizationID).Scan(&outbox); err != nil || outbox == 0 {
		t.Errorf("no outbox row of the platform action (%v)", err)
	}

	// Failures stay in the database; the stall and the resumption are recorded once each.
	w.tr.fail = &DeliveryError{Class: "http_500"}
	w.events(w.org, tamper, 1)
	w.round()
	if s := w.state(old); s.failures != 1 || s.pending == nil || s.cursor != 5 {
		t.Fatalf("after failure %+v", s)
	}
	w.now = w.now.Add(2 * time.Minute)
	w.round()
	w.now = w.now.Add(2 * time.Minute)
	w.round()
	if s := w.state(old); s.status != StatusStalled || s.failures != 3 {
		t.Fatalf("after stall %+v", s)
	}
	if a := w.actions(w.org, audit.CodeNotificationDestinationStalled, old); len(a) != 1 || a[0]["last_error"] != "http_500" {
		t.Fatalf("stalled actions %+v", a)
	}
	w.tr.fail = nil
	w.now = w.now.Add(15 * time.Minute)
	w.round()
	if s := w.state(old); s.status != StatusActive || s.failures != 0 || s.cursor != 6 || s.forward != 3 {
		t.Fatalf("after resume %+v", s)
	}
	if a := w.actions(w.org, audit.CodeNotificationDestinationResumed, old); len(a) != 1 {
		t.Fatalf("resumed actions %+v", a)
	}
	if a := w.actions(w.org, audit.CodeNotificationDelivered, old); len(a) != 2 || a[1]["resumed"] != true ||
		a[1]["attempts"] != float64(4) {
		t.Fatalf("delivered actions %+v", a)
	}
}

// TestPGStoreTestAndLookups: a requested test is delivered once and recorded with its result on the delivery, the
// state and the audit trail; pseudonym lookups are answered and expire.
func TestPGStoreTestAndLookups(t *testing.T) {
	w := newWorld(t)
	dest := w.destination(w.org, false)
	test := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO notification_delivery (id, destination_id, organization_id, kind, requested_by)
		VALUES ($1, $2, $3, 'test', 'alice')`, test, dest, w.org)
	w.exec(`INSERT INTO notification_pseudonym_key (organization_id, key_ciphertext) VALUES ($1, $2)`, w.org, "pkey:"+w.org.String())
	fresh, stale := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO notification_pseudonym_lookup (id, organization_id, pseudonym, requested_by) VALUES ($1, $2, 'u_x', 'alice')`,
		fresh, w.org)
	w.exec(`INSERT INTO notification_pseudonym_lookup (id, organization_id, pseudonym, requested_by, created_at)
		VALUES ($1, $2, 'u_y', 'alice', now() - interval '11 minutes')`, stale, w.org)
	w.round()
	if tests := w.tr.kinds(outbound.KindTest); len(tests) != 1 || tests[0].DeliveryID != test.String() {
		t.Fatalf("test messages %+v", tests)
	}
	var delivered *time.Time
	var attempts int
	var ok *bool
	if err := w.super.QueryRow(context.Background(), `SELECT d.delivered_at, d.attempts, s.last_test_ok
		FROM notification_delivery d JOIN notification_destination_state s ON s.destination_id = d.destination_id
		WHERE d.id = $1`, test).Scan(&delivered, &attempts, &ok); err != nil {
		t.Fatal(err)
	}
	if delivered == nil || attempts != 1 || ok == nil || !*ok {
		t.Errorf("test delivery delivered %v attempts %d ok %v", delivered, attempts, ok)
	}
	if a := w.actions(w.org, audit.CodeNotificationTestSent, dest); len(a) != 1 || a[0]["_outcome"] != "success" ||
		a[0]["requested_by"] != "alice" {
		t.Errorf("test_sent actions %+v", a)
	}
	var resolved *string
	if err := w.super.QueryRow(context.Background(), `SELECT resolved_username FROM notification_pseudonym_lookup
		WHERE id = $1`, fresh).Scan(&resolved); err != nil || resolved == nil || *resolved != "" {
		t.Errorf("lookup not answered: %v %v", resolved, err)
	}
	var left int
	if err := w.super.QueryRow(context.Background(), `SELECT count(*) FROM notification_pseudonym_lookup WHERE id = $1`,
		stale).Scan(&left); err != nil || left != 0 {
		t.Errorf("expired lookup kept (%d, %v)", left, err)
	}

	// A failed test is recorded as a failure and changes no delivery state.
	second := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO notification_delivery (id, destination_id, organization_id, kind, requested_by)
		VALUES ($1, $2, $3, 'test', 'bob')`, second, dest, w.org)
	w.tr.fail = &DeliveryError{Class: "redirect"}
	w.round()
	if a := w.actions(w.org, audit.CodeNotificationTestSent, dest); len(a) != 2 || a[1]["_outcome"] != "failure" ||
		a[1]["error"] != "redirect" {
		t.Errorf("failed test_sent actions %+v", a)
	}
	if s := w.state(dest); s.failures != 0 {
		t.Errorf("a failed test counted as a delivery failure: %+v", s)
	}
}

// TestPGStoreExactlyOnce: on the real tables a success applies once (a repeated or overtaken success changes and
// records nothing), and ending a stall records notification.delivered and notification.destination_resumed in the
// same transaction.
func TestPGStoreExactlyOnce(t *testing.T) {
	w := newWorld(t)
	dest := w.destination(w.org, false)
	w.events(w.org, tamper, 1)
	w.tr.fail = &DeliveryError{Class: "http_500"}
	w.round()
	s := w.state(dest)
	if s.pending == nil {
		t.Fatal("no pending batch")
	}
	data, err := w.e.store.Load(context.Background(), Scope{Org: w.org})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range data.Rows {
		if r.Destination.ID == dest && (r.State.Pending != *s.pending || r.State.PendingFrom != 1) {
			t.Fatalf("loaded pending %s from %d, want %s from 1", r.State.Pending, r.State.PendingFrom, *s.pending)
		}
	}
	w.exec(`UPDATE notification_destination_state SET status = 'stalled', stalled_since = now() WHERE destination_id = $1`, dest)
	store := w.e.store
	rec := &Record{Code: audit.CodeNotificationDelivered, Params: map[string]any{"destination": "d"}}
	resume := &Record{Code: audit.CodeNotificationDestinationResumed, Params: map[string]any{"destination": "d"}}
	cursor := int64(1)
	success := Success{Destination: dest, Name: "d", Delivery: *s.pending, Pending: *s.pending, Cursor: &cursor, At: w.now,
		Record: rec, Resume: resume}
	ok, err := store.Succeeded(context.Background(), Scope{Org: w.org}, success)
	if err != nil || !ok {
		t.Fatalf("first success: %t %v", ok, err)
	}
	ok, err = store.Succeeded(context.Background(), Scope{Org: w.org}, success)
	if err != nil || ok {
		t.Fatalf("repeated success: %t %v", ok, err)
	}
	delivered := w.actions(w.org, audit.CodeNotificationDelivered, dest)
	resumed := w.actions(w.org, audit.CodeNotificationDestinationResumed, dest)
	if len(delivered) != 1 || len(resumed) != 1 {
		t.Fatalf("%d delivered, %d resumed actions", len(delivered), len(resumed))
	}
	var sameTx bool
	if err := w.super.QueryRow(context.Background(), `SELECT count(DISTINCT xmin::text) = 1 FROM action
		WHERE organization_id = $1 AND target->>'id' = $2 AND code IN ('notification.delivered', 'notification.destination_resumed')`,
		w.org, dest.String()).Scan(&sameTx); err != nil || !sameTx {
		t.Errorf("delivered and resumed not in one transaction (%v)", err)
	}
	if st := w.state(dest); st.status != StatusActive || st.pending != nil || st.cursor != 1 {
		t.Errorf("state %+v", st)
	}
	// A failure for the batch that is no longer pending changes nothing.
	ok, err = store.Failed(context.Background(), Scope{Org: w.org}, Failure{Destination: dest, Name: "d", Delivery: *s.pending,
		Pending: *s.pending, PreviousStatus: StatusActive, Class: "http_500", At: w.now, ConsecutiveFailures: 9,
		FirstFailureAt: w.now, NextAttemptAt: w.now, Status: StatusStalled, StalledSince: &w.now,
		Record: &Record{Code: audit.CodeNotificationDestinationStalled, Params: map[string]any{"destination": "d"}}})
	if err != nil || ok {
		t.Fatalf("stale failure: %t %v", ok, err)
	}
	if st := w.state(dest); st.failures != 0 || st.status != StatusActive ||
		len(w.actions(w.org, audit.CodeNotificationDestinationStalled, dest)) != 0 {
		t.Errorf("stale failure applied: %+v", st)
	}
}
