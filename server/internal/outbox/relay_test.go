package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicecommand"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/outbox"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/mqtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type relayHarness struct {
	pool     *db.RelayPool
	platform *db.PlatformPool
	super    *pgx.Conn
	broker   *mqtest.Broker
}

func newRelayHarness(t *testing.T, broker *mqtest.Broker) relayHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool, err := db.NewRelayPool(ctx, env.Relay, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	// Every test starts from an empty outbox and an empty queue.
	if _, err := super.Exec(ctx, "DELETE FROM outbox"); err != nil {
		t.Fatal(err)
	}
	if broker != nil {
		purge(t, broker)
	}
	return relayHarness{pool: pool, platform: platform, super: super, broker: broker}
}

type seqPayload struct {
	Org string `json:"organization_id"`
	Seq int    `json:"seq"`
}

// insert writes n outbox rows per organization through the platform role, as the ActionRunner would.
func (h relayHarness) insert(t *testing.T, orgs []uuid.UUID, n int) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	sys := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem})
	err := h.platform.InPlatform(sys, func(ctx context.Context, q *pgstore.Queries) error {
		for i := 0; i < n; i++ {
			for _, org := range orgs {
				id := uuid.Must(uuid.NewV7()).String()
				payload, _ := json.Marshal(seqPayload{Org: org.String(), Seq: i})
				if err := q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
					OrganizationID: org, Subject: audit.Subject(org, audit.SourcePortal), MsgID: id, Payload: payload,
				}); err != nil {
					return err
				}
				ids[id] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func (h relayHarness) unpublished(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM outbox WHERE published_at IS NULL").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type delivery struct {
	id         string
	routingKey string
	persistent bool
	payload    seqPayload
}

// drain reads every message currently in audit.writer (until the queue stays empty for 500 ms).
func drain(t *testing.T, b *mqtest.Broker) []delivery {
	t.Helper()
	conn, err := mq.Dial(b.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := ch.Consume(mq.QueueAudit, "", true, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []delivery
	for {
		select {
		case m := <-msgs:
			var p seqPayload
			if err := json.Unmarshal(m.Body, &p); err != nil {
				t.Fatal(err)
			}
			out = append(out, delivery{id: m.MessageId, routingKey: m.RoutingKey, persistent: m.DeliveryMode == amqp.Persistent, payload: p})
		case <-time.After(500 * time.Millisecond):
			return out
		}
	}
}

func purge(t *testing.T, b *mqtest.Broker) {
	t.Helper()
	conn, err := mq.Dial(b.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.QueuePurge(mq.QueueAudit, false); err != nil {
		t.Fatal(err)
	}
}

func checkComplete(t *testing.T, want map[string]bool, got []delivery) {
	t.Helper()
	seen := map[string]bool{}
	for _, d := range got {
		if !want[d.id] {
			t.Errorf("unexpected message %s", d.id)
		}
		if !d.persistent {
			t.Errorf("message %s is not persistent", d.id)
		}
		seen[d.id] = true
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("message %s was lost", id)
		}
	}
}

// checkOrderPerOrganization: the first delivery of every message arrives in sequence order per organization.
func checkOrderPerOrganization(t *testing.T, got []delivery) {
	t.Helper()
	first := map[string]bool{}
	last := map[string]int{}
	for _, d := range got {
		if first[d.id] {
			continue
		}
		first[d.id] = true
		if prev, ok := last[d.payload.Org]; ok && d.payload.Seq <= prev {
			t.Errorf("organization %s: seq %d after %d", d.payload.Org, d.payload.Seq, prev)
		}
		last[d.payload.Org] = d.payload.Seq
		if want := "audit.portal." + d.payload.Org; d.routingKey != want {
			t.Errorf("routing key %q, want %q", d.routingKey, want)
		}
	}
}

func TestRelayPublishesEverythingInOrder(t *testing.T) {
	broker := mqtest.Start(t)
	h := newRelayHarness(t, broker)
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()

	orgs := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	want := h.insert(t, orgs, 30)
	relay := outbox.NewRelay(h.pool, pub)
	relay.SetBatchSize(25)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relay.Run(ctx) }()
	deadline := time.Now().Add(20 * time.Second)
	for h.unpublished(t) > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := h.unpublished(t); n != 0 {
		t.Fatalf("%d rows still unpublished", n)
	}
	got := drain(t, broker)
	checkComplete(t, want, got)
	checkOrderPerOrganization(t, got)
	if len(got) != len(want) {
		t.Errorf("got %d deliveries for %d messages (no crash, so no duplicates expected)", len(got), len(want))
	}
}

// TestRelayCrashAfterConfirm: a relay that dies between the publisher confirm and the published_at update
// re-publishes the batch on restart (duplicates allowed) and loses nothing.
func TestRelayCrashAfterConfirm(t *testing.T) {
	broker := mqtest.Start(t)
	h := newRelayHarness(t, broker)
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()

	orgs := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	want := h.insert(t, orgs, 10)

	crashed := outbox.NewRelay(h.pool, pub)
	crashed.SetAfterConfirm(func() error { return errors.New("simulated crash") })
	if _, err := crashed.PublishOnce(context.Background()); err == nil {
		t.Fatal("simulated crash did not surface")
	}
	if n := h.unpublished(t); n != len(want) {
		t.Fatalf("%d rows unpublished after the crash, want %d", n, len(want))
	}

	restarted := outbox.NewRelay(h.pool, pub)
	if _, err := restarted.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.unpublished(t); n != 0 {
		t.Fatalf("%d rows unpublished after restart", n)
	}
	got := drain(t, broker)
	checkComplete(t, want, got)
	checkOrderPerOrganization(t, got)
	if len(got) != 2*len(want) {
		t.Logf("deliveries: %d for %d messages", len(got), len(want))
	}
	counts := map[string]int{}
	for _, d := range got {
		counts[d.id]++
	}
	dups := 0
	for _, c := range counts {
		if c > 1 {
			dups++
		}
	}
	t.Logf("%d of %d messages delivered twice (allowed: at-least-once)", dups, len(want))
}

// TestRelayBrokerDown: while RabbitMQ is stopped rows stay unpublished; after the restart they are delivered.
func TestRelayBrokerDown(t *testing.T) {
	broker := mqtest.Start(t)
	h := newRelayHarness(t, broker)
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()
	relay := outbox.NewRelay(h.pool, pub)

	// Establish the connection first so that the outage hits a live channel.
	if _, err := relay.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	broker.StopApp(t)
	orgs := []uuid.UUID{uuid.Must(uuid.NewV7())}
	want := h.insert(t, orgs, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := relay.PublishOnce(ctx)
	cancel()
	if err == nil {
		t.Fatal("publishing succeeded while RabbitMQ was stopped")
	}
	if n := h.unpublished(t); n != len(want) {
		t.Fatalf("%d rows unpublished during the outage, want %d", n, len(want))
	}

	broker.StartApp(t)
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := relay.PublishOnce(context.Background())
		if err == nil && h.unpublished(t) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rows not delivered after restart: %v", err)
		}
		time.Sleep(time.Second)
	}
	got := drain(t, broker)
	checkComplete(t, want, got)
}

func TestPublisherDetectsUnroutable(t *testing.T) {
	broker := mqtest.Start(t)
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()

	// Every audit.* routing key is bound, so publish to the dead-letter exchange with a key no queue is bound to.
	msgs := []mq.Message{{RoutingKey: "nowhere", MessageID: "x", Body: []byte(`{}`)}}
	results, err := pub.PublishBatch(context.Background(), mq.ExchangeDLX, msgs)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(results[0], mq.ErrReturned) {
		t.Fatalf("unroutable message result = %v, want ErrReturned", results[0])
	}
}

func TestCleanupDeletesOldPublishedRows(t *testing.T) {
	h := newRelayHarness(t, nil)
	orgs := []uuid.UUID{uuid.Must(uuid.NewV7())}
	h.insert(t, orgs, 3)
	if _, err := h.super.Exec(context.Background(),
		"UPDATE outbox SET published_at = now() - interval '8 days' WHERE id = (SELECT min(id) FROM outbox)"); err != nil {
		t.Fatal(err)
	}
	relay := outbox.NewRelay(h.pool, nil)
	n, err := relay.Cleanup(context.Background(), 7*24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("cleanup deleted %d rows (%v), want 1", n, err)
	}
	if left := h.unpublished(t); left != 2 {
		t.Fatalf("%d unpublished rows left, want 2", left)
	}
}

func TestReaperFinalizesStuckAction(t *testing.T) {
	h := newRelayHarness(t, nil)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	stuck, fresh := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, a := range []struct {
		id  uuid.UUID
		age time.Duration
	}{{stuck, 11 * time.Minute}, {fresh, time.Minute}} {
		_, err := h.super.Exec(ctx, `INSERT INTO action (id, organization_id, code, status, actor, target, params, correlation_id, started_at)
			VALUES ($1, $2, 'organization.created', 'started', '{"type":"platform_admin","id":"p1","step_up":false}',
			        '{"type":"organization","id":"o1"}', '{"slug":"acme"}', $3, now() - $4::interval)`,
			a.id, org, "corr-"+a.id.String(), fmt.Sprintf("%d seconds", int(a.age.Seconds())))
		if err != nil {
			t.Fatal(err)
		}
	}

	reaper := outbox.NewReaper(h.pool, outbox.DefaultReaperThreshold)
	n, err := reaper.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reaper finalized %d actions, want 1", n)
	}
	var status, outcome, errorCode string
	if err := h.super.QueryRow(ctx, "SELECT status, outcome, error_code FROM action WHERE id = $1", stuck).Scan(&status, &outcome, &errorCode); err != nil {
		t.Fatal(err)
	}
	if status != "finished" || outcome != "unknown" || errorCode != "reaped" {
		t.Fatalf("stuck action = %s/%s/%s, want finished/unknown/reaped", status, outcome, errorCode)
	}
	var freshStatus string
	if err := h.super.QueryRow(ctx, "SELECT status FROM action WHERE id = $1", fresh).Scan(&freshStatus); err != nil || freshStatus != "started" {
		t.Fatalf("fresh action status %q (%v), want started", freshStatus, err)
	}
	var payloads [][]byte
	rows, err := h.super.Query(ctx, "SELECT payload FROM outbox WHERE msg_id = $1", stuck.String())
	if err != nil {
		t.Fatal(err)
	}
	payloads, err = pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("%d outbox rows for the stuck action, want 1", len(payloads))
	}
	var ev audit.Event
	if err := json.Unmarshal(payloads[0], &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Code != audit.CodeOrganizationCreated || ev.Outcome != audit.OutcomeUnknown || ev.EventID != stuck ||
		ev.Source != audit.SourcePlatform || ev.Params["slug"] != "acme" {
		t.Fatalf("unexpected reaper event %+v", ev)
	}

	// Idempotent: a second run finds nothing.
	if n, err := reaper.RunOnce(ctx); err != nil || n != 0 {
		t.Fatalf("second run finalized %d (%v)", n, err)
	}
}

// TestRelayRoutesStateChanges: state.<org> rows go to paddock.state on the organization's partition queue, priority
// rows to state.priority, command.<org> rows to command.issued (plan M4a decision 2), audit rows of the same batch
// still reach audit.writer.
func TestRelayRoutesStateChanges(t *testing.T) {
	broker := mqtest.Start(t)
	h := newRelayHarness(t, broker)
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()
	org := uuid.Must(uuid.NewV7())
	auditIDs := h.insert(t, []uuid.UUID{org}, 1)
	sys := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem})
	stateID, priorityID := uuid.Must(uuid.NewV7()).String(), uuid.Must(uuid.NewV7()).String()
	state := statechange.Event{OrganizationID: org, Scope: statechange.ScopeOrg, ID: org}
	priority := statechange.Event{OrganizationID: org, Scope: statechange.ScopeUser, ID: uuid.New(), Priority: true}
	commandID := uuid.Must(uuid.NewV7())
	if err := h.platform.InPlatform(sys, func(ctx context.Context, q *pgstore.Queries) error {
		for id, ev := range map[string]statechange.Event{stateID: state, priorityID: priority} {
			payload, _ := json.Marshal(ev)
			if err := q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
				OrganizationID: org, Subject: statechange.Subject(ev), MsgID: id, Payload: payload,
			}); err != nil {
				return err
			}
		}
		payload, _ := json.Marshal(devicecommand.Issued{OrganizationID: org, CommandID: commandID})
		return q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
			OrganizationID: org, Subject: devicecommand.Subject(org), MsgID: commandID.String(), Payload: payload,
		})
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := outbox.NewRelay(h.pool, pub).PublishOnce(context.Background()); err != nil || n != 4 {
		t.Fatalf("PublishOnce: %d %v", n, err)
	}
	checkComplete(t, auditIDs, drain(t, broker))

	conn, err := mq.Dial(broker.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := ch.Consume(mq.StateQueue(mq.StatePartition(org)), "", true, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-msgs:
		var ev statechange.Event
		if err := json.Unmarshal(m.Body, &ev); err != nil || m.MessageId != stateID || ev.OrganizationID != org {
			t.Fatalf("state message %s %s: %v", m.MessageId, m.Body, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("state change not delivered to its partition queue")
	}
	prio, err := ch.Consume(mq.StateQueue(mq.StatePriority), "", true, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-prio:
		var ev statechange.Event
		if err := json.Unmarshal(m.Body, &ev); err != nil || m.MessageId != priorityID || !ev.Priority || ev.Scope != statechange.ScopeUser {
			t.Fatalf("priority message %s %s: %v", m.MessageId, m.Body, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("priority state change not delivered to state.priority")
	}
	commands, err := ch.Consume(mq.QueueCommandIssued, "", true, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-commands:
		var ev devicecommand.Issued
		if err := json.Unmarshal(m.Body, &ev); err != nil || m.MessageId != commandID.String() || ev.CommandID != commandID || ev.OrganizationID != org {
			t.Fatalf("command message %s %s: %v", m.MessageId, m.Body, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("command.issued not delivered to its queue")
	}
}
