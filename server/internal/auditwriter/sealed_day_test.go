package auditwriter_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/mqtest"
)

// hookStore records the keys of all WORM puts. before runs ahead of put n (1-based) and fails it with a non-nil
// error; after runs once put n has stored the object.
type hookStore struct {
	auditwriter.ObjectStore
	mu     sync.Mutex
	keys   []string
	before func(n int) error
	after  func(n int)
}

func (h *hookStore) PutLocked(ctx context.Context, key, contentType string, body []byte, retainUntil time.Time) error {
	h.mu.Lock()
	h.keys = append(h.keys, key)
	n := len(h.keys)
	h.mu.Unlock()
	if h.before != nil {
		if err := h.before(n); err != nil {
			return err
		}
	}
	if err := h.ObjectStore.PutLocked(ctx, key, contentType, body, retainUntil); err != nil {
		return err
	}
	if h.after != nil {
		h.after(n)
	}
	return nil
}

func (h *hookStore) putKeys() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.keys...)
}

// settlement is how a delivery was settled: acked, or nacked or rejected with or without requeue.
type settlement struct{ ack, requeue bool }

// recordingAcknowledger reports every settlement after passing it to the broker.
type recordingAcknowledger struct {
	amqp.Acknowledger
	settled chan<- settlement
}

func (r recordingAcknowledger) Ack(tag uint64, multiple bool) error {
	err := r.Acknowledger.Ack(tag, multiple)
	r.settled <- settlement{ack: true}
	return err
}

func (r recordingAcknowledger) Nack(tag uint64, multiple, requeue bool) error {
	err := r.Acknowledger.Nack(tag, multiple, requeue)
	r.settled <- settlement{requeue: requeue}
	return err
}

func (r recordingAcknowledger) Reject(tag uint64, requeue bool) error {
	err := r.Acknowledger.Reject(tag, requeue)
	r.settled <- settlement{requeue: requeue}
	return err
}

// recordSettlements wraps handle so that every settlement of a delivery is reported on settled.
func recordSettlements(handle mq.ConsumeFunc, settled chan<- settlement) mq.ConsumeFunc {
	return func(ctx context.Context, ch *amqp.Channel, deliveries <-chan amqp.Delivery) error {
		proxied := make(chan amqp.Delivery)
		go func() {
			defer close(proxied)
			for d := range deliveries {
				d.Acknowledger = recordingAcknowledger{Acknowledger: d.Acknowledger, settled: settled}
				select {
				case proxied <- d:
				case <-ctx.Done():
					return
				}
			}
		}()
		return handle(ctx, ch, proxied)
	}
}

func writeOne(t *testing.T, w *auditwriter.Writer, ev audit.Event) {
	t.Helper()
	if n, err := w.WriteBatch(context.Background(), []audit.Event{ev}); err != nil || n != 1 {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
}

func (s stack) verifyOK(t *testing.T, org uuid.UUID, from, to time.Time) {
	t.Helper()
	report, err := s.verifier.Verify(context.Background(), org, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() {
		t.Fatalf("verify %s..%s: %+v", from.Format(time.DateOnly), to.Format(time.DateOnly), report)
	}
}

// TestSealWaitsForWriterHoldingTheDay (PDK-422, writer first): a writer transaction has inserted its object row but
// not committed when the sealer starts on the same day. The sealer waits on the audit-day lock until the writer
// commits and its manifest then lists the object. Without the lock the seal would list the day without the
// uncommitted object, and the object would land in a sealed day.
func TestSealWaitsForWriterHoldingTheDay(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	writer, err := auditwriter.NewWriter(s.pool, s.store, 400)
	if err != nil {
		t.Fatal(err)
	}
	writeOne(t, writer, event(org, time.Now(), audit.CodeDeviceGroupCreated))

	sealDone := make(chan error, 1)
	var sealedDay time.Time
	waited, early := false, false
	auditwriter.SetRowInserted(writer, func(day time.Time) {
		sealedDay = day
		go func() {
			_, err := s.sealer.SealOrganizationThrough(ctx, org, day)
			sealDone <- err
		}()
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			select {
			case err := <-sealDone:
				early = true
				sealDone <- err
				return
			default:
			}
			if s.count(t, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND wait_event = 'advisory'
				AND query LIKE '%pg_advisory_xact_lock(hashtext(''audit-day'')%'`) > 0 {
				waited = true
				return
			}
		}
	})
	late := event(org, time.Now(), audit.CodeDeviceGroupUpdated)
	writeOne(t, writer, late)
	if early {
		t.Fatal("the seal completed while the writer transaction held an uncommitted object of the day")
	}
	if !waited {
		t.Fatal("the seal never waited on the audit-day lock")
	}
	select {
	case err := <-sealDone:
		if err != nil {
			t.Fatalf("seal after the writer committed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the seal did not finish after the writer committed")
	}
	_, key, day := s.recordedObject(t, late.EventID)
	if !day.Equal(sealedDay) {
		t.Fatalf("audit_object.day = %s, want %s", day.Format(time.DateOnly), sealedDay.Format(time.DateOnly))
	}
	_, m := s.manifest(t, org, day)
	listed := false
	for _, o := range m.Objects {
		listed = listed || o.Key == key
	}
	if !listed {
		t.Fatalf("manifest of %s does not list %s: %+v", day.Format(time.DateOnly), key, m.Objects)
	}
	s.verifyOK(t, org, day, day)
}

// TestWORMPutFailureRollsBackRow: the object row is inserted before the WORM put, so a failed put rolls the row back
// with the index rows; nothing points to a missing object, and the redelivered event is written once. The queue
// path of a failed transaction (nack, requeue, redelivery) is TestWriterTransactionTimeout.
func TestWORMPutFailureRollsBackRow(t *testing.T) {
	s := newStack(t)
	org := uuid.Must(uuid.NewV7())
	store := &hookStore{ObjectStore: s.store, before: func(n int) error {
		if n == 1 {
			return errors.New("WORM store unavailable")
		}
		return nil
	}}
	writer, err := auditwriter.NewWriter(s.pool, store, 400)
	if err != nil {
		t.Fatal(err)
	}
	ev := event(org, time.Now(), audit.CodeDeviceGroupCreated)
	if _, err := writer.WriteBatch(context.Background(), []audit.Event{ev}); err == nil {
		t.Fatal("WriteBatch succeeded although the WORM put failed")
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 0 {
		t.Fatalf("%d index rows after the failed put, want 0", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 0 {
		t.Fatalf("%d object rows after the failed put, want 0", n)
	}

	writeOne(t, writer, ev)
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 1 {
		t.Fatalf("%d index rows after the redelivery, want 1", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 1 {
		t.Fatalf("%d object rows after the redelivery, want 1", n)
	}
	recordedAt, _, day := s.recordedObject(t, ev.EventID)
	if _, err := s.sealer.SealOrganizationThrough(context.Background(), org, recordedAt); err != nil {
		t.Fatal(err)
	}
	s.verifyOK(t, org, day, day)
}

// TestCommitFailureAfterPutLeavesUnindexedObject: the WORM put succeeds but the transaction cannot commit (here: it
// exceeds transaction_timeout). The index has neither event nor object row; the stored object stays in the bucket,
// locked and listed by no row or manifest, as with the earlier put-first order. The redelivery writes the event once
// under a new put: with the same first event in the same hour it is a newer version of the same key, which
// verification reads; otherwise a different key. The chain verifies.
func TestCommitFailureAfterPutLeavesUnindexedObject(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	store := &hookStore{ObjectStore: s.store}
	writer, err := auditwriter.NewWriter(s.pool, store, 400)
	if err != nil {
		t.Fatal(err)
	}
	auditwriter.SetTransactionTimeout(writer, 500*time.Millisecond)
	store.after = func(n int) {
		if n == 1 {
			time.Sleep(2 * time.Second)
			// The redelivery runs with the regular timeout; the writer reads it in this goroutine.
			auditwriter.SetTransactionTimeout(writer, db.WriterTransactionTimeout)
		}
	}
	ev := event(org, time.Now(), audit.CodeDeviceGroupCreated)
	if _, err := writer.WriteBatch(ctx, []audit.Event{ev}); err == nil {
		t.Fatal("WriteBatch committed although the transaction outlived its timeout")
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 0 {
		t.Fatalf("%d index rows after the failed commit, want 0", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 0 {
		t.Fatalf("%d object rows after the failed commit, want 0", n)
	}
	keys := store.putKeys()
	if len(keys) != 1 {
		t.Fatalf("puts %v, want 1", keys)
	}
	if _, err := s.store.Get(ctx, keys[0]); err != nil {
		t.Fatalf("the object of the failed commit is not in the bucket: %v", err)
	}

	writeOne(t, writer, ev)
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 1 {
		t.Fatalf("%d index rows after the redelivery, want 1", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 1 {
		t.Fatalf("%d object rows after the redelivery, want 1", n)
	}
	recordedAt, key, day := s.recordedObject(t, ev.EventID)
	if keys = store.putKeys(); len(keys) != 2 || keys[1] != key {
		t.Fatalf("puts %v, want a second put of the indexed key %s", keys, key)
	}
	body, err := s.store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var indexed []byte
	if err := s.super.QueryRow(ctx, "SELECT sha256 FROM audit_object WHERE object_key = $1", key).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(body); string(sum[:]) != string(indexed) {
		t.Fatal("the bucket's current object differs from the indexed hash")
	}
	if _, err := s.sealer.SealOrganizationThrough(ctx, org, recordedAt); err != nil {
		t.Fatal(err)
	}
	s.verifyOK(t, org, day, day)
}

// TestSealedDayRetryIsBounded (PDK-422): when every attempt's day is sealed before its object row is inserted, the
// writer gives up after three transactions with the trigger's error and records nothing. Through the queue the
// batch is then nacked and requeued, and the redelivery writes the event exactly once.
func TestSealedDayRetryIsBounded(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	store := &hookStore{ObjectStore: s.store}
	writer, err := auditwriter.NewWriter(s.pool, store, 400)
	if err != nil {
		t.Fatal(err)
	}
	first := event(org, time.Now(), audit.CodeDeviceGroupCreated)
	writeOne(t, writer, first)
	_, _, firstDay := s.recordedObject(t, first.EventID)

	// Every chosen day is sealed while refusals remain; the writer goroutine is the only caller.
	var chosen []time.Time
	refusals := 3
	auditwriter.SetDayChosen(writer, func(day time.Time) {
		chosen = append(chosen, day)
		if refusals == 0 {
			return
		}
		refusals--
		if _, err := s.sealer.SealOrganizationThrough(ctx, org, day); err != nil {
			t.Errorf("seal %s: %v", day.Format(time.DateOnly), err)
		}
	})
	late := event(org, time.Now(), audit.CodeDeviceGroupUpdated)
	_, err = writer.WriteBatch(ctx, []audit.Event{late})
	if !db.IsAuditDaySealed(err) {
		t.Fatalf("WriteBatch with every day sealed = %v, want the trigger's error", err)
	}
	if len(chosen) != 3 {
		t.Fatalf("%d transactions, want 3", len(chosen))
	}
	if puts := len(store.putKeys()); puts != 1 {
		t.Fatalf("%d WORM puts, want 1 (the first event; refused attempts put nothing)", puts)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", late.EventID); n != 0 {
		t.Fatalf("%d index rows after the refused attempts, want 0", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 1 {
		t.Fatalf("%d object rows after the refused attempts, want 1", n)
	}

	// Through the queue: three refusals in the first delivery, which is nacked; the redelivery is written.
	chosen, refusals = nil, 3
	broker := mqtest.Start(t)
	body, _ := json.Marshal(late)
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()
	msg := mq.Message{RoutingKey: audit.RoutingKey(org, audit.SourcePortal), MessageID: late.EventID.String(), Body: body}
	if results, err := pub.PublishBatch(ctx, mq.ExchangeAudit, []mq.Message{msg}); err != nil || results[0] != nil {
		t.Fatalf("publish: %v %v", err, results)
	}
	runCtx, cancel := context.WithCancel(ctx)
	consumer := mq.NewConsumer(broker.Config, mq.QueueAudit, auditwriter.Prefetch)
	settled := make(chan settlement, 8)
	done := make(chan struct{})
	go func() { _ = consumer.Run(runCtx, recordSettlements(writer.Handle, settled)); close(done) }()
	// The consumer stops only once the redelivery is acked, not when its index row appears: the row is visible at
	// commit, and a cancel during tx.Commit's round trip fails the commit call although the server committed, so
	// the delivery would be nacked and stay in the queue (PDK-502).
	want := []settlement{{requeue: true}, {ack: true}}
	var got []settlement
	timeout := time.After(60 * time.Second)
	for len(got) < len(want) {
		select {
		case st := <-settled:
			got = append(got, st)
		case <-timeout:
			t.Fatalf("settlements %+v after 60s, want %+v", got, want)
		}
	}
	cancel()
	<-done
	if !slices.Equal(got, want) {
		t.Fatalf("settlements %+v, want %+v (nack with requeue, then ack)", got, want)
	}

	// A fourth transaction exists only if the first delivery was nacked with requeue: an acked or dropped delivery is
	// never redelivered, and the writer itself stops after three.
	if len(chosen) != 4 {
		t.Fatalf("%d transactions through the queue, want 3 refused and 1 redelivered", len(chosen))
	}
	if puts := len(store.putKeys()); puts != 2 {
		t.Fatalf("%d WORM puts, want 2 (the first event and the redelivery)", puts)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", late.EventID); n != 1 {
		t.Fatalf("%d index rows, want 1", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 2 {
		t.Fatalf("%d object rows, want 2", n)
	}
	if depth := queueDepth(t, broker, mq.QueueAudit); depth != 0 {
		t.Fatalf("audit.writer still holds %d messages", depth)
	}
	_, _, lateDay := s.recordedObject(t, late.EventID)
	if want := firstDay.AddDate(0, 0, 6); !lateDay.Equal(want) {
		t.Fatalf("audit_object.day = %s, want %s after six sealed days", lateDay.Format(time.DateOnly), want.Format(time.DateOnly))
	}
	if _, err := s.sealer.SealOrganizationThrough(ctx, org, lateDay); err != nil {
		t.Fatal(err)
	}
	s.verifyOK(t, org, firstDay, lateDay)
}
