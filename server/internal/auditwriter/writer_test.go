package auditwriter_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/baotest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/mqtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

type stack struct {
	pool     *db.AuditWriterPool
	super    *pgx.Conn
	store    *objectstore.Store
	rustfs   *s3test.RustFS
	bao      *bao.Client
	writer   *auditwriter.Writer
	verifier *auditwriter.Verifier
	sealer   *auditwriter.Sealer
}

func newStack(t *testing.T) stack {
	t.Helper()
	ctx := context.Background()
	env := pgtest.SharedAudit(t)
	pool, err := db.NewAuditWriterPool(ctx, env.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })

	rfs := s3test.Start(t, "paddock-audit")
	store := objectstore.New(rfs.Endpoint, s3test.RootUser, s3test.RootPassword, rfs.Bucket)

	b := baotest.Start(t)
	role := b.AppRole(t, "paddock-audit-writer")
	client, err := bao.New(b.Addr, role.RoleID, role.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := auditwriter.NewWriter(pool, store, 400)
	if err != nil {
		t.Fatal(err)
	}
	keys := func(ctx context.Context) (map[int][]byte, error) {
		return client.PublicKeys(ctx, auditwriter.SigningKey)
	}
	return stack{
		pool: pool, super: super, store: store, rustfs: rfs, bao: client, writer: writer,
		verifier: auditwriter.NewVerifier(pool, store, keys),
		sealer:   auditwriter.NewSealer(pool, writer, client),
	}
}

func event(org uuid.UUID, at time.Time, code audit.Code) audit.Event {
	return audit.Event{
		Schema: audit.Schema, EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: audit.Timestamp(at),
		Code: code, Outcome: audit.OutcomeSuccess, Actor: audit.Actor{Type: audit.ActorAdmin, ID: "a1", Display: "alice"},
		Source: audit.SourcePortal, Params: map[string]any{"name": "g"}, CorrelationID: "req-" + uuid.NewString(),
	}
}

func (s stack) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.super.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRetentionBelowBucketDefaultIsRejected(t *testing.T) {
	if _, err := auditwriter.NewWriter(nil, nil, 30); err == nil {
		t.Fatal("retention of 30 days accepted")
	}
}

// TestConsumerDuplicateDelivery: the same event delivered twice (relay restart) yields one index row and one object.
func TestConsumerDuplicateDelivery(t *testing.T) {
	s := newStack(t)
	broker := mqtest.Start(t)
	org := uuid.Must(uuid.NewV7())
	ev := event(org, time.Now(), audit.CodeDeviceGroupCreated)
	body, _ := json.Marshal(ev)

	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()
	msg := mq.Message{RoutingKey: audit.RoutingKey(org, audit.SourcePortal), MessageID: ev.EventID.String(), Body: body}
	results, err := pub.PublishBatch(context.Background(), mq.ExchangeAudit, []mq.Message{msg, msg})
	if err != nil || results[0] != nil || results[1] != nil {
		t.Fatalf("publish: %v %v", err, results)
	}
	// A message that is not an audit event goes to the DLQ instead of blocking the queue.
	if _, err := pub.PublishBatch(context.Background(), mq.ExchangeAudit, []mq.Message{{RoutingKey: "audit.portal.x", MessageID: "junk", Body: []byte("not json")}}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	consumer := mq.NewConsumer(broker.Config, mq.QueueAudit, auditwriter.Prefetch)
	done := make(chan struct{})
	go func() { _ = consumer.Run(ctx, s.writer.Handle); close(done) }()
	deadline := time.Now().Add(30 * time.Second)
	for s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID) == 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(auditwriter.MaxBatchWait + time.Second) // give a second delivery the chance to be processed
	cancel()
	<-done

	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 1 {
		t.Fatalf("%d index rows for one event, want 1", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 1 {
		t.Fatalf("%d objects, want 1", n)
	}
	if depth := queueDepth(t, broker, mq.QueueAudit); depth != 0 {
		t.Fatalf("audit.writer still holds %d messages", depth)
	}
	if depth := queueDepth(t, broker, mq.QueueAuditDLQ); depth != 1 {
		t.Fatalf("dlq.audit.writer holds %d messages, want the 1 invalid message", depth)
	}

	recordedAt, key, _ := s.recordedObject(t, ev.EventID)
	mode, until, err := s.store.Retention(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if mode != types.ObjectLockRetentionModeCompliance {
		t.Fatalf("object retention mode %s, want COMPLIANCE", mode)
	}
	// Retention counts from the UTC recording day (architecture §14.4), never from the local date or the test clock.
	if want := utcDay(recordedAt).AddDate(0, 0, 400); !until.Equal(want) {
		t.Fatalf("object retained until %s, want recording day + 400 days = %s", until, want)
	}
	body2, err := s.store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	events, err := auditwriter.DecodeObject(body2)
	if err != nil || len(events) != 1 || events[0].EventID != ev.EventID || events[0].RecordedAt.IsZero() {
		t.Fatalf("object content %+v (%v)", events, err)
	}
}

func queueDepth(t *testing.T, b *mqtest.Broker, queue string) int {
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
	q, err := ch.QueueDeclarePassive(queue, true, false, false, false, amqp.Table{})
	if err != nil {
		t.Fatal(err)
	}
	return q.Messages
}

// historicObject stores events as one object recorded at recorded and indexes it in audit_object, as an earlier
// writer run would have. Writer transactions always record at the database's current time, so objects of earlier
// recording days can only be set up this way.
func (s stack) historicObject(t *testing.T, org uuid.UUID, recorded time.Time, events ...audit.Event) string {
	t.Helper()
	ctx := context.Background()
	for i := range events {
		events[i].RecordedAt = audit.Timestamp(recorded)
	}
	body, err := auditwriter.EncodeObject(events)
	if err != nil {
		t.Fatal(err)
	}
	day := recorded.UTC().Truncate(24 * time.Hour)
	key := auditwriter.ObjectKey(org, recorded.Truncate(time.Hour), events[0].EventID)
	if err := s.store.PutLocked(ctx, key, "application/zstd", body, s.writer.RetainUntil(day)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if _, err := s.super.Exec(ctx, "INSERT INTO audit_object (object_key, organization_id, day, event_count, sha256) VALUES ($1, $2, $3, $4, $5)",
		key, org, day, len(events), sum[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestSealAndVerify covers the daily chain: three recording days (one without objects), verify OK; a manipulated
// object and a missing manifest each make verification fail.
func TestSealAndVerify(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day1 := time.Now().UTC().AddDate(0, 0, -5).Truncate(24 * time.Hour)
	day3 := day1.AddDate(0, 0, 2)
	s.historicObject(t, org, day1.Add(9*time.Hour+2*time.Minute),
		event(org, day1.Add(9*time.Hour), audit.CodeDeviceGroupCreated),
		event(org, day1.Add(9*time.Hour+time.Minute), audit.CodeDeviceGroupUpdated))
	s.historicObject(t, org, day1.Add(15*time.Hour), event(org, day1.Add(15*time.Hour), audit.CodeDeviceGroupDeleted))
	s.historicObject(t, org, day3.Add(1*time.Hour), event(org, day3.Add(1*time.Hour), audit.CodeDeviceGroupCreated))

	// Events written now are recorded today, outside the sealed range.
	events := []audit.Event{
		event(org, day1.Add(9*time.Hour), audit.CodeDeviceGroupCreated),
		event(org, day1.Add(9*time.Hour+time.Minute), audit.CodeDeviceGroupUpdated),
		event(org, day1.Add(15*time.Hour), audit.CodeDeviceGroupDeleted),
		event(org, day3.Add(1*time.Hour), audit.CodeDeviceGroupCreated),
	}
	n, err := s.writer.WriteBatch(ctx, events)
	if err != nil || n != 4 {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
	// Writing the same batch again is a no-op.
	if n, err := s.writer.WriteBatch(ctx, events); err != nil || n != 0 {
		t.Fatalf("second WriteBatch = %d, %v; want 0", n, err)
	}

	sealed, err := s.sealer.SealThrough(ctx, day3)
	if err != nil {
		t.Fatal(err)
	}
	if sealed < 3 {
		t.Fatalf("sealed %d manifests, want at least 3", sealed)
	}
	report, err := s.verifier.Verify(ctx, org, day1, day3)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() || report.Days != 3 || report.Objects != 3 {
		t.Fatalf("verify: %+v", report)
	}
	// Sealing again does nothing.
	if again, err := s.sealer.SealThrough(ctx, day3); err != nil || again != 0 {
		t.Fatalf("second seal = %d, %v", again, err)
	}

	t.Run("manipulated object", func(t *testing.T) {
		var key string
		if err := s.super.QueryRow(ctx, "SELECT object_key FROM audit_object WHERE organization_id = $1 ORDER BY object_key LIMIT 1", org).Scan(&key); err != nil {
			t.Fatal(err)
		}
		// Object Lock keeps the original version, but a new version shadows it for readers; verify must notice.
		retain := time.Now().AddDate(0, 0, 1)
		if _, err := s.rustfs.Root.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &s.rustfs.Bucket, Key: &key, Body: stringsReader("forged"),
			ObjectLockMode: types.ObjectLockModeCompliance, ObjectLockRetainUntilDate: &retain,
		}); err != nil {
			t.Fatal(err)
		}
		report, err := s.verifier.Verify(ctx, org, day1, day3)
		if err != nil {
			t.Fatal(err)
		}
		if report.OK() {
			t.Fatal("verify accepted a manipulated object")
		}
		t.Logf("problems: %v", report.Problems)
	})

	t.Run("missing day", func(t *testing.T) {
		if _, err := s.super.Exec(ctx, "DELETE FROM audit_manifest WHERE organization_id = $1 AND day = $2", org, day1.AddDate(0, 0, 1)); err != nil {
			t.Fatal(err)
		}
		report, err := s.verifier.Verify(ctx, org, day1, day3)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, p := range report.Problems {
			if contains(p, "no manifest") {
				found = true
			}
		}
		if !found {
			t.Fatalf("verify did not report the missing day: %v", report.Problems)
		}
	})
}

func TestSealLockIsExclusive(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	holder, err := pgx.Connect(ctx, pgtest.SharedAudit(t).Writer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close(ctx) }()
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock(hashtext('audit-seal'))"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.sealer.SealThrough(ctx, auditwriter.LastSealableDay(time.Now())); err != auditwriter.ErrLocked {
		t.Fatalf("SealThrough with the lock held elsewhere = %v, want ErrLocked", err)
	}
}
