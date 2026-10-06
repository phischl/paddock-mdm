package auditwriter_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/mqtest"
)

func utcDay(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }

// recordedObject returns recorded_at and object_key of an indexed event and the day of its audit_object row.
func (s stack) recordedObject(t *testing.T, eventID uuid.UUID) (time.Time, string, time.Time) {
	t.Helper()
	var recordedAt, day time.Time
	var key string
	if err := s.super.QueryRow(context.Background(),
		`SELECT e.recorded_at, e.object_key, o.day FROM audit_event e JOIN audit_object o USING (object_key)
		 WHERE e.event_id = $1`, eventID).Scan(&recordedAt, &key, &day); err != nil {
		t.Fatalf("recorded object of %s: %v", eventID, err)
	}
	return recordedAt, key, day
}

func (s stack) manifest(t *testing.T, org uuid.UUID, day time.Time) ([]byte, auditwriter.Manifest) {
	t.Helper()
	raw, err := s.store.Get(context.Background(), auditwriter.ManifestKey(org, day))
	if err != nil {
		t.Fatalf("manifest %s: %v", day.Format(time.DateOnly), err)
	}
	var file auditwriter.ManifestFile
	var m auditwriter.Manifest
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(file.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	return raw, m
}

// TestLateEventCoveredByRecordingDay (AC2): an event that occurred on an already sealed day is stored under its
// recording day and listed in that day's manifest; the sealed manifest stays unchanged and the chain verifies.
func TestLateEventCoveredByRecordingDay(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	occurred := time.Now().UTC().AddDate(0, 0, -2).Truncate(time.Hour).Add(-time.Hour)
	occurredDay := utcDay(occurred)

	// The occurrence day already has an object and is sealed together with the following day.
	s.historicObject(t, org, occurred, event(org, occurred, audit.CodeDeviceGroupCreated))
	if _, err := s.sealer.SealOrganizationThrough(ctx, org, occurredDay.AddDate(0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	sealedBefore, _ := s.manifest(t, org, occurredDay)
	var indexSumBefore []byte
	if err := s.super.QueryRow(ctx, "SELECT sha256 FROM audit_manifest WHERE organization_id = $1 AND day = $2",
		org, occurredDay).Scan(&indexSumBefore); err != nil {
		t.Fatal(err)
	}

	late := event(org, occurred.Add(time.Minute), audit.CodeDeviceGroupUpdated)
	if n, err := s.writer.WriteBatch(ctx, []audit.Event{late}); err != nil || n != 1 {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
	recordedAt, key, day := s.recordedObject(t, late.EventID)
	recordingDay := utcDay(recordedAt)
	if !recordingDay.After(occurredDay.AddDate(0, 0, 1)) {
		t.Fatalf("recorded at %s, want after the sealed days", recordedAt)
	}
	if !day.Equal(recordingDay) {
		t.Fatalf("audit_object.day = %s, want recording day %s", day.Format(time.DateOnly), recordingDay.Format(time.DateOnly))
	}
	if want := auditwriter.ObjectKey(org, recordedAt.Truncate(time.Hour), late.EventID); key != want {
		t.Fatalf("object key %s, want %s (recording hour)", key, want)
	}

	if _, err := s.sealer.SealOrganizationThrough(ctx, org, recordingDay); err != nil {
		t.Fatal(err)
	}
	_, m := s.manifest(t, org, recordingDay)
	listed := false
	for _, o := range m.Objects {
		listed = listed || o.Key == key
	}
	if !listed {
		t.Fatalf("manifest of %s does not list %s: %+v", recordingDay.Format(time.DateOnly), key, m.Objects)
	}

	report, err := s.verifier.Verify(ctx, org, occurredDay, recordingDay)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() || report.Objects != 2 {
		t.Fatalf("verify: %+v", report)
	}

	sealedAfter, _ := s.manifest(t, org, occurredDay)
	if sha256.Sum256(sealedAfter) != sha256.Sum256(sealedBefore) {
		t.Fatal("the sealed manifest of the occurrence day changed")
	}
	var indexSumAfter []byte
	if err := s.super.QueryRow(ctx, "SELECT sha256 FROM audit_manifest WHERE organization_id = $1 AND day = $2",
		org, occurredDay).Scan(&indexSumAfter); err != nil {
		t.Fatal(err)
	}
	if string(indexSumAfter) != string(indexSumBefore) {
		t.Fatal("the indexed hash of the sealed manifest changed")
	}
}

// slowStore delays the first slowPuts calls of PutLocked, so the writer transaction outlives its timeout.
type slowStore struct {
	auditwriter.ObjectStore
	delay    time.Duration
	slowPuts int32
	puts     atomic.Int32
}

func (s *slowStore) PutLocked(ctx context.Context, key, contentType string, body []byte, retainUntil time.Time) error {
	if s.puts.Add(1) <= s.slowPuts {
		time.Sleep(s.delay)
	}
	return s.ObjectStore.PutLocked(ctx, key, contentType, body, retainUntil)
}

// TestWriterTransactionTimeout: a batch whose transaction exceeds transaction_timeout is rolled back, commits no
// object row, and is written once on redelivery.
func TestWriterTransactionTimeout(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	ev := event(org, time.Now(), audit.CodeDeviceGroupCreated)

	slow := &slowStore{ObjectStore: s.store, delay: 2 * time.Second, slowPuts: 2}
	writer, err := auditwriter.NewWriter(s.pool, slow, 400)
	if err != nil {
		t.Fatal(err)
	}
	auditwriter.SetTransactionTimeout(writer, 500*time.Millisecond)

	if _, err := writer.WriteBatch(ctx, []audit.Event{ev}); err == nil {
		t.Fatal("WriteBatch outlived transaction_timeout without an error")
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 0 {
		t.Fatalf("%d index rows after the timed-out transaction, want 0", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 0 {
		t.Fatalf("%d object rows after the timed-out transaction, want 0", n)
	}

	// Through the queue: the first delivery times out and is nacked, the redelivery is written.
	broker := mqtest.Start(t)
	body, _ := json.Marshal(ev)
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()
	msg := mq.Message{RoutingKey: audit.RoutingKey(org, audit.SourcePortal), MessageID: ev.EventID.String(), Body: body}
	if results, err := pub.PublishBatch(ctx, mq.ExchangeAudit, []mq.Message{msg}); err != nil || results[0] != nil {
		t.Fatalf("publish: %v %v", err, results)
	}
	runCtx, cancel := context.WithCancel(ctx)
	consumer := mq.NewConsumer(broker.Config, mq.QueueAudit, auditwriter.Prefetch)
	done := make(chan struct{})
	go func() { _ = consumer.Run(runCtx, writer.Handle); close(done) }()
	deadline := time.Now().Add(60 * time.Second)
	for s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID) == 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	<-done

	if puts := slow.puts.Load(); puts != 3 {
		t.Fatalf("%d object puts, want 3 (timed out directly, timed out from the queue, redelivered)", puts)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 1 {
		t.Fatalf("%d index rows, want 1", n)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_object WHERE organization_id = $1", org); n != 1 {
		t.Fatalf("%d object rows, want 1", n)
	}
	if depth := queueDepth(t, broker, mq.QueueAudit); depth != 0 {
		t.Fatalf("audit.writer still holds %d messages", depth)
	}
}

func TestLastSealableDay(t *testing.T) {
	d := time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		now  time.Time
		want time.Time
	}{
		{d.Add(23 * time.Hour), d.AddDate(0, 0, -1)},
		{d.AddDate(0, 0, 1).Add(14*time.Minute + 59*time.Second), d.AddDate(0, 0, -1)},
		{d.AddDate(0, 0, 1).Add(15 * time.Minute), d},
		{d.AddDate(0, 0, 1).Add(15 * time.Hour), d},
	} {
		if got := auditwriter.LastSealableDay(tc.now); !got.Equal(tc.want) {
			t.Errorf("LastSealableDay(%s) = %s, want %s", tc.now, got.Format(time.DateOnly), tc.want.Format(time.DateOnly))
		}
	}
}

// TestSealerRefusesOpenDay: SealThrough refuses day D before D+1 00:15 UTC and accepts it from then on.
func TestSealerRefusesOpenDay(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	// A day long before any test data, so sealing it touches no organization.
	d := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	sealer := auditwriter.NewSealer(s.pool, s.writer, s.bao)
	for _, now := range []time.Time{d.Add(12 * time.Hour), d.AddDate(0, 0, 1).Add(15*time.Minute - time.Millisecond)} {
		auditwriter.SetSealerClock(sealer, func() time.Time { return now })
		if _, err := sealer.SealThrough(ctx, d); !errors.Is(err, auditwriter.ErrDayOpen) {
			t.Fatalf("SealThrough(%s) at %s = %v, want ErrDayOpen", d.Format(time.DateOnly), now, err)
		}
	}
	auditwriter.SetSealerClock(sealer, func() time.Time { return d.AddDate(0, 0, 1).Add(15 * time.Minute) })
	if n, err := sealer.SealThrough(ctx, d); err != nil || n != 0 {
		t.Fatalf("SealThrough(%s) at 00:15 the next day = %d, %v; want 0, nil", d.Format(time.DateOnly), n, err)
	}
	// With the real clock today is still open.
	if _, err := s.sealer.SealThrough(ctx, time.Now()); !errors.Is(err, auditwriter.ErrDayOpen) || !strings.Contains(err.Error(), "latest sealable day") {
		t.Fatalf("SealThrough(today) = %v, want ErrDayOpen", err)
	}
}

// TestRetentionFollowsRecordingDay: objects and manifests are retained until recording day + retention days.
func TestRetentionFollowsRecordingDay(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	ev := event(org, time.Now().AddDate(0, 0, -3), audit.CodeDeviceGroupCreated)
	if n, err := s.writer.WriteBatch(ctx, []audit.Event{ev}); err != nil || n != 1 {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
	recordedAt, key, _ := s.recordedObject(t, ev.EventID)
	want := utcDay(recordedAt).AddDate(0, 0, 400)
	if got := s.writer.RetainUntil(recordedAt); !got.Equal(want) {
		t.Fatalf("RetainUntil(%s) = %s, want %s", recordedAt, got, want)
	}
	_, until, err := s.store.Retention(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !until.Equal(want) {
		t.Fatalf("object retained until %s, want recording day + 400 days = %s", until, want)
	}

	if _, err := s.sealer.SealOrganizationThrough(ctx, org, recordedAt); err != nil {
		t.Fatal(err)
	}
	_, until, err = s.store.Retention(ctx, auditwriter.ManifestKey(org, recordedAt))
	if err != nil {
		t.Fatal(err)
	}
	if !until.Equal(want) {
		t.Fatalf("manifest retained until %s, want %s", until, want)
	}
}
