package notifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// recorded indexes n matching events of org recorded at at (occurred now, so they land in the test's partition).
func (w *world) recorded(org uuid.UUID, at time.Time, n int) {
	w.t.Helper()
	err := w.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		for range n {
			w.seq[org]++
			if _, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
				EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: w.now, RecordedAt: at,
				Code: string(tamper), Outcome: "success", Source: "device", Actor: []byte(`{"type":"device","id":"x"}`),
				Params: []byte(`{}`), CorrelationID: "c", ObjectKey: "k", CommitSeq: w.seq[org],
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

// seal stores the manifest of day for org, as the audit writer's sealer does.
func (w *world) seal(org uuid.UUID, day time.Time, sha []byte) {
	w.t.Helper()
	err := w.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		return q.InsertAuditManifest(ctx, auditstore.InsertAuditManifestParams{
			OrganizationID: org, Day: day, Sha256: sha, Signature: "vault:v3:sig", KeyVersion: 3,
			ObjectKey: "manifests/" + org.String() + "/" + day.Format(time.DateOnly) + ".json",
		})
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

// TestPGStoreCheckpointsAndReplay: on the real roles a destination with checkpoints receives the checkpoint of a
// sealed day after its events (the manifest read through the audit reader of its own organization only, the count
// from the index), the checkpoint takes a forward sequence number and moves last_checkpoint_day; a replay re-sends
// both deliveries with their IDs and clears replay_from.
func TestPGStoreCheckpointsAndReplay(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	today := utcDay(w.now)
	yesterday := today.AddDate(0, 0, -1)
	dest := w.destination(w.org, false)
	w.exec(`UPDATE notification_destination SET checkpoints = true, created_at = $2 WHERE id = $1`, dest,
		today.AddDate(0, 0, -3).Add(time.Hour))
	other := uuid.Must(uuid.NewV7())
	w.recorded(w.org, yesterday.Add(2*time.Hour), 2)
	w.recorded(w.org, today, 1)
	w.recorded(other, yesterday.Add(time.Hour), 5)
	w.seal(w.org, today.AddDate(0, 0, -4), []byte{0x01})
	w.seal(w.org, yesterday, []byte{0xde, 0xad, 0xbe, 0xef})
	w.seal(other, yesterday, []byte{0x02})
	w.round()

	cps := w.tr.kinds(outbound.KindCheckpoint)
	if len(cps) != 1 {
		t.Fatalf("%d checkpoints, want 1", len(cps))
	}
	if c := cps[0]; c.Day != yesterday.Format(time.DateOnly) || c.EventCount != 2 || c.ManifestSHA256 != "deadbeef" ||
		c.Signature != "vault:v3:sig" || c.KeyVersion != 3 || c.ForwardSeq.From != 4 {
		t.Fatalf("checkpoint %+v", c)
	}
	var kind string
	var day time.Time
	var count int
	if err := w.super.QueryRow(ctx, `SELECT kind, checkpoint_day, event_count FROM notification_delivery WHERE id = $1`,
		uuid.MustParse(cps[0].DeliveryID)).Scan(&kind, &day, &count); err != nil || kind != "checkpoint" ||
		!day.Equal(yesterday) || count != 2 {
		t.Fatalf("checkpoint delivery %s %s %d (%v)", kind, day, count, err)
	}
	var last time.Time
	if err := w.super.QueryRow(ctx, `SELECT last_checkpoint_day FROM notification_destination_state WHERE destination_id = $1`,
		dest).Scan(&last); err != nil || !last.Equal(yesterday) {
		t.Fatalf("last_checkpoint_day %s (%v)", last, err)
	}
	if s := w.state(dest); s.forward != 4 || s.pending != nil || s.cursor != 3 {
		t.Fatalf("state %+v", s)
	}
	if a := w.actions(w.org, audit.CodeNotificationCheckpointSent, dest); len(a) != 1 || a[0]["_outcome"] != "success" ||
		a[0]["event_count"] != float64(2) || a[0]["forward_seq"] != float64(4) {
		t.Fatalf("checkpoint actions %+v", a)
	}

	w.exec(`UPDATE notification_destination_state SET replay_from = 2 WHERE destination_id = $1`, dest)
	w.now = w.now.Add(time.Minute)
	w.round()
	sent := w.tr.sent[len(w.tr.sent)-2:]
	if sent[0].msg.Kind != outbound.KindEvents || sent[0].msg.DeliveryID != w.tr.sent[0].msg.DeliveryID ||
		sent[1].msg.DeliveryID != cps[0].DeliveryID {
		t.Fatalf("replayed %s %s", sent[0].msg.Kind, sent[1].msg.Kind)
	}
	var replayFrom *int64
	if err := w.super.QueryRow(ctx, `SELECT replay_from FROM notification_destination_state WHERE destination_id = $1`,
		dest).Scan(&replayFrom); err != nil || replayFrom != nil {
		t.Fatalf("replay_from %v (%v)", replayFrom, err)
	}
	a := w.actions(w.org, audit.CodeNotificationReplayed, dest)
	if len(a) != 2 || a[0]["original_delivery_id"] != w.tr.sent[0].msg.DeliveryID || a[1]["forward_from"] != float64(4) {
		t.Fatalf("replayed actions %+v", a)
	}
	var delivered int
	if err := w.super.QueryRow(ctx, `SELECT attempts FROM notification_delivery WHERE id = $1`,
		uuid.MustParse(cps[0].DeliveryID)).Scan(&delivered); err != nil || delivered != 1 {
		t.Errorf("the replay changed the stored delivery: attempts %d (%v)", delivered, err)
	}
}

// TestPGStoreReplayGuardsAndDigest: while a replay is requested no new batch or checkpoint takes a forward sequence
// number (both roll back as stale), and a replay advance and a delivered checkpoint store the e-mail digest's
// next_attempt_at (plan M9 decision 28).
func TestPGStoreReplayGuardsAndDigest(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sc := Scope{Org: w.org}
	dest := w.destination(w.org, false)
	w.exec(`UPDATE notification_destination_state SET forward_seq = 2, replay_from = 1 WHERE destination_id = $1`, dest)

	batchID, cpID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	err := w.e.store.CreateBatch(ctx, sc, dest, NewBatch{ID: batchID, Refs: []EventRef{
		{ForwardSeq: 3, EventID: uuid.Must(uuid.NewV7()), CommitSeq: 1}}})
	if !errors.Is(err, errStale) {
		t.Fatalf("batch during a replay: %v, want errStale", err)
	}
	day := utcDay(w.now).AddDate(0, 0, -1)
	err = w.e.store.CreateCheckpoint(ctx, sc, dest, NewCheckpoint{ID: cpID, ForwardSeq: 3, Day: day, EventCount: 1})
	if !errors.Is(err, errStale) {
		t.Fatalf("checkpoint during a replay: %v, want errStale", err)
	}
	var deliveries int
	if err := w.super.QueryRow(ctx, `SELECT count(*) FROM notification_delivery WHERE destination_id = $1`, dest).
		Scan(&deliveries); err != nil || deliveries != 0 {
		t.Fatalf("%d deliveries stored during a replay (%v)", deliveries, err)
	}
	if s := w.state(dest); s.forward != 2 || s.pending != nil {
		t.Fatalf("state %+v", s)
	}

	next := w.now.Add(5 * time.Minute)
	ok, err := w.e.store.Replayed(ctx, sc, ReplayAdvance{Destination: dest, Name: "d", From: 1, At: w.now, NextAttemptAt: &next})
	if err != nil || !ok {
		t.Fatalf("end of replay: %v %v", ok, err)
	}
	nextAttempt := func() *time.Time {
		t.Helper()
		var at *time.Time
		if err := w.super.QueryRow(ctx, `SELECT next_attempt_at FROM notification_destination_state WHERE destination_id = $1`,
			dest).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if at := nextAttempt(); at == nil || !at.Equal(next) {
		t.Fatalf("next_attempt_at after the replay advance %v, want %s", at, next)
	}

	if err := w.e.store.CreateCheckpoint(ctx, sc, dest, NewCheckpoint{ID: cpID, ForwardSeq: 3, Day: day, EventCount: 1}); err != nil {
		t.Fatalf("checkpoint after the replay: %v", err)
	}
	later := next.Add(time.Minute)
	ok, err = w.e.store.Succeeded(ctx, sc, Success{Destination: dest, Name: "d", Delivery: cpID, Pending: cpID, At: w.now,
		CheckpointDay: &day, NextAttemptAt: &later})
	if err != nil || !ok {
		t.Fatalf("checkpoint succeeded: %v %v", ok, err)
	}
	if at := nextAttempt(); at == nil || !at.Equal(later) {
		t.Fatalf("next_attempt_at after the checkpoint %v, want %s", at, later)
	}
}

// TestPGStoreSkipEndsReplay: on the real roles a skip request clears replay_from together with the cursor jump, so a
// replay whose re-send keeps failing no longer holds back new events, and they continue the numbering.
func TestPGStoreSkipEndsReplay(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	dest := w.destination(w.org, false)
	w.recorded(w.org, w.now, 2)
	w.round()
	w.exec(`UPDATE notification_destination_state SET replay_from = 1 WHERE destination_id = $1`, dest)
	w.tr.fail = &DeliveryError{Class: "http_422"}
	w.recorded(w.org, w.now, 1)
	w.round()
	if s := w.state(dest); s.forward != 2 || s.failures != 1 {
		t.Fatalf("state while the replay fails %+v", s)
	}

	w.tr.fail = nil
	w.exec(`UPDATE notification_destination_state SET start_at_latest = true WHERE destination_id = $1`, dest)
	w.round()
	var replayFrom *int64
	if err := w.super.QueryRow(ctx, `SELECT replay_from FROM notification_destination_state WHERE destination_id = $1`,
		dest).Scan(&replayFrom); err != nil || replayFrom != nil {
		t.Fatalf("replay_from after the skip %v (%v)", replayFrom, err)
	}
	w.recorded(w.org, w.now, 1)
	w.round()
	if s := w.state(dest); s.forward != 3 || s.pending != nil {
		t.Fatalf("state after the skip %+v", s)
	}
	last := w.tr.sent[len(w.tr.sent)-1].msg
	if last.ForwardSeq == nil || last.ForwardSeq.From != 3 || last.ForwardSeq.To != 3 {
		t.Fatalf("first batch after the skip %+v", last.ForwardSeq)
	}
	if a := w.actions(w.org, audit.CodeNotificationReplayed, dest); len(a) != 0 {
		t.Fatalf("replayed actions for an abandoned replay %+v", a)
	}
}
