package auditwriter_test

import (
	"context"
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
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
)

// fakeAcks records the acknowledgements; the first failures calls lose their confirm.
type fakeAcks struct {
	mu       sync.Mutex
	failures int
	sent     []offboarding.AuditRetired
	keys     []string
}

func (f *fakeAcks) PublishBatch(_ context.Context, exchange string, msgs []mq.Message) ([]error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if exchange != mq.ExchangeOffboarding || len(msgs) != 1 {
		return nil, errors.New("unexpected publish")
	}
	if f.failures > 0 {
		f.failures--
		return []error{mq.ErrNacked}, nil
	}
	var a offboarding.AuditRetired
	if err := json.Unmarshal(msgs[0].Body, &a); err != nil {
		return nil, err
	}
	f.sent = append(f.sent, a)
	f.keys = append(f.keys, msgs[0].RoutingKey)
	return []error{nil}, nil
}

// of are the acknowledgements of org; the audit database is shared, so a loop may complete other tests' organizations.
func (f *fakeAcks) of(org uuid.UUID) int {
	n := 0
	for _, a := range f.messages() {
		if a.OrganizationID == org {
			n++
		}
	}
	return n
}

// sentFor are the acknowledgements of org with their routing keys.
func (f *fakeAcks) sentFor(org uuid.UUID) ([]offboarding.AuditRetired, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var sent []offboarding.AuditRetired
	var keys []string
	for i, a := range f.sent {
		if a.OrganizationID == org {
			sent, keys = append(sent, a), append(keys, f.keys[i])
		}
	}
	return sent, keys
}

func (f *fakeAcks) messages() []offboarding.AuditRetired {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sent)
}

// settledAcknowledger reports how each delivery was settled.
type settledAcknowledger struct{ settled chan string }

func (a settledAcknowledger) Ack(uint64, bool) error        { a.settled <- "ack"; return nil }
func (a settledAcknowledger) Nack(uint64, bool, bool) error { a.settled <- "nack"; return nil }
func (a settledAcknowledger) Reject(uint64, bool) error     { a.settled <- "reject"; return nil }

// deliver hands body to handle as one delivery and returns how it was settled.
func deliver(t *testing.T, handle mq.ConsumeFunc, body []byte) string {
	t.Helper()
	settled := make(chan string, 1)
	deliveries := make(chan amqp.Delivery, 1)
	deliveries <- amqp.Delivery{Body: body, DeliveryTag: 1, Acknowledger: settledAcknowledger{settled: settled}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = handle(ctx, nil, deliveries); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case s := <-settled:
		return s
	case <-time.After(2 * time.Minute):
		t.Fatal("the delivery was not settled")
		return ""
	}
}

func retirementRequest(t *testing.T, org uuid.UUID) []byte {
	t.Helper()
	ev := event(audit.PlatformOrganizationID, time.Now(), audit.CodeOrganizationAuditRetirementRequested)
	ev.Actor = audit.Actor{Type: audit.ActorSystem, ID: "organization-offboarding", Display: "organization-offboarding"}
	ev.Source = audit.SourceSystem
	ev.Params = map[string]any{"organization_id": org.String(), "slug": "gone"}
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (s stack) retirement(acks auditwriter.AckPublisher) *auditwriter.Retirement {
	return auditwriter.NewRetirement(s.pool, s.writer, s.verifier, s.sealer, auditwriter.NewRecorder(s.pool, s.writer, time.Now), acks)
}

// pending is the number of org's audit_org_retired rows without a recorded final verification.
func (s stack) pending(t *testing.T, org uuid.UUID) int {
	t.Helper()
	return s.count(t, "SELECT count(*) FROM audit_org_retired WHERE organization_id = $1 AND final_verified_at IS NULL", org)
}

// TestRetirement covers plan M17 decision 16 and amendment 2026-11-15 o with review 1: the consumer only closes the log
// (one audit_org_retired row, no verification); the retirement loop seals the days that may be sealed, verifies the
// chain and the unsealed tail (today's object), and records exactly one final verification and one acknowledgement,
// also when the request is delivered again and when the first confirm is lost; a later event of the organization
// lands in the platform pseudo-organization as audit.event_after_retirement, once, while the exporter's own evidence
// keeps its code and params there; the nightly cycle no longer lists the organization; the sealer seals through the
// final day with the retired mark and never after it; and a manifest after the retired day fails the verification.
func TestRetirement(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day1 := time.Now().UTC().AddDate(0, 0, -4).Truncate(24 * time.Hour)
	day3 := day1.AddDate(0, 0, 2)
	s.historicObject(t, org, day1.Add(9*time.Hour), event(org, day1.Add(9*time.Hour), audit.CodeDeviceGroupCreated))
	s.historicObject(t, org, day3.Add(9*time.Hour), event(org, day3.Add(9*time.Hour), audit.CodeDeviceGroupUpdated))
	writeOne(t, s.writer, event(org, time.Now(), audit.CodeDeviceGroupDeleted))

	acks := &fakeAcks{failures: 1}
	retirement := s.retirement(acks)
	request := retirementRequest(t, org)
	if got := deliver(t, retirement.Handle, request); got != "ack" {
		t.Fatalf("request settled with %s", got)
	}
	if s.pending(t, org) != 1 {
		t.Fatal("the consumer did not close the log")
	}
	if err := retirement.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	sealedDays := int(auditwriter.LastSealableDay(time.Now()).Sub(day1)/(24*time.Hour)) + 1
	finals := func() int {
		return s.count(t, `SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code = 'audit.chain_verified'
			AND params->>'final' = 'true' AND params->>'trigger' = 'final' AND (params->>'days')::int = $2
			AND params->>'objects' = '3'`, org, sealedDays)
	}
	if n := finals(); n != 1 {
		t.Fatalf("%d final verifications, want 1", n)
	}
	if n := s.count(t, `SELECT count(*) FROM audit_org_retired WHERE organization_id = $1 AND final_outcome = 'verified'
		AND final_verified_at IS NOT NULL AND ack_published_at IS NULL`, org); n != 1 {
		t.Fatal("no unacknowledged retirement after the lost confirm")
	}
	if n := s.count(t, `SELECT count(*) FROM audit_verification_run WHERE organization_id = $1 AND trigger = 'final' AND ok`, org); n != 1 {
		t.Fatalf("%d final runs, want 1", n)
	}
	if acks.of(org) != 0 {
		t.Fatal("a lost confirm counted as sent")
	}

	if err := retirement.Republish(ctx); err != nil {
		t.Fatal(err)
	}
	sent, keys := acks.sentFor(org)
	if len(sent) != 1 || sent[0].FinalOutcome != offboarding.AuditFinalVerified ||
		sent[0].FinalVerifiedAt.IsZero() || keys[0] != mq.AuditRetiredRoutingKey(org) {
		t.Fatalf("acknowledgements %+v %v", sent, keys)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_org_retired WHERE organization_id = $1 AND ack_published_at IS NOT NULL", org); n != 1 {
		t.Fatal("the confirmed acknowledgement is not marked")
	}

	// A redelivered request changes nothing and is not acknowledged again.
	if got := deliver(t, retirement.Handle, request); got != "ack" {
		t.Fatalf("redelivered request settled with %s", got)
	}
	if err := retirement.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	if err := retirement.Republish(ctx); err != nil {
		t.Fatal(err)
	}
	if n := finals(); n != 1 || acks.of(org) != 1 {
		t.Fatalf("after a redelivery: %d final verifications, %d acknowledgements", n, acks.of(org))
	}

	late := event(org, time.Now(), audit.CodeDeviceGroupDeleted)
	for range 2 {
		if _, err := s.writer.WriteBatch(ctx, []audit.Event{late}); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", late.EventID); n != 0 {
		t.Fatal("a late event was written into the retired organization's log")
	}
	if n := s.count(t, `SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code = 'audit.event_after_retirement'
		AND params->>'organization_id' = $2 AND params->>'original_code' = 'device_group.deleted'
		AND params->>'original_event_id' = $3`, audit.PlatformOrganizationID, org.String(), late.EventID.String()); n != 1 {
		t.Fatalf("%d audit.event_after_retirement for the late event, want 1", n)
	}

	completed := audit.Event{
		Schema: audit.Schema, EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: audit.Timestamp(time.Now()),
		Code: audit.CodeAuditExportCompleted, Outcome: audit.OutcomeSuccess,
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "audit-writer", Display: "audit-writer"},
		Source: audit.SourceSystem, CorrelationID: "export-1",
		Params: map[string]any{"export_id": "e1", "package_sha256": "abc123", "verify_ok": true},
	}
	writeOne(t, s.writer, completed)
	if n := s.count(t, `SELECT count(*) FROM audit_event WHERE event_id = $1 AND organization_id = $2
		AND code = 'audit.export_completed' AND params->>'organization_id' = $3 AND params->>'package_sha256' = 'abc123'
		AND params->>'verify_ok' = 'true'`, completed.EventID, audit.PlatformOrganizationID, org.String()); n != 1 {
		t.Fatal("the exporter's evidence of a retired organization lost its code or params")
	}

	_, _, _, list := auditwriter.PoolIndex(s.pool)
	listed, err := list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(listed, func(o auditwriter.AuditOrganization) bool { return o.ID == org }) {
		t.Fatal("the nightly cycle still lists the retired organization")
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	if _, err := s.sealer.SealOrganizationThrough(ctx, org, today.AddDate(0, 0, 3)); err != nil {
		t.Fatal(err)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_manifest WHERE organization_id = $1 AND day > $2", org, today); n != 0 {
		t.Fatalf("%d manifests after the final day", n)
	}
	var key string
	if err := s.super.QueryRow(ctx, "SELECT object_key FROM audit_manifest WHERE organization_id = $1 AND day = $2", org, today).Scan(&key); err != nil {
		t.Fatalf("the final day is not sealed: %v", err)
	}
	raw, err := s.store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var file auditwriter.ManifestFile
	var manifest auditwriter.Manifest
	if err := json.Unmarshal(raw, &file); err != nil || json.Unmarshal(file.Manifest, &manifest) != nil || !manifest.Retired {
		t.Fatalf("the final day's manifest is not marked retired: %s", raw)
	}
	s.verifyOK(t, org, day1, today.AddDate(0, 0, 3))

	t.Run("manifest after the retired day", func(t *testing.T) {
		if _, err := s.super.Exec(ctx, `INSERT INTO audit_manifest (organization_id, day, sha256, prev_sha256, signature,
			key_version, object_key) SELECT organization_id, day + 1, sha256, sha256, signature, key_version, object_key
			FROM audit_manifest WHERE organization_id = $1 AND day = $2`, org, today); err != nil {
			t.Fatal(err)
		}
		report, err := s.verifier.Verify(ctx, org, day1, today.AddDate(0, 0, 1))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(report.Problems, func(p string) bool { return contains(p, "manifest after the retired day") }) {
			t.Fatalf("a manifest after the retired day was accepted: %v", report.Problems)
		}
	})
}

// TestRetirementFailedOutcome: a broken chain still retires the organization, with outcome failed in the run, the
// retirement row and the acknowledgement (ADR 0052 decision 6: the deletion goes on).
func TestRetirementFailedOutcome(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day1 := time.Now().UTC().AddDate(0, 0, -3).Truncate(24 * time.Hour)
	s.historicObject(t, org, day1.Add(9*time.Hour), event(org, day1.Add(9*time.Hour), audit.CodeDeviceGroupCreated))
	if _, err := s.sealer.SealOrganizationThrough(ctx, org, day1.AddDate(0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.super.Exec(ctx, "DELETE FROM audit_manifest WHERE organization_id = $1 AND day = $2", org, day1); err != nil {
		t.Fatal(err)
	}
	acks := &fakeAcks{}
	retirement := s.retirement(acks)
	if err := retirement.Close(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := retirement.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.count(t, `SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code = 'audit.chain_verification_failed'
		AND params->>'final' = 'true'`, org); n != 1 {
		t.Fatalf("%d failed final verifications, want 1", n)
	}
	if n := s.count(t, `SELECT count(*) FROM audit_org_retired WHERE organization_id = $1 AND final_outcome = 'failed'`, org); n != 1 {
		t.Fatal("the retirement does not record the failed outcome")
	}
	if n := s.count(t, `SELECT count(*) FROM audit_verification_run WHERE organization_id = $1 AND trigger = 'final' AND NOT ok`, org); n != 1 {
		t.Fatal("the failed final run is not recorded for paddock_audit_verify_runs_total")
	}
	if sent, _ := acks.sentFor(org); len(sent) != 1 || sent[0].FinalOutcome != offboarding.AuditFinalFailed {
		t.Fatalf("acknowledgements %+v", sent)
	}
}

// blockingVerifier blocks every call until release is closed and counts the calls.
type blockingVerifier struct {
	release chan struct{}
	calls   chan struct{}
}

func (b blockingVerifier) Verify(ctx context.Context, _ uuid.UUID, _, _ time.Time) (*auditwriter.Report, error) {
	b.calls <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return &auditwriter.Report{}, nil
}

func (b blockingVerifier) VerifyUnsealed(context.Context, uuid.UUID, time.Time, time.Time, *auditwriter.Report) error {
	return nil
}

// failingVerifier fails every final verification.
type failingVerifier struct{}

func (failingVerifier) Verify(context.Context, uuid.UUID, time.Time, time.Time) (*auditwriter.Report, error) {
	return nil, errors.New("object store unreachable")
}

func (failingVerifier) VerifyUnsealed(context.Context, uuid.UUID, time.Time, time.Time, *auditwriter.Report) error {
	return errors.New("object store unreachable")
}

// TestRetirementDoesNotBlockTheConsumer (review 1 M1): the consumer acknowledges the request and another
// organization's event while the final verification of the retiring organization hangs in the retirement loop.
func TestRetirementDoesNotBlockTheConsumer(t *testing.T) {
	s := newStack(t)
	org, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	day := time.Now().UTC().AddDate(0, 0, -3).Truncate(24 * time.Hour)
	s.historicObject(t, org, day.Add(9*time.Hour), event(org, day.Add(9*time.Hour), audit.CodeDeviceGroupCreated))
	retirement := s.retirement(&fakeAcks{})
	v := blockingVerifier{release: make(chan struct{}), calls: make(chan struct{}, 4)}
	auditwriter.SetRetirementVerifier(retirement, v)
	ctx, cancel := context.WithCancel(context.Background())
	loop := make(chan struct{})
	go func() { retirement.RunRetirements(ctx); close(loop) }()
	defer func() { close(v.release); cancel(); <-loop }()

	if got := deliver(t, retirement.Handle, retirementRequest(t, org)); got != "ack" {
		t.Fatalf("request settled with %s", got)
	}
	select {
	case <-v.calls:
	case <-time.After(time.Minute):
		t.Fatal("the retirement loop did not start the final verification")
	}
	ev := event(other, time.Now(), audit.CodeDeviceGroupCreated)
	body, _ := json.Marshal(ev)
	if got := deliver(t, retirement.Handle, body); got != "ack" {
		t.Fatalf("another organization's event settled with %s while the verification hangs", got)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE event_id = $1", ev.EventID); n != 1 {
		t.Fatal("another organization's event was not written while the verification hangs")
	}
}

// TestRetirementCloseFailureIsRecovered (review 1 M1): a database error while the consumer closes the log does not
// requeue or dead-letter the request; the retirement loop finds the indexed request and completes it.
func TestRetirementCloseFailureIsRecovered(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	writeOne(t, s.writer, event(org, time.Now(), audit.CodeDeviceGroupCreated))
	acks := &fakeAcks{}
	retirement := s.retirement(acks)
	auditwriter.SetBeforeClose(retirement, func(uuid.UUID) error { return errors.New("database down") })
	if got := deliver(t, retirement.Handle, retirementRequest(t, org)); got != "ack" {
		t.Fatalf("request settled with %s, want ack (no requeue, no dead letter)", got)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_org_retired WHERE organization_id = $1", org); n != 0 {
		t.Fatal("the failed close inserted the row")
	}
	auditwriter.SetBeforeClose(retirement, nil)
	if err := retirement.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.count(t, `SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code = 'audit.chain_verified'
		AND params->>'final' = 'true'`, org); n != 1 || s.pending(t, org) != 0 || acks.of(org) != 1 {
		t.Fatalf("after the loop: %d final verifications, %d pending, %d acknowledgements", n, s.pending(t, org), acks.of(org))
	}
}

// TestRetirementVerificationFailureRetries (review 1 M1): a failing final verification records nothing and leaves the
// closed log pending, as a crash would; the next run of the loop resumes from the table and completes it once.
func TestRetirementVerificationFailureRetries(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day := time.Now().UTC().AddDate(0, 0, -3).Truncate(24 * time.Hour)
	s.historicObject(t, org, day.Add(9*time.Hour), event(org, day.Add(9*time.Hour), audit.CodeDeviceGroupCreated))
	acks := &fakeAcks{}
	retirement := s.retirement(acks)
	auditwriter.SetRetirementVerifier(retirement, failingVerifier{})
	if err := retirement.Close(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := retirement.Complete(ctx); err == nil {
		t.Fatal("a failing verification reported success")
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code LIKE 'audit.chain_%'", org); n != 0 ||
		s.pending(t, org) != 1 || acks.of(org) != 0 {
		t.Fatalf("after the failure: %d verification events, %d pending, %d acknowledgements", n, s.pending(t, org), acks.of(org))
	}
	auditwriter.SetRetirementVerifier(retirement, s.verifier)
	for range 2 {
		if err := retirement.Complete(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.count(t, `SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code = 'audit.chain_verified'
		AND params->>'final' = 'true'`, org); n != 1 || s.pending(t, org) != 0 || acks.of(org) != 1 {
		t.Fatalf("after the retry: %d final verifications, %d pending, %d acknowledgements", n, s.pending(t, org), acks.of(org))
	}
}

// TestRetirementRetryAfterTheFinalEventKeepsTheRetiredMark (review 2 m3): a retry after the final event was written but
// its outcome not recorded, once the event's day may be sealed, must not seal that day ahead of the regular sealer: the
// final day is sealed with the retired mark.
func TestRetirementRetryAfterTheFinalEventKeepsTheRetiredMark(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day := time.Now().UTC().AddDate(0, 0, -3).Truncate(24 * time.Hour)
	s.historicObject(t, org, day.Add(9*time.Hour), event(org, day.Add(9*time.Hour), audit.CodeDeviceGroupCreated))
	retirement := s.retirement(&fakeAcks{})
	if err := retirement.Close(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := retirement.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	var finalDay time.Time
	if err := s.super.QueryRow(ctx, `SELECT o.day FROM audit_object o JOIN audit_event e ON e.object_key = o.object_key
		WHERE e.organization_id = $1 AND e.code = 'audit.chain_verified' AND e.params->>'final' = 'true'`, org).Scan(&finalDay); err != nil {
		t.Fatalf("the final event's day: %v", err)
	}
	finalDay = finalDay.UTC().Truncate(24 * time.Hour)
	// The state of a failed or interrupted record: the final event is in the log, its outcome is not.
	if _, err := s.super.Exec(ctx, `UPDATE audit_org_retired SET final_verified_at = NULL, final_outcome = NULL,
		ack_published_at = NULL WHERE organization_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	later := finalDay.AddDate(0, 0, 2).Add(12 * time.Hour)
	auditwriter.SetSealerClock(s.sealer, func() time.Time { return later })
	if !auditwriter.LastSealableDay(later).After(finalDay) {
		t.Fatal("the final event's day is not sealable at the retry's clock; the test proves nothing")
	}
	if err := retirement.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	if s.pending(t, org) != 0 {
		t.Fatal("the retry did not record the final verification")
	}
	if n := s.count(t, `SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code LIKE 'audit.chain_%'
		AND params->>'final' = 'true'`, org); n != 1 {
		t.Fatalf("%d final verification events after the retry, want 1", n)
	}
	if _, err := s.sealer.SealOrganizationThrough(ctx, org, finalDay.AddDate(0, 0, 3)); err != nil {
		t.Fatal(err)
	}
	var key string
	if err := s.super.QueryRow(ctx, "SELECT object_key FROM audit_manifest WHERE organization_id = $1 AND day = $2", org,
		finalDay).Scan(&key); err != nil {
		t.Fatalf("the final day is not sealed: %v", err)
	}
	raw, err := s.store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var file auditwriter.ManifestFile
	var manifest auditwriter.Manifest
	if err := json.Unmarshal(raw, &file); err != nil || json.Unmarshal(file.Manifest, &manifest) != nil || !manifest.Retired {
		t.Fatalf("the final day's manifest lost the retired mark after the retry: %s", raw)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_manifest WHERE organization_id = $1 AND day > $2", org, finalDay); n != 0 {
		t.Fatalf("%d manifests after the final day", n)
	}
}
