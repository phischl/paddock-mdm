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

// TestRetirement covers plan M17 decision 16 and amendment 2026-11-15 o: the request yields exactly one final
// verification in the organization's log, one audit_org_retired row and one acknowledgement, also when the request is
// delivered again and when the first confirm is lost; a later event of the organization lands in the platform
// pseudo-organization as audit.event_after_retirement, once; the nightly cycle no longer lists the organization; the
// sealer seals through the final day with the retired mark and never after it; and a manifest after the retired day
// fails the verification.
func TestRetirement(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day1 := time.Now().UTC().AddDate(0, 0, -3).Truncate(24 * time.Hour)
	day2 := day1.AddDate(0, 0, 1)
	s.historicObject(t, org, day1.Add(9*time.Hour), event(org, day1.Add(9*time.Hour), audit.CodeDeviceGroupCreated))
	s.historicObject(t, org, day2.Add(9*time.Hour), event(org, day2.Add(9*time.Hour), audit.CodeDeviceGroupUpdated))
	if _, err := s.sealer.SealOrganizationThrough(ctx, org, day2); err != nil {
		t.Fatal(err)
	}

	acks := &fakeAcks{failures: 1}
	retirement := auditwriter.NewRetirement(s.pool, s.writer, s.verifier, auditwriter.NewRecorder(s.pool, s.writer, time.Now), acks)
	request := retirementRequest(t, org)
	if got := deliver(t, retirement.Handle, request); got != "ack" {
		t.Fatalf("request settled with %s", got)
	}
	finals := func() int {
		return s.count(t, `SELECT count(*) FROM audit_event WHERE organization_id = $1 AND code = 'audit.chain_verified'
			AND params->>'final' = 'true' AND params->>'trigger' = 'final' AND params->>'days' = '2'`, org)
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
	if len(acks.messages()) != 0 {
		t.Fatal("a lost confirm counted as sent")
	}

	if err := retirement.Republish(ctx); err != nil {
		t.Fatal(err)
	}
	sent := acks.messages()
	if len(sent) != 1 || sent[0].OrganizationID != org || sent[0].FinalOutcome != offboarding.AuditFinalVerified ||
		sent[0].FinalVerifiedAt.IsZero() || acks.keys[0] != mq.AuditRetiredRoutingKey(org) {
		t.Fatalf("acknowledgements %+v %v", sent, acks.keys)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_org_retired WHERE organization_id = $1 AND ack_published_at IS NOT NULL", org); n != 1 {
		t.Fatal("the confirmed acknowledgement is not marked")
	}

	// A redelivered request changes nothing and is not acknowledged again.
	if got := deliver(t, retirement.Handle, request); got != "ack" {
		t.Fatalf("redelivered request settled with %s", got)
	}
	if err := retirement.Republish(ctx); err != nil {
		t.Fatal(err)
	}
	if n := finals(); n != 1 || len(acks.messages()) != 1 {
		t.Fatalf("after a redelivery: %d final verifications, %d acknowledgements", n, len(acks.messages()))
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
	retirement := auditwriter.NewRetirement(s.pool, s.writer, s.verifier, auditwriter.NewRecorder(s.pool, s.writer, time.Now), acks)
	if err := retirement.Retire(ctx, org); err != nil {
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
	if sent := acks.messages(); len(sent) != 1 || sent[0].FinalOutcome != offboarding.AuditFinalFailed {
		t.Fatalf("acknowledgements %+v", sent)
	}
}
