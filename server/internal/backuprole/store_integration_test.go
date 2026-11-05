package backuprole

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestPGStore runs every query of the backup role on role paddock_backup (plan M15 decisions 15–16, migration 00100
// and 00107): it reads the active key's ciphertext and the targets with their credentials, writes host state, test
// results, target status and runs, and records each run with one audit event in the platform pseudo-organization.
func TestPGStore(t *testing.T) {
	ctx := context.Background()
	pg := pgtest.SharedPaddock(t)
	pool, err := db.NewBackupPool(ctx, pg.Backup, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	platform, err := db.NewPlatformPool(ctx, pg.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, pg.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("DELETE FROM backup_target_status")
	exec("DELETE FROM backup_target")
	exec("DELETE FROM backup_run")
	exec("DELETE FROM backup_key")
	exec("DELETE FROM backup_schedule")
	runner := app.NewActionRunner(nil, platform, func(context.Context) string { return "" },
		app.WithPlatformScope(pool.InBackup))
	s := NewPGStore(pool, platform, runner)

	if _, ok, err := s.ActiveKey(ctx); err != nil || ok {
		t.Fatalf("active key without a row: %v %v", ok, err)
	}
	exec(`INSERT INTO backup_key (key_id, state, ciphertext, fingerprint, challenge_positions, challenge_sha256, created_by)
		VALUES ($1, 'confirmed', 'vault:v1:key', '1111111111111111', '{1,2,3,4,5,6}', '\x00', 'alice'),
		('bk-20260101-00000001', 'retired', 'vault:v1:old', '2222222222222222', '{1,2,3,4,5,6}', '\x00', 'alice')`, testKeyID)
	exec(`UPDATE backup_key SET retired_at = '2026-11-01T00:00:00Z' WHERE key_id = 'bk-20260101-00000001'`)
	key, ok, err := s.ActiveKey(ctx)
	if err != nil || !ok || key.ID != testKeyID || key.Ciphertext != "vault:v1:key" {
		t.Fatalf("active key %+v %v %v", key, ok, err)
	}
	keys, err := s.Keys(ctx)
	if err != nil || len(keys) != 2 || keys[0] != (KeyRecord{ID: "bk-20260101-00000001", State: "retired",
		RetiredAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}) || keys[1].ID != testKeyID || keys[1].State != "confirmed" ||
		!keys[1].RetiredAt.IsZero() {
		t.Errorf("keys %+v %v", keys, err)
	}
	if sc, err := s.Schedule(ctx); err != nil || sc != backupset.DefaultSchedule() {
		t.Errorf("default schedule %+v %v", sc, err)
	}

	smb, s3 := uuid.New(), uuid.New()
	exec(`INSERT INTO backup_target (id, name, type, settings, credentials_ciphertext, host_state, host_revision,
		test_requested_at, created_by) VALUES
		($1, 'nas', 'smb', '{"host":"nas.example","share":"b"}', 'vault:v1:smb', 'pending_host', 2, now(), 'alice'),
		($2, 'bucket', 's3', '{"endpoint":"https://s3.example","bucket":"b"}', 'vault:v1:s3', 'n/a', 1, NULL, 'alice')`,
		smb, s3)
	targets, err := s.Targets(ctx)
	if err != nil || len(targets) != 2 {
		t.Fatalf("targets %+v %v", targets, err)
	}
	if targets[0].Name != "bucket" || targets[0].CredentialsCiphertext != "vault:v1:s3" || targets[0].TestRequested ||
		targets[1].HostRevision != 2 || !targets[1].TestRequested || targets[1].Settings.Host != "nas.example" {
		t.Errorf("targets %+v", targets)
	}
	if err := s.SetHostState(ctx, smb, HostMounted); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTestResult(ctx, smb, ClassAuth); err != nil {
		t.Fatal(err)
	}
	var state, testErr string
	var requested *time.Time
	if err := super.QueryRow(ctx, `SELECT host_state, last_test_error, test_requested_at FROM backup_target WHERE id = $1`,
		smb).Scan(&state, &testErr, &requested); err != nil || state != HostMounted || testErr != ClassAuth || requested != nil {
		t.Errorf("target after the round: %s %s %v %v", state, testErr, requested, err)
	}
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	if err := s.SetTargetStatus(ctx, s3, KindOpenBao, KindStatus{LastSuccess: at, Bytes: 42}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTargetStatus(ctx, s3, KindOpenBao, KindStatus{Error: ClassDial}); err != nil {
		t.Fatal(err)
	}
	var last time.Time
	var bytes int64
	var lastErr string
	if err := super.QueryRow(ctx, `SELECT last_success_at, bytes, last_error FROM backup_target_status
		WHERE target_id = $1 AND kind = 'openbao'`, s3).Scan(&last, &bytes, &lastErr); err != nil ||
		!last.Equal(at) || bytes != 42 || lastErr != ClassDial {
		t.Errorf("status %v %d %s %v", last, bytes, lastErr, err)
	}

	req := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO backup_run (id, kind, label, state, requested_by) VALUES ($1, 'openbao', 'before upgrade', 'requested', 'alice')`, req)
	reqs, err := s.RequestedRuns(ctx)
	if err != nil || len(reqs) != 1 || reqs[0].Label != "before upgrade" {
		t.Fatalf("requested %+v %v", reqs, err)
	}
	targetsOK := []backupset.RunTarget{{TargetID: s3.String(), OK: true}, {TargetID: smb.String(), ErrorClass: ClassNotMounted}}
	if err := s.RecordRun(ctx, RunRecord{Kind: KindOpenBao, Requests: reqs, Succeeded: true, StartedAt: at,
		FinishedAt: at.Add(3 * time.Second), Bytes: 99, Targets: targetsOK}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordRun(ctx, RunRecord{Kind: KindFleet, ErrorClass: runClassFleet, StartedAt: at, FinishedAt: at,
		Targets: targetsOK}); err != nil {
		t.Fatal(err)
	}
	var outcome, rawTargets string
	if err := super.QueryRow(ctx, `SELECT outcome, targets::text FROM backup_run WHERE id = $1 AND state = 'finished'`,
		req).Scan(&outcome, &rawTargets); err != nil || outcome != "succeeded" {
		t.Fatalf("requested run %s %v", outcome, err)
	}
	if got, err := backupset.ParseRunTargets([]byte(rawTargets)); err != nil || len(got) != 2 || !got[0].OK {
		t.Errorf("run targets %v %v", got, err)
	}
	var params []byte
	var actor []byte
	if err := super.QueryRow(ctx, `SELECT params, actor FROM action WHERE code = 'platform.backup_completed'
		AND organization_id = $1 AND outcome = 'success' AND target->>'id' = $2`,
		audit.PlatformOrganizationID, req.String()).Scan(&params, &actor); err != nil {
		t.Fatalf("completed event: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(params, &p); err != nil || p["label"] != "before upgrade" || p["targets_ok"] != 1.0 ||
		p["targets_failed"] != 1.0 || p["bytes"] != 99.0 || p["duration_s"] != 3.0 {
		t.Errorf("params %s %v", params, err)
	}
	if !json.Valid(actor) || !strings.Contains(string(actor), Actor) {
		t.Errorf("actor %s", actor)
	}
	var failed int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM action WHERE code = 'platform.backup_failed' AND outcome = 'failure'
		AND params->>'error_class' = 'fleet'`).Scan(&failed); err != nil || failed != 1 {
		t.Errorf("failed events %d %v", failed, err)
	}
	var outbox int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE organization_id = $1`, audit.PlatformOrganizationID).
		Scan(&outbox); err != nil || outbox < 2 {
		t.Errorf("outbox rows %d %v", outbox, err)
	}
	hist, err := s.History(ctx)
	if err != nil || !hist[KindOpenBao].LastSuccess.Equal(at.Add(3*time.Second)) || !hist[KindFleet].LastSuccess.IsZero() ||
		!hist[KindFleet].LastAttempt.Equal(at) {
		t.Errorf("history %+v %v", hist, err)
	}
	if id, err := s.InstallationID(ctx); err != nil || uuid.Validate(id) != nil {
		t.Errorf("installation ID %q %v", id, err)
	}
	if v, err := s.SchemaVersion(ctx); err != nil || v < 107 {
		t.Errorf("schema version %d %v", v, err)
	}
}

// TestPGStoreEscrowEvidence: the store reads the newest successful Destroy per device of any organization through
// paddock_backup (migration 00107), one entry per device, and ignores failed Destroys.
func TestPGStoreEscrowEvidence(t *testing.T) {
	ctx := context.Background()
	pg := pgtest.SharedPaddock(t)
	pool, err := db.NewBackupPool(ctx, pg.Backup, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, pg.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org, device, failedDevice := uuid.New(), uuid.NewString(), uuid.NewString()
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		device  string
		outcome string
		at      time.Time
	}{{device, "success", at}, {device, "success", at}, {failedDevice, "failure", at}} {
		if _, err := super.Exec(ctx, `INSERT INTO action (id, organization_id, code, status, outcome, actor, target, params,
			correlation_id, started_at, finished_at) VALUES ($1, $2, 'device.escrow_destroyed', 'finished', $3,
			'{"kind":"system","id":"issuer"}', jsonb_build_object('type', 'device', 'id', $4::text), '{}', $5, $6, $6)`,
			uuid.New(), org, row.outcome, row.device, uuid.NewString(), row.at); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NewPGStore(pool, nil, nil).EscrowEvidence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The action_integrity trigger (migration 00084) stamps finished_at with the database clock.
	if at, ok := got[org.String()+"/"+device]; !ok || time.Since(at).Abs() > time.Minute {
		t.Errorf("evidence of the device %v %v, want the Destroy's finish time", at, ok)
	}
	if _, ok := got[org.String()+"/"+failedDevice]; ok {
		t.Error("a failed Destroy counts as evidence")
	}
}
