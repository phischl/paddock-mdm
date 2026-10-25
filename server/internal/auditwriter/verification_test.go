package auditwriter_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// memStore is an in-memory WORM store.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (m *memStore) PutLocked(_ context.Context, key, _ string, body []byte, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[key]; ok {
		return fmt.Errorf("object %s is locked", key)
	}
	m.objects[key] = append([]byte(nil), body...)
	return nil
}

func (m *memStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.objects[key]
	if !ok {
		return nil, errors.New("no such key")
	}
	return body, nil
}

type recorderEnv struct {
	pool     *db.AuditWriterPool
	store    *memStore
	recorder *auditwriter.Recorder
	now      time.Time
}

func newRecorderEnv(t *testing.T) recorderEnv {
	t.Helper()
	env := pgtest.SharedAudit(t)
	pool, err := db.NewAuditWriterPool(context.Background(), env.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := &memStore{objects: map[string][]byte{}}
	writer, err := auditwriter.NewWriter(pool, store, 400)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	return recorderEnv{pool: pool, store: store, recorder: auditwriter.NewRecorder(pool, writer, func() time.Time { return now }), now: now}
}

type indexedRun struct {
	event auditstore.AuditEvent
	row   *auditstore.AuditVerificationRun
}

// lookup reads the event of correlation verify-<runID> and the run row as the superuser.
func lookup(t *testing.T, runID uuid.UUID) indexedRun {
	t.Helper()
	ctx := context.Background()
	s := stack{super: superConn(t)}
	defer func() { _ = s.super.Close(ctx) }()
	var out indexedRun
	e := &out.event
	if err := s.super.QueryRow(ctx, `SELECT event_id, organization_id, occurred_at, code, outcome, source, actor, target,
		params, correlation_id, object_key FROM audit_event WHERE correlation_id = $1`, "verify-"+runID.String()).Scan(
		&e.EventID, &e.OrganizationID, &e.OccurredAt, &e.Code, &e.Outcome, &e.Source, &e.Actor, &e.Target, &e.Params,
		&e.CorrelationID, &e.ObjectKey); err != nil {
		t.Fatalf("event of run %s: %v", runID, err)
	}
	var r auditstore.AuditVerificationRun
	err := s.super.QueryRow(ctx, `SELECT id, organization_id, trigger, from_day, to_day, started_at, finished_at, days,
		objects, ok, problems, event_id FROM audit_verification_run WHERE id = $1`, runID).Scan(
		&r.ID, &r.OrganizationID, &r.Trigger, &r.FromDay, &r.ToDay, &r.StartedAt, &r.FinishedAt, &r.Days, &r.Objects,
		&r.Ok, &r.Problems, &r.EventID)
	if err == nil {
		out.row = &r
	} else if !db.IsNoRows(err) {
		t.Fatal(err)
	}
	return out
}

func superConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), pgtest.SharedAudit(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func day(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

func problems(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("2026-10-%02d: no manifest (chain broken)", i%28+1)
	}
	out[0] = strings.Repeat("x", 600)
	return out
}

// TestRecorderRecordsEventThenRow (AC unit 1): an ok report becomes one audit.chain_verified in the index and the
// WORM store and one run row that points at it.
func TestRecorderRecordsEventThenRow(t *testing.T) {
	e := newRecorderEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	started := e.now.Add(-time.Minute)
	report := &auditwriter.Report{Days: 7, Objects: 12}

	runID, err := e.recorder.Record(ctx, org, auditwriter.TriggerNightly, day("2026-10-08"), day("2026-10-14"), started, report)
	if err != nil {
		t.Fatal(err)
	}
	got := lookup(t, runID)
	ev := got.event
	if ev.OrganizationID != org || ev.Code != string(audit.CodeAuditChainVerified) || ev.Outcome != "success" ||
		ev.Source != audit.SourceSystem || !ev.OccurredAt.Equal(e.now) {
		t.Fatalf("event: %+v", ev)
	}
	var actor audit.Actor
	var target audit.Target
	var params map[string]any
	for raw, into := range map[string]any{string(ev.Actor): &actor, string(ev.Target): &target, string(ev.Params): &params} {
		if err := json.Unmarshal([]byte(raw), into); err != nil {
			t.Fatal(err)
		}
	}
	if actor.Type != audit.ActorSystem || actor.ID != "audit-writer" || actor.Display != "audit-writer" {
		t.Errorf("actor: %+v", actor)
	}
	if target.Type != "audit_chain" || target.ID != org.String() || target.Display != "2026-10-08..2026-10-14" {
		t.Errorf("target: %+v", target)
	}
	want := map[string]any{"run_id": runID.String(), "trigger": "nightly", "from_day": "2026-10-08", "to_day": "2026-10-14",
		"days": float64(7), "objects": float64(12)}
	if len(params) != len(want) {
		t.Errorf("params: %v, want %v", params, want)
	}
	for k, v := range want {
		if params[k] != v {
			t.Errorf("params[%s] = %v, want %v", k, params[k], v)
		}
	}

	stored, err := e.store.Get(ctx, ev.ObjectKey)
	if err != nil {
		t.Fatalf("WORM object %s: %v", ev.ObjectKey, err)
	}
	events, err := auditwriter.DecodeObject(stored)
	if err != nil || len(events) != 1 || events[0].EventID != ev.EventID {
		t.Fatalf("WORM object holds %+v, %v", events, err)
	}

	row := got.row
	if row == nil {
		t.Fatal("no audit_verification_run row")
	}
	if row.EventID != ev.EventID || row.OrganizationID != org || row.Trigger != "nightly" || !row.Ok ||
		row.Days != 7 || row.Objects != 12 || !row.StartedAt.Equal(started) || !row.FinishedAt.Equal(e.now) ||
		row.FromDay.Format(time.DateOnly) != "2026-10-08" || row.ToDay.Format(time.DateOnly) != "2026-10-14" ||
		string(row.Problems) != "[]" {
		t.Fatalf("row: %+v (problems %s)", row, row.Problems)
	}
}

// TestRecorderCapsProblems (AC unit 1): 70 problems are recorded as audit.chain_verification_failed with
// problem_count 70 and the first 50 problems, each cut to 500 characters, and a failed row.
func TestRecorderCapsProblems(t *testing.T) {
	e := newRecorderEnv(t)
	org := uuid.Must(uuid.NewV7())
	report := &auditwriter.Report{Days: 3, Objects: 4, Problems: problems(70)}

	runID, err := e.recorder.Record(context.Background(), org, auditwriter.TriggerCLI, day("2026-10-01"), day("2026-10-03"), e.now, report)
	if err != nil {
		t.Fatal(err)
	}
	got := lookup(t, runID)
	if got.event.Code != string(audit.CodeAuditChainVerificationFailed) || got.event.Outcome != "failure" {
		t.Fatalf("event: %+v", got.event)
	}
	var params struct {
		ProblemCount int      `json:"problem_count"`
		Problems     []string `json:"problems"`
		ErrorCode    string   `json:"error_code"`
		Trigger      string   `json:"trigger"`
	}
	if err := json.Unmarshal(got.event.Params, &params); err != nil {
		t.Fatal(err)
	}
	if params.ProblemCount != 70 || len(params.Problems) != auditwriter.MaxRecordedProblems ||
		params.ErrorCode != "chain_broken" || params.Trigger != "cli" {
		t.Fatalf("params: count %d, %d problems, error_code %q, trigger %q", params.ProblemCount, len(params.Problems), params.ErrorCode, params.Trigger)
	}
	if n := utf8.RuneCountInString(params.Problems[0]); n != auditwriter.MaxProblemLength {
		t.Errorf("first problem has %d characters, want %d", n, auditwriter.MaxProblemLength)
	}
	if got.row == nil || got.row.Ok || got.row.EventID != got.event.EventID {
		t.Fatalf("row: %+v", got.row)
	}
	var rowProblems []string
	if err := json.Unmarshal(got.row.Problems, &rowProblems); err != nil || len(rowProblems) != auditwriter.MaxRecordedProblems {
		t.Fatalf("row problems: %d, %v", len(rowProblems), err)
	}
}

// TestRecorderEventIsEvidenceOfRecord: when the row insert fails, the event is already written, the run ID is
// returned with the error, and the failure is counted as record_error.
func TestRecorderEventIsEvidenceOfRecord(t *testing.T) {
	e := newRecorderEnv(t)
	org := uuid.Must(uuid.NewV7())
	before := collected(t, e.recorder.Collector(), "bogus", "record_error")

	// The table's CHECK constraint rejects the trigger; the event has no such constraint.
	runID, err := e.recorder.Record(context.Background(), org, "bogus", day("2026-10-01"), day("2026-10-01"), e.now, &auditwriter.Report{Days: 1})
	if err == nil || runID == uuid.Nil {
		t.Fatalf("Record = %s, %v; want the run ID and an error", runID, err)
	}
	got := lookup(t, runID)
	if got.row != nil {
		t.Fatalf("row inserted: %+v", got.row)
	}
	if got.event.Code != string(audit.CodeAuditChainVerified) {
		t.Fatalf("event: %+v", got.event)
	}
	if after := collected(t, e.recorder.Collector(), "bogus", "record_error"); after != before+1 {
		t.Errorf("record_error = %v, want %v", after, before+1)
	}
}

// TestVerifyRunsCollectorCountsCLIRuns: a run recorded by another process (the CLI) is visible as
// {trigger="cli"} on the collector of the serving writer, which reads audit_verification_run at scrape time.
func TestVerifyRunsCollectorCountsCLIRuns(t *testing.T) {
	cli := newRecorderEnv(t)
	writer := newRecorderEnv(t)
	collector := writer.recorder.Collector()
	org := uuid.Must(uuid.NewV7())
	okBefore := collected(t, collector, "cli", "ok")
	failedBefore := collected(t, collector, "cli", "failed")

	if _, err := cli.recorder.Record(context.Background(), org, auditwriter.TriggerCLI, day("2026-10-01"), day("2026-10-01"), cli.now, &auditwriter.Report{Days: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.recorder.Record(context.Background(), org, auditwriter.TriggerCLI, day("2026-10-01"), day("2026-10-02"), cli.now,
		&auditwriter.Report{Days: 2, Problems: []string{"2026-10-02: no manifest (chain broken)"}}); err != nil {
		t.Fatal(err)
	}
	if got := collected(t, collector, "cli", "ok"); got != okBefore+1 {
		t.Errorf(`{trigger="cli",result="ok"} = %v, want %v`, got, okBefore+1)
	}
	if got := collected(t, collector, "cli", "failed"); got != failedBefore+1 {
		t.Errorf(`{trigger="cli",result="failed"} = %v, want %v`, got, failedBefore+1)
	}
}

// TestVerifyRunsCollectorSurvivesDatabaseError: without the database the scrape still succeeds with the in-process
// error series and without ok/failed.
func TestVerifyRunsCollectorSurvivesDatabaseError(t *testing.T) {
	m := auditwriter.NewTestVerifyMetrics()
	auditwriter.SetVerifyCounts(m, func(context.Context) ([]auditstore.CountAuditVerificationRunsRow, error) {
		return nil, errors.New("database down")
	})
	auditwriter.CountVerifyError(m, auditwriter.TriggerNightly, "error")
	series := gather(t, m)
	if series[[2]string{"nightly", "error"}] != 1 {
		t.Errorf("nightly/error = %v, want 1", series[[2]string{"nightly", "error"}])
	}
	if len(series) != 6 {
		t.Errorf("series %v, want the 6 in-process ones", series)
	}
	for k := range series {
		if k[1] == "ok" || k[1] == "failed" {
			t.Errorf("series %v emitted without the database", k)
		}
	}

	auditwriter.SetVerifyCounts(m, func(context.Context) ([]auditstore.CountAuditVerificationRunsRow, error) {
		return []auditstore.CountAuditVerificationRunsRow{{Trigger: "sample", Ok: false, Runs: 3}}, nil
	})
	series = gather(t, m)
	if len(series) != 12 || series[[2]string{"sample", "failed"}] != 3 || series[[2]string{"nightly", "error"}] != 1 {
		t.Errorf("series after recovery: %v", series)
	}
}

// gather registers c in a pedantic registry (which rejects inconsistent or duplicate series) and returns
// paddock_audit_verify_runs_total by (trigger, result).
func gather(t *testing.T, c prometheus.Collector) map[[2]string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[[2]string]float64{}
	for _, f := range families {
		if f.GetName() != "paddock_audit_verify_runs_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			out[[2]string{label(m, "trigger"), label(m, "result")}] = m.GetCounter().GetValue()
		}
	}
	return out
}

func collected(t *testing.T, c prometheus.Collector, trigger, result string) float64 {
	t.Helper()
	return gather(t, c)[[2]string{trigger, result}]
}

func label(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}
