package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/finding"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// findingsHarness records device events with the worker's role and changes findings with the api's role.
type findingsHarness struct {
	reports  *app.DeviceReports
	worker   *app.Findings
	api      *app.Findings
	accounts *app.AccountList
	super    *pgx.Conn
}

func newFindingsHarness(t *testing.T) findingsHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	api, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	workerRunner := app.NewActionRunner(worker, platform, httpx.RequestID)
	apiRunner := app.NewActionRunner(api, platform, httpx.RequestID)
	return findingsHarness{
		reports: app.NewDeviceReports(workerRunner, worker), worker: app.NewFindings(workerRunner, worker),
		api: app.NewFindings(apiRunner, api), accounts: app.NewAccountList(api), super: super,
	}
}

func (h findingsHarness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (h findingsHarness) org(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'F', 'active')", id, "f"+id.String()[24:])
	return id
}

func (h findingsHarness) device(t *testing.T, org uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'ws-17', 'active')", id, org)
	return id
}

// account creates an administrator account of org with role; disabled accounts are not assignable.
func (h findingsHarness) account(t *testing.T, org uuid.UUID, username, role string, disabled bool) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	h.exec(t, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role, disabled_at)
		VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN now() END)`, id, org, id.String(), username, strings.ToUpper(username), role, disabled)
	return id
}

func adminCtx(org uuid.UUID, role principal.Role, display string) context.Context {
	ctx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindAdmin, Role: role, OrganizationID: org, ID: uuid.New(), Display: display,
	})
	return httpx.WithRequestID(ctx, uuid.NewString())
}

func sudoersEvent(seq int64, file string) protocol.Event {
	return protocol.Event{EventSeq: seq, Type: protocol.EventTamperSudoersDFile, OccurredAt: time.Now().UTC(),
		Data: json.RawMessage(fmt.Sprintf(`{"file":%q,"quarantined_as":"q"}`, file))}
}

type findingRow struct {
	id                    uuid.UUID
	status                string
	occurrences           int
	firstEvent, lastEvent uuid.UUID
	closed                bool
}

func (h findingsHarness) tamperFindings(t *testing.T, device uuid.UUID, code string) []findingRow {
	t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT id, status, occurrences, first_event_id, last_event_id, closed_at IS NOT NULL
		FROM finding WHERE device_id = $1 AND kind = 'tamper' AND code = $2 ORDER BY opened_at, id`, device, code)
	if err != nil {
		t.Fatal(err)
	}
	return collect(t, rows, func(r pgx.CollectableRow) (findingRow, error) {
		var f findingRow
		err := r.Scan(&f.id, &f.status, &f.occurrences, &f.firstEvent, &f.lastEvent, &f.closed)
		return f, err
	})
}

func collect[T any](t *testing.T, rows pgx.Rows, fn pgx.RowToFunc[T]) []T {
	t.Helper()
	out, err := pgx.CollectRows(rows, fn)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// eventID is the audit event of a device event, by its event_seq.
func (h findingsHarness) eventID(t *testing.T, device uuid.UUID, seq int64) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := h.super.QueryRow(context.Background(), `SELECT id FROM action WHERE target ->> 'id' = $1 AND params ->> 'event_seq' = $2`,
		device.String(), fmt.Sprint(seq)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestTamperFindingCountsEvents (N8, plan M9 decision 31): three tamper.sudoers_d_file events of one device and file
// are one open finding with three occurrences, naming the first and the last audit event; a redelivered event counts
// nothing, another file is another finding, and an event after the close opens a second finding.
func TestTamperFindingCountsEvents(t *testing.T) {
	h := newFindingsHarness(t)
	org := h.org(t)
	dev := h.device(t, org)
	ctx := systemCtx(org)
	if err := h.reports.RecordEvents(ctx, dev, time.Now(), []protocol.Event{sudoersEvent(1, "evil"), sudoersEvent(2, "evil")}); err != nil {
		t.Fatal(err)
	}
	if fresh, err := h.reports.RecordEvent(ctx, dev, sudoersEvent(3, "evil")); err != nil || !fresh {
		t.Fatalf("event 3: %v %v", fresh, err)
	}
	if err := h.reports.RecordEvents(ctx, dev, time.Now(), []protocol.Event{sudoersEvent(3, "evil"), sudoersEvent(4, "other")}); err != nil {
		t.Fatal(err)
	}
	got := h.tamperFindings(t, dev, "device.tamper_sudoers_d_file")
	if len(got) != 2 {
		t.Fatalf("%d findings, want 2 (evil, other)", len(got))
	}
	evil := got[0]
	if evil.occurrences != 3 || evil.status != "open" || evil.firstEvent != h.eventID(t, dev, 1) || evil.lastEvent != h.eventID(t, dev, 3) {
		t.Fatalf("finding of evil: %+v", evil)
	}
	if got[1].occurrences != 1 || got[1].firstEvent != h.eventID(t, dev, 4) {
		t.Fatalf("finding of other: %+v", got[1])
	}
	if _, err := h.api.Close(adminCtx(org, principal.RoleOrgOperator, "olga"), evil.id, finding.StatusResolved, "removed the file", ""); err != nil {
		t.Fatal(err)
	}
	if err := h.reports.RecordEvents(ctx, dev, time.Now(), []protocol.Event{sudoersEvent(5, "evil")}); err != nil {
		t.Fatal(err)
	}
	got = h.tamperFindings(t, dev, "device.tamper_sudoers_d_file")
	if len(got) != 3 || !got[0].closed || got[0].occurrences != 3 || got[2].closed || got[2].occurrences != 1 || got[2].firstEvent != h.eventID(t, dev, 5) {
		t.Fatalf("after the close and a new event: %+v", got)
	}
	// The newer open finding of the same file keeps the closed one from reopening (the live key is unique).
	_, err := h.api.Reopen(adminCtx(org, principal.RoleOrgOperator, "olga"), evil.id, "still there")
	if !errors.Is(err, problem.InvalidState) {
		t.Fatalf("reopen beside a newer open finding: %v, want invalid_state", err)
	}
}

// TestCloneFinding (plan M9 decision 31): device.clone_suspected opens a finding in the transaction of its event.
func TestCloneFinding(t *testing.T) {
	h := newFindingsHarness(t)
	org := h.org(t)
	dev := h.device(t, org)
	if ok, err := h.reports.QuarantineClone(systemCtx(org), ingest.Heartbeat{DeviceID: dev, ReportedSeq: 3, Seq: 9}); err != nil || !ok {
		t.Fatalf("quarantine: %v %v", ok, err)
	}
	var event uuid.UUID
	if err := h.super.QueryRow(context.Background(), "SELECT id FROM action WHERE target ->> 'id' = $1 AND code = 'device.clone_suspected'", dev.String()).Scan(&event); err != nil {
		t.Fatal(err)
	}
	got := h.tamperFindings(t, dev, "device.clone_suspected")
	if len(got) != 1 || got[0].firstEvent != event || got[0].lastEvent != event || got[0].occurrences != 1 {
		t.Fatalf("clone findings %+v, want one naming %s", got, event)
	}
}

// TestAttentionFindingsRound (N8, plan M9 decision 32): an open attention condition becomes a finding opened when
// the condition began, without an audit event; the round is idempotent, and once the condition is gone the finding
// is cleared, also when it was closed meanwhile. A cleared attention finding cannot be reopened.
func TestAttentionFindingsRound(t *testing.T) {
	h := newFindingsHarness(t)
	org := h.org(t)
	dev := h.device(t, org)
	since := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	alert := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at) VALUES ($1, $2, $3, 'stale_critical', $4)", alert, org, dev, since)
	ctx := systemCtx(org)
	round := func() {
		t.Helper()
		if err := h.worker.Materialize(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (n int, opened time.Time, updated time.Time, cleared bool) {
		t.Helper()
		if err := h.super.QueryRow(context.Background(), `SELECT count(*), max(opened_at), max(updated_at), bool_and(cleared_at IS NOT NULL)
			FROM finding WHERE device_id = $1 AND kind = 'attention' AND key = $2 AND code = 'stale_critical'`,
			dev, "attention:stale_critical:"+alert.String()).Scan(&n, &opened, &updated, &cleared); err != nil {
			t.Fatal(err)
		}
		return
	}
	round()
	n, opened, updated, cleared := state()
	if n != 1 || !opened.Equal(since) || cleared {
		t.Fatalf("after one round: %d findings opened %v (want %v), cleared %v", n, opened, since, cleared)
	}
	round()
	if n2, _, updated2, _ := state(); n2 != 1 || !updated2.Equal(updated) {
		t.Fatalf("second round changed the findings: %d, updated %v → %v", n2, updated, updated2)
	}
	list, err := h.api.List(adminCtx(org, principal.RoleOrgAuditor, "audrey"), app.FindingQuery{Page: app.ListPage{Sort: "-last_seen_at", Limit: 10}})
	if err != nil || list.Count != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	id := list.Items[0].ID
	if _, err := h.api.Close(adminCtx(org, principal.RoleOrgOperator, "olga"), id, finding.StatusFalsePositive, "planned outage", "CHG-1"); err != nil {
		t.Fatal(err)
	}
	h.exec(t, "UPDATE device_alert SET cleared_at = now() WHERE id = $1", alert)
	round()
	round()
	if n, _, _, cleared := state(); n != 1 || !cleared {
		t.Fatalf("after the condition is gone: %d findings, cleared %v", n, cleared)
	}
	var events int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE organization_id = $1 AND code <> 'finding.closed'", org).Scan(&events); err != nil || events != 0 {
		t.Fatalf("%d audit events of the round (%v), want 0", events, err)
	}
	if _, err := h.api.Reopen(adminCtx(org, principal.RoleOrgOperator, "olga"), id, "again"); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("reopen of a cleared attention finding: %v, want invalid_state", err)
	}
	clearedList, err := h.api.List(adminCtx(org, principal.RoleOrgAuditor, "audrey"), app.FindingQuery{Page: app.ListPage{Sort: "-last_seen_at", Limit: 10}, Cleared: true})
	if err != nil || clearedList.Count != 1 || clearedList.Items[0].ID != id {
		t.Fatalf("cleared list: %+v %v", clearedList, err)
	}
	if live, err := h.api.List(adminCtx(org, principal.RoleOrgAuditor, "audrey"), app.FindingQuery{Page: app.ListPage{Sort: "-last_seen_at", Limit: 10}}); err != nil || live.Count != 0 {
		t.Fatalf("default list after clearing: %+v %v", live, err)
	}
}

// findingEvent is a recorded finding.* audit event.
type findingEvent struct {
	code, outcome, errorCode string
	params                   map[string]any
}

func (h findingsHarness) findingEvents(t *testing.T, org, id uuid.UUID) []findingEvent {
	t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT code, outcome, coalesce(error_code, ''), params FROM action
		WHERE organization_id = $1 AND target ->> 'type' = 'finding' AND target ->> 'id' = $2 ORDER BY started_at, id`, org, id.String())
	if err != nil {
		t.Fatal(err)
	}
	return collect(t, rows, func(r pgx.CollectableRow) (findingEvent, error) {
		var e findingEvent
		var raw []byte
		if err := r.Scan(&e.code, &e.outcome, &e.errorCode, &raw); err != nil {
			return e, err
		}
		return e, json.Unmarshal(raw, &e.params)
	})
}

// TestFindingStateMachine (N9, plan M9 decision 33): acknowledge, assign, close and reopen with their role rules and
// refusals; every attempt records exactly one event with the params of plan §6.3; auditors read, and another
// organization sees nothing.
func TestFindingStateMachine(t *testing.T) {
	h := newFindingsHarness(t)
	org, other := h.org(t), h.org(t)
	dev := h.device(t, org)
	if err := h.reports.RecordEvents(systemCtx(org), dev, time.Now(), []protocol.Event{sudoersEvent(1, "evil")}); err != nil {
		t.Fatal(err)
	}
	id := h.tamperFindings(t, dev, "device.tamper_sudoers_d_file")[0].id
	operator := adminCtx(org, principal.RoleOrgOperator, "olga")
	admin := adminCtx(org, principal.RoleOrgAdmin, "alice")
	auditor := adminCtx(org, principal.RoleOrgAuditor, "audrey")
	olga := h.account(t, org, "olga", "org_operator", false)
	audrey := h.account(t, org, "audrey", "org_auditor", false)
	gone := h.account(t, org, "gone", "org_admin", true)
	foreign := h.account(t, other, "bob", "org_admin", false)

	if _, err := h.api.Acknowledge(auditor, id); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor acknowledge: %v, want forbidden", err)
	}
	f, err := h.api.Acknowledge(operator, id)
	if err != nil || f.Status != finding.StatusAcknowledged || f.AcknowledgedAt == nil {
		t.Fatalf("acknowledge: %+v %v", f, err)
	}
	if _, err := h.api.Acknowledge(operator, id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("second acknowledge: %v, want invalid_state", err)
	}
	for name, account := range map[string]uuid.UUID{"auditor": audrey, "disabled": gone, "other organization": foreign} {
		if _, err := h.api.Assign(operator, id, &account); !errors.Is(err, problem.NotFound) {
			t.Fatalf("assign to the %s account: %v, want not_found", name, err)
		}
	}
	f, err = h.api.Assign(operator, id, &olga)
	if err != nil || f.Status != finding.StatusInProgress || f.Assignee == nil || f.Assignee.Username != "olga" || f.Assignee.DisplayName != "OLGA" {
		t.Fatalf("assign: %+v %v", f, err)
	}
	if _, err := h.api.Close(operator, id, finding.StatusAcceptedRisk, "known", ""); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator accepts a risk: %v, want forbidden", err)
	}
	for name, reason := range map[string]string{"missing": "", "blank": "  ", "too long": strings.Repeat("r", finding.MaxReason+1)} {
		if _, err := h.api.Close(operator, id, finding.StatusFalsePositive, reason, ""); !errors.Is(err, problem.InvalidRequest) {
			t.Fatalf("close with a %s reason: %v, want invalid_request", name, err)
		}
	}
	if _, err := h.api.Close(operator, id, finding.StatusFalsePositive, "test file", strings.Repeat("x", finding.MaxExternalRef+1)); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("close with a long external_ref: %v, want invalid_request", err)
	}
	f, err = h.api.Close(admin, id, finding.StatusAcceptedRisk, "test file", "CHG-7")
	if err != nil || f.Status != finding.StatusAcceptedRisk || f.ClosedAt == nil || deref(f.ClosedBy) != "alice" || deref(f.Reason) != "test file" || deref(f.ExternalRef) != "CHG-7" {
		t.Fatalf("admin close: %+v %v", f, err)
	}
	if _, err := h.api.Acknowledge(operator, id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("acknowledge a closed finding: %v, want invalid_state", err)
	}
	if _, err := h.api.Close(operator, id, finding.StatusResolved, "again", ""); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("close a closed finding: %v, want invalid_state", err)
	}
	if _, err := h.api.Reopen(operator, id, ""); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("reopen without a reason: %v, want invalid_request", err)
	}
	f, err = h.api.Reopen(operator, id, "seen again")
	if err != nil || f.Status != finding.StatusOpen || f.ClosedAt != nil || f.ClosedBy != nil || deref(f.Reason) != "seen again" {
		t.Fatalf("reopen: %+v %v", f, err)
	}
	if _, err := h.api.Reopen(operator, id, "twice"); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("reopen an open finding: %v, want invalid_state", err)
	}
	f, err = h.api.Assign(operator, id, nil)
	if err != nil || f.Status != finding.StatusInProgress || f.Assignee != nil {
		t.Fatalf("unassign: %+v %v", f, err)
	}

	if got, err := h.api.Get(auditor, id); err != nil || deref(got.Reason) != "seen again" || got.Hostname != "ws-17" {
		t.Fatalf("auditor get: %+v %v", got, err)
	}
	stranger := adminCtx(other, principal.RoleOrgAdmin, "bob")
	if _, err := h.api.Get(stranger, id); !errors.Is(err, problem.NotFound) {
		t.Fatalf("other organization get: %v, want not_found", err)
	}
	if _, err := h.api.Acknowledge(stranger, id); !errors.Is(err, problem.NotFound) {
		t.Fatalf("other organization acknowledge: %v, want not_found", err)
	}
	if list, err := h.api.List(stranger, app.FindingQuery{Page: app.ListPage{Sort: "-last_seen_at", Limit: 10}}); err != nil || list.Count != 0 {
		t.Fatalf("other organization list: %+v %v", list, err)
	}

	type want struct{ code, outcome, errorCode string }
	wants := []want{
		{"finding.acknowledged", "denied", "forbidden"},
		{"finding.acknowledged", "success", ""},
		{"finding.acknowledged", "failure", "invalid_state"},
		{"finding.assigned", "failure", "not_found"},
		{"finding.assigned", "failure", "not_found"},
		{"finding.assigned", "failure", "not_found"},
		{"finding.assigned", "success", ""},
		{"finding.closed", "denied", "forbidden"},
		{"finding.closed", "failure", "invalid_request"},
		{"finding.closed", "failure", "invalid_request"},
		{"finding.closed", "failure", "invalid_request"},
		{"finding.closed", "failure", "invalid_request"},
		{"finding.closed", "success", ""},
		{"finding.acknowledged", "failure", "invalid_state"},
		{"finding.closed", "failure", "invalid_state"},
		{"finding.reopened", "failure", "invalid_request"},
		{"finding.reopened", "success", ""},
		{"finding.reopened", "failure", "invalid_state"},
		{"finding.assigned", "success", ""},
	}
	events := h.findingEvents(t, org, id)
	if len(events) != len(wants) {
		t.Fatalf("%d finding events, want %d: %+v", len(events), len(wants), events)
	}
	for i, w := range wants {
		if e := events[i]; e.code != w.code || e.outcome != w.outcome || e.errorCode != w.errorCode {
			t.Errorf("event %d: %s %s %s, want %+v", i, e.code, e.outcome, e.errorCode, w)
		}
	}
	common := map[string]any{"kind": "tamper", "code": "device.tamper_sudoers_d_file", "hostname": "ws-17", "subject": "evil"}
	checks := map[int]map[string]any{
		1:  {"previous_status": "open"},
		6:  {"previous_status": "acknowledged", "assignee": "olga"},
		12: {"previous_status": "in_progress", "resolution": "accepted_risk", "reason": "test file", "external_ref": "CHG-7"},
		16: {"previous_status": "accepted_risk", "reason": "seen again"},
		18: {"previous_status": "open", "assignee": ""},
	}
	for i, extra := range checks {
		for k, v := range common {
			extra[k] = v
		}
		if len(events[i].params) != len(extra) {
			t.Errorf("event %d (%s): params %v, want %v", i, events[i].code, events[i].params, extra)
			continue
		}
		for k, v := range extra {
			if events[i].params[k] != v {
				t.Errorf("event %d (%s): param %s = %v, want %v", i, events[i].code, k, events[i].params[k], v)
			}
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TestAccountList (plan M9 decision 34): the organization's accounts that are not disabled, filtered by role and
// searched by username and display name; another organization's accounts are not listed.
func TestAccountList(t *testing.T) {
	h := newFindingsHarness(t)
	org, other := h.org(t), h.org(t)
	h.account(t, org, "alice", "org_admin", false)
	h.account(t, org, "olga", "org_operator", false)
	h.account(t, org, "audrey", "org_auditor", false)
	h.account(t, org, "gone", "org_admin", true)
	h.account(t, other, "bob", "org_admin", false)
	ctx := adminCtx(org, principal.RoleOrgAuditor, "audrey")
	names := func(q app.AccountQuery) string {
		t.Helper()
		q.Page.Limit = 10
		if q.Page.Sort == "" {
			q.Page.Sort = "username"
		}
		res, err := h.accounts.List(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range res.Items {
			out = append(out, a.Username+":"+a.Role)
		}
		return fmt.Sprintf("%d %s", res.Count, strings.Join(out, " "))
	}
	if got := names(app.AccountQuery{}); got != "3 alice:org_admin audrey:org_auditor olga:org_operator" {
		t.Fatalf("all: %s", got)
	}
	if got := names(app.AccountQuery{Roles: []string{"org_admin", "org_operator"}, Page: app.ListPage{Sort: "-username"}}); got != "2 olga:org_operator alice:org_admin" {
		t.Fatalf("assignable: %s", got)
	}
	pattern := "%OLG%"
	if got := names(app.AccountQuery{Page: app.ListPage{QPattern: &pattern}}); got != "1 olga:org_operator" {
		t.Fatalf("search: %s", got)
	}
	if _, err := h.accounts.List(systemCtx(org), app.AccountQuery{Page: app.ListPage{Sort: "username", Limit: 10}}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("system principal: %v, want forbidden", err)
	}
}
