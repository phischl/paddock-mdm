package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// exportHarness is the action harness with the audit database: the use case under test and the writer pool that
// seals days for the harness organization.
type exportHarness struct {
	harness
	exports   *app.AuditExports
	writer    *db.AuditWriterPool
	writerDSN string
}

func newExportHarness(t *testing.T) exportHarness {
	t.Helper()
	ag := pgtest.SharedAudit(t)
	ctx := context.Background()
	reader, err := db.NewAuditReader(ctx, ag.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	writer, err := db.NewAuditWriterPool(ctx, ag.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	h := newHarness(t)
	return exportHarness{harness: h, exports: app.NewAuditExports(h.runner, reader), writer: writer, writerDSN: ag.Writer}
}

// seal stores a manifest of the harness organization for each day.
func (h exportHarness) seal(t *testing.T, days ...time.Time) {
	t.Helper()
	err := h.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		for _, d := range days {
			if err := q.InsertAuditManifest(ctx, auditstore.InsertAuditManifestParams{
				OrganizationID: h.org, Day: d, Sha256: make([]byte, 32), Signature: "vault:v1:test", KeyVersion: 1,
				ObjectKey: "org/" + h.org.String() + "/manifests/" + d.Format(time.DateOnly) + ".json",
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// steppedUp is a principal of the harness organization with a fresh step-up.
func (h exportHarness) steppedUp(role principal.Role) context.Context {
	return principal.With(context.Background(), principal.Principal{
		Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "bob", Role: role, OrganizationID: h.org,
		IP: "192.0.2.7", StepUpAt: time.Now(),
	})
}

func exportDay(daysAgo int) time.Time {
	return time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -daysAgo)
}

func TestAuditExportRequestSuccess(t *testing.T) {
	h := newExportHarness(t)
	from, to := exportDay(2), exportDay(1)
	h.seal(t, from, to)
	ctx := h.steppedUp(principal.RoleOrgAuditor)

	got, err := h.exports.Request(ctx, app.AuditExportRequest{FromDay: from, ToDay: to, Purpose: "  ISO audit 2026  "})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.OrganizationID != h.org || !got.FromDay.Equal(from) || !got.ToDay.Equal(to) ||
		got.Purpose != "ISO audit 2026" || got.CorrelationID != "corr-"+t.Name() {
		t.Fatalf("export = %+v", got)
	}
	var by audit.Actor
	if err := json.Unmarshal(got.RequestedBy, &by); err != nil {
		t.Fatal(err)
	}
	p, _ := principal.From(ctx)
	if by.Type != audit.ActorAdmin || by.ID != p.ID.String() || by.Display != "bob" || by.IP != "" || !by.StepUp {
		t.Fatalf("requested_by = %+v", by)
	}
	if strings.Contains(string(got.RequestedBy), "192.0.2.7") {
		t.Fatalf("requested_by carries the client address: %s", got.RequestedBy)
	}
	ev := expectOne(t, h.harness, audit.OutcomeSuccess, "")
	if ev.Code != audit.CodeAuditExportRequested || ev.Params["export_id"] != got.ID.String() ||
		ev.Params["from_day"] != from.Format(time.DateOnly) || ev.Params["to_day"] != to.Format(time.DateOnly) ||
		ev.Params["purpose"] != "ISO audit 2026" || !ev.Actor.StepUp {
		t.Fatalf("event = %+v", ev)
	}

	read, err := h.exports.Get(ctx, got.ID)
	if err != nil || read.ID != got.ID {
		t.Fatalf("Get = %+v, %v", read, err)
	}
}

// TestAuditExportRequestRefusals: every refusal is one recorded attempt with the problem code; nothing is stored.
func TestAuditExportRequestRefusals(t *testing.T) {
	sealed, unsealed := exportDay(1), exportDay(0)
	auditor := func(h exportHarness) context.Context { return h.steppedUp(principal.RoleOrgAuditor) }
	for _, c := range []struct {
		name    string
		ctx     func(h exportHarness) context.Context
		req     app.AuditExportRequest
		want    *problem.Error
		outcome audit.Outcome
	}{
		{"no step-up", func(h exportHarness) context.Context { return h.admin(principal.RoleOrgAuditor) },
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "p"}, problem.StepUpRequired, audit.OutcomeDenied},
		{"mcp session", func(h exportHarness) context.Context {
			ctx := h.steppedUp(principal.RoleOrgAuditor)
			p, _ := principal.From(ctx)
			p.Channel, p.MCPClient = principal.ChannelMCP, "claude-code/2.1"
			return principal.With(context.Background(), p)
		}, app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "p"}, problem.StepUpRequired, audit.OutcomeDenied},
		{"operator", func(h exportHarness) context.Context { return h.steppedUp(principal.RoleOrgOperator) },
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "p"}, problem.Forbidden, audit.OutcomeDenied},
		{"to_day not sealed", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: unsealed, Purpose: "p"}, problem.DayNotSealed, audit.OutcomeFailure},
		{"from_day not sealed", auditor,
			app.AuditExportRequest{FromDay: exportDay(3), ToDay: sealed, Purpose: "p"}, problem.DayNotSealed, audit.OutcomeFailure},
		{"401 days", auditor,
			app.AuditExportRequest{FromDay: sealed.AddDate(0, 0, -401), ToDay: sealed, Purpose: "p"}, problem.RangeTooLarge, audit.OutcomeFailure},
		{"from after to", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed.AddDate(0, 0, -1), Purpose: "p"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"blank purpose", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "   "}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose too long", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: strings.Repeat("ä", 501)}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose with NUL", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "ISO\x00audit"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose with escape", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "ISO\x1baudit"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose with C1 control", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "ISO\u0085audit"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose with last C1 control", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "ISO\u009faudit"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose with right-to-left override", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "ISO\u202eaudit"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose with bidi embedding", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "ISO\u202aaudit"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"purpose with bidi isolate", auditor,
			app.AuditExportRequest{FromDay: sealed, ToDay: sealed, Purpose: "ISO\u2066audit\u2069"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"missing days", auditor,
			app.AuditExportRequest{Purpose: "p"}, problem.InvalidRequest, audit.OutcomeFailure},
		{"missing to_day", auditor,
			app.AuditExportRequest{FromDay: sealed, Purpose: "p"}, problem.InvalidRequest, audit.OutcomeFailure},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newExportHarness(t)
			h.seal(t, sealed)
			_, err := h.exports.Request(c.ctx(h), c.req)
			if !errors.Is(err, c.want) {
				t.Fatalf("Request = %v, want %s", err, c.want.Code)
			}
			expectOne(t, h.harness, c.outcome, c.want.Code)
			list, err := h.exports.List(h.steppedUp(principal.RoleOrgAuditor), app.AuditExportQuery{Page: app.ListPage{Sort: "-requested_at", Limit: 10}})
			if err != nil || list.Count != 0 {
				t.Fatalf("exports after the refusal: %+v, %v", list, err)
			}
		})
	}
}

// TestAuditExportPurposeKeepsLineBreaks: tab, newline and carriage return stay allowed in the purpose, and so do the
// characters next to the refused C1 and bidi ranges.
func TestAuditExportPurposeKeepsLineBreaks(t *testing.T) {
	h := newExportHarness(t)
	day := exportDay(1)
	h.seal(t, day)
	purpose := "ISO 27001\r\nsurveillance\taudit \u00a0\u2029\u2065\u206a"
	got, err := h.exports.Request(h.steppedUp(principal.RoleOrgAuditor), app.AuditExportRequest{FromDay: day, ToDay: day, Purpose: purpose})
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose != purpose {
		t.Fatalf("purpose = %q, want %q", got.Purpose, purpose)
	}
}

// TestAuditExportRangeBoundary: a difference of exactly MaxExportDays days is allowed.
func TestAuditExportRangeBoundary(t *testing.T) {
	h := newExportHarness(t)
	to := exportDay(1)
	from := to.AddDate(0, 0, -app.MaxExportDays)
	h.seal(t, from, to)
	if _, err := h.exports.Request(h.steppedUp(principal.RoleOrgAdmin), app.AuditExportRequest{FromDay: from, ToDay: to, Purpose: "p"}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditExportTooManyOpen(t *testing.T) {
	h := newExportHarness(t)
	day := exportDay(1)
	h.seal(t, day)
	ctx := h.steppedUp(principal.RoleOrgAuditor)
	for i := range app.MaxOpenExports {
		if _, err := h.exports.Request(ctx, app.AuditExportRequest{FromDay: day, ToDay: day, Purpose: "p"}); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	if _, err := h.exports.Request(ctx, app.AuditExportRequest{FromDay: day, ToDay: day, Purpose: "p"}); !errors.Is(err, problem.TooManyExports) {
		t.Fatalf("third request = %v, want too_many_exports", err)
	}
	// A finished export no longer counts as open.
	conn, err := pgx.Connect(context.Background(), h.writerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(context.Background(), "UPDATE audit_export SET status = 'failed' WHERE id = (SELECT id FROM audit_export WHERE organization_id = $1 ORDER BY id LIMIT 1)", h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := h.exports.Request(ctx, app.AuditExportRequest{FromDay: day, ToDay: day, Purpose: "p"}); err != nil {
		t.Fatalf("request after one export failed: %v", err)
	}
}

// TestAuditExportConcurrentRequests: parallel requests cannot pass the open-export limit together, and every one is
// recorded exactly once.
func TestAuditExportConcurrentRequests(t *testing.T) {
	h := newExportHarness(t)
	day := exportDay(1)
	h.seal(t, day)
	const n = 5
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := h.exports.Request(h.steppedUp(principal.RoleOrgAuditor), app.AuditExportRequest{FromDay: day, ToDay: day, Purpose: "p"})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	succeeded, refused := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, problem.TooManyExports):
			refused++
		default:
			t.Fatalf("Request = %v", err)
		}
	}
	if succeeded != app.MaxOpenExports || refused != n-app.MaxOpenExports {
		t.Fatalf("%d succeeded, %d refused; want %d and %d", succeeded, refused, app.MaxOpenExports, n-app.MaxOpenExports)
	}
	actions, events := h.recorded(t, "corr-"+t.Name())
	if len(actions) != n || len(events) != n {
		t.Fatalf("want %d actions and events, got %d actions, %d events", n, len(actions), len(events))
	}
	outcomes := map[string]int{}
	for _, ev := range events {
		outcomes[string(ev.Outcome)+"/"+ev.ErrorCode]++
	}
	if outcomes[string(audit.OutcomeSuccess)+"/"] != app.MaxOpenExports ||
		outcomes[string(audit.OutcomeFailure)+"/"+problem.TooManyExports.Code] != n-app.MaxOpenExports {
		t.Fatalf("event outcomes = %v", outcomes)
	}
	list, err := h.exports.List(h.steppedUp(principal.RoleOrgAuditor), app.AuditExportQuery{Page: app.ListPage{Sort: "-requested_at", Limit: 10}})
	if err != nil || list.Count != app.MaxOpenExports {
		t.Fatalf("stored exports: %+v, %v", list, err)
	}
}

func TestAuditExportReadsNeedAuditRole(t *testing.T) {
	h := newExportHarness(t)
	ctx := h.steppedUp(principal.RoleOrgOperator)
	if _, err := h.exports.Get(ctx, uuid.Must(uuid.NewV7())); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("Get as operator = %v", err)
	}
	if _, err := h.exports.List(ctx, app.AuditExportQuery{Page: app.ListPage{Sort: "-requested_at", Limit: 10}}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("List as operator = %v", err)
	}
	if _, err := h.exports.Get(h.steppedUp(principal.RoleOrgAuditor), uuid.Must(uuid.NewV7())); !errors.Is(err, problem.NotFound) {
		t.Fatalf("Get of an unknown export = %v", err)
	}
}
