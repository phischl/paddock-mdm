package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecAuditExportRequest is the request of an evidence export (plan M10 decision 29).
var SpecAuditExportRequest = ActionSpec{Code: audit.CodeAuditExportRequested, AllowedRoles: RolesAudit, RequiresStepUp: true}

// MaxExportDays is the largest difference between to_day and from_day of one export (plan M10 decision 29).
const MaxExportDays = 400

// MaxOpenExports is how many exports of an organization may be pending or running at the same time.
const MaxOpenExports = 2

// maxExportPurpose is the longest purpose in characters (audit migration 00008).
const maxExportPurpose = 500

// AuditExportRequest is the range of recording days and the purpose of a requested export.
type AuditExportRequest struct {
	FromDay, ToDay time.Time
	Purpose        string
}

// AuditExportQuery filters the exports; nil Statuses match every status.
type AuditExportQuery struct {
	Statuses []string
	Page     ListPage
}

// AuditExports requests and reads the evidence exports of the caller's organization (ADR 0032 §5). The request is
// stored on the audit database with the reader role, where the audit writer builds the package.
type AuditExports struct {
	runner *ActionRunner
	reader *db.AuditReader
}

// NewAuditExports creates the use case.
func NewAuditExports(runner *ActionRunner, reader *db.AuditReader) *AuditExports {
	return &AuditExports{runner: runner, reader: reader}
}

// Request records a pending export of the sealed days req.FromDay..req.ToDay as audit.export_requested.
func (a *AuditExports) Request(ctx context.Context, req AuditExportRequest) (auditstore.AuditExport, error) {
	var out auditstore.AuditExport
	id := uuid.Must(uuid.NewV7())
	from, to := utcDay(req.FromDay), utcDay(req.ToDay)
	purpose := strings.TrimSpace(req.Purpose)
	prepare := func(_ context.Context, _ *pgstore.Queries, rec Recorder) error {
		if req.FromDay.IsZero() || req.ToDay.IsZero() {
			return problem.InvalidRequest.WithDetail("from_day and to_day are required")
		}
		if to.Before(from) {
			return problem.InvalidRequest.WithDetail("from_day must not be after to_day")
		}
		if to.Sub(from) > MaxExportDays*24*time.Hour {
			return problem.RangeTooLarge.WithDetail(fmt.Sprintf("an export spans at most %d days", MaxExportDays))
		}
		if n := utf8.RuneCountInString(purpose); n < 1 || n > maxExportPurpose {
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("purpose must have 1 to %d characters", maxExportPurpose))
		}
		if hasControls(purpose) {
			return problem.InvalidRequest.WithDetail("purpose must not contain control characters")
		}
		rec.SetParam("export_id", id.String())
		rec.SetParam("from_day", from.Format(time.DateOnly))
		rec.SetParam("to_day", to.Format(time.DateOnly))
		rec.SetParam("purpose", purpose)
		return nil
	}
	external := func(ctx context.Context) error {
		p, _ := principal.From(ctx)
		requestedBy, err := json.Marshal(exportRequester(p))
		if err != nil {
			return fmt.Errorf("encode requester: %w", err)
		}
		return a.reader.InOrgWrite(ctx, func(ctx context.Context, q *auditstore.Queries) error {
			if err := q.LockAuditExportRequests(ctx); err != nil {
				return fmt.Errorf("lock export requests: %w", err)
			}
			for _, day := range []time.Time{to, from} {
				if _, err := q.GetAuditManifest(ctx, auditstore.GetAuditManifestParams{OrganizationID: p.OrganizationID, Day: day}); db.IsNoRows(err) {
					return problem.DayNotSealed.WithDetail(day.Format(time.DateOnly) + " is not sealed yet")
				} else if err != nil {
					return fmt.Errorf("manifest of %s: %w", day.Format(time.DateOnly), err)
				}
			}
			open, err := q.CountOpenAuditExports(ctx)
			if err != nil {
				return fmt.Errorf("count open exports: %w", err)
			}
			if open >= MaxOpenExports {
				return problem.TooManyExports.WithDetail(fmt.Sprintf("at most %d exports may be pending or running", MaxOpenExports))
			}
			out, err = q.InsertAuditExport(ctx, auditstore.InsertAuditExportParams{
				ID: id, OrganizationID: p.OrganizationID, FromDay: from, ToDay: to, Purpose: purpose,
				RequestedBy: requestedBy, CorrelationID: a.correlationID(ctx),
			})
			if err != nil {
				return fmt.Errorf("insert export: %w", err)
			}
			return nil
		})
	}
	finalize := func(context.Context, *pgstore.Queries, Recorder, error) error { return nil }
	err := a.runner.RunExternal(ctx, ScopeOrg, SpecAuditExportRequest, prepare, external, finalize)
	return out, err
}

// exportRequester is the requesting principal as audit actor without the client address (plan M10 decision 29); the
// request passed the step-up check of SpecAuditExportRequest.
func exportRequester(p principal.Principal) audit.Actor {
	actor := actorOf(p)
	actor.IP = ""
	actor.StepUp = true
	return actor
}

// correlationID is the correlation ID the runner records for the request's action.
func (a *AuditExports) correlationID(ctx context.Context) string {
	if a.runner.correlationID == nil {
		return ""
	}
	return a.runner.correlationID(ctx)
}

// Get returns one export of the caller's organization; another organization's is not found.
func (a *AuditExports) Get(ctx context.Context, id uuid.UUID) (auditstore.AuditExport, error) {
	var out auditstore.AuditExport
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return out, err
	}
	err := a.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		out, err = q.GetAuditExport(ctx, id)
		if db.IsNoRows(err) {
			return problem.NotFound
		}
		if err != nil {
			return fmt.Errorf("get export: %w", err)
		}
		return nil
	})
	return out, err
}

// List returns one page of the organization's exports and the capped number of matches (ADR 0018).
func (a *AuditExports) List(ctx context.Context, f AuditExportQuery) (Listed[auditstore.AuditExport], error) {
	var out Listed[auditstore.AuditExport]
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return out, err
	}
	err := a.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		n, err := q.CountAuditExports(ctx, auditstore.CountAuditExportsParams{
			Statuses: f.Statuses, QPattern: f.Page.QPattern, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count exports: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAuditExports(ctx, auditstore.ListAuditExportsParams{
			Statuses: f.Statuses, QPattern: f.Page.QPattern,
			Sort: f.Page.Sort, SkipRows: f.Page.Offset, MaxRows: f.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list exports: %w", err)
		}
		return nil
	})
	return out, err
}

// hasControls reports C0 control characters other than tab, newline and carriage return: PostgreSQL rejects NUL in
// jsonb, so such a purpose would fail the action's audit record (see boundedString).
func hasControls(s string) bool {
	return s != stripControls(s)
}

func utcDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
