package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// SpecAuditExportDownload is the download of a ready evidence export (plan M10 decision 35). Every download is a data
// egress and is recorded, so it is audited like any privileged action; no step-up is required.
var SpecAuditExportDownload = ActionSpec{Code: audit.CodeAuditExportDownloaded, AllowedRoles: RolesAudit}

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
			return problem.InvalidRequest.WithDetail("purpose must not contain control or bidi control characters")
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

// ExportPackage is what Download knows about a package before its first byte: the export row and the file name the
// download is offered as.
type ExportPackage struct {
	Export   auditstore.AuditExport
	Filename string
}

// Download records audit.export_downloaded, then calls begin once and stream once per chunk in sequence order, so at
// most one chunk is in memory. begin runs before the first chunk with the export row the event was recorded for, so a
// caller can send headers; a failure before begin leaves the response untouched. The event is recorded before the
// first byte is sent and is not repeated when the transfer breaks later (exactly one event per attempt, root
// CLAUDE.md); such a failure is returned for the caller to log.
func (a *AuditExports) Download(ctx context.Context, id uuid.UUID, begin func(ExportPackage), stream func(chunk []byte) error) error {
	// Read before the action's transaction opens: that transaction would otherwise hold a main-pool connection while
	// it waits for an audit reader connection. The lookup's error is recorded by the action.
	export, lookupErr := a.Get(ctx, id)
	var slug string
	err := a.runner.RunTx(ctx, ScopeOrg, SpecAuditExportDownload, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		rec.SetParam("export_id", id.String())
		if lookupErr != nil {
			return lookupErr
		}
		if err := requireDownloadable(export, time.Now()); err != nil {
			return err
		}
		org, err := q.GetOrganization(ctx, mustOrg(ctx))
		if err != nil {
			return fmt.Errorf("get organization: %w", err)
		}
		slug = org.Slug
		rec.SetParam("from_day", export.FromDay.Format(time.DateOnly))
		rec.SetParam("to_day", export.ToDay.Format(time.DateOnly))
		rec.SetParam("size", *export.Size)
		rec.SetParam("package_sha256", hex.EncodeToString(export.PackageSha256))
		return nil
	})
	if err != nil {
		return err
	}
	begin(ExportPackage{Export: export, Filename: exportFilename(slug, export)})
	sum := sha256.New()
	var sent int64
	for seq := int32(0); ; seq++ {
		data, err := a.chunk(ctx, id, seq)
		if db.IsNoRows(err) {
			break
		}
		if err != nil {
			return fmt.Errorf("read chunk %d: %w", seq, err)
		}
		sum.Write(data)
		sent += int64(len(data))
		if err := stream(data); err != nil {
			return fmt.Errorf("send chunk %d: %w", seq, err)
		}
	}
	if sent != *export.Size || !bytes.Equal(sum.Sum(nil), export.PackageSha256) {
		return fmt.Errorf("stored chunks of export %s are %d bytes with a different checksum, want %d", id, sent, *export.Size)
	}
	return nil
}

// chunk reads one chunk of a package in its own reader transaction, so a slow client holds no audit reader connection
// while its chunk is written. The chunks of a ready export do not change until its expiry removes them; a chunk
// removed during a transfer ends it like any read failure, caught by the size and checksum check at the latest.
func (a *AuditExports) chunk(ctx context.Context, id uuid.UUID, seq int32) ([]byte, error) {
	var data []byte
	err := a.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		data, err = q.GetAuditExportChunk(ctx, auditstore.GetAuditExportChunkParams{ExportID: id, Seq: seq})
		return err
	})
	return data, err
}

// requireDownloadable refuses an export that is not ready or past its expiry; the audit writer's expiry job may lag
// behind expires_at, and the chunks of an expired package must not be offered.
func requireDownloadable(e auditstore.AuditExport, now time.Time) error {
	if e.Status != "ready" || e.Size == nil || len(e.PackageSha256) == 0 || (e.ExpiresAt != nil && !e.ExpiresAt.After(now)) {
		return problem.ExportNotReady.WithDetail("the export is " + e.Status)
	}
	return nil
}

// exportFilename is the file name of the package (plan M10 decision 35). The organization slug is lowercase ASCII
// letters, digits and hyphens, so the name needs no quoting or encoding in Content-Disposition.
func exportFilename(slug string, e auditstore.AuditExport) string {
	return fmt.Sprintf("paddock-audit-export-%s-%s_%s-%s.tar", slug, e.FromDay.Format(time.DateOnly),
		e.ToDay.Format(time.DateOnly), hex.EncodeToString(e.ID[:4]))
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
// jsonb, so such a purpose would fail the action's audit record (see boundedString). C1 and bidi controls are refused
// too, because the evidence package and the portal show the purpose to auditors and a direction override could
// disguise it (plan M10, amendment 2026-10-30 for PDK-142).
func hasControls(s string) bool {
	if s != stripControls(s) {
		return true
	}
	return strings.ContainsFunc(s, func(r rune) bool {
		return (r >= 0x80 && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
	})
}

func utcDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
