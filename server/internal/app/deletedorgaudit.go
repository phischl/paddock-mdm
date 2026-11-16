package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// The resources of platform.deleted_organization_audit_read.
const (
	DeletedOrgAuditEvents         = "audit_events"
	DeletedOrgAuditExports        = "audit_exports"
	DeletedOrgAuditExportRequest  = "audit_export_request"
	DeletedOrgAuditExportDownload = "audit_export_download"
)

// SpecDeletedOrgAuditRead records a platform administrator's read of a deleted organization's retained audit evidence
// (ADR 0052 decision 7, plan M17 decision 18).
var SpecDeletedOrgAuditRead = ActionSpec{Code: audit.CodePlatformDeletedOrganizationAuditRead, AllowedRoles: RolesPlatform}

// SpecDeletedOrgAuditExport records a new evidence export of a deleted organization; like every export request it
// needs a step-up (plan M17 §6).
var SpecDeletedOrgAuditExport = ActionSpec{Code: audit.CodePlatformDeletedOrganizationAuditRead, AllowedRoles: RolesPlatform,
	RequiresStepUp: true}

// DeletedOrgAudit lets platform administrators read the audit log of a deleted organization and produce its evidence
// exports for the organization's auditors (ADR 0052 decision 7). It is the only user of db.AuditReader.InDeletedOrg.
// Every attempt is recorded as platform.deleted_organization_audit_read in the platform pseudo-organization: the
// organization's own log is closed. An organization that is not deleted, and a caller who is no platform
// administrator, get not_found, so the endpoints do not reveal which organizations exist.
type DeletedOrgAudit struct {
	runner   *ActionRunner
	reader   *db.AuditReader
	platform *db.PlatformPool
	now      func() time.Time
}

// NewDeletedOrgAudit creates the use case.
func NewDeletedOrgAudit(runner *ActionRunner, reader *db.AuditReader, platform *db.PlatformPool) *DeletedOrgAudit {
	return &DeletedOrgAudit{runner: runner, reader: reader, platform: platform, now: time.Now}
}

// hidden maps a refusal to not_found: a caller who is no platform administrator, and an organization that is not
// deleted, are answered alike (plan M17 §8 test 5).
func hidden(err error) error {
	if errors.Is(err, ErrForbidden) || errors.Is(err, db.ErrNotDeleted) {
		return problem.NotFound
	}
	return err
}

// record runs spec for org in the platform scope: the organization must be deleted, its slug becomes the target's
// display, set adds the attempt's params, and readErr, the result of the read done before, decides the outcome. The
// read runs before the action's transaction, which would otherwise hold a main-pool connection while waiting for an
// audit reader connection. A caller who is no platform administrator is recorded as denied in its own log with the
// resource only: the organization ID it sent is no fact of its organization.
func (d *DeletedOrgAudit) record(ctx context.Context, spec ActionSpec, org uuid.UUID, resource string,
	set func(rec Recorder, row pgstore.Organization) error, readErr error) (pgstore.Organization, error) {
	spec.Params = map[string]any{"resource": resource}
	var row pgstore.Organization
	err := d.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		rec.SetTarget(audit.Target{Type: "organization", ID: org.String()})
		rec.SetParam("organization_id", org.String())
		var err error
		row, err = deletedOrganization(ctx, q, org)
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "organization", ID: org.String(), Display: row.Slug})
		rec.SetParam("slug", row.Slug)
		if set != nil {
			if err := set(rec, row); err != nil {
				return err
			}
		}
		return hidden(readErr)
	})
	return row, hidden(err)
}

// deletedOrganization is org's tombstone, or not_found when org does not exist or is not deleted.
func deletedOrganization(ctx context.Context, q *pgstore.Queries, org uuid.UUID) (pgstore.Organization, error) {
	row, err := q.GetOrganization(ctx, org)
	if db.IsNoRows(err) || (err == nil && row.Status != organization.StatusDeleted) {
		return row, problem.NotFound
	}
	if err != nil {
		return row, fmt.Errorf("get organization: %w", err)
	}
	return row, nil
}

// Events returns one page of the deleted organization's events and the capped number of matches (ADR 0018), with the
// filters of the organization's own audit log. The devices are gone, so no hostname is resolved. invalid is the input
// error the handler found (or nil); the attempt is recorded with it.
func (d *DeletedOrgAudit) Events(ctx context.Context, org uuid.UUID, f AuditQuery, invalid error) (AuditListed, error) {
	var out AuditListed
	from, to, readErr := f.effectiveRange(d.now())
	if invalid != nil {
		readErr = invalid
	}
	if readErr == nil {
		var targetID *string
		if f.TargetID != nil {
			id := f.TargetID.String()
			targetID = &id
		}
		readErr = d.reader.InDeletedOrg(ctx, d.platform, org, func(ctx context.Context, q *auditstore.Queries) error {
			n, err := q.CountAuditEvents(ctx, auditstore.CountAuditEventsParams{
				FromTime: from, ToTime: to, Codes: f.Codes, Outcomes: f.Outcomes, ActorTypes: f.ActorTypes, TargetID: targetID,
				QPattern: f.Page.QPattern, CountLimit: countLimit,
			})
			if err != nil {
				return fmt.Errorf("count audit events: %w", err)
			}
			out.Count = int(n)
			out.Items, err = q.ListAuditEvents(ctx, auditstore.ListAuditEventsParams{
				FromTime: from, ToTime: to, Codes: f.Codes, Outcomes: f.Outcomes, ActorTypes: f.ActorTypes, TargetID: targetID,
				QPattern: f.Page.QPattern, Sort: f.Page.Sort, SkipRows: f.Page.Offset, MaxRows: f.Page.Limit,
			})
			if err != nil {
				return fmt.Errorf("list audit events: %w", err)
			}
			return nil
		})
	}
	_, err := d.record(ctx, SpecDeletedOrgAuditRead, org, DeletedOrgAuditEvents, nil, readErr)
	if err != nil {
		return AuditListed{}, err
	}
	out.Devices = map[uuid.UUID]AuditDevice{}
	return out, nil
}

// Exports returns one page of the deleted organization's evidence exports and the capped number of matches; invalid
// is as for Events.
func (d *DeletedOrgAudit) Exports(ctx context.Context, org uuid.UUID, f AuditExportQuery, invalid error) (Listed[auditstore.AuditExport], error) {
	var out Listed[auditstore.AuditExport]
	if invalid != nil {
		_, err := d.record(ctx, SpecDeletedOrgAuditRead, org, DeletedOrgAuditExports, nil, invalid)
		return out, err
	}
	readErr := d.reader.InDeletedOrg(ctx, d.platform, org, func(ctx context.Context, q *auditstore.Queries) error {
		n, err := q.CountAuditExports(ctx, auditstore.CountAuditExportsParams{
			Statuses: f.Statuses, QPattern: f.Page.QPattern, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count exports: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAuditExports(ctx, auditstore.ListAuditExportsParams{
			Statuses: f.Statuses, QPattern: f.Page.QPattern, Sort: f.Page.Sort, SkipRows: f.Page.Offset, MaxRows: f.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list exports: %w", err)
		}
		return nil
	})
	if _, err := d.record(ctx, SpecDeletedOrgAuditRead, org, DeletedOrgAuditExports, nil, readErr); err != nil {
		return Listed[auditstore.AuditExport]{}, err
	}
	return out, nil
}

// RequestExport stores a pending evidence export of the deleted organization's sealed days, built by the audit writer
// as for an active organization (step-up).
func (d *DeletedOrgAudit) RequestExport(ctx context.Context, org uuid.UUID, req AuditExportRequest) (auditstore.AuditExport, error) {
	var out auditstore.AuditExport
	id := uuid.Must(uuid.NewV7())
	from, to, purpose := req.normalized()
	spec := SpecDeletedOrgAuditExport
	spec.Params = map[string]any{"resource": DeletedOrgAuditExportRequest}
	prepare := func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		rec.SetTarget(audit.Target{Type: "organization", ID: org.String()})
		rec.SetParam("organization_id", org.String())
		row, err := deletedOrganization(ctx, q, org)
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "organization", ID: org.String(), Display: row.Slug})
		rec.SetParam("slug", row.Slug)
		if err := req.validate(); err != nil {
			return err
		}
		rec.SetParam("export_id", id.String())
		rec.SetParam("from_day", from.Format(time.DateOnly))
		rec.SetParam("to_day", to.Format(time.DateOnly))
		rec.SetParam("purpose", purpose)
		return nil
	}
	external := func(ctx context.Context) error {
		p, _ := principal.From(ctx)
		return hidden(d.reader.InDeletedOrgWrite(ctx, d.platform, org, func(ctx context.Context, q *auditstore.Queries) error {
			var err error
			out, err = insertExport(ctx, q, p, org, id, req, d.correlationID(ctx))
			return err
		}))
	}
	finalize := func(context.Context, *pgstore.Queries, Recorder, error) error { return nil }
	err := d.runner.RunExternal(ctx, ScopePlatform, spec, prepare, external, finalize)
	return out, hidden(err)
}

// Download records the download of a ready export of the deleted organization, then streams it like
// AuditExports.Download: begin once before the first chunk, stream once per chunk, at most one chunk in memory.
func (d *DeletedOrgAudit) Download(ctx context.Context, org, id uuid.UUID, begin func(ExportPackage), stream func(chunk []byte) error) error {
	var export auditstore.AuditExport
	lookupErr := d.reader.InDeletedOrg(ctx, d.platform, org, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		export, err = q.GetAuditExport(ctx, id)
		if db.IsNoRows(err) {
			return problem.NotFound
		}
		return err
	})
	row, err := d.record(ctx, SpecDeletedOrgAuditRead, org, DeletedOrgAuditExportDownload, func(rec Recorder, _ pgstore.Organization) error {
		rec.SetParam("export_id", id.String())
		if lookupErr != nil {
			return hidden(lookupErr)
		}
		if err := requireDownloadable(export, d.now()); err != nil {
			return err
		}
		rec.SetParam("from_day", export.FromDay.Format(time.DateOnly))
		rec.SetParam("to_day", export.ToDay.Format(time.DateOnly))
		return nil
	}, nil)
	if err != nil {
		return err
	}
	begin(ExportPackage{Export: export, Filename: exportFilename(row.Slug, export)})
	sum := sha256.New()
	var sent int64
	for seq := int32(0); ; seq++ {
		var data []byte
		err := d.reader.InDeletedOrg(ctx, d.platform, org, func(ctx context.Context, q *auditstore.Queries) error {
			var err error
			data, err = q.GetAuditExportChunk(ctx, auditstore.GetAuditExportChunkParams{ExportID: id, Seq: seq})
			return err
		})
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
		return fmt.Errorf("stored chunks of export %s are %d bytes with a different checksum %s, want %d", id, sent,
			hex.EncodeToString(sum.Sum(nil)), *export.Size)
	}
	return nil
}

// correlationID is the correlation ID the runner records for the request's action.
func (d *DeletedOrgAudit) correlationID(ctx context.Context) string {
	if d.runner.correlationID == nil {
		return ""
	}
	return d.runner.correlationID(ctx)
}
