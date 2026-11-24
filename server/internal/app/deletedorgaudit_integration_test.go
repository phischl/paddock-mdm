package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// deletedHarness is the export harness with a deleted organization whose audit log has one event and two sealed days.
type deletedHarness struct {
	exportHarness
	audit   *app.DeletedOrgAudit
	deleted uuid.UUID
	slug    string
}

func newDeletedHarness(t *testing.T) deletedHarness {
	t.Helper()
	ctx := context.Background()
	h := newExportHarness(t)
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	reader, err := db.NewAuditReader(ctx, pgtest.SharedAudit(t).Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	d := deletedHarness{exportHarness: h, audit: app.NewDeletedOrgAudit(h.runner, reader, platform), deleted: uuid.Must(uuid.NewV7())}
	d.slug = "gd" + d.deleted.String()[24:]
	if _, err := h.super.Exec(ctx, `INSERT INTO organization (id, slug, name, status, deletion_requested_at, delete_after, deleted_at)
		VALUES ($1, $2, 'Gone', 'deleted', now(), now(), now())`, d.deleted, d.slug); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err = h.writer.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.EnsureAuditPartition(ctx, now); err != nil {
			return err
		}
		for _, org := range []uuid.UUID{d.deleted, h.org} {
			if _, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
				EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: now, RecordedAt: now,
				Code: string(audit.CodeAuditChainVerified), Outcome: "success", Source: "system",
				Actor: []byte(`{"type":"system","step_up":false}`), Params: []byte(`{"final":true}`), CorrelationID: "test",
				ObjectKey: "org/" + org.String() + "/test",
			}); err != nil {
				return err
			}
		}
		for _, day := range []time.Time{exportDay(2), exportDay(1)} {
			if err := q.InsertAuditManifest(ctx, auditstore.InsertAuditManifestParams{
				OrganizationID: d.deleted, Day: day, Sha256: make([]byte, 32), Signature: "vault:v1:test", KeyVersion: 1,
				ObjectKey: "org/" + d.deleted.String() + "/manifests/" + day.Format(time.DateOnly) + ".json",
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func deletedOrgReader(stepUp bool) context.Context {
	p := principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Display: "root",
		Role: principal.RolePlatform, IP: "192.0.2.9"}
	if stepUp {
		p.StepUpAt = time.Now()
	}
	return principal.With(context.Background(), p)
}

func eventsQuery() app.AuditQuery {
	from := time.Now().Add(-time.Hour)
	return app.AuditQuery{From: &from, Page: app.ListPage{Sort: "-occurred_at", Limit: 10}}
}

// expectRead checks the one recorded attempt: platform.deleted_organization_audit_read in the platform
// pseudo-organization with the resource and the organization.
func expectRead(t *testing.T, d deletedHarness, outcome audit.Outcome, errorCode, resource string, org uuid.UUID) audit.Event {
	t.Helper()
	ev := expectOne(t, d.harness, outcome, errorCode)
	if ev.Code != audit.CodePlatformDeletedOrganizationAuditRead || ev.Params["resource"] != resource {
		t.Fatalf("event = %+v", ev)
	}
	if outcome == audit.OutcomeDenied {
		// The caller's own log records the refusal, without the organization it asked for.
		if ev.OrganizationID != d.org || ev.Params["organization_id"] != nil || ev.Target != nil {
			t.Fatalf("denied event = %+v", ev)
		}
		return ev
	}
	if ev.OrganizationID != audit.PlatformOrganizationID || ev.Params["organization_id"] != org.String() {
		t.Fatalf("event = %+v", ev)
	}
	return ev
}

func TestDeletedOrgAuditEvents(t *testing.T) {
	d := newDeletedHarness(t)
	res, err := d.audit.Events(deletedOrgReader(false), d.deleted, eventsQuery(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Count != 1 || res.Items[0].OrganizationID != d.deleted {
		t.Fatalf("events %+v", res)
	}
	ev := expectRead(t, d, audit.OutcomeSuccess, "", app.DeletedOrgAuditEvents, d.deleted)
	if ev.Params["slug"] != d.slug || ev.Target == nil || ev.Target.Display != d.slug {
		t.Fatalf("event = %+v", ev)
	}
}

// TestDeletedOrgAuditActiveOrganization: an active organization is not_found, recorded as a failed attempt; its log is
// not read.
func TestDeletedOrgAuditActiveOrganization(t *testing.T) {
	d := newDeletedHarness(t)
	if _, err := d.audit.Events(deletedOrgReader(false), d.org, eventsQuery(), nil); !errors.Is(err, problem.NotFound) {
		t.Fatalf("active organization: %v, want not_found", err)
	}
	expectRead(t, d, audit.OutcomeFailure, "not_found", app.DeletedOrgAuditEvents, d.org)
}

// TestDeletedOrgAuditOrganizationPrincipal: an organization administrator, of the deleted organization or another, gets
// not_found and is recorded as denied.
func TestDeletedOrgAuditOrganizationPrincipal(t *testing.T) {
	d := newDeletedHarness(t)
	ctx := d.steppedUp(principal.RoleOrgAdmin)
	if _, err := d.audit.Events(ctx, d.deleted, eventsQuery(), nil); !errors.Is(err, problem.NotFound) {
		t.Fatalf("organization administrator: %v, want not_found", err)
	}
	expectRead(t, d, audit.OutcomeDenied, "forbidden", app.DeletedOrgAuditEvents, d.deleted)
}

func TestDeletedOrgAuditOrganizationPrincipalExport(t *testing.T) {
	d := newDeletedHarness(t)
	_, err := d.audit.RequestExport(d.steppedUp(principal.RoleOrgAuditor), d.deleted,
		app.AuditExportRequest{FromDay: exportDay(2), ToDay: exportDay(1), Purpose: "auditor"})
	if !errors.Is(err, problem.NotFound) {
		t.Fatalf("organization auditor: %v, want not_found", err)
	}
	expectRead(t, d, audit.OutcomeDenied, "forbidden", app.DeletedOrgAuditExportRequest, d.deleted)
}

// TestDeletedOrgAuditExport: a platform administrator with a step-up requests an export of the deleted organization's
// sealed days and lists it; without a step-up the request is refused.
func TestDeletedOrgAuditExport(t *testing.T) {
	d := newDeletedHarness(t)
	got, err := d.audit.RequestExport(deletedOrgReader(true), d.deleted,
		app.AuditExportRequest{FromDay: exportDay(2), ToDay: exportDay(1), Purpose: " evidence for the auditor "})
	if err != nil {
		t.Fatal(err)
	}
	if got.OrganizationID != d.deleted || got.Status != "pending" || got.Purpose != "evidence for the auditor" {
		t.Fatalf("export %+v", got)
	}
	ev := expectRead(t, d, audit.OutcomeSuccess, "", app.DeletedOrgAuditExportRequest, d.deleted)
	if ev.Params["export_id"] != got.ID.String() || ev.Params["from_day"] != exportDay(2).Format(time.DateOnly) || !ev.Actor.StepUp {
		t.Fatalf("event = %+v", ev)
	}
	list, err := d.audit.Exports(deletedOrgReader(false), d.deleted, app.AuditExportQuery{Page: app.ListPage{Sort: "-requested_at", Limit: 10}}, nil)
	if err != nil || list.Count != 1 || list.Items[0].ID != got.ID {
		t.Fatalf("exports %+v, %v", list, err)
	}
}

func TestDeletedOrgAuditExportNeedsStepUp(t *testing.T) {
	d := newDeletedHarness(t)
	_, err := d.audit.RequestExport(deletedOrgReader(false), d.deleted,
		app.AuditExportRequest{FromDay: exportDay(2), ToDay: exportDay(1), Purpose: "auditor"})
	if !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("without step-up: %v", err)
	}
}

// TestDeletedOrgAuditDownloadNotReady: a pending export is not offered; the attempt is recorded with export_id.
func TestDeletedOrgAuditDownloadNotReady(t *testing.T) {
	d := newDeletedHarness(t)
	got, err := d.audit.RequestExport(deletedOrgReader(true), d.deleted,
		app.AuditExportRequest{FromDay: exportDay(2), ToDay: exportDay(1), Purpose: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.super.Exec(context.Background(), "DELETE FROM action WHERE correlation_id = $1", "corr-"+t.Name()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.super.Exec(context.Background(), "DELETE FROM outbox WHERE payload->>'correlation_id' = $1", "corr-"+t.Name()); err != nil {
		t.Fatal(err)
	}
	err = d.audit.Download(deletedOrgReader(false), d.deleted, got.ID, func(app.ExportPackage) { t.Error("begin called") },
		func([]byte) error { return nil })
	if !errors.Is(err, problem.ExportNotReady) {
		t.Fatalf("pending export: %v", err)
	}
	ev := expectRead(t, d, audit.OutcomeFailure, "export_not_ready", app.DeletedOrgAuditExportDownload, d.deleted)
	if ev.Params["export_id"] != got.ID.String() {
		t.Fatalf("event = %+v", ev)
	}
}

// TestDeletedOrgAuditForeignExport (main §46): the export of another organization is not reachable through a deleted
// organization's path; it is not_found (the same organization's pending export answers export_not_ready, see
// TestDeletedOrgAuditDownloadNotReady), recorded as a failed attempt with export_id.
func TestDeletedOrgAuditForeignExport(t *testing.T) {
	d := newDeletedHarness(t)
	d.seal(t, exportDay(2), exportDay(1))
	foreign, err := d.exports.Request(d.steppedUp(principal.RoleOrgAuditor),
		app.AuditExportRequest{FromDay: exportDay(2), ToDay: exportDay(1), Purpose: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.super.Exec(context.Background(), "DELETE FROM action WHERE correlation_id = $1", "corr-"+t.Name()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.super.Exec(context.Background(), "DELETE FROM outbox WHERE payload->>'correlation_id' = $1", "corr-"+t.Name()); err != nil {
		t.Fatal(err)
	}
	err = d.audit.Download(deletedOrgReader(false), d.deleted, foreign.ID, func(app.ExportPackage) { t.Error("begin called") },
		func([]byte) error { return nil })
	if !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization's export: %v, want not_found", err)
	}
	ev := expectRead(t, d, audit.OutcomeFailure, "not_found", app.DeletedOrgAuditExportDownload, d.deleted)
	if ev.Params["export_id"] != foreign.ID.String() {
		t.Fatalf("event = %+v", ev)
	}
}
