package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// deletedAuditOrg is the deleted organization the A3 cases of its retained audit evidence share (PDK-1075): a grace-0
// deletion takes minutes, so one tombstone serves every case. Its day is sealed for the export requests.
type deletedAuditOrg struct {
	id        uuid.UUID
	slug      string
	requested time.Time
	day       string
	ready     bool
}

func (d *deletedAuditOrg) path() string { return orgPath + d.id.String() }

// startDeletedAuditOrg creates the shared organization and requests its deletion with grace 0; the first case that
// needs it waits for the tombstone (deletedAuditOrganization).
func (w *auditWorld) startDeletedAuditOrg(t *testing.T) {
	t.Helper()
	slug, id := gateOrganizationFor(w.owner, t)
	w.deleted = &deletedAuditOrg{id: id, slug: slug, requested: deleteNow(t, id, slug, "a3 gate")}
}

// withoutSlot runs fn without the case's slot of the gate's parallel cases: a wait for a shared fixture would
// otherwise hold a slot the other cases need. The slot is taken back before the case ends, also when fn fails it.
func (w *auditWorld) withoutSlot(fn func()) {
	if w.sem == nil {
		fn()
		return
	}
	<-w.sem
	defer func() { w.sem <- struct{}{} }()
	fn()
}

// deletedAuditOrganization returns the shared deleted organization once it is deleted and its day sealed.
func (w *auditWorld) deletedAuditOrganization(t *testing.T) *deletedAuditOrg {
	t.Helper()
	w.withoutSlot(func() {
		w.deletedMu.Lock()
		defer w.deletedMu.Unlock()
		if w.deletedFailed {
			t.Fatal("the shared deleted organization of the audit evidence cases failed in another case")
		}
		if w.deleted.ready {
			return
		}
		// Stays set when the setup fails the case, so the other cases fail at once instead of waiting again.
		w.deletedFailed = true
		d := w.deleted
		awaitTombstone(t, w.root, d.id, d.slug, d.requested)
		d.day = time.Now().UTC().Format(time.DateOnly)
		if code, out, err := stack.PaddockServer(testContext(t, 5*time.Minute), "audit", "seal", "--day", d.day, "--org", d.id.String()); err != nil || code != 0 {
			t.Fatalf("audit seal of the deleted organization: exit %d, %v\n%s", code, err, out)
		}
		d.ready = true
		w.deletedFailed = false
	})
	return w.deleted
}

// expectDeletedAuditRead requires exactly one platform.deleted_organization_audit_read of the request in the platform
// pseudo-organization, the only log a read of a deleted organization's evidence lands in.
func expectDeletedAuditRead(t *testing.T, w *auditWorld, res env.Response, outcome, resource string) env.IndexEvent {
	t.Helper()
	// The export job's audit.export_completed carries the request's correlation ID too, so events are counted per code.
	ev := expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1 AND code = 'platform.deleted_organization_audit_read'", res.RequestID,
		"platform.deleted_organization_audit_read", outcome, auditPollTimeout)
	if ev.Params["resource"] != resource {
		t.Fatalf("event params %v, want resource %s", ev.Params, resource)
	}
	return ev
}

func deletedExportBody(from, to string) map[string]string {
	return map[string]string{"from_day": from, "to_day": to, "purpose": "a3 gate"}
}

// deletedAuditListCases are the cases of a list of a deleted organization's evidence (path below the organization): a
// caller who is no platform administrator and an organization that does not exist or is not deleted get not_found,
// the denial in the caller's own log, every other attempt in the platform log.
func deletedAuditListCases(suffix, resource string) []auditCase {
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			d := w.deletedAuditOrganization(t)
			res := call(t, w.root, http.MethodGet, d.path()+suffix+"?page_size=10", nil)
			expectStatus(t, res, http.StatusOK, "")
			ev := expectDeletedAuditRead(t, w, res, "success", resource)
			if ev.Params["organization_id"] != d.id.String() || ev.Params["slug"] != d.slug {
				t.Fatalf("event params %v, want organization %s (%s)", ev.Params, d.id, d.slug)
			}
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			d := w.deletedAuditOrganization(t)
			res := call(t, w.root, http.MethodGet, d.path()+suffix+"?page_size=7", nil)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectDeletedAuditRead(t, w, res, "failure", resource)
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodGet, orgPath+uuid.NewString()+suffix, nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "platform.deleted_organization_audit_read", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			// An unknown organization and one that is not deleted are answered alike.
			for _, org := range []string{uuid.NewString(), w.acme.String()} {
				res := call(t, w.root, http.MethodGet, orgPath+org+suffix, nil)
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectDeletedAuditRead(t, w, res, "failure", resource)
			}
		}},
	}
}

// deletedOrgAuditCases are the A3 cases of the retained audit evidence of a deleted organization (ADR 0052 decision 7,
// PDK-1018): every attempt is one platform.deleted_organization_audit_read.
var deletedOrgAuditCases = map[string][]auditCase{
	"GET /api/platform/v1/organizations/{id}/audit-events":  deletedAuditListCases("/audit-events", "audit_events"),
	"GET /api/platform/v1/organizations/{id}/audit-exports": deletedAuditListCases("/audit-exports", "audit_exports"),
	"POST /api/platform/v1/organizations/{id}/audit-exports": {
		{"success", func(t *testing.T, w *auditWorld) {
			d := w.deletedAuditOrganization(t)
			res := call(t, steppedUpRoot(t), http.MethodPost, d.path()+"/audit-exports", deletedExportBody(d.day, d.day))
			expectStatus(t, res, http.StatusAccepted, "")
			var export auditExport
			if err := res.JSON(&export); err != nil {
				t.Fatal(err)
			}
			ev := expectDeletedAuditRead(t, w, res, "success", "audit_export_request")
			if ev.Params["export_id"] != export.ID || ev.Params["organization_id"] != d.id.String() {
				t.Fatalf("event params %v, want export %s of %s", ev.Params, export.ID, d.id)
			}
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			day := time.Now().UTC().Format(time.DateOnly)
			res := call(t, login(t, env.PlatformAdmin), http.MethodPost, orgPath+uuid.NewString()+"/audit-exports", deletedExportBody(day, day))
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectDeletedAuditRead(t, w, res, "denied", "audit_export_request")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			day := time.Now().UTC().Format(time.DateOnly)
			res := call(t, w.alice, http.MethodPost, orgPath+uuid.NewString()+"/audit-exports", deletedExportBody(day, day))
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "platform.deleted_organization_audit_read", "denied")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			d := w.deletedAuditOrganization(t)
			// The day before the sealed one, not before today: across midnight UTC that would be the sealed day itself.
			day, err := time.Parse(time.DateOnly, d.day)
			if err != nil {
				t.Fatal(err)
			}
			yesterday := day.AddDate(0, 0, -1).Format(time.DateOnly)
			res := call(t, steppedUpRoot(t), http.MethodPost, d.path()+"/audit-exports", deletedExportBody(d.day, yesterday))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectDeletedAuditRead(t, w, res, "failure", "audit_export_request")
		}},
		{"day not sealed", func(t *testing.T, w *auditWorld) {
			d := w.deletedAuditOrganization(t)
			tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
			res := call(t, steppedUpRoot(t), http.MethodPost, d.path()+"/audit-exports", deletedExportBody(d.day, tomorrow))
			expectStatus(t, res, http.StatusUnprocessableEntity, "day_not_sealed")
			expectDeletedAuditRead(t, w, res, "failure", "audit_export_request")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			day := time.Now().UTC().Format(time.DateOnly)
			root := steppedUpRoot(t)
			for _, org := range []string{uuid.NewString(), w.acme.String()} {
				res := call(t, root, http.MethodPost, orgPath+org+"/audit-exports", deletedExportBody(day, day))
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectDeletedAuditRead(t, w, res, "failure", "audit_export_request")
			}
		}},
	},
	"GET /api/platform/v1/organizations/{id}/audit-exports/{export_id}/download": {
		{"success", func(t *testing.T, w *auditWorld) {
			d := w.deletedAuditOrganization(t)
			res := call(t, steppedUpRoot(t), http.MethodPost, d.path()+"/audit-exports", deletedExportBody(d.day, d.day))
			expectStatus(t, res, http.StatusAccepted, "")
			var export auditExport
			if err := res.JSON(&export); err != nil {
				t.Fatal(err)
			}
			w.withoutSlot(func() {
				eventually(t, "the export of the deleted organization", 2*time.Minute, func() bool {
					res := call(t, w.root, http.MethodGet, d.path()+"/audit-exports?page_size=10", nil)
					var page struct {
						Items []auditExport `json:"items"`
					}
					if res.Status != http.StatusOK || res.JSON(&page) != nil {
						return false
					}
					for _, e := range page.Items {
						if e.ID == export.ID {
							return e.Status == "ready"
						}
					}
					return false
				})
			})
			res = call(t, w.root, http.MethodGet, d.path()+"/audit-exports/"+export.ID+"/download", nil)
			expectStatus(t, res, http.StatusOK, "")
			ev := expectDeletedAuditRead(t, w, res, "success", "audit_export_download")
			if ev.Params["export_id"] != export.ID {
				t.Fatalf("event params %v, want export %s", ev.Params, export.ID)
			}
		}},
		{"unknown export", func(t *testing.T, w *auditWorld) {
			d := w.deletedAuditOrganization(t)
			res := call(t, w.root, http.MethodGet, d.path()+"/audit-exports/"+uuid.NewString()+"/download", nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectDeletedAuditRead(t, w, res, "failure", "audit_export_download")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodGet, orgPath+uuid.NewString()+"/audit-exports/"+uuid.NewString()+"/download", nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "platform.deleted_organization_audit_read", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			for _, org := range []string{uuid.NewString(), w.acme.String()} {
				res := call(t, w.root, http.MethodGet, orgPath+org+"/audit-exports/"+uuid.NewString()+"/download", nil)
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectDeletedAuditRead(t, w, res, "failure", "audit_export_download")
			}
		}},
	},
}
