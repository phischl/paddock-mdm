package acceptance

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// largeOrgDeletedWithin is the bound for the large organization's tombstone in gate OF3L: the hour of the deletion's
// stuck alert (plan M17 amendment 2026-11-16 s point 7.1).
const largeOrgDeletedWithin = 60 * time.Minute

// largeOrgMinDevices is the seeded large organization's minimum size (amendment s point 7.2: 20 000 devices are
// seeded, at least 10 000 must be listed).
const largeOrgMinDevices = 10000

// TestOrganizationDeletedWithinFiveMinutesNextToLargeOrganization is gate OF3L (plan M17 amendment 2026-11-16 s point
// 7, PDK-1087): a small organization with 3 active devices, deleted with grace 0 at the same time as a seeded large
// organization, reaches the status deleted within 5 minutes, client- and server-side; one large deletion holds up no
// other. The large organization is deleted within 60 minutes with at least 10 000 objects. The per-step durations of
// both, from their organization.deletion_step_completed events in the audit index, are logged for the result
// document. It runs only when PADDOCK_OF3_LARGE_ORG names the seeded organization (slug); CI does not seed one. Seed it
// on a development stack with `make load-enrol-configs ORG=of3-large TOKENS=20 USES=1000` and `make load-identities
// CONFIGS="$(ls bin/load/token-*.json | tr '\n' ' ')" COUNT=20000`, and run it with `-timeout 90m`: the large
// deletion may take its full hour.
func TestOrganizationDeletedWithinFiveMinutesNextToLargeOrganization(t *testing.T) {
	largeSlug := os.Getenv("PADDOCK_OF3_LARGE_ORG")
	if largeSlug == "" {
		t.Skip("PADDOCK_OF3_LARGE_ORG names no seeded large organization (plan M17 amendment 2026-11-16 s point 7.2)")
	}
	root := login(t, env.PlatformAdmin)
	largeID := orgIDBySlug(t, root, largeSlug)
	largeAdmin := newGateAdmin(t, largeSlug)
	res := call(t, largeAdmin.portal, http.MethodGet, "/api/v1/devices?page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	var devices struct {
		Total       int  `json:"total"`
		TotalCapped bool `json:"total_capped"`
	}
	if err := res.JSON(&devices); err != nil || (devices.Total < largeOrgMinDevices && !devices.TotalCapped) {
		t.Fatalf("OF3L precondition: %s lists %d devices (capped %v, %v), want at least %d", largeSlug, devices.Total,
			devices.TotalCapped, err, largeOrgMinDevices)
	}

	slug, smallID := gateOrganization(t)
	admin := newGateAdmin(t, slug)
	for i := range 3 {
		activeDeviceWith(t, admin.portal, "", fmt.Sprintf("of3l-%d-%s", i, slug), false)
	}

	stepped := steppedUpRoot(t)
	ctx := testContext(t, largeOrgDeletedWithin+15*time.Minute)
	orgs := []struct {
		id   uuid.UUID
		slug string
	}{{largeID, largeSlug}, {smallID, slug}}
	responses := make([]env.Response, len(orgs))
	errs := make([]error, len(orgs))
	var wg sync.WaitGroup
	requested := time.Now()
	for i, o := range orgs {
		wg.Go(func() {
			responses[i], errs[i] = stepped.Do(ctx, http.MethodPost, orgPath+o.id.String()+"/delete",
				map[string]any{"confirm_slug": o.slug, "reason": "of3l gate", "grace_days": 0})
		})
	}
	wg.Wait()
	for i, o := range orgs {
		if errs[i] != nil || responses[i].Status != http.StatusAccepted {
			t.Fatalf("OF3L delete %s: %v, HTTP %d %s", o.slug, errs[i], responses[i].Status, responses[i].Body)
		}
	}

	small, took := awaitTombstone(t, root, smallID, slug, requested)
	t.Logf("OF3L: request to tombstone of the small organization %s in %s (bound %s)", slug, took.Round(time.Second), orgTombstoneWithin)
	if small.Deletion == nil || small.Deletion.DeletedAt == nil {
		t.Fatalf("OF3L: tombstone without deletion.deleted_at: %+v", small)
	}
	server := small.Deletion.DeletedAt.Sub(small.Deletion.RequestedAt)
	t.Logf("OF3L: server-side requested_at to deleted_at of the small organization %s", server.Round(time.Second))
	if took > orgTombstoneWithin || server > orgTombstoneWithin {
		t.Fatalf("OF3L: the small organization took %s (server-side %s), bound %s", took, server, orgTombstoneWithin)
	}
	idx := auditIndex(t)
	logStepDurations(t, idx, "small", smallID, small.Deletion.RequestedAt)

	var large orgDeletionView
	for {
		r := call(t, root, http.MethodGet, orgPath+largeID.String(), nil)
		if r.Status == http.StatusUnauthorized {
			root = login(t, env.PlatformAdmin)
			continue
		}
		expectStatus(t, r, http.StatusOK, "")
		var st gateOrgState
		if err := r.JSON(&large); err != nil || r.JSON(&st) != nil {
			t.Fatalf("OF3L large organization: %v %s", err, r.Body)
		}
		if large.Status == "deleted" {
			break
		}
		if elapsed := time.Since(requested); elapsed > largeOrgDeletedWithin {
			t.Fatalf("OF3L: the large organization %s is not deleted %s after the request: status %q%s", largeSlug,
				elapsed.Round(time.Second), st.Status, stepOf(st))
		}
		time.Sleep(15 * time.Second)
	}
	t.Logf("OF3L: request to tombstone of the large organization %s in %s", largeSlug, time.Since(requested).Round(time.Second))
	if large.Deletion != nil && large.Deletion.DeletedAt != nil {
		t.Logf("OF3L: server-side requested_at to deleted_at of the large organization %s",
			large.Deletion.DeletedAt.Sub(large.Deletion.RequestedAt).Round(time.Second))
	}
	deleted := expectOneIndexEvent(t, idx, platformOrg, "code = 'organization.deleted' AND target->>'id' = $1",
		largeID.String(), "organization.deleted", "success", 5*time.Minute)
	t.Logf("OF3L: organization.deleted of %s: %v", largeSlug, deleted.Params)
	if n, ok := deleted.Params["objects_deleted"].(float64); !ok || n < largeOrgMinDevices {
		t.Fatalf("OF3L: the large organization's deletion removed %v objects, want at least %d (its bundles)",
			deleted.Params["objects_deleted"], largeOrgMinDevices)
	}
	if large.Deletion != nil {
		logStepDurations(t, idx, "large", largeID, large.Deletion.RequestedAt)
	}
}

// orgIDBySlug returns the ID of the organization slug from the platform organization list.
func orgIDBySlug(t *testing.T, root *env.Portal, slug string) uuid.UUID {
	t.Helper()
	res := call(t, root, http.MethodGet, strings.TrimSuffix(orgPath, "/")+"?"+url.Values{"q": {slug}, "page_size": {"100"}}.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID   uuid.UUID `json:"id"`
			Slug string    `json:"slug"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	for _, o := range page.Items {
		if o.Slug == slug {
			return o.ID
		}
	}
	t.Fatalf("no organization %s: %s", slug, res.Body)
	return uuid.Nil
}

// logStepDurations logs how long each step of the organization's deletion took, from the occurrence times of its
// organization.deletion_step_completed events in the audit index; the first step counts from requested (grace 0).
func logStepDurations(t *testing.T, idx *env.AuditIndex, label string, org uuid.UUID, requested time.Time) {
	t.Helper()
	where := "code = 'organization.deletion_step_completed' AND target->>'id' = $1"
	var events []env.IndexEvent
	eventually(t, "the "+label+" organization's tombstone step event in the audit index", 5*time.Minute, func() bool {
		var err error
		events, err = idx.Events(testContext(t, time.Minute), platformOrg, where, org.String())
		if err != nil {
			t.Fatal(err)
		}
		return len(events) > 0 && events[len(events)-1].Params["step"] == "tombstone"
	})
	var b strings.Builder
	previous := requested
	for _, e := range events {
		fmt.Fprintf(&b, " %v=%s(count %v)", e.Params["step"], e.OccurredAt.Sub(previous).Round(100*time.Millisecond), e.Params["count"])
		previous = e.OccurredAt
	}
	t.Logf("OF3L: steps of the %s organization %s:%s", label, org, b.String())
}
