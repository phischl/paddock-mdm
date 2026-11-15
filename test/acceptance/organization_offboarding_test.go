package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestOffboardedDeviceUninstallsAfterTombstone is gate OF6 (plan M17 §8.7, decision 15, amendment l point 3): a device
// that is offline from the deletion request until the organization is deleted checks in only after the tombstone. It
// still receives the disarm of its dead man's switch and then its uninstall (leave), and nothing else: no bundle, no
// agent offer, no time ticket, and escrow is refused. The results of both are accepted (the agent starts the removal
// only after the uninstall's); a batch of other events is answered 200 and dropped. It reports agent.uninstalled, which the platform records as
// platform.offboarded_device_uninstalled; the keys it kept are then deleted (amendment l point 3), so a further
// check-in is refused with 401 (invalid_signature: the key is unknown).
func TestOffboardedDeviceUninstallsAfterTombstone(t *testing.T) {
	slug, orgID := gateOrganization(t)
	admin := newGateAdmin(t, slug)
	d := activeDevice(t, admin.portal, "", "of6-"+slug)

	root := steppedUpRoot(t)
	res := call(t, root, http.MethodPost, orgPath+orgID.String()+"/delete",
		map[string]any{"confirm_slug": slug, "reason": "of6 gate", "grace_days": 0})
	expectStatus(t, res, http.StatusAccepted, "")
	eventually(t, "the tombstone", 5*time.Minute, func() bool {
		res := call(t, root, http.MethodGet, orgPath+orgID.String(), nil)
		var org struct {
			Status string `json:"status"`
		}
		return res.Status == http.StatusOK && res.JSON(&org) == nil && org.Status == "deleted"
	})

	out, r, err := d.Checkin(testContext(t, time.Minute))
	if err != nil || r.Status != http.StatusOK {
		t.Fatalf("check-in after the tombstone: %v HTTP %d %s", err, r.Status, r.Body)
	}
	if out.Bundle != nil || out.AgentUpdate != nil || out.TimeTicket != nil || len(out.Commands) != 2 {
		t.Fatalf("check-in after the tombstone: %s, want the disarm and the uninstall only", r.Body)
	}
	cmds := make([]command.Command, len(out.Commands))
	for i, env := range out.Commands {
		_, payload, err := dsse.Decode(env)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &cmds[i]); err != nil {
			t.Fatal(err)
		}
	}
	// The disarm of the dead man's switch comes first (amendment n point 4).
	disarm, cmd := cmds[0], cmds[1]
	if disarm.Type != command.TypeDeleteSelfLock || cmd.Type != command.TypeUninstall {
		t.Fatalf("commands %s and %s, want delete_self_lock then uninstall", disarm.Type, cmd.Type)
	}

	er, err := d.Escrow(testContext(t, time.Minute), escrow.Request{})
	if err != nil || er.Status != http.StatusUnauthorized {
		t.Fatalf("escrow after the tombstone: %v HTTP %d, want 401", err, er.Status)
	}

	for _, c := range cmds {
		if r, err := d.CommandResult(testContext(t, time.Minute), c.CommandID, protocol.CommandSucceeded, json.RawMessage(`{}`)); err != nil ||
			r.Status != http.StatusAccepted {
			t.Fatalf("result of %s: %v HTTP %d", c.Type, err, r.Status)
		}
	}
	if r, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: 1, Type: protocol.EventBundleApplied,
		OccurredAt: time.Now(), Data: json.RawMessage(`{"bundle_version":1}`)}}); err != nil || r.Status != http.StatusOK {
		t.Fatalf("another event after the tombstone: %v HTTP %d, want 200", err, r.Status)
	}

	data, _ := json.Marshal(protocol.AgentUninstalled{CommandID: cmd.CommandID, Mode: "leave", Outcome: protocol.UninstallCompleted,
		LocalAdmin: "kept", TPM: "not_requested", Steps: map[string]string{"stop": "done", "packages": "done"}})
	if r, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: 1, Type: protocol.EventAgentUninstalled,
		OccurredAt: time.Now(), Data: data}}); err != nil || r.Status != http.StatusAccepted {
		t.Fatalf("agent.uninstalled: %v HTTP %d", err, r.Status)
	}
	expectOneIndexEvent(t, auditIndex(t), platformOrg, "code = 'platform.offboarded_device_uninstalled' AND params->>'device_id' = $1",
		d.DeviceID, "platform.offboarded_device_uninstalled", "success", 2*time.Minute)
	eventually(t, "the identity of the uninstalled device is gone", time.Minute, func() bool {
		_, r, err := d.Checkin(testContext(t, time.Minute))
		return err == nil && r.Status == http.StatusUnauthorized && strings.Contains(string(r.Body), "invalid_signature")
	})
}

// TestGateOrganizationsAreDeleted is gate OF8 (plan M17 §7 step 7, OFB-8, PDK-946): an organization a gate creates is
// deleted when its case ends. The organization of the subtest reaches the status deleted within orgDeletedWithin after
// the subtest returned, so it is then absent from the default list, which leaves out tombstones, and present in the list filtered by status deleted.
// Other gates' organizations are deleted by the same cleanup but may still be in progress while this gate runs, so the
// gate looks at its own only.
func TestGateOrganizationsAreDeleted(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	var slug string
	var id uuid.UUID
	t.Run("case", func(t *testing.T) {
		slug, id = gateOrganization(t)
	})
	if slug == "" {
		t.Fatal("the case created no organization")
	}

	// The cleanup only requests the deletion, so this gate is where a stuck deletion becomes a failure.
	var last gateOrgState
	for deadline := time.Now().Add(orgDeletedWithin); ; time.Sleep(2 * time.Second) {
		res := call(t, root, http.MethodGet, orgPath+id.String(), nil)
		last = gateOrgState{}
		if res.Status == http.StatusOK && res.JSON(&last) == nil && last.Status == "deleted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gate organization %s not deleted within %s: status %q%s", slug, orgDeletedWithin, last.Status, stepOf(last))
		}
	}

	for _, c := range []struct {
		query string
		want  bool
	}{{"", false}, {"&status=deleted", true}} {
		res := call(t, root, http.MethodGet, "/api/platform/v1/organizations?page_size=100&q="+slug+c.query, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []struct {
				Slug string `json:"slug"`
			} `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, it := range page.Items {
			found = found || it.Slug == slug
		}
		if found != c.want {
			t.Fatalf("list %q: organization %s listed = %v, want %v", c.query, slug, found, c.want)
		}
	}
}

// TestDeletedOrganizationAuditEvidence is gate OF5 (plan M17 §8.7, decisions 16 and 18, amendment 2026-11-15 o; ADR
// 0052 decisions 6 and 7): after the deletion a platform administrator reads the deleted organization's audit log,
// which ends with the final audit.chain_verified (final true), sees the outcome verified on the organization, finds
// the request and the outcome in the platform audit log, creates an evidence export with a step-up and downloads a
// package that `paddockctl audit verify-export` accepts. Every read is recorded as
// platform.deleted_organization_audit_read. An administrator of another organization gets 404 on every path, and so
// does a platform administrator for an organization that is not deleted.
func TestDeletedOrganizationAuditEvidence(t *testing.T) {
	ctx := testContext(t, 15*time.Minute)
	slug, orgID := gateOrganization(t)
	admin := newGateAdmin(t, slug)
	createGroup(t, admin.portal)
	root := steppedUpRoot(t)
	res := call(t, root, http.MethodPost, orgPath+orgID.String()+"/delete",
		map[string]any{"confirm_slug": slug, "reason": "of5 gate", "grace_days": 0})
	expectStatus(t, res, http.StatusAccepted, "")
	var org struct {
		Status   string `json:"status"`
		Deletion struct {
			AuditFinalVerifiedAt *string `json:"audit_final_verified_at"`
			AuditFinalOutcome    *string `json:"audit_final_outcome"`
		} `json:"deletion"`
	}
	eventually(t, "the tombstone", 5*time.Minute, func() bool {
		res := call(t, root, http.MethodGet, orgPath+orgID.String(), nil)
		return res.Status == http.StatusOK && res.JSON(&org) == nil && org.Status == "deleted"
	})
	if org.Deletion.AuditFinalVerifiedAt == nil || org.Deletion.AuditFinalOutcome == nil || *org.Deletion.AuditFinalOutcome != "verified" {
		t.Fatalf("OF5 deleted organization: %+v, want audit_final_outcome verified", org)
	}
	idx := auditIndex(t)
	expectOneIndexEvent(t, idx, platformOrg, "code = 'organization.audit_retirement_requested' AND params->>'organization_id' = $1",
		orgID.String(), "organization.audit_retirement_requested", "success", 2*time.Minute)
	deleted := expectOneIndexEvent(t, idx, platformOrg, "code = 'organization.deleted' AND target->>'id' = $1",
		orgID.String(), "organization.deleted", "success", 2*time.Minute)
	if deleted.Params["audit_final_outcome"] != "verified" {
		t.Fatalf("OF5 organization.deleted params: %+v", deleted.Params)
	}

	// The log ends with the final verification.
	from := time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)
	eventsPath := orgPath + orgID.String() + "/audit-events?page_size=100&from=" + from
	res = call(t, root, http.MethodGet, eventsPath, nil)
	expectStatus(t, res, http.StatusOK, "")
	var events struct {
		Items []env.AuditEvent `json:"items"`
		Total int              `json:"total"`
	}
	if err := res.JSON(&events); err != nil || events.Total < 2 || len(events.Items) == 0 {
		t.Fatalf("OF5 events: %v %s", err, res.Body)
	}
	if last := events.Items[0]; last.Code != "audit.chain_verified" || last.Params["final"] != true {
		t.Fatalf("OF5 newest event %+v, want audit.chain_verified with final true", last)
	}
	finals := 0
	for _, e := range events.Items {
		if e.Params["final"] == true {
			finals++
		}
	}
	if finals != 1 {
		t.Fatalf("OF5 %d final verifications in the log, want 1", finals)
	}
	read := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID,
		"platform.deleted_organization_audit_read", "success", 2*time.Minute)
	if read.Params["resource"] != "audit_events" || read.Params["organization_id"] != orgID.String() || read.Params["slug"] != slug {
		t.Fatalf("OF5 read record params: %+v", read.Params)
	}

	// The evidence export of the deleted organization's sealed log, verified offline.
	today := time.Now().UTC().Format(time.DateOnly)
	if code, out, err := stack.PaddockServer(ctx, "audit", "seal", "--day", today, "--org", orgID.String()); err != nil || code != 0 {
		t.Fatalf("OF5 audit seal: exit %d, %v\n%s", code, err, out)
	}
	exportsPath := orgPath + orgID.String() + "/audit-exports"
	body := map[string]string{"from_day": today, "to_day": today, "purpose": "OF5 evidence for the auditor"}
	stepUp(t, root, env.PlatformAdmin, true)
	res = call(t, root, http.MethodPost, exportsPath, body)
	expectStatus(t, res, http.StatusAccepted, "")
	var export auditExport
	if err := res.JSON(&export); err != nil || export.Status != "pending" {
		t.Fatalf("OF5 export: %v %s", err, res.Body)
	}
	var ready auditExport
	eventually(t, "the export of the deleted organization", 2*time.Minute, func() bool {
		res := call(t, root, http.MethodGet, exportsPath+"?page_size=10", nil)
		var page struct {
			Items []auditExport `json:"items"`
		}
		if res.Status != http.StatusOK || res.JSON(&page) != nil || len(page.Items) != 1 {
			return false
		}
		ready = page.Items[0]
		return ready.Status == "ready"
	})
	if ready.ID != export.ID || ready.VerifyOK == nil || !*ready.VerifyOK || ready.KeyVersion == nil {
		t.Fatalf("OF5 ready export: %+v", ready)
	}
	downloadPath := exportsPath + "/" + export.ID + "/download"
	res = call(t, root, http.MethodGet, downloadPath, nil)
	expectStatus(t, res, http.StatusOK, "")
	sum := sha256.Sum256(res.Body)
	if res.Header.Get("X-Paddock-Package-SHA256") != hex.EncodeToString(sum[:]) || int64(len(res.Body)) != *ready.Size {
		t.Fatalf("OF5 download headers %v (%d bytes)", res.Header, len(res.Body))
	}
	download := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID,
		"platform.deleted_organization_audit_read", "success", 2*time.Minute)
	if download.Params["resource"] != "audit_export_download" || download.Params["export_id"] != export.ID {
		t.Fatalf("OF5 download record params: %+v", download.Params)
	}
	code, out, err := stack.PaddockServer(ctx, "audit", "keys")
	if err != nil || code != 0 {
		t.Fatalf("OF5 audit keys: exit %d, %v\n%s", code, err, out)
	}
	fingerprint := ""
	prefix := fmt.Sprintf("audit-chain v%d ", *ready.KeyVersion)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			fingerprint = strings.TrimPrefix(line, prefix)
		}
	}
	if fingerprint == "" {
		t.Fatalf("OF5 audit keys lacks v%d:\n%s", *ready.KeyVersion, out)
	}
	pkg := filepath.Join(t.TempDir(), "of5.tar")
	if err := os.WriteFile(pkg, res.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := newPaddockctl(t).run(t, "", "", "audit", "verify-export", pkg, "--fingerprint", fingerprint); r.code != 0 ||
		!strings.HasPrefix(r.stdout, "OK ") {
		t.Fatalf("OF5 verify-export: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}

	// An administrator of another organization finds nothing on these paths; nor does a platform administrator for an
	// organization that is not deleted.
	carol := login(t, env.Carol)
	expectStatus(t, call(t, carol, http.MethodGet, eventsPath, nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodGet, exportsPath, nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodGet, downloadPath, nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodPost, exportsPath, body), http.StatusNotFound, "not_found")
	_, activeID := gateOrganization(t)
	expectStatus(t, call(t, root, http.MethodGet, orgPath+activeID.String()+"/audit-events", nil), http.StatusNotFound, "not_found")
}

// orgTombstoneWithin is the bound of plan M17 §8.7 and amendment p for a grace-0 deletion of a small gate
// organization, from the request's response to the status deleted. Amendment p makes a longer wait a stop condition,
// not a reason to raise it.
const orgTombstoneWithin = 5 * time.Minute

// orgDeletionView is the part of a platform organization the offboarding gates read.
type orgDeletionView struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Status   string `json:"status"`
	Deletion *struct {
		RequestedAt       time.Time  `json:"requested_at"`
		Reason            string     `json:"reason"`
		DeleteAfter       time.Time  `json:"delete_after"`
		Step              *string    `json:"step"`
		LastErrorCode     *string    `json:"last_error_code"`
		DeletedAt         *time.Time `json:"deleted_at"`
		UninstallsIssued  int        `json:"uninstalls_issued"`
		UninstallsSkipped int        `json:"uninstalls_skipped"`
	} `json:"deletion"`
}

func readOrgDeletion(t *testing.T, p *env.Portal, id uuid.UUID) orgDeletionView {
	t.Helper()
	res := call(t, p, http.MethodGet, orgPath+id.String(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var o orgDeletionView
	if err := res.JSON(&o); err != nil {
		t.Fatal(err)
	}
	return o
}

// deleteNow requests the deletion of a gate organization with grace 0 (a development stack allows it, ADR 0052) and
// returns the time the request was sent.
func deleteNow(t *testing.T, id uuid.UUID, slug, reason string) time.Time {
	t.Helper()
	root := steppedUpRoot(t)
	start := time.Now()
	res := call(t, root, http.MethodPost, orgPath+id.String()+"/delete",
		map[string]any{"confirm_slug": slug, "reason": reason, "grace_days": 0})
	expectStatus(t, res, http.StatusAccepted, "")
	return start
}

// awaitTombstone waits for the status deleted and returns the time from requested to the first read that saw it. It
// fails once orgTombstoneWithin has passed since requested, naming the step the deletion stands at.
func awaitTombstone(t *testing.T, root *env.Portal, id uuid.UUID, slug string, requested time.Time) (orgDeletionView, time.Duration) {
	t.Helper()
	for {
		res := call(t, root, http.MethodGet, orgPath+id.String(), nil)
		var o orgDeletionView
		var st gateOrgState
		if res.Status == http.StatusOK && res.JSON(&o) == nil && res.JSON(&st) == nil && o.Status == "deleted" {
			return o, time.Since(requested)
		}
		if elapsed := time.Since(requested); elapsed > orgTombstoneWithin {
			t.Fatalf("gate organization %s not deleted within %s of the request (%s): HTTP %d, status %q%s", slug,
				orgTombstoneWithin, elapsed.Round(time.Second), res.Status, st.Status, stepOf(st))
		}
		time.Sleep(2 * time.Second)
	}
}

// uninstallCommand returns the uninstall among the check-in's commands, or nil.
func uninstallCommand(t *testing.T, out protocol.CheckinResponse) *command.Command {
	t.Helper()
	for _, e := range out.Commands {
		_, payload, err := dsse.Decode(e)
		if err != nil {
			t.Fatal(err)
		}
		var c command.Command
		if err := json.Unmarshal(payload, &c); err != nil {
			t.Fatal(err)
		}
		if c.Type == command.TypeUninstall {
			return &c
		}
	}
	return nil
}

// TestOrganizationDeletionRequestAndCancel is gate OF1 (plan M17 §8.7, OFB-1, decisions 2, 4 and 19): the deletion
// request needs a step-up, the typed slug, a reason of 2 to 500 characters and a grace period within range; with all
// four the organization stays active with a pending deletion. The cancel is accepted only while the deletion is
// pending and answers 409 invalid_state otherwise. Each attempt is one event in the platform audit log.
func TestOrganizationDeletionRequestAndCancel(t *testing.T) {
	slug, orgID := gateOrganization(t)
	path := orgPath + orgID.String()
	idx := auditIndex(t)
	body := func(confirm, reason string, grace int) map[string]any {
		return map[string]any{"confirm_slug": confirm, "reason": reason, "grace_days": grace}
	}

	res := call(t, login(t, env.PlatformAdmin), http.MethodPost, path+"/delete", body(slug, "of1 gate", 30))
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_requested", "denied", auditPollTimeout)

	// The dev stack's step-up window is 30 s and every audit lookup settles for 5 to 10 s, so the requests that need the
	// step-up go out back to back and their events are looked up afterwards.
	root := steppedUpRoot(t)
	var refused []string
	for _, b := range []map[string]any{
		body(slug+"-x", "of1 gate", 30),
		body(slug, "x", 30),
		body(slug, strings.Repeat("r", 501), 30),
		body(slug, "of1 gate", -1),
		body(slug, "of1 gate", 91),
	} {
		res := call(t, root, http.MethodPost, path+"/delete", b)
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		refused = append(refused, res.RequestID)
	}
	for _, id := range refused {
		expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", id, "organization.deletion_requested", "failure", auditPollTimeout)
	}
	if o := readOrgDeletion(t, root, orgID); o.Status != "active" || o.Deletion != nil {
		t.Fatalf("after the refused requests: %+v, want active without a deletion", o)
	}

	res = call(t, root, http.MethodPost, path+"/cancel-deletion", nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_cancelled", "failure", auditPollTimeout)

	// stepUp waits out Authentik's maximum auth age since the previous step-up, so this one is a fresh login.
	stepUp(t, root, env.PlatformAdmin, true)
	res = call(t, root, http.MethodPost, path+"/delete", body(slug, "of1 gate", 30))
	expectStatus(t, res, http.StatusAccepted, "")
	// Registered after the organization's own cleanup, so it runs first and leaves an active organization to delete.
	t.Cleanup(func() { call(t, root, http.MethodPost, path+"/cancel-deletion", nil) })
	duplicate := call(t, root, http.MethodPost, path+"/delete", body(slug, "of1 gate", 30))
	expectStatus(t, duplicate, http.StatusConflict, "invalid_state")
	var requested orgDeletionView
	if err := res.JSON(&requested); err != nil {
		t.Fatal(err)
	}
	if d := requested.Deletion; requested.Status != "active" || d == nil || d.Reason != "of1 gate" || d.Step != nil || d.DeletedAt != nil ||
		d.UninstallsIssued != 0 || d.UninstallsSkipped != 0 || d.DeleteAfter.Sub(d.RequestedAt).Round(time.Hour) != 30*24*time.Hour {
		t.Fatalf("requested deletion: %s, want active with a deletion after 30 days", res.Body)
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_requested", "success", auditPollTimeout)
	if ev.Params["slug"] != slug || ev.Params["reason"] != "of1 gate" || ev.Params["grace_days"] != float64(30) ||
		ev.Params["uninstalls_issued"] != float64(0) || ev.Params["delete_after"] == nil {
		t.Fatalf("organization.deletion_requested params: %v", ev.Params)
	}
	if o := readOrgDeletion(t, root, orgID); o.Status != "active" || o.Deletion == nil || !o.Deletion.DeleteAfter.Equal(requested.Deletion.DeleteAfter) {
		t.Fatalf("pending deletion: %+v", o)
	}
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", duplicate.RequestID, "organization.deletion_requested", "failure", auditPollTimeout)

	res = call(t, root, http.MethodPost, path+"/cancel-deletion", nil)
	expectStatus(t, res, http.StatusOK, "")
	var cancelled orgDeletionView
	if err := res.JSON(&cancelled); err != nil || cancelled.Status != "active" || cancelled.Deletion != nil {
		t.Fatalf("cancelled deletion: %v %s, want active without a deletion", err, res.Body)
	}
	ev = expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_cancelled", "success", auditPollTimeout)
	if ev.Params["slug"] != slug || ev.Params["uninstalls_cancelled"] != float64(0) {
		t.Fatalf("organization.deletion_cancelled params: %v", ev.Params)
	}
	if o := readOrgDeletion(t, root, orgID); o.Status != "active" || o.Deletion != nil {
		t.Fatalf("after the cancel: %+v", o)
	}

	res = call(t, root, http.MethodPost, path+"/cancel-deletion", nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_cancelled", "failure", auditPollTimeout)
}

// TestOrganizationDeletionUninstallsDevices is gate OF2 (plan M17 §8.7, OFB-2, decision 3): the deletion request
// issues the uninstall (mode leave) to the organization's active device, its administrator sees it pending, and the
// device receives it at its next check-in while the deletion is still pending.
func TestOrganizationDeletionUninstallsDevices(t *testing.T) {
	slug, orgID := gateOrganization(t)
	admin := newGateAdmin(t, slug)
	d := activeDevice(t, admin.portal, "", "of2-"+slug)

	root := steppedUpRoot(t)
	path := orgPath + orgID.String()
	res := call(t, root, http.MethodPost, path+"/delete", map[string]any{"confirm_slug": slug, "reason": "of2 gate", "grace_days": 30})
	expectStatus(t, res, http.StatusAccepted, "")
	// Registered after the organization's own cleanup, so it runs first and leaves an active organization to delete.
	t.Cleanup(func() { call(t, root, http.MethodPost, path+"/cancel-deletion", nil) })
	var o orgDeletionView
	if err := res.JSON(&o); err != nil || o.Deletion == nil || o.Deletion.UninstallsIssued != 1 || o.Deletion.UninstallsSkipped != 0 {
		t.Fatalf("requested deletion: %v %s, want one uninstall issued", err, res.Body)
	}

	s := uninstallOf(t, admin.portal, d.DeviceID)
	if s.Uninstall == nil || s.Uninstall.Mode != "leave" || s.Uninstall.CommandStatus != "pending" {
		t.Fatalf("device after the request: %+v, want a pending uninstall (leave)", s.Uninstall)
	}
	issued := s.Uninstall.CommandID

	// The worker's command round publishes the offboarding uninstalls within one interval of a minute.
	var cmd *command.Command
	checkinUntil(t, d, 3*time.Minute, func(out protocol.CheckinResponse) bool {
		cmd = uninstallCommand(t, out)
		return cmd != nil
	})
	var params command.UninstallParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil || cmd.CommandID != issued || cmd.DeviceID != d.DeviceID ||
		cmd.OrganizationID != orgID.String() || params.Mode != command.UninstallLeave {
		t.Fatalf("uninstall at the device: %+v (%v), want command %s with mode leave", cmd, err, issued)
	}
	if !cmd.ExpiresAt.After(o.Deletion.DeleteAfter) {
		t.Fatalf("uninstall expires %s, want after the deletion date %s", cmd.ExpiresAt, o.Deletion.DeleteAfter)
	}
	eventually(t, "the delivery of the uninstall", time.Minute, func() bool {
		u := uninstallOf(t, admin.portal, d.DeviceID).Uninstall
		return u != nil && u.CommandStatus == "delivered"
	})
}

// TestOrganizationDeletedWithinFiveMinutes is gate OF3 (plan M17 §8.7, OFB-4, decision 10, amendment p): a deletion
// with grace 0 reaches the status deleted within 5 minutes of the request, and the organization's identity objects in
// Authentik are gone: no group paddock.<slug> or paddock.<slug>.*, no application or provider paddock-device-<slug>.
// The cancel of a deleted organization is refused with 409. The measured duration is logged; the plan's result
// document records it.
func TestOrganizationDeletedWithinFiveMinutes(t *testing.T) {
	slug, orgID := gateOrganization(t)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 10*time.Minute)
	app := "paddock-device-" + slug
	// The organization's objects exist before the deletion, so their absence afterwards is the deletion's work.
	if pk, err := ak.GroupPK(ctx, env.RootGroup(slug)); err != nil || pk == "" {
		t.Fatalf("group %s before the deletion: %v, pk %q", env.RootGroup(slug), err, pk)
	}
	if err := ak.Get(ctx, "/core/applications/"+app+"/", &struct{}{}); err != nil {
		t.Fatalf("application %s before the deletion: %v", app, err)
	}
	var providers struct {
		Results []struct{} `json:"results"`
	}
	providersPath := "/providers/oauth2/?" + url.Values{"name": {app}}.Encode()
	if err := ak.Get(ctx, providersPath, &providers); err != nil || len(providers.Results) != 1 {
		t.Fatalf("provider %s before the deletion: %v, %d found, want 1", app, err, len(providers.Results))
	}

	requested := deleteNow(t, orgID, slug, "of3 gate")
	root := login(t, env.PlatformAdmin)
	o, took := awaitTombstone(t, root, orgID, slug, requested)
	t.Logf("OF3: request to tombstone of %s in %s (bound %s)", slug, took.Round(time.Second), orgTombstoneWithin)
	if took > orgTombstoneWithin {
		t.Fatalf("OF3: deletion took %s, bound %s", took, orgTombstoneWithin)
	}
	if o.Deletion == nil || o.Deletion.DeletedAt == nil {
		t.Fatalf("OF3: tombstone without deletion.deleted_at: %+v", o)
	}
	server := o.Deletion.DeletedAt.Sub(o.Deletion.RequestedAt)
	t.Logf("OF3: server-side requested_at to deleted_at %s", server.Round(time.Second))
	if server > orgTombstoneWithin {
		t.Fatalf("OF3: server-side deletion took %s, bound %s", server, orgTombstoneWithin)
	}

	var groups struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	rootGroup := env.RootGroup(slug)
	if err := ak.Get(ctx, "/core/groups/?"+url.Values{"search": {rootGroup}, "include_users": {"false"}, "page_size": {"100"}}.Encode(), &groups); err != nil {
		t.Fatal(err)
	}
	for _, g := range groups.Results {
		if g.Name == rootGroup || strings.HasPrefix(g.Name, rootGroup+".") {
			t.Errorf("group %s left in Authentik after the deletion", g.Name)
		}
	}
	if pk, err := ak.GroupPK(ctx, rootGroup); err != nil || pk != "" {
		t.Errorf("group %s after the deletion: %v, pk %q, want none", rootGroup, err, pk)
	}
	if err := ak.Get(ctx, "/core/applications/"+app+"/", &struct{}{}); !env.IsNotFound(err) {
		t.Errorf("application %s after the deletion: %v, want HTTP 404", app, err)
	}
	providers.Results = nil
	if err := ak.Get(ctx, providersPath, &providers); err != nil || len(providers.Results) != 0 {
		t.Errorf("provider %s after the deletion: %v, %d left", app, err, len(providers.Results))
	}

	res := call(t, root, http.MethodPost, orgPath+orgID.String()+"/cancel-deletion", nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	expectOneIndexEvent(t, auditIndex(t), platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_cancelled", "failure", auditPollTimeout)
}

// TestDeletedOrganizationAPITokenRefused is gate OF4 (plan M17 §8.7, OFB-4): an admin API token of the organization
// works before the deletion and is refused with 401 once the organization is deleted.
func TestDeletedOrganizationAPITokenRefused(t *testing.T) {
	slug, orgID := gateOrganization(t)
	admin := newGateAdmin(t, slug)
	admin.stepUp(t)
	res := postAPIToken(t, admin.portal, apiTokenName("of4"), "org_admin", 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	var created apiTokenCreated
	if err := res.JSON(&created); err != nil || created.Secret == "" {
		t.Fatalf("API token: %v", err)
	}
	token := tokenPortal(t, created.Secret)
	paths := []string{"/api/v1/me", "/api/v1/devices?page_size=10"}
	for _, p := range paths {
		expectStatus(t, call(t, token, http.MethodGet, p, nil), http.StatusOK, "")
	}

	requested := deleteNow(t, orgID, slug, "of4 gate")
	awaitTombstone(t, login(t, env.PlatformAdmin), orgID, slug, requested)
	for _, p := range paths {
		if res := call(t, token, http.MethodGet, p, nil); res.Status != http.StatusUnauthorized {
			t.Errorf("GET %s with the deleted organization's API token: HTTP %d %s, want 401", p, res.Status, res.ProblemCode())
		}
	}
}

// TestDeletedOrganizationSlugReuse is gate OF7 (plan M17 §8.7, decision 17): once an organization is deleted, its slug
// is free; a new organization with that slug is created and is a different organization, while the tombstone stays.
func TestDeletedOrganizationSlugReuse(t *testing.T) {
	slug, orgID := gateOrganization(t)
	requested := deleteNow(t, orgID, slug, "of7 gate")
	root := login(t, env.PlatformAdmin)
	awaitTombstone(t, root, orgID, slug, requested)

	// createOrg registers the new organization for deletion at the end of the gate (PDK-946).
	res := createOrg(t, root, map[string]string{"slug": slug, "name": "Gate " + slug})
	expectStatus(t, res, http.StatusCreated, "")
	reused := responseID(t, res)
	if reused == orgID {
		t.Fatalf("the new organization %s has the tombstone's ID", reused)
	}
	if o := readOrgDeletion(t, root, reused); o.Slug != slug || o.Status != "active" || o.Deletion != nil {
		t.Fatalf("new organization with the reused slug: %+v", o)
	}
	if o := readOrgDeletion(t, root, orgID); o.Slug != slug || o.Status != "deleted" {
		t.Fatalf("tombstone after the reuse: %+v", o)
	}
}
