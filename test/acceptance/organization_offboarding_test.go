package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
