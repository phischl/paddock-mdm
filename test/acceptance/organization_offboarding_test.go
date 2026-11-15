package acceptance

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestOffboardedDeviceUninstallsAfterTombstone is gate OF6 (plan M17 §8.7, decision 15, amendment l point 3): a device
// that is offline from the deletion request until the organization is deleted checks in only after the tombstone. It
// still receives its uninstall (leave) and nothing else: no bundle, no agent offer, no time ticket, and escrow is
// refused. The result of its uninstall is accepted (the agent starts the removal only then); a batch of other events is
// answered 200 and dropped. It reports agent.uninstalled, which the platform records as
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
	if out.Bundle != nil || out.AgentUpdate != nil || out.TimeTicket != nil || len(out.Commands) != 1 {
		t.Fatalf("check-in after the tombstone: %s, want the uninstall only", r.Body)
	}
	_, payload, err := dsse.Decode(out.Commands[0])
	if err != nil {
		t.Fatal(err)
	}
	var cmd command.Command
	if err := json.Unmarshal(payload, &cmd); err != nil || cmd.Type != "uninstall" {
		t.Fatalf("command %s, want uninstall: %v", payload, err)
	}

	er, err := d.Escrow(testContext(t, time.Minute), escrow.Request{})
	if err != nil || er.Status != http.StatusUnauthorized {
		t.Fatalf("escrow after the tombstone: %v HTTP %d, want 401", err, er.Status)
	}

	if r, err := d.CommandResult(testContext(t, time.Minute), cmd.CommandID, protocol.CommandSucceeded, json.RawMessage(`{}`)); err != nil ||
		r.Status != http.StatusAccepted {
		t.Fatalf("result of the uninstall: %v HTTP %d", err, r.Status)
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
