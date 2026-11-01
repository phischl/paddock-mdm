package acceptance

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestConfigStatus is the gate of the apply status (plan M11 §3.3, PDK-151): a bundle.applied report with two
// resources shows on the device, in the device's counts and in the fleet view; a drift correction and a rejection are
// recorded; the list contract holds and a foreign device is not found.
func TestConfigStatus(t *testing.T) {
	alice := login(t, env.Alice)
	suffix := uniqueSuffix()
	d := activeDevice(t, alice, "", "cs-"+suffix)
	okID, failedID := "file:/etc/paddock-gates/cs-ok-"+suffix+".conf", "unit:cs-failed-"+suffix+".service"

	var version int64
	for deadline := time.Now().Add(time.Minute); version == 0; time.Sleep(time.Second) {
		version = getDevice(t, alice, d.DeviceID).BundleVersion
		if version == 0 && time.Now().After(deadline) {
			t.Fatal("the device has no bundle")
		}
	}
	sendBundleEvent(t, d, 1, protocol.EventBundleApplied, map[string]any{
		"version": version, "changed": 1, "mode": "enforce", "errors": []map[string]string{{"id": failedID, "message": "unit not found"}},
		"resources": []map[string]any{
			{"id": okID, "status": "applied"}, {"id": failedID, "status": "failed", "message": "unit not found"},
		},
	})
	items := waitDeviceResources(t, alice, d.DeviceID, "sort=resource_id", func(i []resourceStatusItem) bool { return len(i) == 2 })
	if items[0].ResourceID != okID || items[0].Type != "file" || items[0].Status != "applied" ||
		items[1].ResourceID != failedID || items[1].Type != "unit" || items[1].Status != "failed" || items[1].Message != "unit not found" {
		t.Fatalf("items %+v", items)
	}
	if got := waitDeviceResources(t, alice, d.DeviceID, "status=failed", func(i []resourceStatusItem) bool { return len(i) == 1 }); got[0].ResourceID != failedID {
		t.Fatalf("status filter: %+v", got)
	}
	if got := waitDeviceResources(t, alice, d.DeviceID, url.Values{"q": {"cs-ok-" + suffix}}.Encode(), func(i []resourceStatusItem) bool { return len(i) == 1 }); got[0].ResourceID != okID {
		t.Fatalf("search: %+v", got)
	}

	counts := func() map[string]float64 {
		detail := getDeviceDetail(t, alice, d.DeviceID)
		raw, _ := detail["config_status"].(map[string]any)
		out := map[string]float64{}
		for k, v := range raw {
			out[k], _ = v.(float64)
		}
		return out
	}
	if c := counts(); c["applied"] != 1 || c["failed"] != 1 || c["pending"] != 0 || c["drift_corrected"] != 0 {
		t.Fatalf("config_status %v", c)
	}

	res := call(t, alice, http.MethodGet, "/api/v1/config-status?"+url.Values{"q": {suffix}, "status": {"failed"}}.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var fleet struct {
		Items []struct {
			ResourceID    string  `json:"resource_id"`
			Type          string  `json:"type"`
			Applied       int     `json:"applied"`
			Failed        int     `json:"failed"`
			LastFailureAt *string `json:"last_failure_at"`
		} `json:"items"`
		Sort string `json:"sort"`
	}
	if err := res.JSON(&fleet); err != nil {
		t.Fatal(err)
	}
	if len(fleet.Items) != 1 || fleet.Items[0].ResourceID != failedID || fleet.Items[0].Failed != 1 || fleet.Items[0].LastFailureAt == nil || fleet.Sort != "-failed" {
		t.Fatalf("fleet %+v", fleet)
	}

	sendBundleEvent(t, d, 2, protocol.EventConfigDriftCorrected, map[string]any{"version": version, "resource_ids": []string{okID}})
	waitDeviceResources(t, alice, d.DeviceID, "status=drift_corrected", func(i []resourceStatusItem) bool { return len(i) == 1 && i[0].ResourceID == okID })

	sendBundleEvent(t, d, 3, protocol.EventBundleRejected, map[string]any{"version": version + 1000, "reason": "signature"})
	type bundleItem struct {
		Version int64 `json:"version"`
		Report  *struct {
			Outcome string  `json:"outcome"`
			Mode    string  `json:"mode"`
			Reason  *string `json:"reason"`
		} `json:"report"`
		ConfigRolloutID *string `json:"config_rollout_id"`
	}
	bundles := func(query string) []bundleItem {
		res := call(t, alice, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/bundles?"+query, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []bundleItem `json:"items"`
			Sort  string       `json:"sort"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		return page.Items
	}
	var applied []bundleItem
	for deadline := time.Now().Add(time.Minute); len(applied) == 0; time.Sleep(time.Second) {
		applied = bundles("outcome=applied")
		if len(applied) == 0 && time.Now().After(deadline) {
			t.Fatal("the applied report does not show in the bundle history")
		}
	}
	if applied[0].Version != version || applied[0].Report.Mode != "enforce" || applied[0].ConfigRolloutID != nil {
		t.Fatalf("applied bundles %+v", applied)
	}
	all := bundles("")
	if len(all) == 0 || all[0].Version < all[len(all)-1].Version {
		t.Fatalf("bundles are not newest first: %+v", all)
	}
	for _, b := range bundles("outcome=none") {
		if b.Report != nil {
			t.Fatalf("outcome=none lists a reported version: %+v", b)
		}
	}
	// Only versions the server compiled for the device are listed, so the rejection of an unknown version is stored
	// but not part of the history.
	for _, b := range bundles("outcome=rejected") {
		t.Fatalf("a rejection of an unknown version is listed: %+v", b)
	}

	for _, path := range []string{"/api/v1/devices/" + d.DeviceID + "/config-status", "/api/v1/devices/" + d.DeviceID + "/bundles", "/api/v1/config-status"} {
		expectStatus(t, call(t, alice, http.MethodGet, path+"?page_size=7", nil), http.StatusBadRequest, "invalid_request")
		expectStatus(t, call(t, alice, http.MethodGet, path+"?sort=bogus", nil), http.StatusBadRequest, "invalid_request")
	}
	expectStatus(t, call(t, alice, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/bundles?outcome=bogus", nil), http.StatusBadRequest, "invalid_request")
	expectStatus(t, call(t, alice, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/config-status?status=bogus", nil), http.StatusBadRequest, "invalid_request")

	carol := login(t, env.Carol)
	expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/config-status", nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/bundles", nil), http.StatusNotFound, "not_found")
	res = call(t, carol, http.MethodGet, "/api/v1/config-status?q="+suffix, nil)
	expectStatus(t, res, http.StatusOK, "")
	var foreign struct {
		Total int `json:"total"`
	}
	if err := res.JSON(&foreign); err != nil || foreign.Total != 0 {
		t.Fatalf("carol sees acme's resources: %s (%v)", res.Body, err)
	}
}
