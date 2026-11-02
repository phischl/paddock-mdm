package acceptance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestAdoption is the gate of adoption (plan M11 §3.11 and §8, PDK-160): a device that enrolls as adopted is
// report-only, its bundle says so, its report-only report lists the planned changes, and the attention list shows it;
// enabling enforcement needs the device's hostname, enforces the next bundle, ends the attention item and is audited.
// A device that sends no enrollment method is unknown and enforced.
func TestAdoption(t *testing.T) {
	alice := login(t, env.Alice)
	tok := createToken(t, alice, tokenOptions{autoApprove: true})
	hostname := "adopt-" + uniqueSuffix()
	d := newSim(t, tok.EnrollmentConfig)
	d.EnrollmentMethod = protocol.EnrollmentAdopted
	res, err := d.Enroll(testContext(t, time.Minute), hostname)
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("enroll: %v HTTP %d %s", err, res.Status, res.Body)
	}
	if s, err := d.WaitEnrollment(testContext(t, 30*time.Second), func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing }); err != nil ||
		s.Status != protocol.EnrollActive {
		t.Fatalf("enrollment %+v, %v", s, err)
	}
	detail := getDeviceDetail(t, alice, d.DeviceID)
	if detail["enrollment_method"] != "adopted" || detail["config_mode"] != "report_only" || detail["config_mode_changed_at"] != nil {
		t.Fatalf("adopted device %v %v %v", detail["enrollment_method"], detail["config_mode"], detail["config_mode_changed_at"])
	}
	listed := call(t, alice, http.MethodGet, "/api/v1/devices?"+url.Values{"q": {hostname}, "enrollment_method": {"adopted"}, "config_mode": {"report_only"}}.Encode(), nil)
	expectStatus(t, listed, http.StatusOK, "")
	if !strings.Contains(string(listed.Body), d.DeviceID) {
		t.Fatalf("device list filters: %s", listed.Body)
	}

	first := latestBundle(t, d, time.Minute, func(*bundle.Bundle) bool { return true })
	if first.Mode != bundle.ModeReportOnly {
		t.Fatalf("first bundle mode %q, want report_only", first.Mode)
	}
	suffix := uniqueSuffix()
	pendingID, planErrorID := "file:/etc/paddock-gates/adopt-"+suffix+".conf", "unit:adopt-"+suffix+".service"
	sendBundleEvent(t, d, 1, protocol.EventBundleApplied, map[string]any{
		"version": first.BundleVersion, "changed": 0, "mode": "report_only", "errors": []any{},
		"resources": []map[string]any{
			{"id": pendingID, "status": "pending", "changes": []string{"create " + pendingID}},
			{"id": planErrorID, "status": "failed", "message": "plan failed"},
		},
	})
	items := waitDeviceResources(t, alice, d.DeviceID, "status=pending", func(i []resourceStatusItem) bool { return len(i) == 1 })
	if items[0].ResourceID != pendingID || len(items[0].Changes) != 1 {
		t.Fatalf("pending resources %+v", items)
	}
	// A failed resource of a report-only report is a plan error (plan M11 amendments R6.6, R6.15): marked with its
	// report's mode on the device and counted as no failure in the fleet view, before and after enforcement, until an
	// enforced report replaces it.
	planError := func(when, wantMode string, wantFailed int) {
		t.Helper()
		rows := waitDeviceResources(t, alice, d.DeviceID, "status=failed", func(i []resourceStatusItem) bool { return len(i) == 1 && i[0].ReportMode == wantMode })
		if rows[0].ResourceID != planErrorID {
			t.Fatalf("%s: failed rows %+v", when, rows)
		}
		res := call(t, alice, http.MethodGet, "/api/v1/config-status?"+url.Values{"q": {planErrorID}}.Encode(), nil)
		expectStatus(t, res, http.StatusOK, "")
		var fleet struct {
			Items []struct {
				Failed int `json:"failed"`
			} `json:"items"`
		}
		if err := res.JSON(&fleet); err != nil || len(fleet.Items) != 1 || fleet.Items[0].Failed != wantFailed {
			t.Fatalf("%s: fleet %s", when, res.Body)
		}
	}
	planError("report-only", "report_only", 0)
	attention := func() string {
		res := call(t, alice, http.MethodGet, "/api/v1/attention?"+url.Values{"q": {hostname}, "kind": {"report_only"}}.Encode(), nil)
		expectStatus(t, res, http.StatusOK, "")
		return string(res.Body)
	}
	eventually(t, "the report_only attention item", time.Minute, func() bool { return strings.Contains(attention(), `"detail":"adopted"`) })

	enforce := "/api/v1/devices/" + d.DeviceID + "/enforce"
	wrong := call(t, alice, http.MethodPost, enforce, map[string]any{"hostname": hostname + "x"})
	expectStatus(t, wrong, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, alice, wrong.RequestID, "device.enforcement_enabled", "failure")
	ok := call(t, alice, http.MethodPost, enforce, map[string]any{"hostname": hostname})
	expectStatus(t, ok, http.StatusOK, "")
	var enforced struct {
		ConfigMode          string  `json:"config_mode"`
		ConfigModeChangedAt *string `json:"config_mode_changed_at"`
	}
	if err := ok.JSON(&enforced); err != nil || enforced.ConfigMode != "enforce" || enforced.ConfigModeChangedAt == nil {
		t.Fatalf("enforced device %+v, %v", enforced, err)
	}
	ev := expectOneEvent(t, alice, ok.RequestID, "device.enforcement_enabled", "success")
	if ev.Params["hostname"] != hostname || ev.Params["enrollment_method"] != "adopted" || ev.Params["report_only_since"] == nil {
		t.Fatalf("event params %v", ev.Params)
	}
	expectStatus(t, call(t, alice, http.MethodPost, enforce, map[string]any{"hostname": hostname}), http.StatusConflict, "invalid_state")
	planError("enforced, before an enforced report", "report_only", 0)
	next := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.BundleVersion > first.BundleVersion })
	if next.Mode != bundle.ModeEnforce {
		t.Fatalf("bundle after enforcement has mode %q", next.Mode)
	}
	sendBundleEvent(t, d, 2, protocol.EventBundleApplied, map[string]any{
		"version": next.BundleVersion, "changed": 1, "mode": "enforce", "errors": []map[string]string{{"id": planErrorID, "message": "unit not found"}},
		"resources": []map[string]any{{"id": pendingID, "status": "applied"}, {"id": planErrorID, "status": "failed", "message": "unit not found"}},
	})
	planError("enforced report", "enforce", 1)
	if body := attention(); strings.Contains(body, d.DeviceID) {
		t.Fatalf("attention after enforcement: %s", body)
	}

	plain, s := enroll(t, tok.EnrollmentConfig, "plain-"+uniqueSuffix())
	if s.Status != protocol.EnrollActive {
		t.Fatalf("enrollment without a method %+v", s)
	}
	if detail := getDeviceDetail(t, alice, plain.DeviceID); detail["enrollment_method"] != "unknown" || detail["config_mode"] != "enforce" {
		t.Fatalf("device without a method %v %v", detail["enrollment_method"], detail["config_mode"])
	}
}
