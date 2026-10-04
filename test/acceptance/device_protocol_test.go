package acceptance

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// TestDeviceProtocol is gate D1 (plan M2a §8, AC1, AC2): a device enrolls with an auto-approve token and becomes
// active, receives and verifies its bundle (resources equal the effective configuration), gets no bundle while
// current, receives a managed-file change at the next check-in within 10 s, keeps its version on a no-op edit; a
// manual-approve token leaves the device pending until an administrator approves it.
func TestDeviceProtocol(t *testing.T) {
	alice := login(t, env.Alice)
	groupID := namedGroup(t, alice, "d1 laptops")
	dev := activeDevice(t, alice, groupID, "d1-"+uniqueSuffix())
	if d := getDevice(t, alice, dev.DeviceID); d.State != "active" {
		t.Fatalf("device %+v, want active", d)
	}

	// The first bundle arrives once the compiler processed the enrollment.
	first := checkinUntil(t, dev, 30*time.Second, func(r protocol.CheckinResponse) bool { return r.Bundle != nil })
	b, err := dev.Fetch(testContext(t, time.Minute), first.Bundle)
	if err != nil {
		t.Fatalf("bundle does not verify with the keys of the enrollment configuration: %v", err)
	}
	expectEffectiveResources(t, alice, dev.DeviceID, b)

	if again, _, err := dev.Checkin(testContext(t, time.Minute)); err != nil || again.Bundle != nil {
		t.Fatalf("current device got a bundle: %+v %v", again.Bundle, err)
	}

	// A managed file for the device's group is visible at the next check-in within 10 s.
	path := "/etc/paddock-gate-" + uniqueSuffix() + ".conf"
	res := call(t, alice, http.MethodPost, "/api/v1/managed-files", map[string]any{
		"device_group_id": groupID, "path": path, "content": "gate=d1\n",
	})
	expectStatus(t, res, http.StatusCreated, "")
	fileID := responseID(t, res).String()
	changed := time.Now()
	next := checkinUntil(t, dev, 10*time.Second, func(r protocol.CheckinResponse) bool { return r.Bundle != nil })
	t.Logf("managed-file change visible after %s", time.Since(changed).Round(time.Millisecond))
	b, err = dev.Fetch(testContext(t, time.Minute), next.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(asJSON(t, b.Resources), path) {
		t.Fatalf("bundle v%d lacks %s", b.BundleVersion, path)
	}
	expectEffectiveResources(t, alice, dev.DeviceID, b)

	// A no-op edit keeps the version.
	version := b.BundleVersion
	expectStatus(t, call(t, alice, http.MethodPatch, "/api/v1/managed-files/"+fileID, map[string]any{"content": "gate=d1\n"}), http.StatusOK, "")
	time.Sleep(6 * time.Second) // longer than relay + debounce
	if out, _, err := dev.Checkin(testContext(t, time.Minute)); err != nil || out.Bundle != nil {
		t.Fatalf("no-op edit produced a bundle: %+v %v", out.Bundle, err)
	}
	if d := getDevice(t, alice, dev.DeviceID); d.BundleVersion != version {
		t.Fatalf("bundle version %d after a no-op edit, want %d", d.BundleVersion, version)
	}

	// Manual approval.
	manual := createToken(t, alice, tokenOptions{autoApprove: false})
	pending, s := enroll(t, manual.EnrollmentConfig, "d1-manual-"+uniqueSuffix())
	if s.Status != protocol.EnrollPending || s.DeviceID == "" {
		t.Fatalf("manual enrollment %+v, want pending", s)
	}
	if d := getDevice(t, alice, s.DeviceID); d.State != "pending" {
		t.Fatalf("device %+v, want pending", d)
	}
	if _, res, _ := pending.Checkin(testContext(t, time.Minute)); res.Status != http.StatusUnauthorized {
		t.Fatalf("pending device checked in: HTTP %d", res.Status)
	}
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/devices/"+s.DeviceID+"/approve", nil), http.StatusOK, "")
	if s, err := pending.WaitEnrollment(testContext(t, 30*time.Second), func(s protocol.EnrollStatus) bool { return s.Status == protocol.EnrollActive }); err != nil {
		t.Fatalf("approved enrollment %+v: %v", s, err)
	}
	checkinUntil(t, pending, 30*time.Second, func(r protocol.CheckinResponse) bool { return r.Bundle != nil })
}

// expectEffectiveResources compares the bundle's resources with GET /api/v1/devices/{id}/effective-config.
func expectEffectiveResources(t *testing.T, p *env.Portal, deviceID string, b *bundle.Bundle) {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+deviceID+"/effective-config", nil)
	expectStatus(t, res, http.StatusOK, "")
	var cfg struct {
		Resources json.RawMessage `json:"resources"`
	}
	if err := res.JSON(&cfg); err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(cfg.Resources, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(asJSON(t, b.Resources)), &got); err != nil {
		t.Fatal(err)
	}
	if asJSON(t, want) != asJSON(t, got) {
		t.Fatalf("bundle resources differ from the effective configuration:\nbundle: %s\napi:    %s", asJSON(t, got), asJSON(t, want))
	}
}
