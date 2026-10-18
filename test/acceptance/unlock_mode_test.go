package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oasdiff/yaml"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// diskSetupOf returns the disk-setup.json the autoinstall of cfg writes.
func diskSetupOf(t *testing.T, p *env.Portal, cfg any) map[string]any {
	t.Helper()
	res := call(t, p, http.MethodPost, "/api/v1/autoinstall", map[string]any{"enrollment_config": cfg, "release": "24.04",
		"hostname": "gate-laptop", "locale": "en_US.UTF-8", "keyboard_layout": "us", "timezone": "Europe/Berlin"})
	expectStatus(t, res, http.StatusOK, "")
	var doc generated
	js, err := yaml.YAMLToJSON(res.Body)
	if err == nil {
		err = json.Unmarshal(js, &doc)
	}
	if err != nil {
		t.Fatalf("user-data is not YAML: %v", err)
	}
	for _, c := range doc.Autoinstall.LateCommands {
		args, _ := c.([]any)
		for _, a := range args {
			if s, _ := a.(string); strings.HasPrefix(s, `{"boot_pin_min_length"`) {
				var out map[string]any
				if err := json.Unmarshal([]byte(s), &out); err != nil {
					t.Fatalf("disk-setup.json %q: %v", s, err)
				}
				return out
			}
		}
	}
	t.Fatal("no disk-setup.json in the user-data")
	return nil
}

// TestUnlockMode is gate A9 of plan M8d (AC10, AC11 server part): the organization's mode (default tpm_pin) and the
// override of the token's device group reach the autoinstall's disk-setup.json and the bundles; a device reporting
// unlock_mode_mismatch is listed as disk_not_compliant with that detail and found by the disk state filter.
func TestUnlockMode(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	installRelease(t, root)
	slug, _ := gateOrganization(t)
	user, password := tempUser(t, "unlockmode", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	settings := currentLoginSettings(t, admin)
	if settings["disk_unlock_mode"] != "tpm_pin" {
		t.Fatalf("default mode %v", settings["disk_unlock_mode"])
	}
	plain := createToken(t, admin, tokenOptions{autoApprove: true})
	if s := diskSetupOf(t, admin, plain.EnrollmentConfig); s["unlock_mode"] != "tpm_pin" || s["boot_pin_min_length"] == nil {
		t.Fatalf("default disk-setup.json %v", s)
	}
	d := v2Device(t, admin, "", bundle.SchemaVersion, bundle.SchemaVersion2)
	if b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Disk != nil }); b.Disk.UnlockMode != "tpm_pin" {
		t.Fatalf("bundle disk %+v", b.Disk)
	}

	bad := currentLoginSettings(t, admin)
	bad["disk_unlock_mode"] = "tpm"
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/settings/login", bad), http.StatusBadRequest, "")
	settings["disk_unlock_mode"] = "tpm_only"
	res := call(t, admin, http.MethodPut, "/api/v1/settings/login", settings)
	expectStatus(t, res, http.StatusOK, "")
	if ev := expectOneEvent(t, admin, res.RequestID, "settings.login_changed", "success"); ev.Params["disk_unlock_mode"] != "tpm_only" {
		t.Fatalf("params %v", ev.Params)
	}
	res = call(t, admin, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(plain.EnrollmentConfig, "26.04"))
	expectStatus(t, res, http.StatusOK, "")
	if ev := expectOneEvent(t, admin, res.RequestID, "autoinstall.generated", "success"); ev.Params["unlock_mode"] != "tpm_only" {
		t.Fatalf("autoinstall params %v", ev.Params)
	}
	if s := diskSetupOf(t, admin, plain.EnrollmentConfig); s["unlock_mode"] != "tpm_only" {
		t.Fatalf("disk-setup.json %v", s)
	}
	if b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Disk != nil && b.Disk.UnlockMode == "tpm_only" }); b.Disk.UnlockMode != "tpm_only" {
		t.Fatalf("bundle disk %+v", b.Disk)
	}

	// A token whose group overrides the mode, and a member of that group.
	group := namedGroup(t, admin, "a9 pin")
	expectStatus(t, call(t, admin, http.MethodPatch, "/api/v1/device-groups/"+group, map[string]any{"disk_unlock_mode": "tpm_pin"}),
		http.StatusOK, "")
	tokRes := call(t, admin, http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{"name": uniqueName("a9 token"),
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "max_uses": 2, "auto_approve": true, "device_group_id": group})
	expectStatus(t, tokRes, http.StatusCreated, "")
	grouped := createdTokenOf(t, admin, tokRes)
	if s := diskSetupOf(t, admin, grouped.EnrollmentConfig); s["unlock_mode"] != "tpm_pin" {
		t.Fatalf("group disk-setup.json %v", s)
	}
	member := v2Device(t, admin, group, bundle.SchemaVersion, bundle.SchemaVersion2)
	if b := latestBundle(t, member, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Disk != nil && b.Disk.UnlockMode == "tpm_pin" }); b.Disk.UnlockMode != "tpm_pin" {
		t.Fatalf("member bundle disk %+v", b.Disk)
	}

	// A device that reports the mismatch.
	d.Health = json.RawMessage(`{"reconcile":"ok","disk":{"state":"unlock_mode_mismatch","tokens":["recovery","tpm2+pin"],"keyslots":2,"unlock_mode":"tpm_only"}}`)
	if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
		t.Fatal(err)
	}
	hostname := getDevice(t, admin, d.DeviceID).Hostname
	eventually(t, "the mismatch on the attention list", 2*time.Minute, func() bool {
		res := call(t, admin, http.MethodGet, "/api/v1/attention?"+url.Values{"q": {hostname}, "kind": {"disk_not_compliant"}}.Encode(), nil)
		return res.Status == http.StatusOK && strings.Contains(string(res.Body), `"detail":"unlock_mode_mismatch"`)
	})
	if n := listCount(t, admin, "/api/v1/devices", url.Values{"disk_state": {"unlock_mode_mismatch"}, "q": {hostname}}); n != 1 {
		t.Fatalf("disk_state filter found %d devices", n)
	}
	var disk struct {
		State      string `json:"state"`
		UnlockMode string `json:"unlock_mode"`
	}
	if err := call(t, admin, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/disk", nil).JSON(&disk); err != nil ||
		disk.State != "unlock_mode_mismatch" || disk.UnlockMode != "tpm_only" {
		t.Fatalf("disk %+v (%v)", disk, err)
	}
}
