package acceptance

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// securityReview is the part of GET /api/v1/security-review the gate reads.
type securityReview struct {
	RootGrants struct {
		Total int `json:"total"`
		Items []struct {
			Profile struct {
				ID string `json:"id"`
			} `json:"profile"`
		} `json:"items"`
	} `json:"root_grants"`
	DeniedFiles struct {
		Total int `json:"total"`
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	} `json:"denied_files"`
}

func getSecurityReview(t *testing.T, p *env.Portal) (securityReview, env.Response) {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/security-review", nil)
	expectStatus(t, res, http.StatusOK, "")
	var r securityReview
	if err := res.JSON(&r); err != nil {
		t.Fatal(err)
	}
	return r, res
}

func (r securityReview) profileIDs() []string {
	var out []string
	for _, i := range r.RootGrants.Items {
		out = append(out, i.Profile.ID)
	}
	return out
}

func (r securityReview) deniedIDs() []string {
	var out []string
	for _, i := range r.DeniedFiles.Items {
		out = append(out, i.ID)
	}
	return out
}

// TestSecurityReview is gate S8 of plan M8s (ADR 0034 decision 7): a root grant without confirmation and a file on a
// denied path (both made to look like data from before the rules with SQL on the development stack) are listed by
// the review and counted by the overview, the denied file is not part of a device's configuration, the confirmation
// needs a step-up and removes the profile from the review, and another organization never sees acme's items.
func TestSecurityReview(t *testing.T) {
	admin := adminUser(t, "s8")
	auditor := login(t, env.Bob)
	acme := orgOf(t, admin.Portal)

	res := call(t, admin.Portal, http.MethodPost, "/api/v1/permission-profiles", rootProfile())
	expectStatus(t, res, http.StatusCreated, "")
	profile := createdID(t, admin.Portal, "/api/v1/permission-profiles", res)
	paddockSQL(t, "UPDATE permission_profile SET root_grant_confirmed_at = NULL, root_grant_confirmed_by = NULL WHERE id = '"+profile+"'")

	group := namedGroup(t, admin.Portal, "s8 devices")
	device := activeDevice(t, admin.Portal, group, "s8-"+uniqueSuffix())
	file := uuid.NewString()
	paddockSQL(t, "INSERT INTO managed_file (id, organization_id, device_group_id, path, mode, content) VALUES ('"+file+"', '"+
		acme.String()+"', '"+group+"', '/etc/ld.so.preload', '0644', 's8')")
	deleteOnCleanup(t, admin.Portal, "/api/v1/managed-files/"+file)

	for _, viewer := range []*env.Portal{admin.Portal, auditor} {
		r, _ := getSecurityReview(t, viewer)
		if !slices.Contains(r.profileIDs(), profile) || !slices.Contains(r.deniedIDs(), file) {
			t.Fatalf("review lacks the profile %s or the file %s: %+v", profile, file, r)
		}
	}
	var overview struct {
		SecurityReview struct {
			RootGrants  int `json:"root_grants"`
			DeniedFiles int `json:"denied_files"`
		} `json:"security_review"`
	}
	res = call(t, admin.Portal, http.MethodGet, "/api/v1/overview", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&overview); err != nil || overview.SecurityReview.RootGrants < 1 || overview.SecurityReview.DeniedFiles < 1 {
		t.Fatalf("overview counts %s (%v)", res.Body, err)
	}

	res = call(t, admin.Portal, http.MethodGet, "/api/v1/devices/"+device.DeviceID+"/effective-config", nil)
	expectStatus(t, res, http.StatusOK, "")
	if id := containsAny(res.Body, []string{file, "/etc/ld.so.preload"}); id != "" {
		t.Fatalf("the device's configuration lists the denied file (%s): %s", id, res.Body)
	}

	confirm := "/api/v1/permission-profiles/" + profile + "/confirm-root-grant"
	expectRefusal(t, admin.Portal, call(t, withoutStepUp(t, admin), http.MethodPost, confirm, nil), http.StatusForbidden,
		"step_up_required", "permission_profile.root_grant_confirmed")
	admin.stepUp(t)
	res = call(t, admin.Portal, http.MethodPost, confirm, nil)
	expectStatus(t, res, http.StatusOK, "")
	if ev := expectOneEvent(t, admin.Portal, res.RequestID, "permission_profile.root_grant_confirmed", "success"); !ev.Actor.StepUp ||
		ev.Params["effective_class"] != "full" {
		t.Fatalf("confirm event %+v", ev)
	}
	if r, _ := getSecurityReview(t, admin.Portal); slices.Contains(r.profileIDs(), profile) {
		t.Fatalf("the confirmed profile %s is still listed", profile)
	}

	_, globex := getSecurityReview(t, login(t, env.Carol))
	if id := containsAny(globex.Body, []string{profile, file}); id != "" {
		t.Fatalf("globex's review contains acme's %s", id)
	}
}
