package acceptance

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// rootProfile is the restricted profile of plan M8s §9 S1: one root-equivalent command makes it effectively Full.
func rootProfile() map[string]any {
	return map[string]any{"name": uniqueName("s1 shell"), "class": "restricted", "commands": []string{"/usr/bin/bash"}}
}

// TestEffectiveStepUp is gate S1–S4 of plan M8s (ADR 0034 decision 1): creating, changing the grant of, assigning and
// re-scoping a profile that is effectively Full needs a step-up, in the admin API and in a declarative document; a
// rename does not; an API token never completes a step-up.
func TestEffectiveStepUp(t *testing.T) {
	admin := adminUser(t, "s1")
	noStepUp := withoutStepUp(t, admin)
	auditor := login(t, env.Bob)

	var profileID string
	t.Run("S1 create", func(t *testing.T) {
		res := call(t, noStepUp, http.MethodPost, "/api/v1/permission-profiles", rootProfile())
		expectRefusal(t, admin.Portal, res, http.StatusForbidden, "step_up_required", "permission_profile.created")

		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPost, "/api/v1/permission-profiles", rootProfile())
		expectStatus(t, res, http.StatusCreated, "")
		profileID = createdID(t, admin.Portal, "/api/v1/permission-profiles", res)
		var p struct {
			EffectiveClass       string  `json:"effective_class"`
			RootGrantConfirmedAt *string `json:"root_grant_confirmed_at"`
		}
		if err := res.JSON(&p); err != nil || p.EffectiveClass != "full" || p.RootGrantConfirmedAt == nil {
			t.Fatalf("created profile %s (%v)", res.Body, err)
		}
		ev := expectOneEvent(t, auditor, res.RequestID, "permission_profile.created", "success")
		if !ev.Actor.StepUp || ev.Params["effective_class"] != "full" || ev.Params["root_equivalent"] != true {
			t.Fatalf("created event %+v", ev)
		}
	})
	if profileID == "" {
		t.FailNow()
	}

	t.Run("S2 update", func(t *testing.T) {
		res := call(t, noStepUp, http.MethodPatch, "/api/v1/permission-profiles/"+profileID, map[string]any{"name": uniqueName("s2 renamed")})
		expectStatus(t, res, http.StatusOK, "")
		res = call(t, noStepUp, http.MethodPatch, "/api/v1/permission-profiles/"+profileID,
			map[string]any{"commands": []string{"/usr/bin/bash", "/usr/bin/python3"}})
		expectRefusal(t, admin.Portal, res, http.StatusForbidden, "step_up_required", "permission_profile.updated")
	})

	t.Run("S3 assign", func(t *testing.T) {
		user := createLocalUser(t, admin.Portal, "s3")
		// Within an empty device group the assignment reaches no device.
		group := namedGroup(t, admin.Portal, "s3 empty")
		body := map[string]any{"profile_id": profileID, "subject_type": "user", "subject_id": user.ID, "device_group_id": group}
		res := call(t, noStepUp, http.MethodPost, "/api/v1/profile-assignments", body)
		expectRefusal(t, admin.Portal, res, http.StatusForbidden, "step_up_required", "profile_assignment.created")

		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPost, "/api/v1/profile-assignments", body)
		expectStatus(t, res, http.StatusCreated, "")
		assignment := createdID(t, admin.Portal, "/api/v1/profile-assignments", res)
		if ev := expectOneEvent(t, admin.Portal, res.RequestID, "profile_assignment.created", "success"); ev.Params["effective_class"] != "full" || !ev.Actor.StepUp {
			t.Fatalf("assignment event %+v", ev)
		}
		other := namedGroup(t, admin.Portal, "s3 other")
		res = call(t, noStepUp, http.MethodPatch, "/api/v1/profile-assignments/"+assignment, map[string]any{"device_group_id": other})
		expectRefusal(t, admin.Portal, res, http.StatusForbidden, "step_up_required", "profile_assignment.updated")
	})

	// A declarative document replaces everything of its organization, so S4 runs in an organization of its own.
	t.Run("S4 declarative", func(t *testing.T) {
		orgAdmin, _ := gateOrg(t, "s4")
		doc := getConfig(t, orgAdmin.Portal)
		doc["permission_profiles"] = append(doc["permission_profiles"].([]any),
			map[string]any{"name": "s4-shell", "class": "restricted", "commands": []string{"/usr/bin/bash"}})
		doc["profile_assignments"] = append(doc["profile_assignments"].([]any),
			map[string]any{"profile": "s4-shell", "subject": map[string]any{"type": "global"}})

		orgAdmin.stepUp(t)
		created := postAPIToken(t, orgAdmin.Portal, apiTokenName("s4"), "org_operator", 2*time.Hour)
		expectStatus(t, created, http.StatusCreated, "")
		removeCreated(t, orgAdmin.Portal, "/api/v1/api-tokens", created)
		var token apiTokenCreated
		if err := created.JSON(&token); err != nil {
			t.Fatal(err)
		}
		res := putConfig(t, tokenPortal(t, token.Secret), doc, false)
		expectRefusal(t, orgAdmin.Portal, res, http.StatusForbidden, "step_up_required", "config.applied")
		if d := problemDetail(t, res); !strings.Contains(d, "API tokens") {
			t.Fatalf("token detail %q", d)
		}

		// The change set's actor is the event's actor; the API shows the step-up on the event.
		orgAdmin.stepUp(t)
		res = putConfig(t, orgAdmin.Portal, doc, false)
		if out := configResultOf(t, res); out.ChangeSetID == nil || out.Plan.Created != 2 {
			t.Fatalf("stepped-up apply: %s", res.Body)
		}
		if ev := expectOneEvent(t, orgAdmin.Portal, res.RequestID, "config.applied", "success"); !ev.Actor.StepUp {
			t.Fatalf("config.applied event %+v", ev)
		}
	})
}
