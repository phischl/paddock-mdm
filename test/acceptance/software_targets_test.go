package acceptance

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestSoftwareTargets is the server side of plan M13b §3.2 (PDK-798) against the running stack: an available
// assignment targets a user or a user group, GET /users/{id}/software lists both with their intents and is 404 for
// another organization (SS5, SS6), two targets and available with a version are 400, and a Flatpak source takes one
// URI and never changes its kind (SS4 needs the step-up).
func TestSoftwareTargets(t *testing.T) {
	alice, carol := login(t, env.Alice), login(t, env.Carol)
	user, _ := localUserIn(t, alice, "sw-target", "acme.test")
	res := call(t, alice, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "sw-" + uniqueSuffix(), "name": uniqueName("software targets")})
	expectStatus(t, res, http.StatusCreated, "")
	group := createdID(t, alice, "/api/v1/user-groups", res)
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/user-groups/"+group+"/members", map[string]string{"user_id": user}),
		http.StatusNoContent, "")

	entry := func(prefix string) string {
		res := call(t, alice, http.MethodPost, softwareCatalog, entryBody(prefix))
		expectStatus(t, res, http.StatusCreated, "")
		return createdID(t, alice, softwareCatalog, res)
	}
	direct, viaGroup := entry("sw-direct"), entry("sw-group")
	expectStatus(t, call(t, alice, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": direct, "user_id": user, "intent": "available",
	}), http.StatusCreated, "")
	expectStatus(t, call(t, alice, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": viaGroup, "user_group_id": group, "intent": "required",
	}), http.StatusCreated, "")
	expectStatus(t, call(t, alice, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": direct, "user_id": user, "user_group_id": group, "intent": "available",
	}), http.StatusBadRequest, "invalid_request")
	expectStatus(t, call(t, alice, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": viaGroup, "user_id": user, "intent": "available", "version": "1.0",
	}), http.StatusBadRequest, "invalid_request")

	res = call(t, alice, http.MethodGet, "/api/v1/users/"+user+"/software?sort=name", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			CatalogEntryID string  `json:"catalog_entry_id"`
			Intent         string  `json:"intent"`
			UserGroupID    *string `json:"user_group_id"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(res.Body, &page); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range page.Items {
		via := "direct"
		if it.UserGroupID != nil {
			via = *it.UserGroupID
		}
		got[it.CatalogEntryID] = it.Intent + " " + via
	}
	if page.Total != 2 || got[direct] != "available direct" || got[viaGroup] != "required "+group {
		t.Fatalf("software of the user %s", res.Body)
	}
	expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/users/"+user+"/software", nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, alice, http.MethodGet, softwareAssignments+"?target=user&user_id="+user, nil), http.StatusOK, "")

	flatpak := sourceBody("sw-flatpak")
	flatpak["kind"], flatpak["uris"], flatpak["suites"], flatpak["components"] = "flatpak", []string{"https://dl.flathub.example/repo/"}, []string{}, []string{}
	expectStatus(t, call(t, alice, http.MethodPost, softwareSources, flatpak), http.StatusForbidden, "step_up_required")
	stepUp(t, alice, env.Alice, true)
	twoURIs := sourceBody("sw-two")
	twoURIs["kind"], twoURIs["uris"], twoURIs["suites"], twoURIs["components"] = "flatpak", []string{"https://a.example/", "https://b.example/"}, []string{}, []string{}
	expectStatus(t, call(t, alice, http.MethodPost, softwareSources, twoURIs), http.StatusBadRequest, "invalid_request")
	res = call(t, alice, http.MethodPost, softwareSources, flatpak)
	expectStatus(t, res, http.StatusCreated, "")
	path := softwareSources + "/" + responseID(t, res).String()
	deleteSourceOnCleanup(t, alice, func(t *testing.T) { stepUp(t, alice, env.Alice, true) }, path)
	expectStatus(t, call(t, alice, http.MethodPatch, path, map[string]any{"kind": "apt"}), http.StatusBadRequest, "invalid_request")
	expectStatus(t, call(t, alice, http.MethodPost, softwareCatalog, map[string]any{
		"name": "sw-apt-on-flatpak-" + uniqueSuffix(), "source_id": responseID(t, res).String(),
		"packages": []map[string]any{{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": "nano"}},
	}), http.StatusBadRequest, "invalid_request")
}
