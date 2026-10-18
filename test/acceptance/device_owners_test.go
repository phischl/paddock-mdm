package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// localUserIn creates a local user as p in the domain of p's organization and deletes it when the test ends.
func localUserIn(t *testing.T, p *env.Portal, prefix, domain string) (id, username string) {
	t.Helper()
	username = prefix + "-" + uniqueSuffix() + "@" + domain
	res := call(t, p, http.MethodPost, "/api/v1/users", map[string]string{"username": username, "display_name": prefix})
	expectStatus(t, res, http.StatusCreated, "")
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil || out.User.ID == "" {
		t.Fatalf("created user %s: %v", res.Body, err)
	}
	t.Cleanup(func() { _, _ = p.Do(testContext(t, time.Minute), http.MethodDelete, "/api/v1/users/"+out.User.ID, nil) })
	return out.User.ID, username
}

type ownedDevice struct {
	Owners []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"owners"`
}

func devicePage(t *testing.T, p *env.Portal, path string) []struct {
	ID string `json:"id"`
} {
	t.Helper()
	res := call(t, p, http.MethodGet, path, nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Total *int `json:"total"`
	}
	if err := json.Unmarshal(res.Body, &page); err != nil || page.Total == nil {
		t.Fatalf("page %s: %v", res.Body, err)
	}
	return page.Items
}

// TestDeviceOwners is gate A1 of plan M8d (AC1): an operator sets the owners of a device (one device.owners_changed
// event per change with added and removed), the device list filters and searches by owner, the user's page lists the
// device, deleting the user drops the ownership, and invalid, foreign and unauthorized requests are refused.
func TestDeviceOwners(t *testing.T) {
	alice := login(t, env.Alice)
	operator := operatorUser(t)
	bob := login(t, env.Bob)
	carol := login(t, env.Carol)
	dev := activeDevice(t, alice, "", "owned-"+uniqueSuffix())
	a, aName := localUserIn(t, alice, "owner-a", "acme.test")
	b, bName := localUserIn(t, alice, "owner-b", "acme.test")
	ownersPath := "/api/v1/devices/" + dev.DeviceID + "/owners"

	res := call(t, operator.Portal, http.MethodPut, ownersPath, map[string]any{"user_ids": []string{b, a}})
	expectStatus(t, res, http.StatusOK, "")
	var got ownedDevice
	if err := json.Unmarshal(res.Body, &got); err != nil || len(got.Owners) != 2 {
		t.Fatalf("owners %s: %v", res.Body, err)
	}
	ev := expectOneEvent(t, alice, res.RequestID, "device.owners_changed", "success")
	if asJSON(t, ev.Params["added"]) != asJSON(t, sortedPair(aName, bName)) || asJSON(t, ev.Params["removed"]) != "[]" {
		t.Fatalf("event params %+v", ev.Params)
	}

	res = call(t, operator.Portal, http.MethodPut, ownersPath, map[string]any{"user_ids": []string{a}})
	expectStatus(t, res, http.StatusOK, "")
	ev = expectOneEvent(t, alice, res.RequestID, "device.owners_changed", "success")
	if asJSON(t, ev.Params["removed"]) != asJSON(t, []string{bName}) || asJSON(t, ev.Params["owners"]) != asJSON(t, []string{aName}) {
		t.Fatalf("second event params %+v", ev.Params)
	}

	many := make([]string, 21)
	for i := range many {
		many[i] = uuid.NewString()
	}
	expectStatus(t, call(t, operator.Portal, http.MethodPut, ownersPath, map[string]any{"user_ids": many}), http.StatusBadRequest, "invalid_request")
	foreign, _ := localUserIn(t, carol, "owner-g", "globex.test")
	res = call(t, operator.Portal, http.MethodPut, ownersPath, map[string]any{"user_ids": []string{a, foreign}})
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	if detail := problemDetail(t, res); detail != "unknown user "+foreign {
		t.Fatalf("detail %q", detail)
	}
	res = call(t, bob, http.MethodPut, ownersPath, map[string]any{"user_ids": []string{b}})
	expectStatus(t, res, http.StatusForbidden, "forbidden")
	expectOneEvent(t, alice, res.RequestID, "device.owners_changed", "denied")

	for _, path := range []string{
		"/api/v1/devices?owner_id=" + a,
		"/api/v1/devices?q=" + url.QueryEscape(strings.SplitN(aName, "@", 2)[0]),
		"/api/v1/users/" + a + "/devices",
	} {
		items := devicePage(t, bob, path)
		if len(items) != 1 || items[0].ID != dev.DeviceID {
			t.Fatalf("%s lists %+v, want only %s", path, items, dev.DeviceID)
		}
	}
	if items := devicePage(t, bob, "/api/v1/users/"+b+"/devices"); len(items) != 0 {
		t.Fatalf("the former owner still owns %+v", items)
	}

	res = call(t, alice, http.MethodPut, ownersPath, map[string]any{"user_ids": []string{a, b}})
	expectStatus(t, res, http.StatusOK, "")
	expectOneEvent(t, alice, res.RequestID, "device.owners_changed", "success")
	before := eventCount(t, alice, "device.owners_changed", dev.DeviceID)
	expectStatus(t, call(t, alice, http.MethodDelete, "/api/v1/users/"+b, nil), http.StatusNoContent, "")
	time.Sleep(auditSettleDelay)
	if n := eventCount(t, alice, "device.owners_changed", dev.DeviceID); n != before {
		t.Fatalf("deleting a user recorded device.owners_changed (%d events, before %d)", n, before)
	}
	res = call(t, bob, http.MethodGet, "/api/v1/devices/"+dev.DeviceID, nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := json.Unmarshal(res.Body, &got); err != nil || len(got.Owners) != 1 || got.Owners[0].ID != a {
		t.Fatalf("owners after deleting %s: %s", bName, res.Body)
	}

	// globex sees neither the device nor the user.
	expectStatus(t, call(t, carol, http.MethodPut, ownersPath, map[string]any{"user_ids": []string{}}), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/users/"+a+"/devices", nil), http.StatusNotFound, "not_found")
}

func sortedPair(x, y string) []string {
	if y < x {
		return []string{y, x}
	}
	return []string{x, y}
}
