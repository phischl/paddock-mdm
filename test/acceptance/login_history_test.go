package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type loginPage struct {
	Items []struct {
		Username string    `json:"username"`
		At       time.Time `json:"at"`
	} `json:"items"`
	Total int    `json:"total"`
	Sort  string `json:"sort"`
}

func deviceLogins(t *testing.T, p *env.Portal, deviceID, query string) loginPage {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+deviceID+"/logins"+query, nil)
	expectStatus(t, res, http.StatusOK, "")
	var page loginPage
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page
}

// TestLoginHistory is gate A4 of plan M8d (AC4, server part): off by default and nothing recorded; enabled, every
// session start of the device is listed (sorted, filtered); the development stack's seconds unit lets the purge round
// delete rows older than login_history_days with one retention.purged; switching it off deletes the rest.
func TestLoginHistory(t *testing.T) {
	slug, org := gateOrganization(t)
	user, password := tempUser(t, "loginhistory", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	cur := currentLoginSettings(t, admin)
	if cur["login_history_enabled"] != false || cur["login_history_days"] != float64(90) {
		t.Fatalf("defaults %v %v", cur["login_history_enabled"], cur["login_history_days"])
	}
	for _, days := range []int{6, 366} {
		expectStatus(t, putLoginHistory(t, admin, true, days), http.StatusBadRequest, "invalid_request")
	}
	d := activeDevice(t, admin, "", "a4-"+uniqueSuffix())
	now := time.Now().UTC().Truncate(time.Millisecond)
	sendSessionLogins(t, d, 1, "dave@"+slug+".test", now.Add(-3*time.Second), now.Add(-2*time.Second), now.Add(-time.Second))
	time.Sleep(5 * time.Second)
	if page := deviceLogins(t, admin, d.DeviceID, ""); page.Total != 0 {
		t.Fatalf("history off lists %+v", page)
	}

	res := putLoginHistory(t, admin, true, 30)
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, admin, res.RequestID, "settings.login_changed", "success")
	if ev.Params["login_history_enabled"] != true || ev.Params["login_history_days"] != float64(30) {
		t.Fatalf("enabled params %v", ev.Params)
	}
	// Milliseconds apart: the rows cross the purge cutoff together, so one round deletes all three (the purge runs
	// every 15 s and the development stack counts days in seconds).
	now = time.Now().UTC().Truncate(time.Millisecond)
	newest := now.Add(-time.Millisecond)
	sendSessionLogins(t, d, 10, "dave@"+slug+".test", now.Add(-3*time.Millisecond), now.Add(-2*time.Millisecond), newest)
	var page loginPage
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(time.Second) {
		if page = deviceLogins(t, admin, d.DeviceID, ""); page.Total == 3 || time.Now().After(deadline) {
			break
		}
	}
	if page.Total != 3 || page.Sort != "-at" || !page.Items[0].At.After(page.Items[1].At) {
		t.Fatalf("logins %+v", page)
	}
	if filtered := deviceLogins(t, admin, d.DeviceID, "?username=nobody@x.test"); filtered.Total != 0 {
		t.Fatalf("filter %+v", filtered)
	}
	if filtered := deviceLogins(t, admin, d.DeviceID, "?username=DAVE@"+slug+".test"); filtered.Total != 3 {
		t.Fatalf("filter %+v", filtered)
	}
	expectStatus(t, call(t, login(t, env.Carol), http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/logins", nil), http.StatusNotFound, "not_found")

	// Development counts the days in seconds: with 7 days every row is older than the cutoff within a round. Waiting
	// until the newest row is 8 s old makes the first round after the change delete all three at once.
	time.Sleep(time.Until(newest.Add(8 * time.Second)))
	expectStatus(t, putLoginHistory(t, admin, true, 7), http.StatusOK, "")
	for deadline := time.Now().Add(time.Minute); deviceLogins(t, admin, d.DeviceID, "").Total != 0; time.Sleep(2 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("the purge round did not delete the expired logins within a minute")
		}
	}
	idx := auditIndex(t)
	purged := expectOneIndexEvent(t, idx, org, "code = 'retention.purged' AND params->>'store' = $1", "device_login_event",
		"retention.purged", "success", time.Minute)
	if purged.Params["deleted"] != float64(3) {
		t.Fatalf("retention.purged params %v", purged.Params)
	}

	now = time.Now().UTC().Truncate(time.Millisecond)
	sendSessionLogins(t, d, 20, "erin@"+slug+".test", now)
	for deadline := time.Now().Add(5 * time.Second); deviceLogins(t, admin, d.DeviceID, "").Total == 0 && time.Now().Before(deadline); {
		time.Sleep(500 * time.Millisecond)
	}
	res = putLoginHistory(t, admin, false, 7)
	expectStatus(t, res, http.StatusOK, "")
	ev = expectOneEvent(t, admin, res.RequestID, "settings.login_changed", "success")
	if _, ok := ev.Params["login_history_deleted"]; !ok || ev.Params["login_history_enabled"] != false {
		t.Fatalf("disabled params %v", ev.Params)
	}
	if page := deviceLogins(t, admin, d.DeviceID, ""); page.Total != 0 {
		t.Fatalf("after switching off %+v", page)
	}
}
