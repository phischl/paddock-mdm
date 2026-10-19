package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// setLoginHistory switches acme's login history on or off and keeps every other login setting.
func setLoginHistory(t *testing.T, w *identityWorld, enabled bool, days int) {
	t.Helper()
	var set map[string]any
	if err := json.Unmarshal(w.s.Call(http.MethodGet, "/api/v1/settings/login", nil, http.StatusOK).Body, &set); err != nil {
		t.Fatal(err)
	}
	delete(set, "updated_at")
	set["login_history_enabled"], set["login_history_days"] = enabled, days
	w.s.Call(http.MethodPut, "/api/v1/settings/login", set, http.StatusOK)
}

// loginRows counts the login history rows of the device for a user.
func loginRows(t *testing.T, w *identityWorld, user string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := paddockSQL(ctx, fmt.Sprintf("SELECT count(*) FROM device_login_event WHERE device_id = '%s' AND username = '%s'", w.ID, user))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// gateLH1 is gate S-LH1 of plan M8d (AC4, device part), run after L1 with dave's GDM session open: with the login
// history off the session only refreshed device_user_seen; switched on, the agent reports every session start, so
// dave's open session and a second GDM login are two rows.
func gateLH1(t *testing.T, w *identityWorld) {
	if n := loginRows(t, w, w.dave.name); n != "0" {
		t.Fatalf("login history rows while it is off: %s", n)
	}
	// Development counts the retention days in seconds: 365 keeps the rows for the gate's six minutes.
	setLoginHistory(t, w, true, 365)
	t.Cleanup(func() { setLoginHistory(t, w, false, 90) })
	Until(t, "the open session in the login history", 4*time.Minute, 5*time.Second, w.Checkin, func() bool {
		return loginRows(t, w, w.dave.name) == "1"
	})
	w.Must("sudo loginctl terminate-user " + w.dave.name)
	Until(t, "no session of "+w.dave.name, time.Minute, 2*time.Second, nil, func() bool {
		return len(w.UserSessions(w.dave.name)) == 0
	})
	time.Sleep(10 * time.Second) // GDM shows the greeter again
	w.gdmLogin(t, w.dave, 1, false)
	Until(t, "the second session in the login history", 3*time.Minute, 5*time.Second, w.Checkin, func() bool {
		return loginRows(t, w, w.dave.name) == "2"
	})
	res := w.s.Call(http.MethodGet, "/api/v1/devices/"+w.ID+"/logins", nil, http.StatusOK)
	var page struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(res.Body, &page); err != nil || page.Total < 2 {
		t.Fatalf("GET logins: %s (%v)", res.Body, err)
	}
}
