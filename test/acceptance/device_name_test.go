package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type deviceName struct {
	Hostname  string  `json:"hostname"`
	Name      *string `json:"name"`
	NameState string  `json:"name_state"`
}

func getDeviceName(t *testing.T, p *env.Portal, id string) deviceName {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var d deviceName
	if err := res.JSON(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestDeviceName (plan M8h §9, AC-1, AC-4 to AC-7, AC-9): an operator names a device; the next v2 bundle carries the
// section; a check-in reporting the name makes it applied; the list finds the device by its name; a taken, an
// invalid and an auditor's name are refused; clearing it drops the section; a managed /etc/hostname is refused.
func TestDeviceName(t *testing.T) {
	admin := login(t, env.Alice)
	operator := operatorUser(t)
	auditor := login(t, env.Bob)
	d := v2Device(t, admin, "", 1, 2)
	other := activeDevice(t, admin, "", "m8h-other-"+uniqueSuffix())
	name := "lap-" + uniqueSuffix()
	path := "/api/v1/devices/" + d.DeviceID + "/name"

	res := call(t, operator.Portal, http.MethodPut, path, map[string]any{"name": name})
	expectStatus(t, res, http.StatusOK, "")
	var set deviceName
	if err := res.JSON(&set); err != nil {
		t.Fatal(err)
	}
	if set.Name == nil || *set.Name != name || set.NameState != "pending" {
		t.Fatalf("after set: %+v", set)
	}
	ev := expectOneEvent(t, admin, res.RequestID, "device.name_changed", "success")
	if ev.Params["name"] != name || ev.Params["previous_name"] != "" || ev.Params["hostname"] != set.Hostname {
		t.Fatalf("event params %+v", ev.Params)
	}
	b := latestBundle(t, d, 90*time.Second, func(b *bundle.Bundle) bool { return b.Hostname != nil })
	if b.Hostname.Name != name {
		t.Fatalf("bundle hostname %+v", b.Hostname)
	}

	q := url.Values{"q": {name[:len(name)-2]}}
	list := call(t, admin, http.MethodGet, "/api/v1/devices?"+q.Encode(), nil)
	expectStatus(t, list, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := list.JSON(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != d.DeviceID {
		t.Fatalf("q by name: %+v", page.Items)
	}

	d.Health = json.RawMessage(`{"reconcile":"ok","hostname":"` + name + `"}`)
	if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for got := getDeviceName(t, admin, d.DeviceID); got.Hostname != name || got.NameState != "applied"; got = getDeviceName(t, admin, d.DeviceID) {
		if time.Now().After(deadline) {
			t.Fatalf("after the check-in: %+v", got)
		}
		time.Sleep(time.Second)
	}

	taken := call(t, operator.Portal, http.MethodPut, "/api/v1/devices/"+other.DeviceID+"/name", map[string]any{"name": name})
	expectStatus(t, taken, http.StatusConflict, "conflict")
	expectOneEvent(t, admin, taken.RequestID, "device.name_changed", "failure")
	for _, bad := range []string{"A1", "a.b", "localhost"} {
		expectStatus(t, call(t, operator.Portal, http.MethodPut, path, map[string]any{"name": bad}), http.StatusBadRequest, "invalid_request")
	}
	expectRefusal(t, admin, call(t, auditor, http.MethodPut, path, map[string]any{"name": "x"}), http.StatusForbidden, "forbidden", "device.name_changed")

	cleared := call(t, operator.Portal, http.MethodPut, path, map[string]any{"name": nil})
	expectStatus(t, cleared, http.StatusOK, "")
	if got := getDeviceName(t, admin, d.DeviceID); got.Name != nil || got.NameState != "unmanaged" {
		t.Fatalf("after clear: %+v", got)
	}
	latestBundle(t, d, 90*time.Second, func(b *bundle.Bundle) bool { return b.Hostname == nil })

	file := call(t, admin, http.MethodPost, "/api/v1/managed-files", map[string]any{"path": "/etc/hostname", "content": "x\n"})
	expectStatus(t, file, http.StatusBadRequest, "invalid_request")
}
