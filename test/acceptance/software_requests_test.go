package acceptance

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const softwareRequests = "/api/v1/software-requests"

// softwareRequestRound bounds the wait for the worker's software request round (worker.SoftwareRequestInterval is
// 10 minutes, and the round also runs when the worker starts).
const softwareRequestRound = 12 * time.Minute

// softwareRequest is a software request as the admin API returns it.
type softwareRequest struct {
	ID             string  `json:"id"`
	CatalogEntryID string  `json:"catalog_entry_id"`
	EntryApproval  string  `json:"entry_approval"`
	DeviceID       string  `json:"device_id"`
	Hostname       string  `json:"hostname"`
	UserID         *string `json:"user_id"`
	Username       string  `json:"username"`
	State          string  `json:"state"`
	DecidedBy      *string `json:"decided_by"`
	DecisionReason *string `json:"decision_reason"`
}

// requestFixture is a device in a device group of its own, the catalog entries that group is offered and the next
// event number of the device. Everything is removed when the test that created it ends.
type requestFixture struct {
	p      *env.Portal
	group  string
	device *devicesim.Device
	seq    int64
}

// newRequestFixture creates the device group and its device (bundle schema 2, which carries the software section).
func newRequestFixture(t *testing.T, p *env.Portal, prefix string) *requestFixture {
	t.Helper()
	group := namedGroup(t, p, prefix)
	d := activeDevice(t, p, group, prefix+"-"+uniqueSuffix())
	d.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
	return &requestFixture{p: p, group: group, device: d}
}

// offer creates a catalog entry of pkg with approval ("none" or "required") and offers it to the fixture's group as
// available; it returns the entry's ID. The assignment is removed before the entry.
func (f *requestFixture) offer(t *testing.T, pkg, approval string) string {
	t.Helper()
	body := map[string]any{"name": "sw-req-" + uniqueSuffix(), "packages": []map[string]any{packageRef("ubuntu", "*", pkg)},
		"approval": approval}
	res := call(t, f.p, http.MethodPost, softwareCatalog, body)
	expectStatus(t, res, http.StatusCreated, "")
	entry := createdID(t, f.p, softwareCatalog, res)
	assign(t, f.p, map[string]any{"catalog_entry_id": entry, "device_group_id": f.group, "intent": "available"})
	return entry
}

// ask sends the device's software.request of user for entry with extra fields the server must drop.
func (f *requestFixture) ask(t *testing.T, entry, user string) {
	t.Helper()
	f.seq++
	sendBundleEvent(t, f.device, f.seq, protocol.EventSoftwareRequest, map[string]any{
		"user": user, "entry_id": entry, "justification": `<script>alert("gate")</script>`,
	})
}

// requestsOf lists the requests of entry in the given states (all states when none is given).
func requestsOf(t *testing.T, p *env.Portal, entry string, states ...string) []softwareRequest {
	t.Helper()
	q := url.Values{"catalog_entry_id": {entry}, "page_size": {"100"}}
	for _, s := range states {
		q.Add("state", s)
	}
	res := call(t, p, http.MethodGet, softwareRequests+"?"+q.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []softwareRequest `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Items
}

// waitRequest polls until entry has a request of user in state and returns it.
func waitRequest(t *testing.T, p *env.Portal, entry, user, state string, timeout time.Duration) softwareRequest {
	t.Helper()
	for deadline := time.Now().Add(timeout); ; time.Sleep(2 * time.Second) {
		polled := time.Now()
		for _, r := range requestsOf(t, p, entry) {
			if r.Username == user && r.State == state {
				return r
			}
		}
		if polled.After(deadline) {
			t.Fatalf("no %s request of %s for entry %s within %s: %+v", state, user, entry, timeout, requestsOf(t, p, entry))
		}
	}
}

// openRequest offers a new approval-required entry to a new device and opens a request of a new user for it; it
// returns the request.
func openRequest(t *testing.T, p *env.Portal, prefix string) softwareRequest {
	t.Helper()
	f := newRequestFixture(t, p, prefix)
	entry := f.offer(t, "paddock-gate-req-"+uniqueSuffix(), "required")
	user := prefix + "-" + uniqueSuffix() + "@acme.test"
	f.ask(t, entry, user)
	return waitRequest(t, p, entry, user, "requested", time.Minute)
}

// waitDeviceEvents polls until the device has n audit events of code (as viewer sees them).
func waitDeviceEvents(t *testing.T, viewer *env.Portal, code, deviceID string, n int) {
	t.Helper()
	for deadline := time.Now().Add(auditPollTimeout); ; time.Sleep(time.Second) {
		polled := time.Now()
		got := eventCount(t, viewer, code, deviceID)
		if got == n {
			return
		}
		if got > n || polled.After(deadline) {
			t.Fatalf("%d %s events of device %s, want %d", got, code, deviceID, n)
		}
	}
}

// requestEvent waits for the one event of code whose target is the software request id.
func requestEvent(t *testing.T, viewer *env.Portal, code, id string) env.AuditEvent {
	t.Helper()
	for deadline := time.Now().Add(auditPollTimeout); ; time.Sleep(time.Second) {
		polled := time.Now()
		events, err := viewer.AuditEvents(testContext(t, time.Minute), code)
		if err != nil {
			t.Fatal(err)
		}
		var found []env.AuditEvent
		for _, e := range events {
			if e.Target != nil && e.Target.ID == id {
				found = append(found, e)
			}
		}
		if len(found) > 1 {
			t.Fatalf("%d %s events of request %s, want 1", len(found), code, id)
		}
		if len(found) == 1 {
			return found[0]
		}
		if polled.After(deadline) {
			t.Fatalf("no %s event of request %s", code, id)
		}
	}
}

// TestSoftwareRequests is the gate of plan M13c decisions 8 to 10 (C3) on the server side, with the PDK-943 agent
// gate and architect decision A10-17. The request flow on the device and the bundle's approved users follow with
// PDK-811 (the self-service app's Request button, the agent gate's release); until then a devicesim reports the
// software.request event directly.
//   - PDK-943: no agent gets an approval-required package, not a devicesim and not an alpha.10 build, also when another
//     entry offers the same package without approval; the group's other available package arrives.
//   - A request opens one request (also when repeated), records device.software_requested without the justification
//     text the device sent (Q7: not stored) and software_request.opened, and shows in the attention list.
//   - Deny needs a reason, the user sees it, a re-request within 24 hours opens nothing; approve with or without a
//     reason; a decided request cannot be decided again (409 invalid_state); an approved user's re-request opens nothing.
//   - Expiry by the worker's request round: validity_ended after expires_at, approval_removed for open and approved
//     requests once the entry no longer requires approval; deciding such a request is 409 invalid_state at once.
func TestSoftwareRequests(t *testing.T) {
	alice, bob := login(t, env.Alice), login(t, env.Bob)
	suffix := uniqueSuffix()
	f := newRequestFixture(t, alice, "swreq")
	pkg := "paddock-gate-req-" + suffix
	free := "paddock-gate-req-free-" + suffix

	// PDK-943: the merged package of an approval-required entry and an entry without approval is withheld as well.
	entry := f.offer(t, pkg, "required")
	merged := gateEntry(t, alice, "", packageRef("ubuntu", "*", pkg))
	mergedAssignment := assign(t, alice, map[string]any{"catalog_entry_id": merged, "device_group_id": f.group, "intent": "available"})
	f.offer(t, free, "none")
	alpha10 := activeDevice(t, alice, f.group, "swreq-a10-"+suffix)
	alpha10.SchemaVersions, alpha10.AgentVersion = []int{bundle.SchemaVersion, bundle.SchemaVersion2}, "0.1.0-alpha.10"
	for _, d := range []*devicesim.Device{f.device, alpha10} {
		b := latestBundle(t, d, 2*time.Minute, hasPackage(free))
		if p, ok := softwarePackage(b, pkg); ok {
			t.Fatalf("agent %q received the approval-required package: %s", d.AgentVersion, asJSON(t, p))
		}
	}
	expectStatus(t, call(t, alice, http.MethodDelete, softwareAssignments+"/"+mergedAssignment, nil), http.StatusNoContent, "")

	u1, u2 := "swreq-u1-"+suffix+"@acme.test", "swreq-u2-"+suffix+"@acme.test"
	t.Run("request", func(t *testing.T) {
		f.ask(t, entry, u1)
		r := waitRequest(t, alice, entry, u1, "requested", time.Minute)
		if r.DeviceID != f.device.DeviceID || r.EntryApproval != "required" || r.UserID != nil || r.DecidedBy != nil || r.Hostname == "" {
			t.Fatalf("request %+v", r)
		}
		requested := requestEvent(t, alice, "software_request.opened", r.ID)
		if requested.Params["user"] != u1 || requested.Params["catalog_entry_id"] != entry || requested.Params["expires_at"] == nil {
			t.Fatalf("software_request.opened params %v", requested.Params)
		}
		f.ask(t, entry, u1)
		waitDeviceEvents(t, alice, "device.software_requested", f.device.DeviceID, 2)
		events, err := alice.AuditEvents(testContext(t, time.Minute), "device.software_requested")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Target != nil && e.Target.ID == f.device.DeviceID {
				if _, ok := e.Params["justification"]; ok || e.Params["user"] != u1 || e.Params["entry_id"] != entry {
					t.Fatalf("device.software_requested params %v: user and entry, never the justification", e.Params)
				}
			}
		}
		if open := requestsOf(t, alice, entry, "requested"); len(open) != 1 {
			t.Fatalf("a repeated request opened another one: %+v", open)
		}
		q := url.Values{"kind": {"software_requests_open"}, "q": {r.Hostname}, "page_size": {"10"}}
		if n := listCount(t, alice, "/api/v1/attention", q); n != 1 {
			t.Fatalf("software_requests_open rows for %s: %d, want 1", r.Hostname, n)
		}
		// The auditor reads the requests, never decides them.
		if got := requestsOf(t, bob, entry); len(got) != 1 {
			t.Fatalf("the auditor's list %+v", got)
		}
	})

	t.Run("deny", func(t *testing.T) {
		r := waitRequest(t, alice, entry, u1, "requested", time.Minute)
		path := softwareRequests + "/" + r.ID
		expectStatus(t, call(t, alice, http.MethodPost, path+"/deny", map[string]any{}), http.StatusBadRequest, "invalid_request")
		res := call(t, alice, http.MethodPost, path+"/deny", map[string]any{"reason": "Not licensed for this team"})
		expectStatus(t, res, http.StatusOK, "")
		var denied softwareRequest
		if err := res.JSON(&denied); err != nil || denied.State != "denied" || denied.DecisionReason == nil ||
			*denied.DecisionReason != "Not licensed for this team" || denied.DecidedBy == nil {
			t.Fatalf("denied request %s (%v)", res.Body, err)
		}
		if ev := expectOneEvent(t, alice, res.RequestID, "software_request.denied", "success"); ev.Params["user"] != u1 ||
			ev.Params["reason"] != "Not licensed for this team" {
			t.Fatalf("software_request.denied params %v", ev.Params)
		}
		res = call(t, alice, http.MethodPost, path+"/approve", nil)
		expectStatus(t, res, http.StatusConflict, "invalid_state")
		expectOneEvent(t, alice, res.RequestID, "software_request.approved", "failure")
		// Within 24 hours of the denial the device's next request opens nothing.
		f.ask(t, entry, u1)
		waitDeviceEvents(t, alice, "device.software_requested", f.device.DeviceID, 3)
		if open := requestsOf(t, alice, entry, "requested"); len(open) != 0 {
			t.Fatalf("a request within 24 hours of the denial opened one: %+v", open)
		}
	})

	t.Run("approve", func(t *testing.T) {
		f.ask(t, entry, u2)
		r := waitRequest(t, alice, entry, u2, "requested", time.Minute)
		res := call(t, alice, http.MethodPost, softwareRequests+"/"+r.ID+"/approve", map[string]any{"reason": "Approved for the project"})
		expectStatus(t, res, http.StatusOK, "")
		if ev := expectOneEvent(t, alice, res.RequestID, "software_request.approved", "success"); ev.Params["user"] != u2 ||
			ev.Params["device_id"] != f.device.DeviceID {
			t.Fatalf("software_request.approved params %v", ev.Params)
		}
		res = call(t, alice, http.MethodPost, softwareRequests+"/"+r.ID+"/approve", nil)
		expectStatus(t, res, http.StatusConflict, "invalid_state")
		// The approval holds: the user's next request opens nothing.
		f.ask(t, entry, u2)
		waitDeviceEvents(t, alice, "device.software_requested", f.device.DeviceID, 5)
		if open := requestsOf(t, alice, entry, "requested"); len(open) != 0 {
			t.Fatalf("a request beside an approval opened one: %+v", open)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		u3, u4 := "swreq-u3-"+suffix+"@acme.test", "swreq-u4-"+suffix+"@acme.test"
		other := f.offer(t, "paddock-gate-req-other-"+suffix, "required")
		f.ask(t, entry, u3)
		f.ask(t, other, u4)
		open := waitRequest(t, alice, entry, u3, "requested", time.Minute)
		due := waitRequest(t, alice, other, u4, "requested", time.Minute)

		// The validity of u4's request ends now (a request is valid for 30 days; the gate cannot wait for that).
		if _, err := ownerDB(t).Exec(testContext(t, time.Minute),
			`UPDATE software_request SET expires_at = now() - interval '1 minute' WHERE id = $1`, due.ID); err != nil {
			t.Fatal(err)
		}
		expectStatus(t, call(t, alice, http.MethodPost, softwareRequests+"/"+due.ID+"/approve", nil), http.StatusConflict, "invalid_state")

		// The entry no longer requires approval: its open and approved requests no longer hold, and the package reaches
		// every agent.
		res := call(t, alice, http.MethodGet, softwareCatalog+"/"+entry, nil)
		expectStatus(t, res, http.StatusOK, "")
		var e map[string]any
		if err := res.JSON(&e); err != nil {
			t.Fatal(err)
		}
		expectStatus(t, call(t, alice, http.MethodPatch, softwareCatalog+"/"+entry, map[string]any{
			"name": e["name"], "packages": e["packages"], "approval": "none",
		}), http.StatusOK, "")
		expectStatus(t, call(t, alice, http.MethodPost, softwareRequests+"/"+open.ID+"/approve", nil), http.StatusConflict, "invalid_state")
		b := latestBundle(t, f.device, 2*time.Minute, hasPackage(pkg))
		if p, _ := softwarePackage(b, pkg); p.Approval != "" || p.Approved != nil {
			t.Fatalf("package of an entry without approval %s", asJSON(t, p))
		}

		for _, c := range []struct{ entry, user, cause string }{
			{entry, u3, "approval_removed"}, {entry, u2, "approval_removed"}, {other, u4, "validity_ended"},
		} {
			r := waitRequest(t, alice, c.entry, c.user, "expired", softwareRequestRound)
			if ev := requestEvent(t, alice, "software_request.expired", r.ID); ev.Params["cause"] != c.cause {
				t.Errorf("software_request.expired of %s: params %v, want cause %s", c.user, ev.Params, c.cause)
			}
		}
		if got := requestsOf(t, alice, entry, "requested", "approved"); len(got) != 0 {
			t.Fatalf("open or approved requests after the expiry: %+v", got)
		}
	})
}

// requestAuditCases are the A3 cases of POST /api/v1/software-requests/{id}/<verb> (plan M13c decision 9): success on
// an open request, a decided request (409 invalid_state), a missing request, the auditor (no role to decide), and for
// deny a missing reason.
func requestAuditCases(verb, code string, body func() any) []auditCase {
	cases := []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			r := openRequest(t, w.alice, "a3-req")
			res := call(t, w.alice, http.MethodPost, softwareRequests+"/"+r.ID+"/"+verb, body())
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"decided", func(t *testing.T, w *auditWorld) {
			r := openRequest(t, w.alice, "a3-req")
			expectStatus(t, call(t, w.alice, http.MethodPost, softwareRequests+"/"+r.ID+"/"+verb, body()), http.StatusOK, "")
			res := call(t, w.alice, http.MethodPost, softwareRequests+"/"+r.ID+"/"+verb, body())
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, softwareRequests+"/00000000-0000-7000-8000-000000000000/"+verb, body())
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, softwareRequests+"/00000000-0000-7000-8000-000000000000/"+verb, body())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
	if verb == "deny" {
		cases = append(cases, auditCase{"no reason", func(t *testing.T, w *auditWorld) {
			r := openRequest(t, w.alice, "a3-req")
			res := call(t, w.alice, http.MethodPost, softwareRequests+"/"+r.ID+"/deny", map[string]any{})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}})
	}
	return cases
}

// maintenanceWindowPath is the maintenance window of a device group.
func maintenanceWindowPath(group string) string {
	return "/api/v1/device-groups/" + group + "/maintenance-window"
}

// nightlyWindow is a valid maintenance window.
func nightlyWindow() map[string]any {
	return map[string]any{"days": []int{1, 2, 3, 4, 5}, "start_minute": 1320, "duration_minutes": 180, "timezone": "Europe/Berlin"}
}

// windowAuditCases are the A3 cases of the maintenance window writes (plan M13c decision 4): success on a fresh group,
// a missing group, the auditor, and for PUT an unknown timezone.
func windowAuditCases(method, code string, success int) []auditCase {
	body := func() any {
		if method == http.MethodPut {
			return nightlyWindow()
		}
		return nil
	}
	cases := []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			g := createGroup(t, w.alice)
			if method == http.MethodDelete {
				expectStatus(t, call(t, w.alice, http.MethodPut, maintenanceWindowPath(g.id), nightlyWindow()), http.StatusOK, "")
			}
			res := call(t, w.alice, method, maintenanceWindowPath(g.id), body())
			expectStatus(t, res, success, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, method, maintenanceWindowPath("00000000-0000-7000-8000-000000000000"), body())
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, method, maintenanceWindowPath("00000000-0000-7000-8000-000000000000"), body())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
	if method == http.MethodPut {
		cases = append(cases, auditCase{"unknown timezone", func(t *testing.T, w *auditWorld) {
			g := createGroup(t, w.alice)
			invalid := nightlyWindow()
			invalid["timezone"] = "Europe/Mars"
			res := call(t, w.alice, method, maintenanceWindowPath(g.id), invalid)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}})
	}
	return cases
}

// softwareRequestAuditCases are the A3 cases of the M13c operations (PDK-809, PDK-810).
var softwareRequestAuditCases = map[string][]auditCase{
	"POST /api/v1/software-requests/{id}/approve": requestAuditCases("approve", "software_request.approved",
		func() any { return map[string]any{"reason": "a3"} }),
	"POST /api/v1/software-requests/{id}/deny": requestAuditCases("deny", "software_request.denied",
		func() any { return map[string]any{"reason": "a3"} }),
	"PUT /api/v1/device-groups/{id}/maintenance-window":    windowAuditCases(http.MethodPut, "device_group.maintenance_window_changed", http.StatusOK),
	"DELETE /api/v1/device-groups/{id}/maintenance-window": windowAuditCases(http.MethodDelete, "device_group.maintenance_window_removed", http.StatusNoContent),
}

// hasEntry is a latestBundle condition: the section has a package of the catalog entry.
func hasEntry(entry string) func(*bundle.Bundle) bool {
	return func(b *bundle.Bundle) bool {
		return b.Software != nil && slices.ContainsFunc(b.Software.Packages, func(p bundle.SoftwarePackage) bool { return p.CatalogEntryID == entry })
	}
}
