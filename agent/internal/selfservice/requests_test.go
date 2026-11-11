package selfservice

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// approvalSpec is spec() with entryB (gimp-apt, offered to everyone) requiring approval; approve lists the approved
// users and deny the denied ones.
func approvalSpec(approve []string, deny ...bundle.SoftwareDenial) bundle.SoftwareSpec {
	sp := spec()
	sp.Packages[1].Approval = bundle.SoftwareApprovalRequired
	if approve != nil {
		sp.Packages[1].Approved = &approve
	}
	if deny != nil {
		sp.Packages[1].Denied = &deny
	}
	return sp
}

// send sends a request with body as uid.
func (f *fixture) send(t *testing.T, uid int, method, path, body string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://selfservice"+path, rd)
	req = req.WithContext(withPeer(req.Context(), peer{uid: uid}))
	rec := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (f *fixture) request(t *testing.T, uid int, entry, justification string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"justification": justification})
	return f.send(t, uid, http.MethodPost, "/v1/apps/"+entry+"/request", string(body))
}

func (f *fixture) requestEvent(t *testing.T) protocol.SoftwareRequest {
	t.Helper()
	select {
	case ev := <-f.svc.Requests():
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no software.request event")
	}
	return protocol.SoftwareRequest{}
}

func (f *fixture) noRequestEvent(t *testing.T) {
	t.Helper()
	select {
	case ev := <-f.svc.Requests():
		t.Fatalf("unexpected software.request %+v", ev)
	default:
	}
}

func requestState(body map[string]any) string {
	r, _ := body["request"].(map[string]any)
	s, _ := r["state"].(string)
	return s
}

// TestRequestNeedsApproval (ADR 0024): no entry of a bundle without a package that requires approval can be requested,
// and no software.request is ever emitted for it.
func TestRequestNeedsApproval(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	if code, body := f.request(t, alice, entryB, "please"); code != http.StatusConflict || body["code"] != CodeNotRequired {
		t.Errorf("entry without approval: %d %v", code, body)
	}
	if code, body := f.request(t, alice, entryA, ""); code != http.StatusConflict || body["code"] != CodeNotRequired {
		t.Errorf("own entry without approval: %d %v", code, body)
	}
	if code, body := f.request(t, alice, entryC, ""); code != http.StatusForbidden || body["code"] != protocol.SelfServiceRequiredByPolicy {
		t.Errorf("managed entry: %d %v", code, body)
	}
	if code, body := f.request(t, bob, entryA, ""); code != http.StatusNotFound || body["code"] != CodeUnknownEntry {
		t.Errorf("entry of another audience: %d %v", code, body)
	}
	f.noRequestEvent(t)
	if _, body := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryB); body["approval"] != nil || body["requestable"] != false || body["installable"] != true {
		t.Errorf("entry without approval view: %v", body)
	}
}

// TestRequestFlow (plan M13c decision 9): a request is recorded once with the justification, a second one while it is
// pending is refused, an install needs the approval, and a withdrawal clears the state.
func TestRequestFlow(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	_, body := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryB)
	if body["approval"] != bundle.SoftwareApprovalRequired || body["requestable"] != true || body["installable"] != false || body["request"] != nil {
		t.Fatalf("before the request: %v", body)
	}
	if code, body := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryB+"/install"); code != http.StatusForbidden || body["code"] != CodeApprovalRequired {
		t.Errorf("install without approval: %d %v", code, body)
	}
	code, body := f.request(t, alice, entryB, "  For the design\nreview  ")
	if code != http.StatusAccepted || requestState(body) != RequestRequested || body["requestable"] != false {
		t.Fatalf("request: %d %v", code, body)
	}
	if ev := f.requestEvent(t); ev != (protocol.SoftwareRequest{User: "alice@example.org", EntryID: entryB, Justification: "For the design\nreview"}) {
		t.Errorf("event %+v", ev)
	}
	if code, body := f.request(t, alice, entryB, "again"); code != http.StatusConflict || body["code"] != CodeAlreadyRequested {
		t.Errorf("second request: %d %v", code, body)
	}
	f.noRequestEvent(t)
	if _, body := f.call(t, alice, http.MethodGet, "/v1/apps"); requestState(body["apps"].([]any)[1].(map[string]any)) != RequestRequested {
		t.Errorf("list: %v", body)
	}
	if _, body := f.call(t, bob, http.MethodGet, "/v1/apps/"+entryB); body["request"] != nil || body["requestable"] != true {
		t.Errorf("another user sees alice's request: %v", body)
	}
	if data, _, _ := f.sys.ReadFile(StateFile); !strings.Contains(string(data), `"username":"alice@example.org"`) || strings.Contains(string(data), "design") {
		t.Errorf("record %s", data)
	}
	// A restarted agent keeps the pending request.
	restarted := New(Config{Sys: f.sys, Now: func() time.Time { return f.now }}).withBundle(approvalSpec(nil))
	if v, err := restarted.App(Principal{UID: alice, UPN: "alice@example.org", Directory: true}, entryB); err != nil || v.Request == nil {
		t.Errorf("request lost on restart: %+v %v", v, err)
	}
	code, body = f.send(t, alice, http.MethodDelete, "/v1/apps/"+entryB+"/request", "")
	if code != http.StatusOK || body["request"] != nil || body["requestable"] != true {
		t.Errorf("withdraw: %d %v", code, body)
	}
	if code, body := f.send(t, alice, http.MethodDelete, "/v1/apps/"+entryB+"/request", ""); code != http.StatusNotFound || body["code"] != CodeNotFound {
		t.Errorf("second withdraw: %d %v", code, body)
	}
	if data, _, _ := f.sys.ReadFile(StateFile); strings.Contains(string(data), "alice") {
		t.Errorf("record after withdraw %s", data)
	}
}

// withBundle hands s a bundle with sp and returns s.
func (s *Service) withBundle(sp bundle.SoftwareSpec) *Service {
	s.SetBundle(softwareBundle(sp), nil)
	return s
}

// TestRequestApproved: an approved user installs; a pending request ends once the bundle approves it.
func TestRequestApproved(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	f.request(t, alice, entryB, "")
	f.requestEvent(t)
	f.svc.SetBundle(softwareBundle(approvalSpec([]string{"alice@example.org"})), nil)
	_, body := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryB)
	if body["installable"] != true || body["request"] != nil || body["requestable"] != false {
		t.Errorf("approved: %v", body)
	}
	if data, _, _ := f.sys.ReadFile(StateFile); strings.Contains(string(data), "alice") {
		t.Errorf("the approval did not end the pending request: %s", data)
	}
	if code, body := f.request(t, alice, entryB, ""); code != http.StatusConflict || body["code"] != CodeNotRequired {
		t.Errorf("request when approved: %d %v", code, body)
	}
	if _, body := f.call(t, bob, http.MethodGet, "/v1/apps/"+entryB); body["installable"] != false || body["requestable"] != true {
		t.Errorf("bob is not approved: %v", body)
	}
	if code, body := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryB+"/install"); code != http.StatusAccepted {
		t.Errorf("install when approved: %d %v", code, body)
	}
}

// TestRequestDenied (A10-27): a denial is shown only to its user, with the reason as plain text; a pending request ends
// with it and the user cannot ask again while the bundle lists it.
func TestRequestDenied(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	f.request(t, alice, entryB, "")
	f.requestEvent(t)
	reason := "Use <b>LibreOffice</b>\x1b[31m‮\ninstead\x00"
	f.svc.SetBundle(softwareBundle(approvalSpec(nil, bundle.SoftwareDenial{User: "alice@example.org", Reason: reason})), nil)
	_, body := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryB)
	r, _ := body["request"].(map[string]any)
	if r["state"] != RequestDenied || r["reason"] != "Use <b>LibreOffice</b>[31m\ninstead" || body["requestable"] != false || body["installable"] != false {
		t.Errorf("denied: %v", body)
	}
	if code, body := f.request(t, alice, entryB, ""); code != http.StatusConflict || body["code"] != RequestDenied {
		t.Errorf("request while denied: %d %v", code, body)
	}
	f.noRequestEvent(t)
	if _, body := f.call(t, bob, http.MethodGet, "/v1/apps/"+entryB); body["request"] != nil || body["requestable"] != true {
		t.Errorf("bob sees alice's denial: %v", body)
	}
	if data, _, _ := f.sys.ReadFile(StateFile); strings.Contains(string(data), "alice") {
		t.Errorf("the denial did not end the pending request: %s", data)
	}
	long := strings.Repeat("ä", bundle.MaxSoftwareDenialReason+20)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil, bundle.SoftwareDenial{User: "alice@example.org", Reason: long})), nil)
	_, body = f.call(t, alice, http.MethodGet, "/v1/apps/"+entryB)
	if r, _ := body["request"].(map[string]any); r["reason"] != long[:2*bundle.MaxSoftwareDenialReason] {
		t.Errorf("long reason not cut: %v", body)
	}
}

// TestRequestCompat (A10-27): a bundle from a server before denials (no "denied") works, and a bundle with denials of
// other users shows the caller none.
func TestRequestCompat(t *testing.T) {
	gimp := `{"package":"gimp-apt","intent":"available","version":null,"source":"","catalog_entry_id":"` + entryB +
		`","audience":{"all":true},"approval":"required"`
	for name, tc := range map[string]struct {
		pkg   string
		state string
	}{
		"without denied":        {gimp + `}`, ""},
		"denied for another":    {gimp + `,"denied":[{"user":"bob@example.org","reason":"no"}]}`, ""},
		"denied for the caller": {gimp + `,"denied":[{"user":"alice@example.org","reason":"no"},{"user":"bob@example.org","reason":"x"}]}`, RequestDenied},
	} {
		t.Run(name, func(t *testing.T) {
			var sp bundle.SoftwareSpec
			if err := json.Unmarshal([]byte(`{"sources":[],"packages":[`+tc.pkg+`]}`), &sp); err != nil {
				t.Fatal(err)
			}
			if err := bundle.ValidateSoftware(sp); err != nil {
				t.Fatal(err)
			}
			f := newFixture(t)
			f.svc.SetBundle(softwareBundle(sp), nil)
			_, body := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryB)
			if requestState(body) != tc.state || body["installable"] != false || body["requestable"] != (tc.state == "") {
				t.Errorf("view %v", body)
			}
			if r, _ := body["request"].(map[string]any); tc.state != "" && r["reason"] != "no" {
				t.Errorf("reason %v", body)
			}
		})
	}
}

// TestJustification (maintainer answer Q7): plain text of at most 500 characters, newlines allowed, nothing else.
func TestJustification(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"empty body":        {"", true},
		"no justification":  {`{}`, true},
		"500 characters":    {`{"justification":"` + strings.Repeat("ä", MaxJustification) + `"}`, true},
		"html":              {`{"justification":"<script>alert(1)</script>"}`, true},
		"501 characters":    {`{"justification":"` + strings.Repeat("a", MaxJustification+1) + `"}`, false},
		"control character": {`{"justification":"a\u001bb"}`, false},
		"carriage return":   {`{"justification":"a\r\nb"}`, false},
		"unknown field":     {`{"justification":"a","user":"bob@example.org"}`, false},
		"not a string":      {`{"justification":1}`, false},
		"two objects":       {`{"justification":"a"}{}`, false},
		"invalid utf-8":     {"{\"justification\":\"\xff\"}", false},
		"not json":          {`please`, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
			code, body := f.send(t, alice, http.MethodPost, "/v1/apps/"+entryB+"/request", tc.body)
			switch {
			case tc.ok && code != http.StatusAccepted:
				t.Errorf("refused: %d %v", code, body)
			case !tc.ok && (code != http.StatusBadRequest || body["code"] != CodeInvalidRequest):
				t.Errorf("accepted: %d %v", code, body)
			case !tc.ok && strings.Contains(body["detail"].(string), "script"):
				t.Errorf("detail echoes the text: %v", body)
			case tc.ok:
				f.requestEvent(t)
			default:
				f.noRequestEvent(t)
			}
		})
	}
}

// TestRequestLocalAccount: approvals name directory users, so a local account cannot ask.
func TestRequestLocalAccount(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	if _, body := f.call(t, carol, http.MethodGet, "/v1/apps/"+entryB); body["requestable"] != false || body["installable"] != false {
		t.Errorf("view %v", body)
	}
	if code, body := f.request(t, carol, entryB, ""); code != http.StatusForbidden || body["code"] != protocol.SelfServiceNotInAudience {
		t.Errorf("request: %d %v", code, body)
	}
	f.noRequestEvent(t)
}

// TestRequestExpires: a request the bundle never reflected ends after RequestValidity, as on the server.
func TestRequestExpires(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	f.request(t, alice, entryB, "")
	f.requestEvent(t)
	f.now = f.now.Add(RequestValidity)
	if _, body := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryB); body["request"] != nil || body["requestable"] != true {
		t.Errorf("expired request still shown: %v", body)
	}
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	if data, _, _ := f.sys.ReadFile(StateFile); strings.Contains(string(data), "alice") {
		t.Errorf("expired request kept: %s", data)
	}
}

// TestRequestEntryWithdrawn: a pending request ends when the bundle no longer offers the entry with approval.
func TestRequestEntryWithdrawn(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	f.request(t, alice, entryB, "")
	f.requestEvent(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	if data, _, _ := f.sys.ReadFile(StateFile); strings.Contains(string(data), "alice") {
		t.Errorf("request kept after the approval was removed: %s", data)
	}
}

// TestRequestRate: a user who withdraws and asks again in a loop is stopped after RequestsPerHour requests.
func TestRequestRate(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(approvalSpec(nil)), nil)
	for i := range RequestsPerHour {
		if code, body := f.request(t, alice, entryB, ""); code != http.StatusAccepted {
			t.Fatalf("request %d: %d %v", i, code, body)
		}
		f.requestEvent(t)
		f.send(t, alice, http.MethodDelete, "/v1/apps/"+entryB+"/request", "")
	}
	if code, body := f.request(t, alice, entryB, ""); code != http.StatusTooManyRequests || body["code"] != CodeBusy {
		t.Errorf("over the rate: %d %v", code, body)
	}
	f.noRequestEvent(t)
	if code, _ := f.request(t, bob, entryB, ""); code != http.StatusAccepted {
		t.Errorf("another user: %d", code)
	}
	f.now = f.now.Add(time.Hour)
	if code, _ := f.request(t, alice, entryB, ""); code != http.StatusAccepted {
		t.Errorf("next hour: %d", code)
	}
}
