package selfservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	alice   = 200001
	bob     = 200002
	carol   = 1000
	root    = 0
	entryA  = "aaaaaaaa-0000-4000-8000-000000000001" // code, available to alice only
	entryB  = "aaaaaaaa-0000-4000-8000-000000000002" // gimp-apt, available to everyone
	entryC  = "aaaaaaaa-0000-4000-8000-000000000003" // nano, required
	entryD  = "aaaaaaaa-0000-4000-8000-000000000004" // vlc, forbidden
	entryE  = "aaaaaaaa-0000-4000-8000-000000000005" // user-scope Flatpak, required for bob only
	pngData = "\x89PNG\r\n\x1a\nicon"
)

type notified struct {
	mu    sync.Mutex
	calls []string
}

func (n *notified) list() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.calls)
}

type fixture struct {
	sys    *fakesys.System
	svc    *Service
	notes  *notified
	now    time.Time
	cancel context.CancelFunc
}

func spec() bundle.SoftwareSpec {
	bobs := []string{"bob@example.org"}
	return bundle.SoftwareSpec{Packages: []bundle.SoftwarePackage{
		{Package: "code", Intent: bundle.SoftwareAvailable, CatalogEntryID: entryA, Audience: &bundle.SoftwareAudience{Users: []string{"alice@example.org"}}},
		{Package: "gimp-apt", Intent: bundle.SoftwareAvailable, CatalogEntryID: entryB, Audience: &bundle.SoftwareAudience{All: true}},
		{Package: "nano", Intent: bundle.SoftwareRequired, CatalogEntryID: entryC},
		{Package: "vlc", Intent: bundle.SoftwareForbid, CatalogEntryID: entryD},
		{FlatpakRef: "org.example.Secret", Scope: bundle.SoftwareScopeUser, Intent: bundle.SoftwareRequired, CatalogEntryID: entryE, Users: &bobs},
		{Package: "flatpak", Intent: bundle.SoftwareRequired, CatalogEntryID: bundle.SoftwareRuntimeEntryID},
	}}
}

func softwareBundle(sp bundle.SoftwareSpec) *bundle.Bundle {
	return &bundle.Bundle{BundleVersion: 7, Software: &sp}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	sys := fakesys.New()
	sys.AptVersion = "1.0-1"
	sys.Packages["nano"] = true
	sys.Passwd = map[string]int{"alice@example.org": alice, "bob@example.org": bob, "carol": carol, "root": root}
	f := &fixture{sys: sys, notes: &notified{}, now: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)}
	f.svc = New(Config{Sys: sys, Packages: &reconcile.Software{Sys: sys}, Version: "0.1.0-alpha.10", Now: func() time.Time { return f.now },
		Notify: func(_ context.Context, uid int, _, body string) {
			f.notes.mu.Lock()
			f.notes.calls = append(f.notes.calls, itoa(uid)+" "+body)
			f.notes.mu.Unlock()
		}})
	f.svc.icons.gap = 0
	return f
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// start runs the executor until the test ends.
func (f *fixture) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.cancel = cancel
	f.svc.Start(ctx)
}

// call sends a request as uid through the handler, with uid as its peer credentials.
func (f *fixture) call(t *testing.T, uid int, method, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "http://selfservice"+path, nil)
	if uid >= -1 {
		req = req.WithContext(withPeer(req.Context(), peer{uid: uid}))
	}
	rec := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func entries(body map[string]any) []string {
	var out []string
	apps, _ := body["apps"].([]any)
	for _, a := range apps {
		out = append(out, a.(map[string]any)["entry_id"].(string))
	}
	slices.Sort(out)
	return out
}

// event waits for the next software.self_service event.
func (f *fixture) event(t *testing.T) protocol.SoftwareSelfService {
	t.Helper()
	select {
	case ev := <-f.svc.Events():
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no software.self_service event")
	}
	return protocol.SoftwareSelfService{}
}

func (f *fixture) noEvent(t *testing.T) {
	t.Helper()
	select {
	case ev := <-f.svc.Events():
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

// waitRefreshed waits until the executor took up the last SetBundle.
func (f *fixture) waitRefreshed(t *testing.T) {
	t.Helper()
	eventually(t, func() bool {
		f.svc.mu.Lock()
		defer f.svc.mu.Unlock()
		return !f.svc.reconcile
	})
}

// eventually waits up to five seconds for cond.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
	}
}

func (f *fixture) recorded(pkg string) bool {
	data, _, _ := f.sys.ReadFile(StateFile)
	return strings.Contains(string(data), `"`+pkg+`"`)
}

// TestVisibility (decision 11): a directory UID sees everything offered to everyone and to its UPN plus the managed
// entries; a local UID and UID 0 see what is offered to everyone; nobody sees the runtime entry or a user-scope entry
// targeted at someone else.
func TestVisibility(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	for _, tc := range []struct {
		uid  int
		want []string
	}{
		{alice, []string{entryA, entryB, entryC, entryD}},
		{bob, []string{entryB, entryC, entryD, entryE}},
		{carol, []string{entryB, entryC, entryD}},
		{root, []string{entryB, entryC, entryD}},
	} {
		code, body := f.call(t, tc.uid, http.MethodGet, "/v1/apps")
		if code != http.StatusOK || !slices.Equal(entries(body), tc.want) {
			t.Errorf("uid %d: %d %v, want %v", tc.uid, code, entries(body), tc.want)
		}
	}
	_, body := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryC)
	if body["managed"] != true || body["installable"] != false || body["removable"] != false || body["state"] != "installed" && body["state"] != "absent" {
		t.Errorf("managed entry %v", body)
	}
	_, body = f.call(t, alice, http.MethodGet, "/v1/status")
	if body["notice"] != DefaultNotice || body["user"].(map[string]any)["name"] != "alice@example.org" ||
		body["user"].(map[string]any)["directory"] != true || body["bundle_version"] != float64(7) {
		t.Errorf("status %v", body)
	}
}

// TestUnknownEntryRevealsNothing: another user's entry is a plain 404, like one that does not exist.
func TestUnknownEntryRevealsNothing(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	for _, path := range []string{"/v1/apps/" + entryA, "/v1/apps/" + entryA + "/install", "/v1/apps/bbbbbbbb-0000-4000-8000-000000000009/install"} {
		method := http.MethodPost
		if !strings.HasSuffix(path, "install") {
			method = http.MethodGet
		}
		code, body := f.call(t, bob, method, path)
		if code != http.StatusNotFound || body["code"] != CodeUnknownEntry || strings.Contains(body["detail"].(string), "code") {
			t.Errorf("%s: %d %v", path, code, body)
		}
	}
}

// TestShortNameDirectoryUser: Himmelblau's short name gets the UPN only when name@domain resolves to the same UID.
func TestShortNameDirectoryUser(t *testing.T) {
	f := newFixture(t)
	f.sys.Passwd = map[string]int{"alice": alice, "alice@example.org": alice, "mallory": 200009, "mallory@example.org": 200010}
	ctx := context.Background()
	p, err := Authorize(ctx, f.sys, alice, "Example.org")
	if err != nil || p.UPN != "alice@example.org" || !p.Directory {
		t.Errorf("alice %+v %v", p, err)
	}
	p, err = Authorize(ctx, f.sys, 200009, "example.org")
	if err != nil || p.UPN != "" {
		t.Errorf("mallory %+v %v", p, err)
	}
	if _, err := Authorize(ctx, f.sys, 4242, "example.org"); !errors.Is(err, errUnknownUser) {
		t.Errorf("unknown UID: %v", err)
	}
}

// TestRefusals: managed entries are read-only; an available app self-service did not install cannot be removed; no
// bundle is 503 no_bundle (also for a report-only one); a caller without peer credentials or account is refused.
func TestRefusals(t *testing.T) {
	f := newFixture(t)
	if code, body := f.call(t, alice, http.MethodGet, "/v1/apps"); code != http.StatusServiceUnavailable || body["code"] != CodeNoBundle {
		t.Errorf("no bundle: %d %v", code, body)
	}
	b := softwareBundle(spec())
	b.Mode = bundle.ModeReportOnly
	f.svc.SetBundle(b, nil)
	if code, _ := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryB+"/install"); code != http.StatusServiceUnavailable {
		t.Errorf("report-only: %d", code)
	}
	f.svc.SetBundle(softwareBundle(spec()), nil)
	for _, path := range []string{"/v1/apps/" + entryC + "/remove", "/v1/apps/" + entryC + "/install", "/v1/apps/" + entryD + "/install",
		"/v1/apps/" + entryB + "/remove", "/v1/apps/" + entryB + "/update"} {
		if code, body := f.call(t, alice, http.MethodPost, path); code != http.StatusForbidden || body["code"] != protocol.SelfServiceRequiredByPolicy {
			t.Errorf("%s: %d %v", path, code, body)
		}
	}
	if code, body := f.call(t, root, http.MethodPost, "/v1/apps/"+entryC+"/remove"); code != http.StatusForbidden || body["code"] != protocol.SelfServiceRequiredByPolicy {
		t.Errorf("root: %d %v", code, body)
	}
	if code, body := f.call(t, -2, http.MethodGet, "/v1/apps"); code != http.StatusForbidden || body["code"] != CodeUnauthenticated {
		t.Errorf("no peer: %d %v", code, body)
	}
	if code, body := f.call(t, 4242, http.MethodGet, "/v1/apps"); code != http.StatusForbidden || body["code"] != CodeUnauthenticated {
		t.Errorf("no account: %d %v", code, body)
	}
	req := httptest.NewRequest(http.MethodPost, "http://selfservice/v1/apps/"+entryB+"/install", strings.NewReader(strings.Repeat("x", MaxBody+1)))
	req = req.WithContext(withPeer(req.Context(), peer{uid: alice}))
	rec := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: %d", rec.Code)
	}
}

// TestRateLimit: more than 60 requests a minute from one UID are refused; other UIDs and the next minute are not.
func TestRateLimit(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	for i := range RatePerMinute {
		if code, _ := f.call(t, alice, http.MethodGet, "/v1/status"); code != http.StatusOK {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code, body := f.call(t, alice, http.MethodGet, "/v1/status"); code != http.StatusTooManyRequests || body["code"] != CodeRateLimited {
		t.Errorf("61st: %d %v", code, body)
	}
	if code, _ := f.call(t, bob, http.MethodGet, "/v1/status"); code != http.StatusOK {
		t.Errorf("bob: %d", code)
	}
	f.now = f.now.Add(time.Minute)
	if code, _ := f.call(t, alice, http.MethodGet, "/v1/status"); code != http.StatusOK {
		t.Errorf("next minute: %d", code)
	}
}

// TestQueueLimit: five queued operations per UID, then 429; another user still queues.
func TestQueueLimit(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	for i := range MaxQueuedPerUser {
		if code, _ := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryB+"/install"); code != http.StatusAccepted {
			t.Fatalf("operation %d: %d", i, code)
		}
	}
	if code, body := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryB+"/install"); code != http.StatusTooManyRequests || body["code"] != CodeBusy {
		t.Errorf("6th: %d %v", code, body)
	}
	if code, _ := f.call(t, carol, http.MethodPost, "/v1/apps/"+entryB+"/install"); code != http.StatusAccepted {
		t.Errorf("carol: %d", code)
	}
	if _, body := f.call(t, alice, http.MethodGet, "/v1/status"); body["queue"] != float64(MaxQueuedPerUser) {
		t.Errorf("queue %v", body["queue"])
	}
}

// TestInstallAndRemove: an install runs through the reconciler's primitives, is recorded, reported once with every
// field and told to the user once; the app is then installed and removable, and its removal works the same way.
func TestInstallAndRemove(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.start(t)
	f.waitRefreshed(t)
	code, body := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/install")
	if code != http.StatusAccepted {
		t.Fatalf("install: %d %v", code, body)
	}
	id := body["operation_id"].(string)
	ev := f.event(t)
	want := protocol.SoftwareSelfService{User: "alice@example.org", EntryID: entryA, Package: "code", Scope: "system", Action: "install",
		Outcome: "succeeded", Version: "1.0-1"}
	if ev != want {
		t.Fatalf("event %+v, want %+v", ev, want)
	}
	f.noEvent(t)
	if !f.sys.Packages["code"] {
		t.Fatal("not installed")
	}
	_, op := f.call(t, alice, http.MethodGet, "/v1/operations/"+id)
	if op["state"] != "succeeded" || op["entry_id"] != entryA || op["finished_at"] == nil {
		t.Errorf("operation %v", op)
	}
	if code, _ := f.call(t, bob, http.MethodGet, "/v1/operations/"+id); code != http.StatusNotFound {
		t.Errorf("bob reads alice's operation: %d", code)
	}
	_, app := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryA)
	if app["state"] != "installed" || app["removable"] != true || app["updatable"] != true || app["installable"] != false {
		t.Errorf("app %v", app)
	}
	var rec Record
	data, _, _ := f.sys.ReadFile(StateFile)
	if err := json.Unmarshal(data, &rec); err != nil || len(rec.Installs) != 1 || rec.Installs[0].Username != "alice@example.org" ||
		rec.Installs[0].Package != "code" || f.sys.Files[StateFile].Mode != 0o600 {
		t.Errorf("record %s %v", data, err)
	}
	if notes := f.notes.list(); !slices.Equal(notes, []string{"200001 Installed: code"}) {
		t.Errorf("notifications %v", notes)
	}

	if code, _ := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/remove"); code != http.StatusAccepted {
		t.Fatalf("remove: %d", code)
	}
	if ev := f.event(t); ev.Action != "remove" || ev.Outcome != "succeeded" || f.sys.Packages["code"] {
		t.Fatalf("remove event %+v", ev)
	}
	if data, _, _ := f.sys.ReadFile(StateFile); strings.Contains(string(data), "code") {
		t.Errorf("record after removal %s", data)
	}
}

// TestSimulationGuard: the executor uses Apply's guard — an install that would remove another package fails.
func TestSimulationGuard(t *testing.T) {
	f := newFixture(t)
	f.sys.Packages["vim"] = true
	f.sys.Conflicts = map[string]string{"gimp-apt": "vim"}
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.start(t)
	f.call(t, carol, http.MethodPost, "/v1/apps/"+entryB+"/install")
	ev := f.event(t)
	if ev.Outcome != "failed" || ev.Reason != protocol.SoftwareWouldRemoveDependents || ev.User != "carol" || !f.sys.Packages["vim"] {
		t.Fatalf("event %+v", ev)
	}
	_, app := f.call(t, carol, http.MethodGet, "/v1/apps/"+entryB)
	if app["state"] != "failed" || app["reason"] != protocol.SoftwareWouldRemoveDependents {
		t.Errorf("app %v", app)
	}
	if notes := f.notes.list(); len(notes) != 1 || !strings.Contains(notes[0], "Installation failed") {
		t.Errorf("notifications %v", notes)
	}
}

// TestBundleChangedWhileQueued (F3): an operation is authorized again when it starts.
func TestBundleChangedWhileQueued(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/install")
	f.call(t, alice, http.MethodPost, "/v1/apps/"+entryB+"/install")
	changed := spec()
	changed.Packages[0].Intent, changed.Packages[0].Audience = bundle.SoftwareRequired, nil
	changed.Packages[1].Audience = &bundle.SoftwareAudience{Users: []string{"bob@example.org"}}
	f.svc.SetBundle(softwareBundle(changed), nil)
	f.start(t)
	for _, want := range []string{protocol.SelfServiceRequiredByPolicy, protocol.SelfServiceNotInAudience} {
		if ev := f.event(t); ev.Outcome != protocol.SelfServiceRefused || ev.Reason != want {
			t.Errorf("event %+v, want refused/%s", ev, want)
		}
	}
	if len(aptCalls(f.sys)) != 0 {
		t.Errorf("apt ran: %v", f.sys.Calls)
	}
}

// TestInterrupted (F4): an operation the last process left running is failed/interrupted at start, once.
func TestInterrupted(t *testing.T) {
	f := newFixture(t)
	marker, _ := json.Marshal(running{ID: "op1", UID: alice, User: "alice@example.org", EntryID: entryA, Package: "code", Scope: "system",
		Action: "install", StartedAt: f.now.Add(-time.Minute)})
	if err := f.sys.WriteFileAtomic(RunningFile, marker, 0o600, 0, 0); err != nil {
		t.Fatal(err)
	}
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.start(t)
	ev := f.event(t)
	if ev.Outcome != protocol.SelfServiceFailed || ev.Reason != protocol.SelfServiceInterrupted || ev.User != "alice@example.org" || ev.Package != "code" {
		t.Fatalf("event %+v", ev)
	}
	if _, _, err := f.sys.ReadFile(RunningFile); err == nil {
		t.Error("the marker is left")
	}
	_, op := f.call(t, alice, http.MethodGet, "/v1/operations/op1")
	if op["state"] != "failed" || op["reason"] != "interrupted" {
		t.Errorf("operation %v", op)
	}
}

// TestOrdering (F9): operations of two users run one after the other in queue order and show their positions.
func TestOrdering(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	_, a := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/install")
	_, c := f.call(t, carol, http.MethodPost, "/v1/apps/"+entryB+"/install")
	_, opA := f.call(t, alice, http.MethodGet, "/v1/operations/"+a["operation_id"].(string))
	_, opC := f.call(t, carol, http.MethodGet, "/v1/operations/"+c["operation_id"].(string))
	if opA["position"] != float64(1) || opC["position"] != float64(2) || opC["state"] != StateQueued {
		t.Errorf("positions %v %v", opA, opC)
	}
	f.start(t)
	if first, second := f.event(t), f.event(t); first.User != "alice@example.org" || second.User != "carol" {
		t.Errorf("order %+v %+v", first, second)
	}
	if !slices.Equal(aptCalls(f.sys), []string{"apt-get -s install code", "apt-get install code", "apt-get -s install gimp-apt", "apt-get install gimp-apt"}) {
		t.Errorf("calls %v", f.sys.Calls)
	}
}

func aptCalls(sys *fakesys.System) []string {
	return slices.DeleteFunc(slices.Clone(sys.Calls), func(c string) bool { return !strings.HasPrefix(c, "apt-get") })
}

// TestRemovedByHand (F10): a self-service app the user removed by hand leaves the record at the next pass, shows as
// absent and is never reinstalled.
func TestRemovedByHand(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.start(t)
	f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/install")
	f.event(t)
	delete(f.sys.Packages, "code")
	f.sys.Calls = nil
	f.svc.SetBundle(softwareBundle(spec()), nil)
	eventually(t, func() bool { return !f.recorded("code") })
	_, app := f.call(t, alice, http.MethodGet, "/v1/apps/"+entryA)
	if app["state"] != "absent" || app["removable"] != false || app["installable"] != true {
		t.Errorf("app %v", app)
	}
	if calls := aptCalls(f.sys); len(calls) != 0 {
		t.Errorf("calls %v", calls)
	}
	f.noEvent(t)
}

// TestPolicyTakesOver (F11): an app the policy now requires leaves the record and is read-only.
func TestPolicyTakesOver(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.start(t)
	f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/install")
	f.event(t)
	changed := spec()
	changed.Packages[0].Intent, changed.Packages[0].Audience = bundle.SoftwareRequired, nil
	f.svc.SetBundle(softwareBundle(changed), nil)
	eventually(t, func() bool { return !f.recorded("code") })
	if code, body := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/remove"); code != http.StatusForbidden || body["code"] != protocol.SelfServiceRequiredByPolicy {
		t.Errorf("remove: %d %v", code, body)
	}
}

// TestNotificationCap: at most five notifications per user and hour; every operation still has its event.
func TestNotificationCap(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.start(t)
	for i := range 7 {
		action := "install"
		if i%2 == 1 {
			action = "remove"
		}
		if code, _ := f.call(t, carol, http.MethodPost, "/v1/apps/"+entryB+"/"+action); code != http.StatusAccepted {
			t.Fatalf("operation %d: %d", i, code)
		}
		f.event(t)
	}
	if n := len(f.notes.list()); n != NoticesPerHour {
		t.Errorf("%d notifications", n)
	}
	f.now = f.now.Add(time.Hour)
	f.call(t, carol, http.MethodPost, "/v1/apps/"+entryB+"/remove")
	f.event(t)
	if n := len(f.notes.list()); n != NoticesPerHour+1 {
		t.Errorf("%d notifications after an hour", n)
	}
}

// TestNoEventWithoutSelfServiceBundle (ADR 0024): a bundle without available packages or Flatpak sources gets no
// software.self_service event, because its server does not know it.
func TestNoEventWithoutSelfServiceBundle(t *testing.T) {
	f := newFixture(t)
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.call(t, carol, http.MethodPost, "/v1/apps/"+entryB+"/install")
	f.svc.SetBundle(softwareBundle(bundle.SoftwareSpec{Packages: spec().Packages[2:4]}), nil)
	f.start(t)
	f.waitRefreshed(t)
	f.noEvent(t)
	eventually(t, func() bool { return len(f.notes.list()) == 1 })
	if len(f.notes.list()) != 1 {
		t.Errorf("notifications %v", f.notes.list())
	}
}

// withIcons gives the entries ids an icon digest.
func withIcons(sp bundle.SoftwareSpec, ids ...string) bundle.SoftwareSpec {
	for i := range sp.Packages {
		if slices.Contains(ids, sp.Packages[i].CatalogEntryID) {
			sp.Packages[i].IconSHA256 = strings.Repeat("ab", 32)
		}
	}
	return sp
}

// TestIcons: icons come from the server once per entry that has a digest, are served for visible entries only and
// leave the cache with their entry.
func TestIcons(t *testing.T) {
	f := newFixture(t)
	var mu sync.Mutex
	fetched := map[string]int{}
	fetch := func(_ context.Context, id string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		fetched[id]++
		if id == entryB || id == entryA {
			return []byte(pngData), nil
		}
		return nil, &client.APIError{Status: http.StatusNotFound}
	}
	f.sys.Files[IconDir+"/bbbbbbbb-0000-4000-8000-000000000099.png"] = &fakesys.File{Data: []byte(pngData)}
	sp := withIcons(spec(), entryA, entryB, entryC)
	f.svc.SetBundle(softwareBundle(sp), fetch)
	f.start(t)
	eventually(t, func() bool {
		f.svc.icons.mu.Lock()
		defer f.svc.icons.mu.Unlock()
		return len(f.svc.icons.tried) == 3
	})
	req := httptest.NewRequest(http.MethodGet, "http://selfservice/v1/apps/"+entryB+"/icon", nil)
	req = req.WithContext(withPeer(req.Context(), peer{uid: carol}))
	rec := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != pngData || rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("icon %d %q", rec.Code, rec.Body.String())
	}
	if code, _ := f.call(t, carol, http.MethodGet, "/v1/apps/"+entryA+"/icon"); code != http.StatusNotFound {
		t.Errorf("carol reads the icon of alice's entry: %d", code)
	}
	if code, _ := f.call(t, carol, http.MethodGet, "/v1/apps/"+entryC+"/icon"); code != http.StatusNotFound {
		t.Errorf("entry without icon: %d", code)
	}
	if _, ok := f.sys.Files[IconDir+"/bbbbbbbb-0000-4000-8000-000000000099.png"]; ok {
		t.Error("the icon of a gone entry stayed")
	}
	f.svc.SetBundle(softwareBundle(sp), fetch)
	f.waitRefreshed(t)
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if fetched[entryB] != 1 || fetched[entryC] != 1 || fetched[bundle.SoftwareRuntimeEntryID] != 0 {
		t.Errorf("fetched %v", fetched)
	}
	// An entry without a digest has no icon; asking for it would spend the device key's rate budget on a 404.
	if fetched[entryD] != 0 || fetched[entryE] != 0 {
		t.Errorf("entries without an icon digest were fetched: %v", fetched)
	}
}

// TestIconsStopOn429: a 429 ends the icon round without marking the entry, and no fetch goes before Retry-After has
// passed, so icons never crowd check-in and events out of the device key's rate budget.
func TestIconsStopOn429(t *testing.T) {
	f := newFixture(t)
	var mu sync.Mutex
	calls, limited := 0, true
	fetch := func(_ context.Context, _ string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if limited {
			return nil, &client.APIError{Status: http.StatusTooManyRequests, RetryAfter: 30 * time.Second}
		}
		return []byte(pngData), nil
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
	b := softwareBundle(withIcons(spec(), entryA, entryB, entryC))
	f.svc.SetBundle(b, fetch)
	f.start(t)
	eventually(t, func() bool { return count() == 1 })
	f.svc.SetBundle(b, fetch)
	f.waitRefreshed(t)
	time.Sleep(50 * time.Millisecond)
	if n := count(); n != 1 {
		t.Fatalf("fetches after a 429: %d, want 1", n)
	}
	f.svc.icons.mu.Lock()
	tried := len(f.svc.icons.tried)
	f.svc.icons.mu.Unlock()
	if tried != 0 {
		t.Fatalf("a limited entry counts as tried (%d)", tried)
	}
	mu.Lock()
	limited = false
	mu.Unlock()
	f.now = f.now.Add(31 * time.Second)
	f.svc.SetBundle(b, fetch)
	eventually(t, func() bool { return f.svc.icons.has(entryA) && f.svc.icons.has(entryB) && f.svc.icons.has(entryC) })
}

// TestIconsPaced: icon fetches keep the gap between them.
func TestIconsPaced(t *testing.T) {
	f := newFixture(t)
	const gap = 40 * time.Millisecond
	f.svc.icons.gap = gap
	var mu sync.Mutex
	var at []time.Time
	fetch := func(_ context.Context, _ string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, time.Now())
		return []byte(pngData), nil
	}
	f.svc.SetBundle(softwareBundle(withIcons(spec(), entryA, entryB, entryC)), fetch)
	f.start(t)
	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(at) == 3 })
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(at); i++ {
		if d := at[i].Sub(at[i-1]); d < gap {
			t.Errorf("fetch %d came %v after the one before, want at least %v", i, d, gap)
		}
	}
}

// TestPresentAppNotClaimed (ADR 0049 decision 3): an install of an application that is already on the device — an
// APT package or a system Flatpak application, known to the probe or installed only after it — never enters the
// record, so no audience user can remove it afterwards.
func TestPresentAppNotClaimed(t *testing.T) {
	const entryF = "aaaaaaaa-0000-4000-8000-000000000006"
	withFlatpak := func() bundle.SoftwareSpec {
		sp := spec()
		sp.Packages = append(sp.Packages, bundle.SoftwarePackage{FlatpakRef: "org.gimp.GIMP", Source: "flathub", Intent: bundle.SoftwareAvailable,
			CatalogEntryID: entryF, Audience: &bundle.SoftwareAudience{All: true}})
		return sp
	}
	cases := []struct {
		name, entry string
		present     func(sys *fakesys.System)
	}{
		{"apt", entryB, func(sys *fakesys.System) { sys.Packages["gimp-apt"] = true }},
		{"system flatpak", entryF, func(sys *fakesys.System) { sys.FlatpakSystem.Apps["org.gimp.GIMP"] = "1.0" }},
	}
	for _, c := range cases {
		for _, probed := range []bool{true, false} {
			t.Run(c.name+map[bool]string{true: " probed", false: " after the probe"}[probed], func(t *testing.T) {
				f := newFixture(t)
				f.sys.Packages["flatpak"] = true
				f.sys.FlatpakSystem = fakesys.NewFlatpakInstallation()
				if probed {
					c.present(f.sys)
				}
				f.svc.SetBundle(softwareBundle(withFlatpak()), nil)
				f.start(t)
				f.waitRefreshed(t)
				if !probed {
					c.present(f.sys)
				}
				code, body := f.call(t, carol, http.MethodPost, "/v1/apps/"+c.entry+"/install")
				switch {
				case probed && (code != http.StatusForbidden || body["code"] != protocol.SelfServiceRequiredByPolicy):
					t.Fatalf("install of a known present app: %d %v", code, body)
				case !probed && code != http.StatusAccepted:
					t.Fatalf("install: %d %v", code, body)
				case !probed:
					if ev := f.event(t); ev.Outcome != protocol.SelfServiceRefused || ev.Reason != protocol.SelfServiceRequiredByPolicy {
						t.Fatalf("event %+v", ev)
					}
				}
				if f.recorded("gimp-apt") || f.recorded("org.gimp.GIMP") {
					t.Fatal("a present app entered the record")
				}
				for _, uid := range []int{carol, alice} {
					if code, body := f.call(t, uid, http.MethodPost, "/v1/apps/"+c.entry+"/remove"); code != http.StatusForbidden ||
						body["code"] != protocol.SelfServiceRequiredByPolicy {
						t.Errorf("remove as %d: %d %v", uid, code, body)
					}
				}
				if len(aptCalls(f.sys)) != 0 || slices.ContainsFunc(f.sys.FlatpakCalls, func(c string) bool { return strings.Contains(c, "install") }) {
					t.Errorf("a package tool changed the device: %v %v", f.sys.Calls, f.sys.FlatpakCalls)
				}
			})
		}
	}
}

// stallingPackages stalls every probe of one UID until its context ends, as a user's stopped service manager does.
type stallingPackages struct {
	*reconcile.Software
	uid int
}

func (p stallingPackages) SelfServiceInstalled(ctx context.Context, pkg bundle.SoftwarePackage, uid int) (bool, string, error) {
	if uid == p.uid {
		<-ctx.Done()
		return false, "", ctx.Err()
	}
	return p.Software.SelfServiceInstalled(ctx, pkg, uid)
}

// TestStalledProbe (decision 13): a user who stalls the probe of their own user-scope install delays the executor by
// at most the probe deadline, and refreshes asked for again and again never keep another user's operation from
// running; the stalled user's record entry stays.
func TestStalledProbe(t *testing.T) {
	f := newFixture(t)
	rec, _ := json.Marshal(Record{Installs: []Install{
		{EntryID: entryE, FlatpakRef: "org.example.Mine", Scope: bundle.SoftwareScopeUser, Username: "bob@example.org", UID: bob},
		{EntryID: entryE, FlatpakRef: "org.example.Other", Scope: bundle.SoftwareScopeUser, Username: "bob@example.org", UID: bob},
	}})
	if err := f.sys.WriteFileAtomic(StateFile, rec, 0o600, 0, 0); err != nil {
		t.Fatal(err)
	}
	f.sys.Packages["flatpak"] = true
	f.svc = New(Config{Sys: f.sys, Packages: stallingPackages{Software: &reconcile.Software{Sys: f.sys}, uid: bob},
		Now: func() time.Time { return f.now }, Notify: func(context.Context, int, string, string) {}, ProbeTimeout: 100 * time.Millisecond})
	f.svc.SetBundle(softwareBundle(spec()), nil)
	f.start(t)
	if code, body := f.call(t, alice, http.MethodPost, "/v1/apps/"+entryA+"/install"); code != http.StatusAccepted {
		t.Fatalf("install: %d %v", code, body)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				f.svc.SetBundle(softwareBundle(spec()), nil)
			}
		}
	}()
	ev := f.event(t)
	close(stop)
	if ev.Outcome != protocol.SelfServiceSucceeded || ev.EntryID != entryA {
		t.Fatalf("event %+v", ev)
	}
	if !f.recorded("org.example.Mine") || !f.recorded("org.example.Other") {
		t.Error("the stalled user's install left the record")
	}
}

// TestCatchAllLimited (decision 12): an unknown endpoint passes the peer and rate checks like every other one.
func TestCatchAllLimited(t *testing.T) {
	f := newFixture(t)
	if code, body := f.call(t, -2, http.MethodGet, "/nothing"); code != http.StatusForbidden || body["code"] != CodeUnauthenticated {
		t.Errorf("no peer: %d %v", code, body)
	}
	for range RatePerMinute {
		if code, _ := f.call(t, alice, http.MethodGet, "/nothing"); code != http.StatusNotFound {
			t.Fatalf("unknown endpoint: %d", code)
		}
	}
	if code, body := f.call(t, alice, http.MethodGet, "/nothing"); code != http.StatusTooManyRequests || body["code"] != CodeRateLimited {
		t.Errorf("61st: %d %v", code, body)
	}
}
