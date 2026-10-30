package acceptance

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

const ipAllowlistPath = "/api/platform/v1/ip-allowlist"

type ipAllowlistEntry struct {
	ID           string `json:"id"`
	CIDR         string `json:"cidr"`
	Label        string `json:"label"`
	CreatedBy    string `json:"created_by"`
	CoversCaller bool   `json:"covers_caller"`
}

func listIPAllowlist(t *testing.T, p *env.Portal) []ipAllowlistEntry {
	t.Helper()
	res := call(t, p, http.MethodGet, ipAllowlistPath+"?page_size=100", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []ipAllowlistEntry `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Items
}

// disableIPAllowlist switches the list off on the host, as the break-glass runbook does, so that a failed gate never
// leaves the stack restricted.
func disableIPAllowlist(t *testing.T) {
	t.Helper()
	out, err := stack.Compose(context.Background(), nil, "run", "--rm", "--no-deps", "paddock-worker", "admin", "allowlist", "disable")
	if err != nil {
		t.Logf("paddock-server admin allowlist disable: %v\n%s", err, out)
	}
}

// denialWhere matches the denial events of ip since since (the development window is 20 s, so a previous run's
// events are older).
func denialWhere(since time.Time) string {
	return fmt.Sprintf("params->>'ip' = $1 AND occurred_at >= '%s'", since.UTC().Format(time.RFC3339))
}

// TestIPAllowlist is gate A1 (plan M7a step 2; AC1, AC3, AC4): the platform admin manages the list with a step-up,
// self-lockout and switch-off need an explicit confirmation, every attempt is one audit event, and once the list has
// entries the api refuses sessions and API tokens from other addresses before anything is read — aggregated into the
// denial events of decision 20. A spoofed address on the untrusted listener does not count.
func TestIPAllowlist(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	idx := auditIndex(t)
	if entries := listIPAllowlist(t, root); len(entries) != 0 {
		t.Fatalf("the ip allow list has %d entries; run `docker compose … run --rm --no-deps paddock-worker admin allowlist disable` first", len(entries))
	}
	t.Cleanup(func() { disableIPAllowlist(t) })

	me := call(t, root, http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, me, http.StatusOK, "")
	var m struct {
		ClientIP string `json:"client_ip"`
	}
	if err := me.JSON(&m); err != nil || m.ClientIP == "" {
		t.Fatalf("client_ip: %v %s", err, me.Body)
	}
	own := m.ClientIP + "/32"
	if strings.Contains(m.ClientIP, ":") {
		own = m.ClientIP + "/128"
	}
	t.Logf("client address C = %s", m.ClientIP)

	res := call(t, root, http.MethodPost, ipAllowlistPath, map[string]string{"cidr": "198.51.100.0/24", "label": "office"})
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.ip_allowlist_changed", "denied", auditPollTimeout)

	freshStepUp(t, root, env.PlatformAdmin)
	res = call(t, root, http.MethodPost, ipAllowlistPath, map[string]string{"cidr": "198.51.100.0/24", "label": "office"})
	expectStatus(t, res, http.StatusConflict, "lockout_confirmation_required")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.ip_allowlist_changed", "failure", auditPollTimeout)
	if entries := listIPAllowlist(t, root); len(entries) != 0 {
		t.Fatalf("a refused change changed the list: %+v", entries)
	}

	// The development step-up window (30 s) is shorter than the audit polls between the writes.
	freshStepUp(t, root, env.PlatformAdmin)
	res = call(t, root, http.MethodPost, ipAllowlistPath, map[string]string{"cidr": own, "label": "gate host"})
	expectStatus(t, res, http.StatusCreated, "")
	var mine ipAllowlistEntry
	if err := res.JSON(&mine); err != nil || !mine.CoversCaller {
		t.Fatalf("own entry: %v %s", err, res.Body)
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.ip_allowlist_changed", "success", auditPollTimeout)
	if ev.Params["action"] != "added" || ev.Params["consequence"] != "none" || ev.Params["entries"] != float64(1) || ev.Params["cidr"] != own {
		t.Fatalf("added params: %v", ev.Params)
	}
	freshStepUp(t, root, env.PlatformAdmin)
	res = call(t, root, http.MethodPost, ipAllowlistPath, map[string]string{"cidr": "198.51.100.0/24", "label": "office"})
	expectStatus(t, res, http.StatusCreated, "")
	var office ipAllowlistEntry
	if err := res.JSON(&office); err != nil {
		t.Fatal(err)
	}
	res = call(t, root, http.MethodPost, ipAllowlistPath, map[string]string{"cidr": "2001:db8::/32", "label": "v6"})
	expectStatus(t, res, http.StatusCreated, "")
	var v6 ipAllowlistEntry
	if err := res.JSON(&v6); err != nil {
		t.Fatal(err)
	}
	freshStepUp(t, root, env.PlatformAdmin)
	res = call(t, root, http.MethodPost, ipAllowlistPath, map[string]string{"cidr": "198.51.100.0/24", "label": "again"})
	expectStatus(t, res, http.StatusConflict, "already_exists")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.ip_allowlist_changed", "failure", auditPollTimeout)
	freshStepUp(t, root, env.PlatformAdmin)
	res = call(t, root, http.MethodPatch, ipAllowlistPath+"/"+office.ID, map[string]string{"label": "branch office"})
	expectStatus(t, res, http.StatusOK, "")
	ev = expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.ip_allowlist_changed", "success", auditPollTimeout)
	if ev.Params["action"] != "updated" || ev.Params["previous_label"] != "office" {
		t.Fatalf("updated params: %v", ev.Params)
	}

	// Allowed addresses through the trusted listener (Caddy resolves them from X-Forwarded-For).
	for _, ip := range []string{"198.51.100.7", "2001:db8::9"} {
		r, got := clientIPOf(t, root, stack.AdminURL(), map[string]string{"X-Forwarded-For": ip})
		if r.Status != http.StatusOK || got != ip {
			t.Fatalf("%s: HTTP %d client_ip %q: %s", ip, r.Status, got, r.Body)
		}
	}

	// A foreign address is refused before the session or token is read.
	alice := login(t, env.Alice)
	token := createAPIToken(t, alice, env.Alice, "org_admin")
	foreign := map[string]string{"X-Forwarded-For": "192.0.2.9"}
	since := time.Now().Add(-time.Second)
	ctx := testContext(t, 3*time.Minute)
	denied := func(client *http.Client, path string) env.Response {
		t.Helper()
		r, err := env.Call(ctx, client, http.MethodGet, stack.AdminURL()+path, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	sent := 0
	r := denied(sessionWith(t, root, foreign), "/api/v1/me")
	sent++
	if r.Status != http.StatusForbidden || r.ProblemCode() != "ip_not_allowed" || r.RequestID == "" {
		t.Fatalf("session from 192.0.2.9: HTTP %d %s (request id %q)", r.Status, r.Body, r.RequestID)
	}
	r = denied(sessionWith(t, root, foreign), "/")
	sent++
	if r.Status != http.StatusForbidden || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("portal from 192.0.2.9: HTTP %d %s %s", r.Status, r.Header.Get("Content-Type"), r.Body)
	}
	r = denied(sessionWith(t, root, foreign), "/api/platform/v1/organizations")
	sent++
	if r.Status != http.StatusForbidden || r.ProblemCode() != "ip_not_allowed" {
		t.Fatalf("organizations from 192.0.2.9: HTTP %d %s", r.Status, r.Body)
	}
	tokenClient, err := env.HeaderClient(map[string]string{"X-Forwarded-For": "192.0.2.9", "Authorization": "Bearer " + token.Secret})
	if err != nil {
		t.Fatal(err)
	}
	r = denied(tokenClient, "/api/v1/me")
	sent++
	if r.Status != http.StatusForbidden || r.ProblemCode() != "ip_not_allowed" {
		t.Fatalf("api token from 192.0.2.9: HTTP %d %s", r.Status, r.Body)
	}
	first := expectOneIndexEvent(t, idx, platformOrg, denialWhere(since), "192.0.2.9", "platform.ip_allowlist_denied", "denied", auditPollTimeout)
	if first.Params["count"] != float64(1) || first.Params["aggregated"] != false {
		t.Fatalf("first denial: %v", first.Params)
	}
	for range 20 {
		denied(sessionWith(t, root, foreign), "/api/v1/me")
		sent++
	}
	time.Sleep(5 * time.Second)
	if events, err := idx.Events(ctx, platformOrg, denialWhere(since), "192.0.2.9"); err != nil || len(events) != 1 {
		t.Fatalf("further denials within the window are counted, not recorded: %v %v", events, err)
	}
	var summary *env.IndexEvent
	for deadline := time.Now().Add(40 * time.Second); summary == nil; {
		// The deadline is checked against the poll's start, as in expectOneIndexEvent (PDK-551, PDK-561).
		polled := time.Now()
		events, err := idx.Events(ctx, platformOrg, denialWhere(since), "192.0.2.9")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Params["aggregated"] == true {
				summary = &e
			}
		}
		if summary == nil && polled.After(deadline) {
			t.Fatalf("no summary event of 192.0.2.9 within 40 s: %v", events)
		}
		time.Sleep(time.Second)
	}
	if summary.Params["count"] != float64(sent) || summary.CorrelationID != first.CorrelationID {
		t.Fatalf("summary: %v (correlation %s, first %s), want count %d", summary.Params, summary.CorrelationID, first.CorrelationID, sent)
	}

	// On the untrusted listener the spoofed address is ignored: the peer is covered.
	if r, _ := clientIPOf(t, root, stack.AdminUntrustedURL(), foreign); r.Status != http.StatusOK {
		t.Fatalf("untrusted listener with a spoofed foreign address: HTTP %d %s", r.Status, r.Body)
	}

	freshStepUp(t, root, env.PlatformAdmin)
	res = call(t, root, http.MethodDelete, ipAllowlistPath+"/"+mine.ID, nil)
	expectStatus(t, res, http.StatusConflict, "lockout_confirmation_required")
	for _, e := range []ipAllowlistEntry{office, v6} {
		expectStatus(t, call(t, root, http.MethodDelete, ipAllowlistPath+"/"+e.ID, nil), http.StatusNoContent, "")
	}
	res = call(t, root, http.MethodDelete, ipAllowlistPath+"/"+mine.ID, nil)
	expectStatus(t, res, http.StatusConflict, "disable_confirmation_required")
	res = call(t, root, http.MethodDelete, ipAllowlistPath+"/"+mine.ID+"?confirm=disable", nil)
	expectStatus(t, res, http.StatusNoContent, "")
	ev = expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.ip_allowlist_changed", "success", auditPollTimeout)
	if ev.Params["consequence"] != "disable" || ev.Params["entries"] != float64(0) {
		t.Fatalf("disable params: %v", ev.Params)
	}
	if entries := listIPAllowlist(t, root); len(entries) != 0 {
		t.Fatalf("list after: %+v", entries)
	}
	if r, _ := clientIPOf(t, root, stack.AdminURL(), foreign); r.Status != http.StatusOK {
		t.Fatalf("after switching off 192.0.2.9 is admitted again: HTTP %d %s", r.Status, r.Body)
	}
}
