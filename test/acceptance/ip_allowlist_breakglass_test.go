package acceptance

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestIPAllowlistBreakGlass is gate A3 (plan M7a step 3, AC5): an operator on the host adds an entry, lists the
// entries and switches the list off without portal access; add and disable are audited with actor system, and a
// second disable records nothing.
func TestIPAllowlistBreakGlass(t *testing.T) {
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

	since := time.Now().Add(-time.Second)
	out := runAdmin(t, "allowlist", "add", "--cidr", own, "--label", "host")
	if !strings.Contains(out, "ip allowlist: added "+own) {
		t.Fatalf("add: %s", out)
	}
	ev := expectIndexEventSince(t, idx, platformOrg, "platform.ip_allowlist_changed", since)
	if ev.ActorDisplay != "paddock-server admin" || ev.Params["action"] != "added" || ev.Params["cidr"] != own {
		t.Fatalf("added event: actor %q params %v", ev.ActorDisplay, ev.Params)
	}
	// The api follows the version within 2 s.
	var entries []ipAllowlistEntry
	for deadline := time.Now().Add(15 * time.Second); ; {
		entries = listIPAllowlist(t, root)
		if len(entries) == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if len(entries) != 1 || entries[0].CIDR != own || entries[0].CreatedBy != "paddock-server admin" || !entries[0].CoversCaller {
		t.Fatalf("entries after the break-glass add: %+v", entries)
	}
	show := runAdmin(t, "allowlist", "show")
	if !strings.Contains(show, own+"\thost\tpaddock-server admin\t") {
		t.Fatalf("show: %q", show)
	}

	since = time.Now().Add(-time.Second)
	out = runAdmin(t, "allowlist", "disable")
	if !strings.Contains(out, "ip allowlist disabled: 1 entries removed") {
		t.Fatalf("disable: %s", out)
	}
	ev = expectIndexEventSince(t, idx, platformOrg, "platform.ip_allowlist_disabled", since)
	removed, _ := ev.Params["removed"].([]any)
	if ev.ActorDisplay != "paddock-server admin" || ev.Params["method"] != "cli" || ev.Params["entries_removed"] != float64(1) ||
		len(removed) != 1 || removed[0] != own {
		t.Fatalf("disabled event: actor %q params %v", ev.ActorDisplay, ev.Params)
	}
	if entries := listIPAllowlist(t, root); len(entries) != 0 {
		t.Fatalf("entries after disable: %+v", entries)
	}
	if show := runAdmin(t, "allowlist", "show"); !strings.Contains(show, "ip allowlist: off (no entries)") {
		t.Fatalf("show after disable: %q", show)
	}

	since = time.Now().Add(-time.Second)
	if out := runAdmin(t, "allowlist", "disable"); !strings.Contains(out, "ip allowlist: already off") {
		t.Fatalf("second disable: %s", out)
	}
	time.Sleep(5 * time.Second)
	events, err := idx.Events(testContext(t, time.Minute), platformOrg, "code = 'platform.ip_allowlist_disabled' AND occurred_at >= $1", since)
	if err != nil || len(events) != 0 {
		t.Fatalf("a disable of an empty list records nothing: %v %v", events, err)
	}
}
