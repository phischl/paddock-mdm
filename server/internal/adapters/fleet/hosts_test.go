package fleet_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestListHostsChangedSince: the host list is filtered by the newest of the hosts' update times; the zero time lists
// every host, and the refs are Fleet's IDs.
func TestListHostsChangedSince(t *testing.T) {
	ctx := context.Background()
	_, srv := newFake(t)
	c := client(srv.URL)
	page, err := c.ListHostsChangedSince(ctx, time.Time{}, "")
	if err != nil || len(page.Hosts) != 2 || page.Next != "" {
		t.Fatalf("all hosts %+v, %v", page, err)
	}
	if h := page.Hosts[1]; h.Ref != "2" || h.HardwareUUID != "a7ace4c5-76d1-ab48-a28d-55cd12a90b68" ||
		!h.ChangedAt.Equal(time.Date(2026, 10, 7, 13, 18, 30, 0, time.UTC)) {
		t.Fatalf("host %+v", h)
	}
	page, err = c.ListHostsChangedSince(ctx, time.Date(2026, 10, 7, 13, 18, 25, 0, time.UTC), "")
	if err != nil || len(page.Hosts) != 1 || page.Hosts[0].Ref != "2" {
		t.Fatalf("changed hosts %+v, %v", page, err)
	}
	if _, err := c.ListHostsChangedSince(ctx, time.Time{}, "x"); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}

// TestHostInventory maps Fleet's host detail: software with its CVEs (no CVSS score or fixed version in Fleet free),
// answered policies only, osquery's version without an orbit version.
func TestHostInventory(t *testing.T) {
	_, srv := newFake(t)
	inv, err := client(srv.URL).HostInventory(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	if inv.OSVersion != "Ubuntu 24.04.5 LTS" || inv.AgentVersion != "5.23.1" || inv.LastSeenAt == nil || len(inv.Software) != 3 {
		t.Fatalf("inventory %+v", inv)
	}
	apport := inv.Software[2]
	if apport.Name != "apport" || apport.Source != "deb_packages" ||
		!slices.Equal(apport.Vulnerabilities, []ports.Vulnerability{{CVE: "CVE-2022-28653"}}) {
		t.Fatalf("apport %+v", apport)
	}
	if !slices.Equal(inv.Policies, []ports.PolicyResult{{Key: "disk_encrypted", Passing: true}, {Key: "paddock_agent_running"}}) {
		t.Fatalf("policies %+v", inv.Policies)
	}
	want := ports.HostHardware{Vendor: "LENOVO", Model: "21HD003LGE", Serial: "PF4XK2QZ",
		CPUBrand: "13th Gen Intel(R) Core(TM) i7-1365U", CPUCores: 10, MemoryBytes: 33328349184, DiskTotalBytes: 510440000000}
	if inv.Hardware != want {
		t.Fatalf("hardware %+v, want %+v", inv.Hardware, want)
	}
	if _, err := client(srv.URL).HostInventory(context.Background(), "../config"); err == nil {
		t.Fatal("invalid host reference accepted")
	}
}

// TestDeleteHost (plan M10 decision 17): the host is deleted through Fleet's API; a host Fleet no longer knows counts
// as deleted; an unavailable Fleet is upstream_unavailable after the retries; an invalid reference never reaches Fleet
// and is invalid_state.
func TestDeleteHost(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t)
	c := client(srv.URL)
	if err := c.DeleteHost(ctx, "1"); err != nil || !f.deletedHosts["1"] {
		t.Fatalf("delete: %v, deleted %v", err, f.deletedHosts)
	}
	if err := c.DeleteHost(ctx, "1"); err != nil {
		t.Fatalf("delete of a deleted host: %v, want nil", err)
	}
	f.failNext = 4
	if err := c.DeleteHost(ctx, "2"); !errors.Is(err, problem.UpstreamUnavailable) || f.deletedHosts["2"] {
		t.Fatalf("delete while Fleet answers 503: %v, deleted %v", err, f.deletedHosts)
	}
	requests := len(f.requests)
	if err := c.DeleteHost(ctx, "../config"); !errors.Is(err, problem.InvalidState) || len(f.requests) != requests {
		t.Fatalf("invalid host reference: %v, %d requests sent", err, len(f.requests)-requests)
	}
	if want := "DELETE /api/v1/fleet/hosts/1"; f.requests[0] != want {
		t.Fatalf("first request %q, want %q", f.requests[0], want)
	}
}

// TestDeleteHostForeign404 (plan M10 amendment 2026-10-30): only Fleet's own JSON error body makes a 404 "already
// gone"; a 404 from anything else between Paddock and Fleet is an upstream_unavailable failure, so no deletion is
// recorded.
func TestDeleteHostForeign404(t *testing.T) {
	for name, body := range map[string]string{
		"proxy text":          "404 page not found",
		"html":                "<html><body>Not Found</body></html>",
		"json without errors": `{"message":"Resource Not Found"}`,
		"empty":               "",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			if err := client(srv.URL).DeleteHost(context.Background(), "1"); !errors.Is(err, problem.UpstreamUnavailable) {
				t.Fatalf("foreign 404: %v, want upstream_unavailable", err)
			}
		})
	}
}

// fleetError is Fleet's own JSON error body.
const fleetError = `{"message":"refused","errors":[{"name":"base","reason":"refused"}]}`

// TestDeleteHostErrorClass (plan M10 amendments 2026-10-30, PDK-583): Fleet's refusal of the one host, a 4xx with
// Fleet's own error body, is invalid_state; a failure of Fleet itself or of the way to it, including a 4xx a proxy
// answers for every host alike, is upstream_unavailable, the only class the retention round's Fleet breaker counts.
func TestDeleteHostErrorClass(t *testing.T) {
	for _, c := range []struct {
		code int
		body string
		want error
	}{
		{http.StatusBadRequest, fleetError, problem.InvalidState},
		{http.StatusConflict, fleetError, problem.InvalidState},
		{http.StatusUnprocessableEntity, fleetError, problem.InvalidState},
		{http.StatusMethodNotAllowed, "405 Not Allowed", problem.UpstreamUnavailable},
		{http.StatusBadRequest, "<html><body>400 Request Header Or Cookie Too Large</body></html>", problem.UpstreamUnavailable},
		{http.StatusBadRequest, `{"message":"bad request"}`, problem.UpstreamUnavailable},
		{http.StatusMisdirectedRequest, "", problem.UpstreamUnavailable},
		{http.StatusUnauthorized, fleetError, problem.UpstreamUnavailable},
		{http.StatusForbidden, fleetError, problem.UpstreamUnavailable},
		{http.StatusRequestTimeout, fleetError, problem.UpstreamUnavailable},
		{http.StatusTooManyRequests, fleetError, problem.UpstreamUnavailable},
		{http.StatusInternalServerError, fleetError, problem.UpstreamUnavailable},
		{http.StatusBadGateway, fleetError, problem.UpstreamUnavailable},
	} {
		t.Run(fmt.Sprintf("%d %.12s", c.code, c.body), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.code)
				_, _ = w.Write([]byte(c.body))
			}))
			t.Cleanup(srv.Close)
			if err := client(srv.URL).DeleteHost(context.Background(), "1"); !errors.Is(err, c.want) {
				t.Fatalf("HTTP %d %q: %v, want %v", c.code, c.body, err, c.want)
			}
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	if err := client(srv.URL).DeleteHost(context.Background(), "1"); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("connection refused: %v, want upstream_unavailable", err)
	}
}

// TestDeleteHostRedirect (PDK-583): a redirect is not followed, so a DELETE never turns into a GET whose 200 would read
// as a deleted host; it is upstream_unavailable.
func TestDeleteHostRedirect(t *testing.T) {
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
			return
		}
		http.Redirect(w, r, "/moved"+r.URL.Path, http.StatusMovedPermanently)
	}))
	t.Cleanup(srv.Close)
	if err := client(srv.URL).DeleteHost(context.Background(), "1"); !errors.Is(err, problem.UpstreamUnavailable) || gets != 0 {
		t.Fatalf("301: %v after %d GETs, want upstream_unavailable and none", err, gets)
	}
}

// TestDeleteHostCanceled (PDK-583): a canceled context is neither upstream_unavailable nor invalid_state, so a shutdown
// does not count toward the retention round's Fleet breaker.
func TestDeleteHostCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client(srv.URL).DeleteHost(ctx, "1")
	if err == nil || errors.Is(err, problem.UpstreamUnavailable) || errors.Is(err, problem.InvalidState) {
		t.Fatalf("canceled: %v, want an unclassified error", err)
	}
}

// TestHostSeenAt (plan M10 amendment 2026-10-30, PDK-583): the host's last check-in from its detail without software;
// a host Fleet no longer knows or that never checked in reports the zero time; failures are classified like
// DeleteHost's.
func TestHostSeenAt(t *testing.T) {
	seen := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		code int
		body string
		want time.Time
		err  error
	}{
		{"seen", http.StatusOK, `{"host":{"id":1,"seen_time":"2026-10-29T08:00:00Z"}}`, seen, nil},
		{"never seen", http.StatusOK, `{"host":{"id":1,"seen_time":"0001-01-01T00:00:00Z"}}`, time.Time{}, nil},
		{"null seen_time", http.StatusOK, `{"host":{"id":1,"seen_time":null}}`, time.Time{}, problem.UpstreamUnavailable},
		{"no seen_time", http.StatusOK, `{"host":{"id":1}}`, time.Time{}, problem.UpstreamUnavailable},
		{"no host", http.StatusOK, `{}`, time.Time{}, problem.UpstreamUnavailable},
		{"null host", http.StatusOK, `{"host":null}`, time.Time{}, problem.UpstreamUnavailable},
		{"host without id", http.StatusOK, `{"host":{"seen_time":"2026-10-29T08:00:00Z"}}`, time.Time{}, problem.UpstreamUnavailable},
		{"gone", http.StatusNotFound, fleetError, time.Time{}, nil},
		{"foreign 404", http.StatusNotFound, "404 page not found", time.Time{}, problem.UpstreamUnavailable},
		{"refused", http.StatusBadRequest, fleetError, time.Time{}, problem.InvalidState},
		{"down", http.StatusServiceUnavailable, "", time.Time{}, problem.UpstreamUnavailable},
		{"redirect", http.StatusFound, "", time.Time{}, problem.UpstreamUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			var asked string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked = r.Method + " " + r.URL.RequestURI()
				if c.code == http.StatusFound {
					w.Header().Set("Location", "/elsewhere")
				}
				w.WriteHeader(c.code)
				_, _ = w.Write([]byte(c.body))
			}))
			t.Cleanup(srv.Close)
			got, err := client(srv.URL).HostSeenAt(context.Background(), "1")
			if !got.Equal(c.want) || (c.err == nil) != (err == nil) || c.err != nil && !errors.Is(err, c.err) {
				t.Fatalf("seen %v, %v; want %v, %v", got, err, c.want, c.err)
			}
			if want := "GET /api/v1/fleet/hosts/1?exclude_software=true"; asked != want {
				t.Fatalf("asked %q, want %q", asked, want)
			}
		})
	}
	if _, err := client("http://127.0.0.1:1").HostSeenAt(context.Background(), "../config"); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("invalid host reference: %v", err)
	}
}

// TestApplyPolicies sends Paddock's policies as Fleet's policy spec for Linux hosts.
func TestApplyPolicies(t *testing.T) {
	f, srv := newFake(t)
	err := client(srv.URL).ApplyPolicies(context.Background(), []ports.PolicyDefinition{{Key: "k", Description: "d", Query: "SELECT 1;"}})
	if err != nil || len(f.policySpecs) != 1 {
		t.Fatalf("%v, specs %v", err, f.policySpecs)
	}
	if s := f.policySpecs[0]; s["name"] != "k" || s["query"] != "SELECT 1;" || s["description"] != "d" || s["platform"] != "linux" {
		t.Fatalf("spec %v", s)
	}
}

// TestVulnerabilityState: the digest of Fleet's vulnerable software versions is stable and changes with a new match.
func TestVulnerabilityState(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t)
	c := client(srv.URL)
	first, err := c.VulnerabilityState(ctx)
	if err != nil || first == "" {
		t.Fatalf("state %q, %v", first, err)
	}
	if again, _ := c.VulnerabilityState(ctx); again != first {
		t.Fatalf("unstable state %q, %q", first, again)
	}
	f.vulnerableSoftware = []map[string]any{{"id": 82, "vulnerabilities": []map[string]any{{"cve": "CVE-2022-28653"}, {"cve": "CVE-2026-0001"}}}}
	if changed, _ := c.VulnerabilityState(ctx); changed == first {
		t.Fatal("a new match did not change the state")
	}
}
