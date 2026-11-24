package fleet_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/problem"
)

const deviceToken = "0b6e8a0c-1d2f-4a3b-9c4d-5e6f7a8b9c0d"

// TestListHostsSeen (ADR 0057): every listed host with a hardware UUID is in Seen, changed or not, in list order, with
// its seen time (zero when absent) and its latest enrollment.
func TestListHostsSeen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hosts": [
			{"id": 7, "uuid": "u-7", "seen_time": "2026-11-17T10:00:00Z", "last_enrolled_at": "2026-11-16T09:00:00Z",
			 "detail_updated_at": "2026-11-01T00:00:00Z", "software_updated_at": "2026-11-01T00:00:00Z", "policy_updated_at": "2026-11-01T00:00:00Z"},
			{"id": 8, "uuid": "", "seen_time": "2026-11-17T10:00:00Z"},
			{"id": 9, "uuid": "u-9", "detail_updated_at": "2026-11-17T10:00:00Z", "software_updated_at": "2026-11-17T10:00:00Z",
			 "policy_updated_at": "2026-11-17T10:00:00Z"}]}`))
	}))
	t.Cleanup(srv.Close)
	page, err := client(srv.URL).ListHostsChangedSince(context.Background(), time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Hosts) != 1 || page.Hosts[0].Ref != "9" {
		t.Fatalf("changed %+v", page.Hosts)
	}
	if len(page.Seen) != 2 || page.Seen[0].Ref != "7" || page.Seen[1].Ref != "9" {
		t.Fatalf("seen %+v", page.Seen)
	}
	s := page.Seen[0]
	if !s.SeenAt.Equal(time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)) || s.EnrolledAt == nil ||
		!s.EnrolledAt.Equal(time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)) || s.HardwareUUID != "u-7" {
		t.Fatalf("host 7 %+v", s)
	}
	if s.PolicyUpdatedAt == nil || !s.PolicyUpdatedAt.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("host 7 policy_updated_at %v", s.PolicyUpdatedAt)
	}
	if page.Seen[1].PolicyUpdatedAt == nil || !page.Seen[1].PolicyUpdatedAt.Equal(time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("host 9 policy_updated_at %v", page.Seen[1].PolicyUpdatedAt)
	}
	if !page.Seen[1].SeenAt.IsZero() || page.Seen[1].EnrolledAt != nil {
		t.Fatalf("host 9 %+v", page.Seen[1])
	}
}

// TestResolveDeviceToken (ADR 0057, H5): one request to Fleet's device endpoint; 401 and 404 are not found, any other
// failure is upstream unavailable without a retry, a malformed token is refused without a request, and no error text
// carries the token.
func TestResolveDeviceToken(t *testing.T) {
	var calls atomic.Int32
	status, body := http.StatusOK, `{"host": {"id": 42, "uuid": "04BD9B98-B777-DE46-BB10-C2FC5696CFA7"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/latest/fleet/device/"+deviceToken || r.URL.Query().Get("exclude_software") != "true" {
			t.Errorf("request %s", r.URL)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := client(srv.URL)
	ctx := context.Background()
	ref, hw, err := c.ResolveDeviceToken(ctx, deviceToken)
	if err != nil || ref != "42" || hw != "04bd9b98-b777-de46-bb10-c2fc5696cfa7" {
		t.Fatalf("resolved %q %q %v", ref, hw, err)
	}
	for code, want := range map[int]error{http.StatusUnauthorized: problem.NotFound, http.StatusNotFound: problem.NotFound,
		http.StatusInternalServerError: problem.UpstreamUnavailable, http.StatusForbidden: problem.UpstreamUnavailable} {
		status, body = code, `{"message": "`+deviceToken+`", "errors": [{"reason": "`+deviceToken+`"}]}`
		calls.Store(0)
		_, _, err := c.ResolveDeviceToken(ctx, deviceToken)
		if !errors.Is(err, want) || calls.Load() != 1 {
			t.Errorf("HTTP %d: %v after %d requests, want %v after one", code, err, calls.Load(), want)
		}
		if err != nil && strings.Contains(err.Error(), deviceToken) {
			t.Errorf("HTTP %d: the error carries the token: %v", code, err)
		}
	}
	status, body = http.StatusOK, `{"host": {}}`
	if _, _, err := c.ResolveDeviceToken(ctx, deviceToken); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Errorf("a 200 without host.id: %v", err)
	}
	calls.Store(0)
	for _, bad := range []string{"", "../../hosts", strings.ToUpper(deviceToken), deviceToken + "0"} {
		if _, _, err := c.ResolveDeviceToken(ctx, bad); !errors.Is(err, problem.NotFound) {
			t.Errorf("malformed %q: %v", bad, err)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("%d requests for malformed tokens", calls.Load())
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	_, _, err = client("http://"+addr).ResolveDeviceToken(ctx, deviceToken)
	if !errors.Is(err, problem.UpstreamUnavailable) || strings.Contains(err.Error(), deviceToken) {
		t.Fatalf("transport error %v", err)
	}
}
