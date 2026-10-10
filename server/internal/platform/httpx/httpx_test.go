package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

// TestClientIPDerivation: only a trusted peer may name the client, and only through X-Paddock-Client-IP (plan M7a
// decision 5).
func TestClientIPDerivation(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("fd00::/8")}
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
		want    string
	}{
		{"untrusted peer, canonical header", "203.0.113.5:4000", map[string]string{httpx.ClientIPHeader: "198.51.100.1"}, "203.0.113.5"},
		{"untrusted peer, X-Forwarded-For", "203.0.113.5:4000", map[string]string{"X-Forwarded-For": "198.51.100.1"}, "203.0.113.5"},
		{"untrusted peer, CF-Connecting-IP", "203.0.113.5:4000", map[string]string{"CF-Connecting-IP": "198.51.100.1"}, "203.0.113.5"},
		{"trusted peer, canonical header", "172.18.0.3:4000", map[string]string{httpx.ClientIPHeader: "198.51.100.1"}, "198.51.100.1"},
		{"trusted peer, only X-Forwarded-For", "172.18.0.3:4000", map[string]string{"X-Forwarded-For": "198.51.100.1"}, "172.18.0.3"},
		{"trusted peer, only CF-Connecting-IP", "172.18.0.3:4000", map[string]string{"CF-Connecting-IP": "198.51.100.1"}, "172.18.0.3"},
		{"trusted peer, only X-Real-IP", "172.18.0.3:4000", map[string]string{"X-Real-IP": "198.51.100.1"}, "172.18.0.3"},
		{"trusted peer, unparsable header", "172.18.0.3:4000", map[string]string{httpx.ClientIPHeader: "not-an-ip"}, "172.18.0.3"},
		{"trusted peer, no header", "172.18.0.3:4000", nil, "172.18.0.3"},
		{"trusted IPv6 peer, IPv6 header", "[fd00::5]:4000", map[string]string{httpx.ClientIPHeader: "2001:db8::9"}, "2001:db8::9"},
		{"untrusted IPv6 peer", "[2001:db8::7]:4000", map[string]string{httpx.ClientIPHeader: "198.51.100.1"}, "2001:db8::7"},
		{"IPv4-mapped trusted peer", "[::ffff:172.18.0.3]:4000", map[string]string{httpx.ClientIPHeader: "::ffff:198.51.100.1"}, "198.51.100.1"},
		{"zone in header is stripped", "[fd00::5]:4000", map[string]string{httpx.ClientIPHeader: "fe80::1%eth0"}, "fe80::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			var gotAddr netip.Addr
			h := httpx.WithClientIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = httpx.ClientIP(r)
				gotAddr, _ = httpx.ClientAddr(r)
			}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
			if got != tc.want || gotAddr.String() != tc.want {
				t.Fatalf("ClientIP %q, ClientAddr %v, want %q", got, gotAddr, tc.want)
			}
		})
	}
}

// TestClientIPWithoutMiddleware: without WithClientIP no header counts, the peer is the client.
func TestClientIPWithoutMiddleware(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.4:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	r.Header.Set(httpx.ClientIPHeader, "198.51.100.1")
	if got := httpx.ClientIP(r); got != "192.0.2.4" {
		t.Fatalf("ClientIP %q", got)
	}
}

// TestClientIPNoTrustedProxies: an empty list trusts no peer.
func TestClientIPNoTrustedProxies(t *testing.T) {
	var got string
	h := httpx.WithClientIP(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = httpx.ClientIP(r) }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:1"
	r.Header.Set(httpx.ClientIPHeader, "198.51.100.1")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "10.0.0.2" {
		t.Fatalf("ClientIP %q", got)
	}
}
