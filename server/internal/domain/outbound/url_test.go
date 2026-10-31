package outbound_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// stubResolver resolves names from a map; a missing name fails.
type stubResolver map[string][]netip.Addr

func (s stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	a, ok := s[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

// representative returns an address inside p.
func representative(p netip.Prefix) netip.Addr {
	a := p.Addr()
	if p.Bits() < a.BitLen() {
		a = a.Next()
	}
	return a
}

// TestValidateWebhookURL covers ADR 0031 decision 12 with a stub resolver.
func TestValidateWebhookURL(t *testing.T) {
	ctx := context.Background()
	res := stubResolver{
		"hooks.example.org": addrs("93.184.215.14"),
		"mixed.example.org": addrs("93.184.215.14", "10.1.2.3"),
	}
	p := outbound.Policy{Resolver: res}
	for _, ok := range []string{
		"https://hooks.example.org/x",
		"https://hooks.example.org:8443/x?token=a",
		"https://hooks.example.org:443/",
		"https://93.184.215.14/x",
	} {
		if err := p.Validate(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	bad := []string{
		"http://hooks.example.org/x",
		"https://user:pw@hooks.example.org/x",
		"https://user@hooks.example.org/x",
		"https://hooks.example.org:80/x",
		"https://hooks.example.org:1023/x",
		"https://hooks.example.org:99999/x",
		"https://mixed.example.org/x",
		"https://unknown.example.org/x",
		"https:///x",
		"ftp://hooks.example.org/x",
		"://broken",
	}
	for _, prefix := range outbound.DeniedPrefixes {
		a := representative(prefix)
		name := "denied-" + a.StringExpanded() + ".example.org"
		res[name] = []netip.Addr{a}
		host := a.String()
		if a.Is6() {
			host = "[" + host + "]"
		}
		bad = append(bad, "https://"+host+"/x", "https://"+name+"/x")
	}
	for _, b := range bad {
		err := p.Validate(ctx, b)
		if !errors.Is(err, outbound.ErrInvalidURL) {
			t.Errorf("%s: err %v, want ErrInvalidURL", b, err)
			continue
		}
		if u, perr := url.Parse(b); perr == nil && u.RawQuery != "" && strings.Contains(err.Error(), u.RawQuery) {
			t.Errorf("%s: the error repeats the query", b)
		}
	}

	for _, a := range []string{"64:ff9b::a00:1", "2002:a00:1::1", "2001:0:4136:e378:8000:63bf:f5ff:fffe"} {
		if !outbound.Denied(netip.MustParseAddr(a)) {
			t.Errorf("%s (IPv6 embedding an IPv4 address) is not denied", a)
		}
	}
	if outbound.Denied(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Error("a public IPv6 address in 2001::/16 outside Teredo is denied")
	}

	dev := outbound.Policy{AllowPrivate: true, Resolver: res}
	for _, ok := range []string{"http://mixed.example.org:8080/x", "https://10.0.0.1:9000/x"} {
		if err := dev.Validate(ctx, ok); err != nil {
			t.Errorf("allowPrivate %s: %v", ok, err)
		}
	}
	if err := dev.Validate(ctx, "https://u:p@10.0.0.1:9000/x"); err == nil {
		t.Error("allowPrivate admits userinfo")
	}
}

// TestSafeTransport: the dial refuses a denied address unless allowPrivate; the client refuses redirects.
func TestSafeTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	strict := &http.Client{Transport: outbound.SafeTransport(false)}
	resp, err := strict.Get(srv.URL + "/ok")
	closeBody(resp)
	if !errors.Is(err, outbound.ErrDeniedAddress) {
		t.Fatalf("dial of 127.0.0.1 without allowPrivate: %v, want ErrDeniedAddress", err)
	}
	named := outbound.Policy{Resolver: stubResolver{"sink.example.org": addrs("127.0.0.1")}}.Client()
	u, _ := url.Parse(srv.URL)
	resp, err = named.Get("http://sink.example.org:" + u.Port() + "/ok")
	closeBody(resp)
	if !errors.Is(err, outbound.ErrDeniedAddress) {
		t.Fatalf("dial of a name resolving to 127.0.0.1: %v, want ErrDeniedAddress", err)
	}

	dev := outbound.Policy{AllowPrivate: true}.Client()
	resp, err = dev.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("allowPrivate: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp, err = dev.Get(srv.URL + "/redirect")
	if !errors.Is(err, outbound.ErrRedirect) {
		t.Fatalf("redirect: %v, want ErrRedirect", err)
	}
	closeBody(resp)

	tr := outbound.SafeTransport(false)
	if tr.Proxy != nil || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Error("the transport uses a proxy or allows TLS below 1.2")
	}
}

// TestDisplayURL: scheme and host, the path and query masked, never shown.
func TestDisplayURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://hooks.slack.com/services/T0/B0/secret": "https://hooks.slack.com/…",
		"https://hooks.slack.com?token=secret":          "https://hooks.slack.com/…",
		"https://hooks.slack.com/":                      "https://hooks.slack.com",
		"https://hooks.slack.com":                       "https://hooks.slack.com",
		"https://siem.example.org:8443/ingest?k=s":      "https://siem.example.org:8443/…",
		"https://user:pw@hooks.example.org/x":           "https://hooks.example.org/…",
		"not a url":                                     "",
	} {
		if got := outbound.DisplayURL(in); got != want {
			t.Errorf("DisplayURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func closeBody(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}
