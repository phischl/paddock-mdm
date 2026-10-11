package acceptance

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// sessionWith returns a client that carries p's session and sends headers on every request.
func sessionWith(t *testing.T, p *env.Portal, headers map[string]string) *http.Client {
	t.Helper()
	hc, err := env.HeaderClient(headers)
	if err != nil {
		t.Fatal(err)
	}
	hc.Jar = p.Client.Jar
	return hc
}

// clientIPOf calls GET /api/v1/me at base with headers in p's session and returns the response and its client_ip.
func clientIPOf(t *testing.T, p *env.Portal, base string, headers map[string]string) (env.Response, string) {
	t.Helper()
	res, err := env.Call(testContext(t, time.Minute), sessionWith(t, p, headers), http.MethodGet, base+"/api/v1/me", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var me struct {
		ClientIP string `json:"client_ip"`
	}
	if res.Status == http.StatusOK {
		if err := res.JSON(&me); err != nil {
			t.Fatal(err)
		}
	}
	return res, me.ClientIP
}

// TestEdgeClientIP is gate A2 (plan M7a step 1, AC2, AC6): behind the trusted listener Caddy resolves the client from
// CF-Connecting-IP or X-Forwarded-For (right to left, IPv6 too) and forwards it as X-Paddock-Client-IP, overwriting a
// client-sent one; the edge refuses 203.0.113.0/24 on admin. and on Authentik's administrative paths but not the
// device-code login; on the untrusted listener every header is ignored; device. carries the resolved address to the
// gateway's access log.
func TestEdgeClientIP(t *testing.T) {
	admin := login(t, env.PlatformAdmin)
	trusted, untrusted := stack.AdminURL(), stack.AdminUntrustedURL()

	expectIP := func(base string, headers map[string]string, want string) {
		t.Helper()
		res, got := clientIPOf(t, admin, base, headers)
		if res.Status != http.StatusOK || got != want {
			t.Fatalf("%s %v: HTTP %d client_ip %q, want 200 %q: %s", base, headers, res.Status, got, want, res.Body)
		}
	}
	res, peer := clientIPOf(t, admin, trusted, nil)
	if res.Status != http.StatusOK || peer == "" {
		t.Fatalf("no header: HTTP %d client_ip %q", res.Status, peer)
	}
	t.Logf("peer address P = %s", peer)

	expectIP(trusted, map[string]string{"X-Forwarded-For": "198.51.100.7"}, "198.51.100.7")
	expectIP(trusted, map[string]string{"CF-Connecting-IP": "198.51.100.8"}, "198.51.100.8")
	expectIP(trusted, map[string]string{"CF-Connecting-IP": "198.51.100.8", "X-Forwarded-For": "198.51.100.7"}, "198.51.100.8")
	expectIP(trusted, map[string]string{"X-Forwarded-For": "198.51.100.9, 198.51.100.10"}, "198.51.100.10")
	expectIP(trusted, map[string]string{"X-Forwarded-For": "2001:db8::9"}, "2001:db8::9")
	expectIP(trusted, map[string]string{"X-Paddock-Client-IP": "198.51.100.11"}, peer)

	denied, err := env.Call(testContext(t, time.Minute), sessionWith(t, admin, map[string]string{"X-Forwarded-For": "203.0.113.9"}),
		http.MethodGet, trusted+"/api/v1/me", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != http.StatusForbidden || denied.RequestID != "" || json.Valid(denied.Body) && len(denied.Body) > 0 {
		t.Fatalf("203.0.113.9 on admin.: HTTP %d request ID %q body %q, want an edge 403", denied.Status, denied.RequestID, denied.Body)
	}

	for _, h := range []map[string]string{
		{"X-Forwarded-For": "198.51.100.7"}, {"CF-Connecting-IP": "198.51.100.8"}, {"X-Paddock-Client-IP": "198.51.100.11"},
		{"X-Forwarded-For": "203.0.113.9"},
	} {
		expectIP(untrusted, h, peer)
	}

	t.Run("auth", func(t *testing.T) {
		ctx := testContext(t, 3*time.Minute)
		foreign := map[string]string{"X-Forwarded-For": "203.0.113.9"}
		hc, err := env.HeaderClient(foreign)
		if err != nil {
			t.Fatal(err)
		}
		for path, wantDenied := range map[string]bool{
			"/if/admin/": true, "/api/v3/core/users/me/": true, "/if/user/": true, "/api/v3/root/config/": false,
		} {
			res, err := env.Call(ctx, hc, http.MethodGet, stack.AuthURL()+path, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if (res.Status == http.StatusForbidden) != wantDenied {
				t.Errorf("auth. %s from 203.0.113.9: HTTP %d, want denied=%v", path, res.Status, wantDenied)
			}
		}

		// The device-code login of a device user works from the foreign address (IPA-2).
		da, err := authflow.StartDevice(ctx, hc, stack.AuthURL(), "paddock-device-acme")
		if err != nil {
			t.Fatalf("device authorization from 203.0.113.9: %v", err)
		}
		password, err := env.Password(env.Alice)
		if err != nil {
			t.Fatal(err)
		}
		totp, err := env.TOTP(env.Alice)
		if err != nil {
			t.Fatal(err)
		}
		browser, err := env.HeaderClient(foreign)
		if err != nil {
			t.Fatal(err)
		}
		if stages, err := authflow.ApproveDeviceWith(ctx, browser, da, env.Alice, password, totp); err != nil {
			t.Fatalf("device approval from 203.0.113.9 (a path outside the public list of decision 7?): %v; stages %v", err, stages)
		}
		tokens, err := authflow.PollDeviceToken(ctx, hc, stack.AuthURL(), "paddock-device-acme", da, time.Minute)
		if err != nil {
			t.Fatalf("token from 203.0.113.9: %v", err)
		}
		if _, err := authflow.UserInfo(ctx, hc, stack.AuthURL(), tokens.AccessToken); err != nil {
			t.Fatalf("userinfo from 203.0.113.9: %v", err)
		}

		// The host (a private range) keeps reaching Authentik's API with the bootstrap token.
		ak, err := env.NewAuthentik()
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err := ak.Get(ctx, "/core/users/?page_size=1", &cfg); err != nil {
			t.Fatalf("Authentik API from the host: %v", err)
		}
	})

	t.Run("device", func(t *testing.T) {
		alice := login(t, env.Alice)
		tok := createToken(t, alice, tokenOptions{autoApprove: true})
		hc, err := env.HeaderClient(map[string]string{"X-Forwarded-For": "198.51.100.12"})
		if err != nil {
			t.Fatal(err)
		}
		d := newSimWith(t, tok.EnrollmentConfig, hc)
		ctx := testContext(t, 2*time.Minute)
		if res, err := d.Enroll(ctx, "a2-"+uniqueSuffix()); err != nil || res.Status != http.StatusAccepted {
			t.Fatalf("enroll through device. with X-Forwarded-For: %v HTTP %d %s", err, res.Status, res.Body)
		}
		if s, err := d.WaitEnrollment(testContext(t, 30*time.Second), func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing }); err != nil || s.Status != protocol.EnrollActive {
			t.Fatalf("enrollment %+v: %v", s, err)
		}
		since := time.Now().Add(-5 * time.Second)
		checkinUntil(t, d, 30*time.Second, func(protocol.CheckinResponse) bool { return true })
		waitLog(t, ctx, "paddock-gateway", since, `"ip":"198.51.100.12"`)
	})
}

// waitLog waits until a log line of service since contains want.
func waitLog(t *testing.T, ctx context.Context, service string, since time.Time, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		out, err := stack.Compose(ctx, nil, "logs", "--no-log-prefix", "--since", since.UTC().Format(time.RFC3339), service)
		if err == nil && strings.Contains(out, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s log line with %s since %s (err %v)", service, want, since.Format(time.RFC3339), err)
		}
		time.Sleep(time.Second)
	}
}
