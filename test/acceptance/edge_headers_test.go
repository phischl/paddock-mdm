package acceptance

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestEdgeHeaders is the gate of plan M12h decision 16 (ADR 0051 decision 6): every site of the edge answers with
// nosniff, a Referrer-Policy, HSTS with includeSubDomains and X-Frame-Options DENY, on proxied answers and on the
// edge's own refusals alike.
func TestEdgeHeaders(t *testing.T) {
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	for site, target := range map[string]string{
		"admin":         stack.AdminURL() + "/",
		"admin API":     stack.AdminURL() + "/api/v1/me",
		"auth":          stack.AuthURL() + "/",
		"device":        stack.DeviceURL() + "/v1/enroll/x",
		"bundles":       stack.BundlesURL() + "/",
		"bundles proxy": stack.BundlesURL() + "/packages/none",
		"fleet":         stack.FleetURL() + "/",
		"fleet proxy":   stack.FleetURL() + "/api/fleet/orbit/ping",
	} {
		req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", site, err)
		}
		_ = res.Body.Close()
		h := res.Header
		if got := h.Values("X-Content-Type-Options"); len(got) != 1 || got[0] != "nosniff" {
			t.Errorf("%s (HTTP %d): X-Content-Type-Options %q", site, res.StatusCode, got)
		}
		if got := h.Values("Strict-Transport-Security"); len(got) != 1 || got[0] != "max-age=31536000; includeSubDomains" {
			t.Errorf("%s (HTTP %d): Strict-Transport-Security %q", site, res.StatusCode, got)
		}
		if got := h.Values("X-Frame-Options"); len(got) != 1 || got[0] != "DENY" {
			t.Errorf("%s (HTTP %d): X-Frame-Options %q", site, res.StatusCode, got)
		}
		// The edge sets strict-origin-when-cross-origin; an upstream that sends a stricter policy keeps it (the admin API
		// sends no-referrer).
		switch got := h.Values("Referrer-Policy"); {
		case len(got) != 1:
			t.Errorf("%s (HTTP %d): Referrer-Policy %q", site, res.StatusCode, got)
		case got[0] != "strict-origin-when-cross-origin" && got[0] != "no-referrer" && got[0] != "same-origin" &&
			got[0] != "strict-origin":
			t.Errorf("%s (HTTP %d): Referrer-Policy %q is weaker than strict-origin-when-cross-origin", site, res.StatusCode, got[0])
		}
	}
}

// TestEdgeBodyLimits covers the body limits per site of plan M12h decision 16: 3 MiB to the admin API, 2 MiB to the
// device API and 2 MiB to Authentik are refused by the edge with 413; a 200 MiB platform upload passes the edge (the
// api answers it), 257 MiB does not.
func TestEdgeBodyLimits(t *testing.T) {
	for _, c := range []struct {
		name, method, target string
		size                 int64
		refused              bool
	}{
		{"3 MiB to the admin API", http.MethodPost, stack.AdminURL() + "/api/v1/devices", 3 << 20, true},
		{"2 MiB to the device API", http.MethodPost, stack.DeviceURL() + "/v1/checkin", 2 << 20, true},
		{"2 MiB to Authentik", http.MethodPost, stack.AuthURL() + "/api/v3/flows/executor/x/", 2 << 20, true},
		{"200 MiB agent release upload", http.MethodPut, stack.AdminURL() + "/api/platform/v1/agent-releases/0.0.0-edge/artifacts/amd64", 200 << 20, false},
		{"257 MiB agent release upload", http.MethodPut, stack.AdminURL() + "/api/platform/v1/agent-releases/0.0.0-edge/artifacts/amd64", 257 << 20, true},
	} {
		code := edgeSendZeros(t, c.method, c.target, c.size)
		if refused := code == http.StatusRequestEntityTooLarge; refused != c.refused {
			t.Errorf("%s: HTTP %d, want refused by the edge = %v", c.name, code, c.refused)
		}
	}
}

// edgeSendZeros sends size zero bytes with a declared Content-Length through Caddy and returns the HTTP status; the
// body is streamed, so a large size costs no memory. It reads the answer on a raw connection while the body is still
// being written: the api answers the unauthenticated upload without reading it and the connection is then reset, so
// net/http's client could report the broken pipe instead of the status that already arrived.
func edgeSendZeros(t *testing.T, method, target string, size int64) int {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	conn := edgeDial(testContext(t, 5*time.Minute), t, u)
	if err := conn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	head := method + " " + u.RequestURI() + " HTTP/1.1\r\nHost: " + u.Host +
		"\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.FormatInt(size, 10) +
		"\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(conn, io.LimitReader(zeros{}, size)) }()
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

// edgeDial opens an HTTP/1.1 TLS connection to the edge site of u, trusting the stack's CA; the caller writes the
// request by hand.
func edgeDial(ctx context.Context, t *testing.T, u *url.URL) *tls.Conn {
	t.Helper()
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	cfg := client.Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.ServerName = host
	cfg.NextProtos = []string{"http/1.1"}
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, cfg)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	return conn
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestSlowBody covers plan M12h decision 15 (ADR 0051 decision 6): a request body sent at one byte per second does not
// hold a gateway goroutine beyond the server's 60 s ReadTimeout; the request is answered or the connection is closed
// long before the announced body could have arrived.
func TestSlowBody(t *testing.T) {
	const announced = 300
	u, err := url.Parse(stack.DeviceURL())
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 3*time.Minute)
	conn := edgeDial(ctx, t, u)
	start := time.Now()
	head := "POST /v1/checkin HTTP/1.1\r\nHost: " + u.Host + "\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(announced) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			line = "closed: " + err.Error()
		}
		done <- strings.TrimSpace(line)
	}()
	go func(ctx context.Context) {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for range announced {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if _, err := conn.Write([]byte(" ")); err != nil {
					return
				}
			}
		}
	}(ctx)
	select {
	case line := <-done:
		elapsed := time.Since(start)
		// A 429 or any other early answer would end the request before the ReadTimeout and prove nothing about it.
		if strings.Contains(line, " 429 ") {
			t.Fatalf("slow body answered %q after %s: rate limited, the ReadTimeout was not reached", line, elapsed)
		}
		if elapsed < 55*time.Second || elapsed > 100*time.Second {
			t.Fatalf("slow body ended after %s (%s), want about the 60 s ReadTimeout", elapsed, line)
		}
		t.Logf("slow body ended after %s: %s", elapsed.Round(time.Second), line)
	case <-time.After(150 * time.Second):
		t.Fatal("slow body still open after 150 s, want it ended after the 60 s ReadTimeout")
	}
}
