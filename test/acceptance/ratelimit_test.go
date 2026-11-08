package acceptance

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// docPrefix returns a random /64 of the IPv6 documentation range: the development stack exempts its private clients
// from the rate limiter, so the gate sends from a documentation address through the trusted edge listener and gets
// the production limits on a budget no other gate shares.
func docPrefix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("2001:db8:%x:%x", binary.BigEndian.Uint16(b[:2]), binary.BigEndian.Uint16(b[2:]))
}

// awayFromWindowEdge waits while the current minute has less than 20 s left, so that a burst lies in one counting
// window: the limiter weighs the previous window by the part of it that is still within the last minute.
func awayFromWindowEdge() {
	if s := time.Now().Unix() % 60; s > 40 {
		time.Sleep(time.Duration(61-s) * time.Second)
	}
}

func expectRateLimited(t *testing.T, what string, res env.Response) {
	t.Helper()
	if res.Status != http.StatusTooManyRequests || res.ProblemCode() != "rate_limited" {
		t.Fatalf("%s: HTTP %d %s, want 429 rate_limited: %s", what, res.Status, res.ProblemCode(), res.Body)
	}
	if n, err := strconv.Atoi(res.Header.Get("Retry-After")); err != nil || n < 1 || n > 60 {
		t.Fatalf("%s: Retry-After %q, want 1–60 seconds", what, res.Header.Get("Retry-After"))
	}
}

// TestRateLimit is the gate of plan M12h decision 7 (AC C3): 21 sign-in starts within a minute from one address are
// answered 429 with Retry-After, also when the address changes inside its IPv6 /64; admin reads above 600 per minute
// of one session are refused while another session is not; /healthz is never limited and a device's check-in is not
// affected by the admin limits.
func TestRateLimit(t *testing.T) {
	ctx := testContext(t, 5*time.Minute)
	prefix := docPrefix(t)

	t.Run("sign-in starts per address", func(t *testing.T) {
		awayFromWindowEdge()
		for i := 1; i <= 21; i++ {
			hc, err := env.HeaderClient(map[string]string{"X-Forwarded-For": fmt.Sprintf("%s::%x", prefix, i)})
			if err != nil {
				t.Fatal(err)
			}
			hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			res, err := env.Call(ctx, hc, http.MethodGet, stack.AdminURL()+"/api/auth/login?return_to=%2F", nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if i <= 20 && res.Status == http.StatusTooManyRequests {
				t.Fatalf("sign-in start %d refused: %s", i, res.Body)
			}
			if i == 21 {
				expectRateLimited(t, "sign-in start 21", res)
			}
		}
	})

	t.Run("admin reads per session", func(t *testing.T) {
		headers := map[string]string{"X-Forwarded-For": prefix + "::1:1"}
		alice := sessionWith(t, login(t, env.Alice), headers)
		bob := sessionWith(t, login(t, env.Bob), headers)
		read := func(hc *http.Client) env.Response {
			res, err := env.Call(ctx, hc, http.MethodGet, stack.AdminURL()+"/api/v1/me", nil, false)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}
		awayFromWindowEdge()
		var (
			mu      sync.Mutex
			refused []int
			wg      sync.WaitGroup
			next    = make(chan struct{})
		)
		for range 20 {
			wg.Go(func() {
				for range next {
					if res := read(alice); res.Status != http.StatusOK {
						mu.Lock()
						refused = append(refused, res.Status)
						mu.Unlock()
					}
				}
			})
		}
		for range 600 {
			next <- struct{}{}
		}
		close(next)
		wg.Wait()
		if len(refused) > 0 {
			t.Fatalf("%d of 600 reads within the limit refused: %v", len(refused), refused)
		}
		expectRateLimited(t, "read 601", read(alice))
		if res := read(bob); res.Status != http.StatusOK {
			t.Fatalf("another session after the first is limited: HTTP %d %s", res.Status, res.Body)
		}
	})

	t.Run("healthz is never limited", func(t *testing.T) {
		for i := range 25 {
			if out, err := stack.Compose(ctx, nil, "exec", "-T", "paddock-api", "/paddock-server", "healthcheck"); err != nil {
				t.Fatalf("healthcheck %d: %v\n%s", i+1, err, out)
			}
		}
	})

	t.Run("device check-ins unaffected by the admin limits", func(t *testing.T) {
		d := activeDevice(t, login(t, env.Alice), "", "ratelimit-"+uniqueSuffix())
		if _, res, err := d.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("check-in: %v HTTP %d %s", err, res.Status, res.Body)
		}
	})
}
