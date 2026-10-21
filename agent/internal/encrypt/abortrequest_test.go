package encrypt_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// clock is the fake time of a waiting subcommand: every sleep advances it and gives the agent goroutine a moment.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	time.Sleep(time.Millisecond)
	return nil
}

type requestResult struct {
	resp encrypt.AbortResponse
	err  error
}

func request(l paths.Layout, c *clock) <-chan requestResult {
	out := make(chan requestResult, 1)
	go func() {
		resp, err := encrypt.RequestAbort(context.Background(), l, "conv", c.Now, c.Sleep)
		out <- requestResult{resp, err}
	}()
	return out
}

// claim waits for the subcommand's request and claims it as the agent does.
func claim(t *testing.T, l paths.Layout, now time.Time) *encrypt.AbortRequest {
	t.Helper()
	for range 5000 {
		req, err := encrypt.ClaimAbortRequest(l, now)
		if err != nil {
			t.Fatal(err)
		}
		if req != nil {
			return req
		}
		time.Sleep(100 * time.Microsecond)
	}
	t.Fatal("no request")
	return nil
}

// TestAbortRequestRoundtrip: the subcommand writes a root-only request, the agent claims it, answers running, then
// done; a response with another nonce is ignored.
func TestAbortRequestRoundtrip(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	c := &clock{now: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	done := request(l, c)
	req := claim(t, l, c.Now())
	if req.ConversionID != "conv" || req.By != "operator" || req.Nonce == "" {
		t.Fatalf("request %+v", req)
	}
	if _, err := os.Stat(l.EncryptAbortRequest()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the claimed request is still there")
	}
	if err := encrypt.WriteAbortResponse(l, encrypt.AbortResponse{Nonce: "other", State: encrypt.AbortDone, Aborted: true}); err != nil {
		t.Fatal(err)
	}
	if err := encrypt.WriteAbortResponse(l, encrypt.AbortResponse{Nonce: req.Nonce, State: encrypt.AbortRunning}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // the subcommand keeps waiting past the pickup bound while the agent works
	if err := encrypt.WriteAbortResponse(l, encrypt.AbortResponse{Nonce: req.Nonce, State: encrypt.AbortDone, Reason: "not_abortable"}); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.resp.Aborted || r.resp.Reason != "not_abortable" {
		t.Fatalf("result %+v", r)
	}
	if _, err := os.Stat(l.EncryptAbortResponse()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("response left behind")
	}
}

// TestAbortRequestNoAgent: without an agent the request is withdrawn after a minute and nothing is left.
func TestAbortRequestNoAgent(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	c := &clock{now: time.Now()}
	r := <-request(l, c)
	if !errors.Is(r.err, encrypt.ErrNoAgent) {
		t.Fatalf("result %+v", r)
	}
	entries, _ := os.ReadDir(l.Join("/var/lib/paddock"))
	if len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
	if req, err := encrypt.ClaimAbortRequest(l, c.Now()); req != nil || err != nil {
		t.Fatalf("an agent could still claim it: %+v %v", req, err)
	}
}

// TestAbortRequestStale: a request older than 30 minutes is removed and ignored.
func TestAbortRequestStale(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	raw, _ := json.Marshal(encrypt.AbortRequest{Nonce: "n", By: "operator", RequestedAt: at})
	if err := os.MkdirAll(l.Join("/var/lib/paddock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.EncryptAbortRequest(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if req, err := encrypt.ClaimAbortRequest(l, at.Add(31*time.Minute)); req != nil || err == nil {
		t.Fatalf("stale request taken: %+v %v", req, err)
	}
	if entries, _ := os.ReadDir(l.Join("/var/lib/paddock")); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

// TestAbortRequestInterrupted: a wait that ends before an agent took the request withdraws it, so that no agent can
// abort after the subcommand gave up; once an agent may have taken it, the outcome is reported unknown.
func TestAbortRequestInterrupted(t *testing.T) {
	interrupted := errors.New("interrupted")
	l := paths.Layout{Root: t.TempDir()}
	_, err := encrypt.RequestAbort(context.Background(), l, "conv", time.Now, func(context.Context, time.Duration) error {
		return interrupted
	})
	if !errors.Is(err, encrypt.ErrWithdrawn) || errors.Is(err, encrypt.ErrOutcomeUnknown) {
		t.Fatalf("before the claim: %v", err)
	}
	if req, err := encrypt.ClaimAbortRequest(l, time.Now()); req != nil || err != nil {
		t.Fatalf("an agent could still claim it: %+v %v", req, err)
	}
	if entries, _ := os.ReadDir(l.Join("/var/lib/paddock")); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}

	l = paths.Layout{Root: t.TempDir()}
	_, err = encrypt.RequestAbort(context.Background(), l, "conv", time.Now, func(context.Context, time.Duration) error {
		if req, _ := encrypt.ClaimAbortRequest(l, time.Now()); req == nil {
			t.Error("no request to claim")
		}
		return interrupted
	})
	if !errors.Is(err, encrypt.ErrOutcomeUnknown) || errors.Is(err, encrypt.ErrWithdrawn) {
		t.Fatalf("after the claim: %v", err)
	}
}
