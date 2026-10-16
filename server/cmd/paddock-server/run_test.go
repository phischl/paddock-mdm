package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRetryUntilDone: failures are retried with a growing wait until the call succeeds; a cancelled context stops
// the retries.
func TestRetryUntilDone(t *testing.T) {
	var calls []time.Time
	ok := retryUntilDone(context.Background(), "test", 5*time.Millisecond, 20*time.Millisecond, func(context.Context) error {
		calls = append(calls, time.Now())
		if len(calls) < 4 {
			return errors.New("database down")
		}
		return nil
	})
	if !ok || len(calls) != 4 {
		t.Fatalf("ok %v after %d calls, want true after 4", ok, len(calls))
	}
	for i, want := range []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond} {
		if d := calls[i+1].Sub(calls[i]); d < want {
			t.Fatalf("wait %d: %v, want at least %v", i+1, d, want)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	done := make(chan bool)
	go func() {
		done <- retryUntilDone(ctx, "test", time.Millisecond, time.Millisecond, func(context.Context) error {
			n++
			if n == 3 {
				cancel()
			}
			return errors.New("database down")
		})
	}()
	select {
	case ok := <-done:
		if ok || n != 3 {
			t.Fatalf("ok %v after %d calls, want false after 3", ok, n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retries do not stop when the context ends")
	}
}

// TestNewHTTPServer: the api, gateway and escrow-reader servers bound reading a request to 60 s and writing the
// response to 120 s next to the header and idle timeouts.
func TestNewHTTPServer(t *testing.T) {
	srv := newHTTPServer(":8080", nil)
	if srv.Addr != ":8080" {
		t.Errorf("Addr = %q", srv.Addr)
	}
	for name, got := range map[string]struct{ got, want time.Duration }{
		"ReadHeaderTimeout": {srv.ReadHeaderTimeout, 10 * time.Second},
		"ReadTimeout":       {srv.ReadTimeout, 60 * time.Second},
		"WriteTimeout":      {srv.WriteTimeout, 120 * time.Second},
		"IdleTimeout":       {srv.IdleTimeout, 2 * time.Minute},
	} {
		if got.got != got.want {
			t.Errorf("%s = %s, want %s", name, got.got, got.want)
		}
	}
}
