package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// failingSettings fails its first calls, then succeeds.
type failingSettings struct {
	failures int32
	calls    atomic.Int32
}

func (s *failingSettings) EnsureSettings(context.Context) ([]string, error) {
	if s.calls.Add(1) <= s.failures {
		return nil, errors.New("fleet: HTTP 502")
	}
	return []string{"features"}, nil
}

// TestInventorySettingsRetryUntilChecked: an unreachable Fleet is retried soon; once the settings are checked, the
// next round waits for the round interval (plan M5a decision 2).
func TestInventorySettingsRetryUntilChecked(t *testing.T) {
	s := &failingSettings{failures: 2}
	i := &Inventory{settings: s, every: time.Hour, retry: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- i.RunSettings(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for s.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("%d calls after 5 s, want 3", s.calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := s.calls.Load(); n != 3 {
		t.Fatalf("%d calls, want 3 (no retry after success)", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
