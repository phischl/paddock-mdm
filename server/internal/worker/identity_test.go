package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// failingBrand fails its first calls, then succeeds.
type failingBrand struct {
	failures int32
	calls    atomic.Int32
}

func (b *failingBrand) EnsureBrandFlows(context.Context) error {
	if b.calls.Add(1) <= b.failures {
		return errors.New("flow paddock-recovery missing")
	}
	return nil
}

// TestBrandFlowsRetryUntilSet: a failure (blueprints not applied yet at the first start) is retried soon; once the
// flows are set, the next round waits for the reconcile interval (plan M3.1 decision 5).
func TestBrandFlowsRetryUntilSet(t *testing.T) {
	brand := &failingBrand{failures: 2}
	i := &Identity{brand: brand, brandRetry: time.Millisecond, reconcile: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- i.RunBrandFlows(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for brand.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("%d calls after 5 s, want 3", brand.calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := brand.calls.Load(); n != 3 {
		t.Fatalf("%d calls, want 3 (no retry after success)", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
