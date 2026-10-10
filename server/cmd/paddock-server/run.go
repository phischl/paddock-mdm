package main

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// runAll runs fns concurrently. The first one to return cancels the others; the first non-nil error is returned.
func runAll(ctx context.Context, fns ...func(ctx context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg       sync.WaitGroup
		once     sync.Once
		firstErr error
	)
	for _, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := fn(ctx)
			once.Do(func() { firstErr = err })
			cancel()
		}()
	}
	wg.Wait()
	return firstErr
}

// retryUntilDone calls fn until it succeeds or ctx ends, waiting first between the attempts and doubling the wait up
// to maxWait; every failure is logged with what. It reports whether fn succeeded.
func retryUntilDone(ctx context.Context, what string, first, maxWait time.Duration, fn func(context.Context) error) bool {
	wait := first
	for {
		err := fn(ctx)
		if err == nil {
			return true
		}
		slog.ErrorContext(ctx, what+" failed; retrying", "error", err, "retry", wait)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
		wait = min(wait*2, maxWait)
	}
}
