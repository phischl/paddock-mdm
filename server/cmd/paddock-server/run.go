package main

import (
	"context"
	"sync"
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
