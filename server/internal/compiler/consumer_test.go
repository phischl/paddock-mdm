package compiler

import (
	"context"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

func TestCollectDebounces(t *testing.T) {
	ch := make(chan amqp.Delivery, 10)
	ctx := context.Background()
	go func() {
		for i := range 3 {
			ch <- amqp.Delivery{MessageId: string(rune('a' + i))}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	start := time.Now()
	batch, open := collect(ctx, ch, 100*time.Millisecond, time.Second, 500)
	if !open || len(batch) != 3 {
		t.Fatalf("batch of %d (open %v)", len(batch), open)
	}
	if took := time.Since(start); took < 140*time.Millisecond || took > 600*time.Millisecond {
		t.Fatalf("waited %s, want quiet period after the last message", took)
	}

	// A steady stream is cut at maxWait.
	stream := make(chan amqp.Delivery)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case stream <- amqp.Delivery{}:
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	start = time.Now()
	batch, _ = collect(ctx, stream, 100*time.Millisecond, 300*time.Millisecond, 500)
	close(stop)
	<-stopped
	if took := time.Since(start); took > 500*time.Millisecond || len(batch) < 5 {
		t.Fatalf("steady stream: %d messages after %s", len(batch), took)
	}

	closed := make(chan amqp.Delivery)
	close(closed)
	if _, open := collect(ctx, closed, time.Millisecond, time.Millisecond, 1); open {
		t.Fatal("closed channel reported open")
	}
}
