package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// acks records the settlement of fake deliveries.
type acks struct {
	mu    sync.Mutex
	acked map[uint64]bool
}

func (a *acks) Ack(tag uint64, _ bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acked[tag] = true
	return nil
}
func (a *acks) Nack(uint64, bool, bool) error { return nil }
func (a *acks) Reject(uint64, bool) error     { return nil }

// TestConsumeConcurrently: deliveries are handled n at a time and each is acknowledged; a closed delivery channel ends
// every loop with an error, so the consumer reconnects.
func TestConsumeConcurrently(t *testing.T) {
	a := &acks{acked: map[uint64]bool{}}
	deliveries := make(chan amqp.Delivery, 32)
	for i := range 32 {
		deliveries <- amqp.Delivery{Acknowledger: a, DeliveryTag: uint64(i + 1)}
	}
	close(deliveries)
	var running, peak atomic.Int32
	err := consumeConcurrently(context.Background(), deliveries, 4, time.Millisecond, func(context.Context, amqp.Delivery) outcome {
		n := running.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		return ack
	})
	if err == nil {
		t.Fatal("closed delivery channel: want an error")
	}
	if len(a.acked) != 32 {
		t.Fatalf("acknowledged %d of 32 deliveries", len(a.acked))
	}
	if p := peak.Load(); p != 4 {
		t.Fatalf("peak concurrency %d, want 4", p)
	}
}

// TestConsumeConcurrentlyStops: a cancelled context ends every loop without an error.
func TestConsumeConcurrentlyStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- consumeConcurrently(ctx, make(chan amqp.Delivery), 4, time.Millisecond, func(context.Context, amqp.Delivery) outcome { return ack })
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("consumeConcurrently did not return after cancel")
	}
}
