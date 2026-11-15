package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/mqtest"
)

// alpha10WorkerRead is the worker's read pattern before 0.1.0-alpha.11, which has no worker.offboarding: the broker
// of an upgrade before its definitions are applied.
const alpha10WorkerRead = `^(ingest\.(enroll|heartbeat|event|command_result|escrow)|command\.issued)$`

// TestOffboardingConsumerOutsideReadiness (main §45): a broker that refuses worker.offboarding leaves the worker ready,
// the consumer reconnects by itself once the permission appears, and paddock_worker_offboarding_consumer_connected
// follows its state.
func TestOffboardingConsumerOutsideReadiness(t *testing.T) {
	broker := mqtest.Start(t)
	broker.Ctl(t, "add_user", "worker", "worker-pw")
	broker.Ctl(t, "set_permissions", "-p", "paddock", "worker", "^$", "^$", alpha10WorkerRead)
	wc := newWorkerConsumers(broker.As("worker", "worker-pw"))

	if err := consumersReady(wc.ready()); err == nil {
		t.Fatal("ready before any consumer connected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	idle := func(_ context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
		for d := range deliveries {
			_ = d.Ack(false)
		}
		return errors.New("deliveries closed")
	}
	for _, c := range append(wc.ready(), wc.offboarding) {
		wg.Go(func() { _ = c.Run(ctx, idle) })
	}

	waitFor(t, 30*time.Second, "the six ready consumers", func() bool { return consumersReady(wc.ready()) == nil })
	// Long enough for the offboarding consumer's first refused attempts (backoff 1 s, 2 s).
	time.Sleep(4 * time.Second)
	if wc.offboarding.Connected() {
		t.Fatal("the broker did not refuse worker.offboarding; the test proves nothing")
	}
	if err := consumersReady(wc.ready()); err != nil {
		t.Fatalf("a refused worker.offboarding made the worker unready: %v", err)
	}
	if got := offboardingConnectedGauge(t); got != 0 {
		t.Errorf("gauge while refused = %v, want 0", got)
	}

	broker.Ctl(t, "set_permissions", "-p", "paddock", "worker", "^$", "^$", definitionsWorkerRead(t))
	waitFor(t, 60*time.Second, "worker.offboarding after its permission appeared", wc.offboarding.Connected)
	if got := offboardingConnectedGauge(t); got != 1 {
		t.Errorf("gauge once connected = %v, want 1", got)
	}
	if err := consumersReady(wc.ready()); err != nil {
		t.Errorf("not ready after the reconnect: %v", err)
	}
}

func waitFor(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not after %s", what, limit)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// definitionsWorkerRead is the worker's read pattern of the deployment's definitions.
func definitionsWorkerRead(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../../deploy/compose/rabbitmq/definitions.json.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var defs struct {
		Permissions []struct{ User, Read string } `json:"permissions"`
	}
	if err := json.Unmarshal(raw, &defs); err != nil {
		t.Fatal(err)
	}
	for _, p := range defs.Permissions {
		if p.User == "worker" {
			return p.Read
		}
	}
	t.Fatal("the definitions give the worker no permissions")
	return ""
}

func offboardingConnectedGauge(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "paddock_worker_offboarding_consumer_connected" && len(f.GetMetric()) == 1 {
			return f.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("paddock_worker_offboarding_consumer_connected is not registered")
	return 0
}
