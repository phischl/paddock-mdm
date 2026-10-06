package mq_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/mqtest"
)

func TestStatePartition(t *testing.T) {
	seen := map[string]bool{}
	for range 2000 {
		org := uuid.New()
		p := mq.StatePartition(org)
		if p != mq.StatePartition(org) {
			t.Fatal("partition is not deterministic")
		}
		seen[p] = true
	}
	keys := mq.StateRoutingKeys()
	if len(keys) != 17 || keys[0] != "p00" || keys[15] != "p15" || keys[16] != "priority" {
		t.Fatalf("routing keys %v", keys)
	}
	for _, k := range keys[:16] {
		if !seen[k] {
			t.Errorf("partition %s never chosen for 2000 organizations", k)
		}
	}
	if len(seen) != 16 {
		t.Fatalf("partitions outside p00..p15: %v", seen)
	}
}

// TestProvisionTopology: provisioning is idempotent, ingest and state messages reach their queues, and rejected
// messages are dead-lettered to dlq.<queue>.
func TestProvisionTopology(t *testing.T) {
	broker := mqtest.Start(t)
	ctx := context.Background()
	if err := mq.Provision(ctx, broker.Config, mq.ProvisionOptions{AuditQueueMaxBytes: 1 << 30}); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	pub := mq.NewPublisher(broker.Config)
	defer pub.Close()
	org := uuid.New()
	res, err := pub.PublishBatch(ctx, mq.ExchangeIngest, []mq.Message{
		{RoutingKey: mq.IngestRoutingKey(mq.IngestHeartbeat, org), MessageID: "hb-1", Body: []byte(`{}`)},
		{RoutingKey: mq.IngestRoutingKey(mq.IngestEnroll, org), MessageID: "en-1", Body: []byte(`{}`)},
		{RoutingKey: "ingest.unknown." + org.String(), MessageID: "x", Body: []byte(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res[0] != nil || res[1] != nil || res[2] == nil {
		t.Fatalf("publish results %v", res)
	}
	res, err = pub.PublishBatch(ctx, mq.ExchangeState, []mq.Message{{RoutingKey: mq.StatePartition(org), MessageID: "st-1", Body: []byte(`{}`)}})
	if err != nil || res[0] != nil {
		t.Fatalf("state publish: %v %v", res, err)
	}

	conn, err := mq.Dial(broker.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	get := func(queue string) amqp.Delivery {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			d, ok, err := ch.Get(queue, false)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				return d
			}
		}
		t.Fatalf("no message in %s", queue)
		return amqp.Delivery{}
	}
	if d := get(mq.IngestQueue(mq.IngestHeartbeat)); d.MessageId != "hb-1" {
		t.Fatalf("heartbeat queue got %s", d.MessageId)
	} else if err := d.Reject(false); err != nil {
		t.Fatal(err)
	}
	if d := get("dlq." + mq.IngestQueue(mq.IngestHeartbeat)); d.MessageId != "hb-1" {
		t.Fatalf("dead-letter queue got %s", d.MessageId)
	}
	if d := get(mq.IngestQueue(mq.IngestEnroll)); d.MessageId != "en-1" {
		t.Fatalf("enroll queue got %s", d.MessageId)
	}
	// Single-active-consumer queues do not support basic.get.
	deliveries, err := ch.Consume(mq.StateQueue(mq.StatePartition(org)), "", false, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-deliveries:
		if d.MessageId != "st-1" {
			t.Fatalf("state queue got %s", d.MessageId)
		}
		if err := d.Reject(false); err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no message in the state queue")
	}
	if d := get("dlq." + mq.StateQueue(mq.StatePartition(org))); d.MessageId != "st-1" {
		t.Fatalf("state dead-letter queue got %s", d.MessageId)
	}
}
